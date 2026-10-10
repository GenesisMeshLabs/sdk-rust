//! The evidence outbox (v1.2.0): signed execution records the NA has not yet
//! admitted, kept in durable storage the caller supplies.
//!
//! With an outbox configured ([`ClientOptions::with_outbox`](crate::ClientOptions::with_outbox)),
//! [`governed_action`](crate::governed_action) writes its signed record here
//! before submitting it, and removes it once the NA admits it. A record whose
//! submission failed stays pending, and
//! [`EvidenceStoreClient::flush_pending`](crate::EvidenceStoreClient::flush_pending)
//! submits it later, in order. A record the NA refuses for good is kept as a
//! dead letter with the refusal code; it is never dropped. The outbox holds
//! signed metadata only, never secret values, but it must be durable and
//! private.

use std::{
    collections::HashMap,
    fs,
    future::Future,
    io::{self, Write as _},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Mutex,
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::GenesisMeshError;

/// Why the NA, or the transport, refused a submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SubmissionFailure {
    /// HTTP status; 0 when no response arrived (network error, timeout) or
    /// the SDK refused it.
    pub status: u16,
    /// The NA's error code, or the SDK's.
    pub code: String,
    /// The error message.
    pub message: String,
}

/// Where an outbox entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutboxState {
    /// To submit.
    Pending,
    /// Refused for good; kept, never dropped.
    DeadLetter,
}

/// One signed record in the outbox. The TypeScript SDK reads and writes the
/// same JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OutboxEntry {
    /// The record's `evidence_id`.
    pub id: String,
    /// The signed record, exactly as it will be submitted.
    pub evidence: Value,
    /// Pending or dead letter.
    pub state: OutboxState,
    /// Submissions attempted so far.
    pub attempts: u32,
    /// When it was added (RFC 3339, UTC).
    pub queued_at: String,
    /// Earliest time `flush_pending` retries it; `None` when it has not failed.
    pub next_attempt_at: Option<String>,
    /// The last submission error.
    pub last_error: Option<SubmissionFailure>,
}

impl OutboxEntry {
    /// A new pending entry for a signed record.
    pub fn new(evidence: Value) -> Self {
        Self {
            id: evidence["evidence_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            evidence,
            state: OutboxState::Pending,
            attempts: 0,
            queued_at: timestamp(Utc::now()),
            next_attempt_at: None,
            last_error: None,
        }
    }

    /// Due for an attempt at `now`: never failed, past its backoff, or with a
    /// retry time that does not parse.
    pub(crate) fn due(&self, now: DateTime<Utc>) -> bool {
        self.next_attempt_at
            .as_deref()
            .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
            .is_none_or(|at| at.with_timezone(&Utc) <= now)
    }
}

/// What an [`EvidenceOutbox`] method returns: a boxed future, so storage
/// backed by a database or a queue can do asynchronous work.
pub type OutboxFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Durable storage for outbox entries. Implement it over a database or a
/// queue when [`FileOutbox`] does not fit. Every method must be durable once
/// its future resolves, `list` must return entries in the order they were
/// added, and one store serves one process at a time.
pub trait EvidenceOutbox: Send + Sync + std::fmt::Debug {
    /// Store a new entry; refuse an `id` already stored.
    fn add<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()>;
    /// Replace the stored entry with the same `id`; nothing when it is gone.
    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()>;
    /// Remove an entry; nothing when it is gone.
    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()>;
    /// Every entry, in the order added.
    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>>;
}

/// What became of a record handed to the outbox: the NA's acknowledgement
/// when it was admitted (`status` `recorded` or `duplicate`), otherwise the
/// outbox entry holding it (pending or dead letter).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Delivery {
    /// The NA's acknowledgement.
    pub submission: Option<Value>,
    /// The outbox entry, when the NA has not admitted the record.
    pub queued: Option<OutboxEntry>,
}

impl Delivery {
    pub(crate) fn admitted(ack: Value) -> Self {
        Self {
            submission: Some(ack),
            queued: None,
        }
    }

    pub(crate) fn queued(entry: OutboxEntry) -> Self {
        Self {
            submission: None,
            queued: Some(entry),
        }
    }
}

/// What one `flush_pending` run did.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct FlushReport {
    /// Entries the NA admitted (or already held), now removed from the outbox.
    pub admitted: Vec<OutboxEntry>,
    /// Entries still pending, in order: not yet due, behind a pending record,
    /// or failed again.
    pub pending: Vec<OutboxEntry>,
    /// Entries this run moved to the dead letters.
    pub dead_lettered: Vec<OutboxEntry>,
}

/// Local refusal code for a record whose predecessor in its chain is a dead
/// letter.
pub const PREDECESSOR_DEAD_LETTERED: &str = "evidence_predecessor_dead_lettered";

/// The NA's refusals that no retry of the same record can overcome. Every
/// other failure (network, timeout, `5xx`, `429`, an unknown or not yet
/// registered executor key, a chain gap behind a record not yet admitted, a
/// disabled store, a proxy's error page) is retried.
pub const PERMANENT_REFUSALS: [&str; 11] = [
    "invalid_evidence",
    "evidence_malformed",
    "evidence_invalid_signature",
    "evidence_decision_denied",
    "evidence_decision_mismatch",
    "evidence_outside_decision_window",
    "evidence_capability_mismatch",
    "evidence_chain_mismatch",
    "resource_chain_mismatch",
    "evidence_conflict",
    "evidence_secret_material",
];

/// The submission error as stored, and whether a later retry may succeed.
pub fn classify_submission_error(err: &GenesisMeshError) -> (SubmissionFailure, bool) {
    let status = match err {
        GenesisMeshError::BadRequest { .. } => 400,
        GenesisMeshError::Unauthorized { .. } => 401,
        GenesisMeshError::NotFound { .. } => 404,
        GenesisMeshError::Validation { .. } => 422,
        GenesisMeshError::RateLimit { .. } => 429,
        GenesisMeshError::Http { status, .. } => *status,
        _ => 0,
    };
    let failure = SubmissionFailure {
        status,
        code: err.code().to_owned(),
        message: err.to_string(),
    };
    let refused =
        PERMANENT_REFUSALS.contains(&err.code()) && (status == 0 || (400..500).contains(&status));
    (failure, !refused)
}

/// Delay before the next attempt after `attempts` failures: 5 s, doubling, at
/// most 15 minutes.
pub fn retry_delay(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    Duration::from_secs((5_u64 << doublings).min(15 * 60))
}

pub(crate) fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn exists(id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("outbox entry {id} exists"),
    )
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An outbox in memory. Not durable: everything in it is lost when the
/// process exits. For tests only.
#[derive(Debug, Default)]
pub struct MemoryOutbox {
    entries: Mutex<Vec<OutboxEntry>>,
}

impl EvidenceOutbox for MemoryOutbox {
    fn add<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            let mut entries = lock(&self.entries);
            if entries.iter().any(|e| e.id == entry.id) {
                return Err(exists(&entry.id));
            }
            entries.push(entry.clone());
            Ok(())
        })
    }

    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            if let Some(stored) = lock(&self.entries).iter_mut().find(|e| e.id == entry.id) {
                *stored = entry.clone();
            }
            Ok(())
        })
    }

    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            lock(&self.entries).retain(|e| e.id != id);
            Ok(())
        })
    }

    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>> {
        Box::pin(async move { Ok(lock(&self.entries).clone()) })
    }
}

const FORMAT: &str = "gm.evidence.outbox.v1";

#[derive(Debug, Clone)]
struct Stored {
    file: String,
    sequence: u64,
    entry: OutboxEntry,
}

/// The default outbox: one JSON file per entry in a directory, written to a
/// temporary file, synced and renamed into place. File names keep the order
/// entries were added. The TypeScript SDK reads and writes the same format.
///
/// One process uses a directory at a time: the directory is read once, then
/// kept in memory. A temporary file left by a crash is recovered (an entry
/// that was being added) or removed (an update that did not finish) on that
/// first read. A directory the outbox creates is `0700` and its files `0600`
/// on Unix; on Windows, and for a directory that already exists, restrict
/// access to it yourself. Its file operations are synchronous and brief, and
/// run on the caller's task.
#[derive(Debug)]
pub struct FileOutbox {
    directory: PathBuf,
    stored: Mutex<Option<HashMap<String, Stored>>>,
}

impl FileOutbox {
    /// An outbox in `directory`, created on first use.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            stored: Mutex::new(None),
        }
    }

    /// The directory holding the entries.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Run `f` on the entries, reading the directory first if needed.
    fn with<T>(
        &self,
        f: impl FnOnce(&mut HashMap<String, Stored>) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut guard = lock(&self.stored);
        if guard.is_none() {
            *guard = Some(self.read()?);
        }
        f(guard.as_mut().expect("loaded"))
    }

    fn read(&self) -> io::Result<HashMap<String, Stored>> {
        create_private_dir(&self.directory)?;
        let names = || -> io::Result<Vec<String>> {
            fs::read_dir(&self.directory)?
                .map(|item| Ok(item?.file_name().to_string_lossy().into_owned()))
                .collect()
        };
        let mut found = names()?;
        let mut recovered = false;
        for name in &found {
            let Some(target) = temp_target(name) else {
                continue;
            };
            let path = self.directory.join(name);
            let complete = fs::read_to_string(&path)
                .ok()
                .and_then(|text| parse_entry(&text))
                .is_some();
            if complete && !found.iter().any(|n| n == target) {
                fs::rename(&path, self.directory.join(target))?;
            } else {
                fs::remove_file(&path)?;
            }
            recovered = true;
        }
        if recovered {
            sync_dir(&self.directory)?;
            found = names()?;
        }
        let mut stored = HashMap::new();
        for file in found {
            let Some((sequence, stem)) = parse_entry_file(&file) else {
                continue;
            };
            let text = fs::read_to_string(self.directory.join(&file))?;
            let entry = parse_entry(&text).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("outbox file {file} is unreadable or not {FORMAT}"),
                )
            })?;
            stored.insert(
                stem,
                Stored {
                    file,
                    sequence,
                    entry,
                },
            );
        }
        Ok(stored)
    }

    fn write(&self, file: &str, entry: &OutboxEntry) -> io::Result<()> {
        let temporary = self
            .directory
            .join(format!(".{file}.{}.tmp", Uuid::new_v4().simple()));
        let body = serde_json::to_string_pretty(&json!({"format": FORMAT, "entry": entry}))
            .map_err(io::Error::other)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut handle = options.open(&temporary)?;
        handle.write_all(body.as_bytes())?;
        handle.write_all(b"\n")?;
        handle.sync_all()?;
        drop(handle);
        fs::rename(&temporary, self.directory.join(file))?;
        sync_dir(&self.directory)
    }
}

impl EvidenceOutbox for FileOutbox {
    fn add<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            self.with(|stored| {
                let stem = file_stem(&entry.id);
                if stored.contains_key(&stem) {
                    return Err(exists(&entry.id));
                }
                let sequence = stored.values().map(|s| s.sequence).max().unwrap_or(0) + 1;
                let file = format!("{sequence:012}-{stem}.json");
                self.write(&file, entry)?;
                stored.insert(
                    stem,
                    Stored {
                        file,
                        sequence,
                        entry: entry.clone(),
                    },
                );
                Ok(())
            })
        })
    }

    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            self.with(|stored| {
                if let Some(found) = stored.get_mut(&file_stem(&entry.id)) {
                    self.write(&found.file, entry)?;
                    found.entry = entry.clone();
                }
                Ok(())
            })
        })
    }

    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        Box::pin(async move {
            self.with(|stored| {
                let stem = file_stem(id);
                if let Some(found) = stored.get(&stem) {
                    match fs::remove_file(self.directory.join(&found.file)) {
                        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
                        _ => sync_dir(&self.directory)?,
                    }
                    stored.remove(&stem);
                }
                Ok(())
            })
        })
    }

    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>> {
        Box::pin(async move {
            self.with(|stored| {
                let mut entries: Vec<&Stored> = stored.values().collect();
                entries.sort_by(|a, b| a.sequence.cmp(&b.sequence).then(a.file.cmp(&b.file)));
                Ok(entries.into_iter().map(|s| s.entry.clone()).collect())
            })
        })
    }
}

/// The entry in a file's text, when it is a well-formed outbox file.
fn parse_entry(text: &str) -> Option<OutboxEntry> {
    let body: Value = serde_json::from_str(text).ok()?;
    if body["format"] != FORMAT {
        return None;
    }
    serde_json::from_value(body["entry"].clone()).ok()
}

fn plain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `<12 digits>-<stem>.json`, the stem a plain identifier.
fn parse_entry_file(file: &str) -> Option<(u64, String)> {
    let name = file.strip_suffix(".json")?;
    let (sequence, stem) = name.split_once('-')?;
    if sequence.len() != 12 || !sequence.bytes().all(|b| b.is_ascii_digit()) || !plain(stem) {
        return None;
    }
    Some((sequence.parse().ok()?, stem.to_owned()))
}

/// The entry file a temporary file was written for:
/// `.<entry file>.<hex>.tmp`.
fn temp_target(name: &str) -> Option<&str> {
    let inner = name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (target, random) = inner.rsplit_once('.')?;
    let hex = !random.is_empty() && random.bytes().all(|b| b.is_ascii_hexdigit());
    (hex && parse_entry_file(target).is_some()).then_some(target)
}

/// A file-name-safe stem for an entry id: the id itself when it is a plain
/// identifier.
fn file_stem(id: &str) -> String {
    if plain(id) {
        return id.to_owned();
    }
    Sha256::digest(id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn create_private_dir(directory: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(directory)
}

/// Make a rename or removal durable on Unix; Windows cannot open a directory
/// to sync it.
fn sync_dir(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let dir = fs::File::open(directory)?;
        match dir.sync_all() {
            // Some file systems cannot sync a directory.
            Err(err) if err.kind() == io::ErrorKind::InvalidInput => Ok(()),
            other => other,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}
