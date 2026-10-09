//! The evidence outbox (v1.2.0): signed execution records the NA has not yet
//! admitted, kept in durable storage the caller supplies.
//!
//! [`governed_action`](crate::governed_action) writes its signed record here
//! before submitting it, and removes it once the NA admits it. A record whose
//! submission failed stays pending, and
//! [`EvidenceStoreClient::flush_pending`](crate::EvidenceStoreClient::flush_pending)
//! submits it later, in order. A record the NA refuses is kept as a dead
//! letter with the refusal code; it is never dropped. The outbox holds signed
//! metadata only, never secret values, but it must be durable and private.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
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
pub struct SubmissionFailure {
    /// HTTP status; 0 when no response arrived (network error, timeout).
    pub status: u16,
    /// The NA's error code, or the SDK's.
    pub code: String,
    /// The error message.
    pub message: String,
}

/// Where an outbox entry stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    /// To submit.
    Pending,
    /// Refused by the NA; kept, never dropped.
    DeadLetter,
}

/// One signed record in the outbox. The TypeScript SDK reads and writes the
/// same JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    pub(crate) fn due(&self, now: DateTime<Utc>) -> bool {
        self.next_attempt_at
            .as_deref()
            .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
            .is_none_or(|at| at.with_timezone(&Utc) <= now)
    }
}

/// Durable storage for outbox entries. Implement it over a database or a
/// queue when [`FileOutbox`] does not fit. Every method must be durable once
/// it returns, and `list` must return entries in the order they were added.
/// Calls are synchronous and brief; they run on the caller's task.
pub trait EvidenceOutbox: Send + Sync + std::fmt::Debug {
    /// Store a new entry.
    fn add(&self, entry: &OutboxEntry) -> io::Result<()>;
    /// Replace the stored entry with the same `id`; nothing when it is gone.
    fn update(&self, entry: &OutboxEntry) -> io::Result<()>;
    /// Remove an entry; nothing when it is gone.
    fn remove(&self, id: &str) -> io::Result<()>;
    /// Every entry, in the order added.
    fn list(&self) -> io::Result<Vec<OutboxEntry>>;
}

/// What happened to a signed record handed to the outbox.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Submission {
    /// The NA admitted it (or already held it): its acknowledgement, with
    /// `status` `recorded` or `duplicate`. It is no longer in the outbox.
    Admitted(Value),
    /// Kept for `flush_pending`: a transient error (network, timeout, `5xx`,
    /// `429`, a lost race between NA instances), or waiting behind a pending
    /// record it chains from.
    Pending(OutboxEntry),
    /// Refused by the NA (any other `4xx`) and kept as a dead letter.
    DeadLettered(OutboxEntry),
}

impl Submission {
    /// `recorded`, `duplicate`, `pending` or `dead_letter`.
    pub fn status(&self) -> &str {
        match self {
            Self::Admitted(ack) => ack["status"].as_str().unwrap_or("recorded"),
            Self::Pending(_) => "pending",
            Self::DeadLettered(_) => "dead_letter",
        }
    }
}

/// What one `flush_pending` run did.
#[derive(Debug, Clone, Default, PartialEq)]
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

/// 409 codes that only mean another NA instance won a race: retryable.
const RETRYABLE_CONFLICTS: [&str; 4] = [
    "boundary_policy_activation_conflict",
    "boundary_policy_version_conflict",
    "crl_publish_contention",
    "retention_in_progress",
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
    let refused = matches!(err, GenesisMeshError::SecretMaterial(_))
        || ((400..500).contains(&status)
            && status != 429
            && !(status == 409 && RETRYABLE_CONFLICTS.contains(&err.code())));
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

/// An outbox in memory. Not durable: for tests, or a process that keeps no
/// evidence across restarts.
#[derive(Debug, Default)]
pub struct MemoryOutbox {
    entries: Mutex<Vec<OutboxEntry>>,
}

impl MemoryOutbox {
    fn entries(&self) -> std::sync::MutexGuard<'_, Vec<OutboxEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl EvidenceOutbox for MemoryOutbox {
    fn add(&self, entry: &OutboxEntry) -> io::Result<()> {
        let mut entries = self.entries();
        if entries.iter().any(|e| e.id == entry.id) {
            return Err(exists(&entry.id));
        }
        entries.push(entry.clone());
        Ok(())
    }

    fn update(&self, entry: &OutboxEntry) -> io::Result<()> {
        if let Some(stored) = self.entries().iter_mut().find(|e| e.id == entry.id) {
            *stored = entry.clone();
        }
        Ok(())
    }

    fn remove(&self, id: &str) -> io::Result<()> {
        self.entries().retain(|e| e.id != id);
        Ok(())
    }

    fn list(&self) -> io::Result<Vec<OutboxEntry>> {
        Ok(self.entries().clone())
    }
}

fn exists(id: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("outbox entry {id} exists"),
    )
}

const FORMAT: &str = "gm.evidence.outbox.v1";

/// The default outbox: one JSON file per entry in a private directory
/// (`0700`, files `0600` on Unix), written to a temporary file, synced and
/// renamed into place. File names keep the order entries were added. The
/// TypeScript SDK reads and writes the same format.
#[derive(Debug, Clone)]
pub struct FileOutbox {
    directory: PathBuf,
}

struct EntryFile {
    file: String,
    sequence: u64,
    stem: String,
}

impl FileOutbox {
    /// An outbox in `directory`, created on first use.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// The directory holding the entries.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn files(&self) -> io::Result<Vec<EntryFile>> {
        create_private_dir(&self.directory)?;
        let mut found = Vec::new();
        for item in fs::read_dir(&self.directory)? {
            let file = item?.file_name().to_string_lossy().into_owned();
            if let Some((sequence, stem)) = parse_entry_file(&file) {
                found.push(EntryFile {
                    file: file.clone(),
                    sequence,
                    stem,
                });
            }
        }
        found.sort_by(|a, b| a.sequence.cmp(&b.sequence).then(a.stem.cmp(&b.stem)));
        Ok(found)
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
        sync_dir(&self.directory);
        Ok(())
    }
}

impl EvidenceOutbox for FileOutbox {
    fn add(&self, entry: &OutboxEntry) -> io::Result<()> {
        let files = self.files()?;
        let stem = file_stem(&entry.id);
        if files.iter().any(|f| f.stem == stem) {
            return Err(exists(&entry.id));
        }
        let sequence = files.iter().map(|f| f.sequence).max().unwrap_or(0) + 1;
        self.write(&format!("{sequence:012}-{stem}.json"), entry)
    }

    fn update(&self, entry: &OutboxEntry) -> io::Result<()> {
        let stem = file_stem(&entry.id);
        match self.files()?.into_iter().find(|f| f.stem == stem) {
            Some(found) => self.write(&found.file, entry),
            None => Ok(()),
        }
    }

    fn remove(&self, id: &str) -> io::Result<()> {
        let stem = file_stem(id);
        if let Some(found) = self.files()?.into_iter().find(|f| f.stem == stem) {
            match fs::remove_file(self.directory.join(found.file)) {
                Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
                _ => sync_dir(&self.directory),
            }
        }
        Ok(())
    }

    fn list(&self) -> io::Result<Vec<OutboxEntry>> {
        let mut entries = Vec::new();
        for found in self.files()? {
            let text = match fs::read_to_string(self.directory.join(&found.file)) {
                Ok(text) => text,
                // Removed meanwhile.
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            let invalid = |why: String| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("outbox file {} is {why}", found.file),
                )
            };
            let body: Value =
                serde_json::from_str(&text).map_err(|e| invalid(format!("unreadable: {e}")))?;
            if body["format"] != FORMAT {
                return Err(invalid(format!("not {FORMAT}")));
            }
            entries.push(
                serde_json::from_value(body["entry"].clone())
                    .map_err(|e| invalid(format!("unreadable: {e}")))?,
            );
        }
        Ok(entries)
    }
}

/// `<12 digits>-<stem>.json`, the stem a plain identifier.
fn parse_entry_file(file: &str) -> Option<(u64, String)> {
    let name = file.strip_suffix(".json")?;
    let (sequence, stem) = name.split_once('-')?;
    let plain = |s: &str| {
        !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if sequence.len() != 12 || !sequence.bytes().all(|b| b.is_ascii_digit()) || !plain(stem) {
        return None;
    }
    Some((sequence.parse().ok()?, stem.to_owned()))
}

/// A file-name-safe stem for an entry id: the id itself when it is a plain
/// identifier.
fn file_stem(id: &str) -> String {
    let plain = !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if plain {
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

/// Make a rename durable on Unix; Windows cannot open a directory and needs
/// no sync.
fn sync_dir(directory: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(directory) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = directory;
}
