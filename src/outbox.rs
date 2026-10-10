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
//!
//! The record outbox (v1.3.0,
//! [`ClientOptions::with_record_outbox`](crate::ClientOptions::with_record_outbox))
//! keeps signed observations and break-glass records the same way, in a
//! directory of its own;
//! [`EvidenceStoreClient::flush_records`](crate::EvidenceStoreClient::flush_records)
//! submits them.

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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
        due(self.next_attempt_at.as_deref(), now)
    }
}

fn due(next_attempt_at: Option<&str>, now: DateTime<Utc>) -> bool {
    next_attempt_at
        .and_then(|at| DateTime::parse_from_rfc3339(at).ok())
        .is_none_or(|at| at.with_timezone(&Utc) <= now)
}

/// What a record outbox entry holds (v1.3.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// An `ObservationRecord`, submitted to `/evidence/observations`.
    Observation,
    /// A `BreakGlassRecord`, submitted to `/evidence/break-glass`.
    BreakGlass,
}

/// One signed observation or break-glass record in the record outbox
/// (v1.3.0). The TypeScript SDK reads and writes the same JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecordOutboxEntry {
    /// The record's `observation_id` or `break_glass_id`.
    pub id: String,
    /// Observation or break-glass.
    pub kind: RecordKind,
    /// The signed record, exactly as it will be submitted.
    pub record: Value,
    /// Pending or dead letter.
    pub state: OutboxState,
    /// Submissions attempted so far.
    pub attempts: u32,
    /// When it was added (RFC 3339, UTC).
    pub queued_at: String,
    /// Earliest time `flush_records` retries it; `None` when it has not failed.
    pub next_attempt_at: Option<String>,
    /// The last submission error.
    pub last_error: Option<SubmissionFailure>,
}

impl RecordOutboxEntry {
    /// A new pending entry for a signed observation (a record with an
    /// `observation_id`) or break-glass record.
    pub fn new(record: Value) -> Self {
        let (kind, key) = if record.get("observation_id").is_some() {
            (RecordKind::Observation, "observation_id")
        } else {
            (RecordKind::BreakGlass, "break_glass_id")
        };
        Self {
            id: record[key].as_str().unwrap_or_default().to_owned(),
            kind,
            record,
            state: OutboxState::Pending,
            attempts: 0,
            queued_at: timestamp(Utc::now()),
            next_attempt_at: None,
            last_error: None,
        }
    }

    /// Due for an attempt at `now`, as an [`OutboxEntry`] is.
    pub(crate) fn due(&self, now: DateTime<Utc>) -> bool {
        due(self.next_attempt_at.as_deref(), now)
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

/// Durable storage for signed observations and break-glass records (v1.3.0),
/// with the contract of [`EvidenceOutbox`]. Implement it over a database or
/// a queue when [`FileRecordOutbox`] does not fit.
pub trait RecordOutbox: Send + Sync + std::fmt::Debug {
    /// Store a new entry; refuse an `id` already stored.
    fn add<'a>(&'a self, entry: &'a RecordOutboxEntry) -> OutboxFuture<'a, ()>;
    /// Replace the stored entry with the same `id`; nothing when it is gone.
    fn update<'a>(&'a self, entry: &'a RecordOutboxEntry) -> OutboxFuture<'a, ()>;
    /// Remove an entry; nothing when it is gone.
    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()>;
    /// Every entry, in the order added.
    fn list(&self) -> OutboxFuture<'_, Vec<RecordOutboxEntry>>;
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

/// What became of a record handed to the record outbox (v1.3.0): the NA's
/// answer when it admitted the record (`status` `recorded`, `duplicate` or
/// `quarantined`), otherwise the record outbox entry holding it (pending or
/// dead letter).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct RecordDelivery {
    /// The NA's answer.
    pub submission: Option<Value>,
    /// The record outbox entry, when the NA has not admitted the record.
    pub queued: Option<RecordOutboxEntry>,
}

impl RecordDelivery {
    pub(crate) fn admitted(ack: Value) -> Self {
        Self {
            submission: Some(ack),
            queued: None,
        }
    }

    pub(crate) fn queued(entry: RecordOutboxEntry) -> Self {
        Self {
            submission: None,
            queued: Some(entry),
        }
    }
}

/// What one `flush_records` run did (v1.3.0).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct RecordFlushReport {
    /// Entries the NA admitted (or already held), now removed from the
    /// record outbox.
    pub admitted: Vec<RecordOutboxEntry>,
    /// Of those, the ones the NA kept as quarantine entries (authentic, but
    /// outside their time bounds).
    pub quarantined: Vec<RecordOutboxEntry>,
    /// Entries still pending: not yet due, after a transient error, or not
    /// answered.
    pub pending: Vec<RecordOutboxEntry>,
    /// Entries this run moved to the dead letters.
    pub dead_lettered: Vec<RecordOutboxEntry>,
}

/// Local refusal code for a record whose predecessor in its chain is a dead
/// letter. Since 1.3.1 the record is submitted all the same, so the NA can
/// quarantine one it refuses for good on its own account; it is given this
/// code when the NA refuses it for the gap the dead letter left
/// (`evidence_chain_gap`, `resource_chain_gap`), which never closes.
pub const PREDECESSOR_DEAD_LETTERED: &str = "evidence_predecessor_dead_lettered";

/// The NA's refusals that no retry of the same record can overcome. Every
/// other failure (network, timeout, `5xx`, `429`, an unknown or not yet
/// registered executor key, a chain gap behind a record not yet admitted, a
/// disabled store, a proxy's error page) is retried. Since 1.3.1 it includes
/// `invalid_json`: the NA's strict JSON reader refused the request, which
/// sending the same record again cannot change.
pub const PERMANENT_REFUSALS: [&str; 14] = [
    "invalid_json",
    "invalid_evidence",
    "evidence_malformed",
    // v1.3.0: a retired key, and a key whose role or resource prefix does not
    // cover the record (both were `evidence_unknown_executor`, retried).
    "evidence_executor_key_retired",
    "evidence_out_of_scope",
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

/// The NA's refusals of an observation or break-glass record that no retry
/// can overcome (v1.3.0). An unknown key is retried: it may not be
/// registered yet; a retired one is not. Since 1.3.1 it includes
/// `invalid_json`, as [`PERMANENT_REFUSALS`] does.
pub const RECORD_PERMANENT_REFUSALS: [&str; 15] = [
    "invalid_json",
    "invalid_observation",
    "observation_malformed",
    "observation_invalid_signature",
    "observation_key_retired",
    "observation_out_of_scope",
    "observation_secret_material",
    "observation_conflict",
    "invalid_break_glass",
    "break_glass_malformed",
    "break_glass_invalid_signature",
    "break_glass_key_retired",
    "break_glass_out_of_scope",
    "break_glass_secret_material",
    "break_glass_conflict",
];

/// The submission error as stored, and whether a later retry may succeed.
pub fn classify_submission_error(err: &GenesisMeshError) -> (SubmissionFailure, bool) {
    classify(err, &PERMANENT_REFUSALS)
}

/// [`classify_submission_error`] for an observation or break-glass record
/// (v1.3.0): refused for good only by [`RECORD_PERMANENT_REFUSALS`].
pub fn classify_record_submission_error(err: &GenesisMeshError) -> (SubmissionFailure, bool) {
    classify(err, &RECORD_PERMANENT_REFUSALS)
}

fn classify(err: &GenesisMeshError, refusals: &[&str]) -> (SubmissionFailure, bool) {
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
    // A response this crate could not read strictly is not the NA's refusal:
    // the NA may have admitted the record (1.3.1).
    let read_locally = matches!(err, GenesisMeshError::StrictJson { .. });
    let refused = !read_locally
        && refusals.contains(&err.code())
        && (status == 0 || (400..500).contains(&status));
    (failure, !refused)
}

/// The longest wait between attempts.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(15 * 60);

/// Delay before the next attempt after `attempts` failures: 5 s, doubling, at
/// most 15 minutes.
pub fn retry_delay(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    Duration::from_secs(5_u64 << doublings).min(MAX_RETRY_DELAY)
}

/// When to try a record again after `attempts` failures: its backoff, or
/// later when the NA asked the caller to wait (`Retry-After`, 1.3.1), at most
/// 15 minutes.
pub(crate) fn next_attempt_at(attempts: u32, wait: Option<Duration>) -> String {
    timestamp(next_attempt(attempts, wait))
}

/// [`next_attempt_at`] as a time.
pub(crate) fn next_attempt(attempts: u32, wait: Option<Duration>) -> DateTime<Utc> {
    let asked = wait.unwrap_or_default().min(MAX_RETRY_DELAY);
    let delay = chrono::Duration::from_std(retry_delay(attempts).max(asked))
        .unwrap_or(chrono::Duration::MAX);
    Utc::now() + delay
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

/// An entry an outbox stores: a signed execution record, or (v1.3.0) a
/// signed observation or break-glass record.
trait Entry: Clone + Serialize + DeserializeOwned + Send + Sync + std::fmt::Debug {
    /// The format of its files.
    const FORMAT: &'static str;
    fn id(&self) -> &str;
}

impl Entry for OutboxEntry {
    const FORMAT: &'static str = "gm.evidence.outbox.v1";
    fn id(&self) -> &str {
        &self.id
    }
}

impl Entry for RecordOutboxEntry {
    const FORMAT: &'static str = "gm.evidence.record-outbox.v1";
    fn id(&self) -> &str {
        &self.id
    }
}

/// Entries in memory, in the order added. Every change runs under one lock,
/// so changes never interleave; the scans are in memory and fail at no size.
#[derive(Debug)]
struct Memory<E>(Mutex<Vec<E>>);

impl<E> Default for Memory<E> {
    fn default() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}

impl<E: Entry> Memory<E> {
    fn add(&self, entry: &E) -> io::Result<()> {
        let mut entries = lock(&self.0);
        if entries.iter().any(|e| e.id() == entry.id()) {
            return Err(exists(entry.id()));
        }
        entries.push(entry.clone());
        Ok(())
    }

    fn update(&self, entry: &E) -> io::Result<()> {
        if let Some(stored) = lock(&self.0).iter_mut().find(|e| e.id() == entry.id()) {
            *stored = entry.clone();
        }
        Ok(())
    }

    fn remove(&self, id: &str) -> io::Result<()> {
        lock(&self.0).retain(|e| e.id() != id);
        Ok(())
    }

    fn list(&self) -> io::Result<Vec<E>> {
        Ok(lock(&self.0).clone())
    }
}

/// Implements an outbox trait over storage whose methods are synchronous.
macro_rules! outbox_over {
    ($outbox:ty, $trait:ident, $entry:ty) => {
        impl $trait for $outbox {
            fn add<'a>(&'a self, entry: &'a $entry) -> OutboxFuture<'a, ()> {
                Box::pin(async move { self.0.add(entry) })
            }

            fn update<'a>(&'a self, entry: &'a $entry) -> OutboxFuture<'a, ()> {
                Box::pin(async move { self.0.update(entry) })
            }

            fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
                Box::pin(async move { self.0.remove(id) })
            }

            fn list(&self) -> OutboxFuture<'_, Vec<$entry>> {
                Box::pin(async move { self.0.list() })
            }
        }
    };
}

/// An outbox in memory. Not durable: everything in it is lost when the
/// process exits. For tests only.
#[derive(Debug, Default)]
pub struct MemoryOutbox(Memory<OutboxEntry>);

outbox_over!(MemoryOutbox, EvidenceOutbox, OutboxEntry);

/// A record outbox in memory (v1.3.0). Not durable: for tests only.
#[derive(Debug, Default)]
pub struct MemoryRecordOutbox(Memory<RecordOutboxEntry>);

outbox_over!(MemoryRecordOutbox, RecordOutbox, RecordOutboxEntry);

#[derive(Debug, Clone)]
struct Stored<E> {
    file: String,
    sequence: u64,
    entry: E,
}

/// The entries of a directory once read, by file stem, and the highest file
/// sequence used, so an add never scans every entry (v1.3.0).
#[derive(Debug)]
struct Loaded<E> {
    entries: HashMap<String, Stored<E>>,
    last_sequence: u64,
}

/// One JSON file per entry in a directory; see [`FileOutbox`]. Every change,
/// file operations included, runs under one lock: changes run one at a time,
/// so an update never renames a file back over one a removal deleted.
#[derive(Debug)]
struct JsonFiles<E> {
    directory: PathBuf,
    stored: Mutex<Option<Loaded<E>>>,
}

impl<E: Entry> JsonFiles<E> {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            stored: Mutex::new(None),
        }
    }

    /// Run `f` on the entries, reading the directory first if needed. The
    /// lock is held until `f` returns.
    fn with<T>(&self, f: impl FnOnce(&mut Loaded<E>) -> io::Result<T>) -> io::Result<T> {
        let mut guard = lock(&self.stored);
        if guard.is_none() {
            let entries = self.read()?;
            let last_sequence = entries.values().map(|s| s.sequence).max().unwrap_or(0);
            *guard = Some(Loaded {
                entries,
                last_sequence,
            });
        }
        f(guard.as_mut().expect("loaded"))
    }

    fn read(&self) -> io::Result<HashMap<String, Stored<E>>> {
        create_private_dir(&self.directory)?;
        let names: Vec<String> = fs::read_dir(&self.directory)?
            .map(|item| Ok(item?.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<_>>()?;
        // Every file is read before any is changed: a directory of the other
        // outbox's files is refused as it is found, its temporary files left
        // for that outbox to recover (1.3.1; they were removed).
        let other_format = |name: &str| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("outbox file {name} is not {}", E::FORMAT),
            )
        };
        let mut temporary = Vec::new();
        for name in &names {
            let Some(target) = temp_target(name) else {
                continue;
            };
            let body = fs::read(self.directory.join(name))
                .ok()
                .and_then(|bytes| json_of(&bytes));
            if body.as_ref().is_some_and(of_other_format::<E>) {
                return Err(other_format(name));
            }
            temporary.push((name, target, body.and_then(entry_of::<E>)));
        }
        let mut stored = HashMap::new();
        let mut unreadable = Vec::new();
        for file in &names {
            let Some((sequence, stem)) = parse_entry_file(file) else {
                continue;
            };
            let body = json_of(&fs::read(self.directory.join(file))?);
            if body.as_ref().is_some_and(of_other_format::<E>) {
                return Err(other_format(file));
            }
            let Some(entry) = body.and_then(entry_of::<E>) else {
                unreadable.push(file.clone());
                continue;
            };
            let file = file.clone();
            stored.insert(
                stem,
                Stored {
                    file,
                    sequence,
                    entry,
                },
            );
        }
        // What a crash left: an entry being added is recovered, an update
        // that did not finish is removed.
        for (name, target, entry) in &temporary {
            let path = self.directory.join(name);
            match (entry, parse_entry_file(target)) {
                (Some(entry), Some((sequence, stem))) if !names.iter().any(|n| n == target) => {
                    fs::rename(&path, self.directory.join(target))?;
                    let file = (*target).to_owned();
                    let entry = entry.clone();
                    stored.insert(
                        stem,
                        Stored {
                            file,
                            sequence,
                            entry,
                        },
                    );
                }
                _ => fs::remove_file(&path)?,
            }
        }
        // 1.3.1: a file that cannot be read is moved aside, so it does not
        // stop every action; the read that finds it fails, once.
        for file in &unreadable {
            fs::rename(
                self.directory.join(file),
                self.directory.join(format!("{file}{UNREADABLE}")),
            )?;
        }
        if !temporary.is_empty() || !unreadable.is_empty() {
            sync_dir(&self.directory)?;
        }
        if !unreadable.is_empty() {
            let (s, were) = if unreadable.len() == 1 {
                ("", "was")
            } else {
                ("s", "were")
            };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                UnreadableFiles(format!(
                    "outbox file{s} {} in {} could not be read as {} and {were} moved aside \
                     (*{UNREADABLE}); the record{s} held there will not be submitted",
                    unreadable.join(", "),
                    self.directory.display(),
                    E::FORMAT,
                )),
            ));
        }
        Ok(stored)
    }

    fn write(&self, file: &str, entry: &E) -> io::Result<()> {
        let temporary = self
            .directory
            .join(format!(".{file}.{}.tmp", Uuid::new_v4().simple()));
        let body = serde_json::to_string_pretty(&json!({"format": E::FORMAT, "entry": entry}))
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

    fn add(&self, entry: &E) -> io::Result<()> {
        self.with(|loaded| {
            let stem = file_stem(entry.id());
            if loaded.entries.contains_key(&stem) {
                return Err(exists(entry.id()));
            }
            let sequence = loaded.last_sequence + 1;
            let file = format!("{sequence:012}-{stem}.json");
            self.write(&file, entry)?;
            loaded.last_sequence = sequence;
            loaded.entries.insert(
                stem,
                Stored {
                    file,
                    sequence,
                    entry: entry.clone(),
                },
            );
            Ok(())
        })
    }

    fn update(&self, entry: &E) -> io::Result<()> {
        self.with(|loaded| {
            if let Some(found) = loaded.entries.get_mut(&file_stem(entry.id())) {
                self.write(&found.file, entry)?;
                found.entry = entry.clone();
            }
            Ok(())
        })
    }

    fn remove(&self, id: &str) -> io::Result<()> {
        self.with(|loaded| {
            let stem = file_stem(id);
            if let Some(found) = loaded.entries.get(&stem) {
                match fs::remove_file(self.directory.join(&found.file)) {
                    Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
                    _ => sync_dir(&self.directory)?,
                }
                loaded.entries.remove(&stem);
            }
            Ok(())
        })
    }

    fn list(&self) -> io::Result<Vec<E>> {
        self.with(|loaded| {
            let mut entries: Vec<&Stored<E>> = loaded.entries.values().collect();
            entries.sort_by(|a, b| a.sequence.cmp(&b.sequence).then(a.file.cmp(&b.file)));
            Ok(entries.into_iter().map(|s| s.entry.clone()).collect())
        })
    }
}

/// The default outbox: one JSON file per entry in a directory, written to a
/// temporary file, synced and renamed into place. File names keep the order
/// entries were added. The TypeScript SDK reads and writes the same format.
///
/// One process uses a directory at a time: the directory is read once, then
/// kept in memory. Nothing enforces that (the file locks of the standard
/// library are newer than this crate's minimum Rust): two processes sharing
/// a directory submit each other's records and overwrite each other's
/// changes, so give each its own. A temporary file left by a crash is
/// recovered (an entry that was being added) or removed (an update that did
/// not finish) on that first read. An entry file that cannot be read is
/// moved aside as `<name>.unreadable` (1.3.1): the read that finds it fails
/// once (`outbox_file_unreadable`), and the record it held is not submitted.
/// A directory holding files of the other outbox's format is refused. A directory the outbox creates is `0700` and its files `0600`
/// on Unix; on Windows, and for a directory that already exists, restrict
/// access to it yourself. Its file operations are synchronous and brief, and
/// run on the caller's task.
#[derive(Debug)]
pub struct FileOutbox(JsonFiles<OutboxEntry>);

impl FileOutbox {
    /// An outbox in `directory`, created on first use.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self(JsonFiles::new(directory.into()))
    }

    /// The directory holding the entries.
    pub fn directory(&self) -> &Path {
        &self.0.directory
    }
}

outbox_over!(FileOutbox, EvidenceOutbox, OutboxEntry);

/// The default record outbox (v1.3.0): signed observations and break-glass
/// records, kept as [`FileOutbox`] keeps execution records, in a directory
/// of its own and in a format of its own (`gm.evidence.record-outbox.v1`,
/// which the TypeScript SDK shares). It refuses a directory of execution
/// records.
#[derive(Debug)]
pub struct FileRecordOutbox(JsonFiles<RecordOutboxEntry>);

impl FileRecordOutbox {
    /// A record outbox in `directory`, created on first use.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self(JsonFiles::new(directory.into()))
    }

    /// The directory holding the entries.
    pub fn directory(&self) -> &Path {
        &self.0.directory
    }
}

outbox_over!(FileRecordOutbox, RecordOutbox, RecordOutboxEntry);

/// The entry in a file's text, when it is a well-formed file of its outbox.
/// The suffix an unreadable entry file is renamed with (1.3.1).
const UNREADABLE: &str = ".unreadable";

/// Entry files that could not be read and were moved aside (1.3.1): what the
/// [`GenesisMeshError::Outbox`] error of the read that found them carries,
/// with the code `outbox_file_unreadable`.
#[derive(Debug)]
pub(crate) struct UnreadableFiles(String);

impl std::fmt::Display for UnreadableFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnreadableFiles {}

/// A file's JSON, when it is JSON.
fn json_of(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice(bytes).ok()
}

/// A well-formed file of another format: the other outbox's, or a later one.
fn of_other_format<E: Entry>(body: &Value) -> bool {
    body["format"].is_string() && body["format"] != E::FORMAT
}

/// The entry in a file's JSON, when it is of its outbox's format.
fn entry_of<E: Entry>(body: Value) -> Option<E> {
    if body["format"] != E::FORMAT {
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
