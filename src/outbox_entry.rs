//! The outboxes' entries and failures (a leaf below `errors`, which
//! carries them): data only. The outboxes that store them are in
//! `outbox`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    /// The NA's quarantine entry, when it refused the record for good and
    /// kept it as one (`error.details.quarantine_id`, 1.7.0). The
    /// TypeScript SDK reads and writes the same field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_id: Option<String>,
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
    /// A `RemediationRecord`, submitted to `/evidence/remediations` (1.4.0).
    Remediation,
    /// A `GrantExecutionEvidence` (one use of a pre-issued grant), submitted
    /// to `/evidence/grant-executions` (1.6.0).
    GrantExecution,
}

/// One signed observation or break-glass record in the record outbox
/// (v1.3.0), remediation record (1.4.0) or grant use (1.6.0). The
/// TypeScript SDK reads and writes the same JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecordOutboxEntry {
    /// The record's `observation_id`, `break_glass_id`, `remediation_id`
    /// or (1.6.0) `use_id`.
    pub id: String,
    /// Observation, break-glass, remediation or grant use.
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
    /// `observation_id`), remediation record (a `remediation_id`, 1.4.0),
    /// grant use (a `use_id`, 1.6.0) or break-glass record.
    pub fn new(record: Value) -> Self {
        let (kind, key) = if record.get("observation_id").is_some() {
            (RecordKind::Observation, "observation_id")
        } else if record.get("remediation_id").is_some() {
            (RecordKind::Remediation, "remediation_id")
        } else if record.get("use_id").is_some() {
            (RecordKind::GrantExecution, "use_id")
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

pub(crate) fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Entry files that could not be read and were moved aside (1.3.1): what the
/// [`GenesisMeshError::Outbox`](crate::GenesisMeshError::Outbox) error of the read that found them carries,
/// with the code `outbox_file_unreadable`.
#[derive(Debug)]
pub(crate) struct UnreadableFiles(pub(crate) String);

impl std::fmt::Display for UnreadableFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnreadableFiles {}
