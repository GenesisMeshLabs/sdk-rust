use std::any::Any;

use serde_json::Value;

use crate::outbox::{OutboxEntry, RecordOutboxEntry};

/// SDK result type.
pub type Result<T> = std::result::Result<T, GenesisMeshError>;

/// Error type for Genesis Mesh SDK operations. Non-exhaustive since 1.2.0:
/// match the variants you handle and keep a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GenesisMeshError {
    /// Invalid client configuration or route.
    #[error("configuration error: {0}")]
    Configuration(String),
    /// The Network Authority rejected admin authentication.
    #[error("unauthorized: {message} [{code}]")]
    Unauthorized { message: String, code: String },

    /// The Network Authority rejected the request body.
    #[error("validation error: {message} [{code}]")]
    Validation { message: String, code: String },

    /// The requested resource was not found.
    #[error("not found: {message} [{code}]")]
    NotFound { message: String, code: String },

    /// The Network Authority rate limit was exceeded.
    #[error("rate limit exceeded: {message} [{code}]")]
    RateLimit { message: String, code: String },

    /// A bad request was sent.
    #[error("bad request: {message} [{code}]")]
    BadRequest { message: String, code: String },

    /// An unmapped HTTP error was returned.
    #[error("http {status}: {message} [{code}]")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Error message.
        message: String,
        /// Error code.
        code: String,
    },

    /// Network transport failure.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// JSON serialization or parsing failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// JSON every implementation would not read alike (v1.2.0): `reason` is
    /// `invalid_json`, `duplicate_key`, `non_finite_number`,
    /// `integer_out_of_range`, `negative_zero` or `lone_surrogate`.
    #[error("JSON refused ({reason}): {detail}")]
    StrictJson {
        /// Why, as every implementation names it.
        reason: String,
        /// Where.
        detail: String,
    },

    /// Signing key decode or validation failure.
    #[error("signing key error: {0}")]
    SigningKey(String),

    /// Admin route was called without a signing key.
    #[error("signing_key_base64 is required for admin routes")]
    MissingSigningKey,

    /// Evidence metadata would carry secret material or exceed the size
    /// limit; refused before anything is signed or sent. Code
    /// `evidence_secret_material`, as the NA would return.
    #[error("evidence metadata refused: {0}")]
    SecretMaterial(String),

    /// A boundary decision failed offline verification; the action was not
    /// run. Holds the verification reason code.
    #[error("decision failed verification: {0}")]
    DecisionVerification(String),

    /// Data from the NA did not verify or was inconsistent (a history that
    /// failed verification, a paging cursor that did not advance).
    #[error("verification failed: {0}")]
    Verification(String),

    /// A governed action failed; its failure was recorded as evidence.
    #[error("governed action failed: {source}")]
    #[non_exhaustive]
    ActionFailed {
        /// The action's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// The signed failure record (v1.2.0): execution evidence, or the
        /// break-glass record when the action ran under break-glass (v1.3.0).
        evidence: Option<Box<Value>>,
        /// With an outbox, the entry holding the failure record when the NA
        /// has not admitted it (v1.2.0).
        queued: Option<Box<OutboxEntry>>,
        /// Under break-glass, the record outbox entry holding the failure
        /// record when the NA has not admitted it (v1.3.0).
        queued_record: Option<Box<RecordOutboxEntry>>,
    },

    /// A governed action failed and its failure record could not be signed,
    /// submitted or (with an outbox) kept.
    #[error("action failed and its failure could not be recorded: {evidence_error}")]
    #[non_exhaustive]
    ActionUnrecorded {
        /// The action's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// Why the failure evidence could not be recorded.
        evidence_error: Box<GenesisMeshError>,
        /// The signed failure record, when signing succeeded (v1.2.0).
        evidence: Option<Box<Value>>,
    },

    /// With an outbox (v1.2.0): the governed action ran, but the secret guard
    /// refused metadata it reported. The outcome was recorded without the
    /// refused fields (`dropped`) as `evidence`; `submission` or `queued` say
    /// what became of it. Do not rerun the action.
    /// [`GenesisMeshError::take_action_value`] takes the action's value.
    #[error("the action ran; its metadata was refused and recorded without {}: {reason}", dropped.join(", "))]
    #[non_exhaustive]
    MetadataRefused {
        /// The guard's reason.
        reason: String,
        /// The refused field names (`outcome_detail` for the detail).
        dropped: Vec<String>,
        /// The recorded outcome.
        evidence: Box<Value>,
        /// The NA's acknowledgement, when it admitted the record.
        submission: Option<Box<Value>>,
        /// The outbox entry, when the NA has not admitted it.
        queued: Option<Box<OutboxEntry>>,
        /// The action's value.
        value: ActionValue,
    },

    /// With an outbox (v1.2.0): the governed action ran, but its evidence
    /// could not be signed or kept in the outbox. `evidence` is the signed
    /// record when signing succeeded: pass it to
    /// [`EvidenceStoreClient::enqueue`](crate::EvidenceStoreClient::enqueue)
    /// once the outbox works (a break-glass record, v1.3.0, to
    /// [`EvidenceStoreClient::enqueue_record`](crate::EvidenceStoreClient::enqueue_record)).
    /// Do not rerun the action.
    /// [`GenesisMeshError::take_action_value`] takes the action's value.
    #[error("the action ran; its evidence was not kept: {source}")]
    #[non_exhaustive]
    EvidenceNotKept {
        /// Why.
        #[source]
        source: Box<GenesisMeshError>,
        /// The signed record, when signing succeeded.
        evidence: Option<Box<Value>>,
        /// The action's value.
        value: ActionValue,
    },

    /// The evidence outbox failed to store, update, remove or list entries
    /// (v1.2.0).
    #[error("evidence outbox error: {0}")]
    Outbox(#[source] std::io::Error),

    /// No evidence outbox is configured
    /// ([`ClientOptions::with_outbox`](crate::ClientOptions::with_outbox)); the
    /// outbox methods need one (v1.2.0).
    #[error("no evidence outbox is configured (ClientOptions::with_outbox)")]
    OutboxRequired,

    /// Another `flush_pending` run is in progress on this client (v1.2.0),
    /// or another `flush_records` run (v1.3.0).
    #[error("a flush of the evidence outbox is already running")]
    FlushInProgress,

    /// A record of a change made outside the controlled path would be
    /// refused, so it was not signed (v1.3.0). `code` is the one the NA would
    /// return: `observation_malformed`, `observation_secret_material`,
    /// `break_glass_malformed` or `break_glass_secret_material`.
    #[error("record refused: {message} [{code}]")]
    OutOfBandRecord {
        /// Why, as the NA names it.
        code: String,
        /// What is wrong.
        message: String,
    },

    /// No record outbox is configured
    /// ([`ClientOptions::with_record_outbox`](crate::ClientOptions::with_record_outbox));
    /// the record outbox methods and break-glass need one (v1.3.0).
    #[error("no record outbox is configured (ClientOptions::with_record_outbox)")]
    RecordOutboxRequired,
}

/// A governed action's value carried by an error that says the action ran
/// (v1.2.0). Take it with [`GenesisMeshError::take_action_value`].
pub struct ActionValue(std::sync::Mutex<Option<Box<dyn Any + Send>>>);

impl ActionValue {
    pub(crate) fn new<T: Send + 'static>(value: Option<T>) -> Self {
        Self(std::sync::Mutex::new(
            value.map(|v| Box::new(v) as Box<dyn Any + Send>),
        ))
    }

    fn slot(&mut self) -> &mut Option<Box<dyn Any + Send>> {
        self.0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl std::fmt::Debug for ActionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActionValue(..)")
    }
}

impl GenesisMeshError {
    /// The stable error code: the NA's `code` for HTTP errors, the reason
    /// for verification failures, and SDK codes otherwise.
    pub fn code(&self) -> &str {
        match self {
            Self::Unauthorized { code, .. }
            | Self::Validation { code, .. }
            | Self::NotFound { code, .. }
            | Self::RateLimit { code, .. }
            | Self::BadRequest { code, .. }
            | Self::Http { code, .. }
            | Self::OutOfBandRecord { code, .. } => code,
            Self::DecisionVerification(reason) => reason,
            Self::StrictJson { reason, .. } => reason,
            Self::SecretMaterial(_) => "evidence_secret_material",
            Self::Verification(_) => "verification_failed",
            Self::ActionFailed { .. } => "governed_action_failed",
            Self::ActionUnrecorded { .. } => "governed_action_unrecorded",
            Self::MetadataRefused { .. } => "governed_action_metadata_refused",
            Self::EvidenceNotKept { .. } => "governed_action_evidence_unkept",
            Self::Outbox(_) => "outbox_error",
            Self::OutboxRequired => "outbox_required",
            Self::FlushInProgress => "outbox_flush_in_progress",
            Self::RecordOutboxRequired => "record_outbox_required",
            Self::Configuration(_) => "configuration",
            Self::Network(_) => "network",
            Self::Json(_) => "json",
            Self::SigningKey(_) | Self::MissingSigningKey => "signing_key",
        }
    }
}

impl GenesisMeshError {
    /// Take the governed action's value out of an error that says the action
    /// ran (`MetadataRefused`, `EvidenceNotKept`), when it is a `T`. Returns
    /// `None` for another type, and after the value was taken.
    pub fn take_action_value<T: 'static>(&mut self) -> Option<T> {
        let (Self::MetadataRefused { value, .. } | Self::EvidenceNotKept { value, .. }) = self
        else {
            return None;
        };
        let slot = value.slot();
        match slot.take()?.downcast::<T>() {
            Ok(v) => Some(*v),
            Err(other) => {
                *slot = Some(other);
                None
            }
        }
    }
}

pub(crate) fn from_http_error(status: u16, body: &Value) -> GenesisMeshError {
    let (message, code) = extract_error(body);

    match status {
        400 => GenesisMeshError::BadRequest { message, code },
        401 => GenesisMeshError::Unauthorized { message, code },
        404 => GenesisMeshError::NotFound { message, code },
        422 => GenesisMeshError::Validation { message, code },
        429 => GenesisMeshError::RateLimit { message, code },
        _ => GenesisMeshError::Http {
            status,
            message,
            code,
        },
    }
}

fn extract_error(body: &Value) -> (String, String) {
    if let Some(message) = body
        .as_str()
        .or_else(|| body.get("detail").and_then(Value::as_str))
    {
        return (message.to_owned(), "unknown".to_owned());
    }
    if let Some(error) = body.get("error") {
        if let Some(object) = error.as_object() {
            return (
                object
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown error")
                    .to_owned(),
                object
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            );
        }

        if let Some(message) = error.as_str() {
            return (
                message.to_owned(),
                body.get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
            );
        }
    }

    (
        body.get("message")
            .and_then(Value::as_str)
            .unwrap_or("Unknown error")
            .to_owned(),
        body.get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_nested_unauthorized_error() {
        let err = from_http_error(
            401,
            &json!({"error": {"message": "bad signature", "code": "admin_auth_failed"}}),
        );
        assert!(matches!(
            err,
            GenesisMeshError::Unauthorized { ref code, .. } if code == "admin_auth_failed"
        ));
    }
}
