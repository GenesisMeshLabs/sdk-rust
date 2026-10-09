use std::any::Any;

use serde_json::Value;

use crate::outbox::Submission;

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
    ActionFailed {
        /// The action's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A governed action failed and its failure record could not be signed
    /// or kept in the outbox.
    #[error("action failed and its failure could not be recorded: {evidence_error}")]
    ActionUnrecorded {
        /// The action's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// Why the failure evidence could not be recorded.
        evidence_error: Box<GenesisMeshError>,
        /// The signed failure record, when signing succeeded (v1.2.0).
        evidence: Option<Box<Value>>,
    },

    /// The governed action ran, but the secret guard refused metadata it
    /// reported (v1.2.0). The outcome was recorded without the refused fields
    /// (`dropped`) as `evidence`; `submission` says whether the NA admitted
    /// it. Do not rerun the action. [`GenesisMeshError::action_value`] reads
    /// the action's value.
    #[error("the action ran; its metadata was refused and recorded without {}: {reason}", dropped.join(", "))]
    MetadataRefused {
        /// The guard's reason.
        reason: String,
        /// The refused field names (`outcome_detail` for the detail).
        dropped: Vec<String>,
        /// The recorded outcome.
        evidence: Box<Value>,
        /// What happened to it.
        submission: Box<Submission>,
        /// The action's value.
        value: Option<Box<dyn Any + Send + Sync>>,
    },

    /// The governed action ran, but its evidence could not be signed or kept
    /// in the outbox (v1.2.0). `evidence` is the signed record when signing
    /// succeeded: submit it (resubmission is idempotent) once the outbox
    /// works. Do not rerun the action. [`GenesisMeshError::action_value`]
    /// reads the action's value.
    #[error("the action ran; its evidence was not kept: {source}")]
    EvidenceNotKept {
        /// Why.
        #[source]
        source: Box<GenesisMeshError>,
        /// The signed record, when signing succeeded.
        evidence: Option<Box<Value>>,
        /// The action's value.
        value: Option<Box<dyn Any + Send + Sync>>,
    },

    /// The evidence outbox failed to store, update, remove or list entries
    /// (v1.2.0).
    #[error("evidence outbox error: {0}")]
    Outbox(#[source] std::io::Error),

    /// No evidence outbox is configured ([`ClientOptions::with_outbox`](crate::ClientOptions::with_outbox));
    /// `governed_action` and the outbox methods need one (v1.2.0).
    #[error("no evidence outbox is configured (ClientOptions::with_outbox)")]
    OutboxRequired,
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
            | Self::Http { code, .. } => code,
            Self::DecisionVerification(reason) => reason,
            Self::SecretMaterial(_) => "evidence_secret_material",
            Self::Verification(_) => "verification_failed",
            Self::ActionFailed { .. } => "governed_action_failed",
            Self::ActionUnrecorded { .. } => "governed_action_unrecorded",
            Self::MetadataRefused { .. } => "governed_action_metadata_refused",
            Self::EvidenceNotKept { .. } => "governed_action_evidence_unkept",
            Self::Outbox(_) => "outbox_error",
            Self::OutboxRequired => "outbox_required",
            Self::Configuration(_) => "configuration",
            Self::Network(_) => "network",
            Self::Json(_) => "json",
            Self::SigningKey(_) | Self::MissingSigningKey => "signing_key",
        }
    }
}

impl GenesisMeshError {
    /// The governed action's value, when this error says the action ran
    /// (`MetadataRefused`, `EvidenceNotKept`) and the value is a `T`.
    pub fn action_value<T: 'static>(&self) -> Option<&T> {
        match self {
            Self::MetadataRefused { value, .. } | Self::EvidenceNotKept { value, .. } => {
                value.as_ref()?.downcast_ref::<T>()
            }
            _ => None,
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
