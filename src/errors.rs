use serde_json::Value;

/// SDK result type.
pub type Result<T> = std::result::Result<T, GenesisMeshError>;

/// Error type for Genesis Mesh SDK operations.
#[derive(Debug, thiserror::Error)]
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
