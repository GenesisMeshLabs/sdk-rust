use std::sync::Arc;

use serde_json::{json, Value};

use crate::{client::HttpTransport, Result};

/// Membership attestation and recognition policy client.
#[derive(Debug, Clone)]
pub struct AttestationClient {
    http: Arc<HttpTransport>,
}

impl AttestationClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Issue a membership attestation.
    pub async fn issue(&self, params: Value) -> Result<Value> {
        self.http.admin_post("/admin/attestations", params).await
    }

    /// Revoke a membership attestation.
    pub async fn revoke(&self, attestation_id: &str, body: Option<Value>) -> Result<Value> {
        if attestation_id.is_empty() || attestation_id == "." || attestation_id == ".." {
            return Err(crate::GenesisMeshError::Configuration(
                "attestation id must be a nonempty path segment".into(),
            ));
        }
        let attestation_id = percent_encoding::utf8_percent_encode(
            attestation_id,
            percent_encoding::NON_ALPHANUMERIC,
        );
        self.http
            .admin_post(
                &format!("/admin/attestations/{attestation_id}/revoke"),
                body.unwrap_or_else(|| json!({})),
            )
            .await
    }

    /// Set the active recognition policy.
    pub async fn save_policy(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/recognition-policy", params)
            .await
    }
}
