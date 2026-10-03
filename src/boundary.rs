use std::sync::Arc;

use serde_json::Value;

use crate::{client::HttpTransport, execution::ensure_metadata_only, GenesisMeshError, Result};

/// Capability boundary decision client.
#[derive(Debug, Clone)]
pub struct BoundaryClient {
    http: Arc<HttpTransport>,
}

impl BoundaryClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Issue a signed boundary decision.
    pub async fn decide(&self, params: Value) -> Result<Value> {
        self.http.admin_post("/admin/boundary/decide", params).await
    }

    /// Policy-aware evaluation under exactly one basis, an `attestation_id`
    /// or an `agreement` (admin). Returns `{decision, justification}`; a
    /// denial is a signed decision with `authorized: false`, not an error.
    pub async fn evaluate(&self, params: Value) -> Result<Value> {
        let has = |key: &str| params.get(key).is_some_and(|v| !v.is_null());
        if has("attestation_id") == has("agreement") {
            return Err(GenesisMeshError::Configuration(
                "exactly one of agreement or attestation_id is required".into(),
            ));
        }
        if let Some(context) = params.get("context").filter(|c| !c.is_null()) {
            ensure_metadata_only(context, None)?;
        }
        self.http
            .admin_post("/admin/boundary/evaluate", params)
            .await
    }

    /// Verify a boundary decision without admin authentication.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http.public_post("/boundary/verify", params).await
    }
}
