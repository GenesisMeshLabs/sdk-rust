use std::sync::Arc;

use serde_json::{json, Value};

use crate::{client::HttpTransport, Result};

/// Trust evidence client.
#[derive(Debug, Clone)]
pub struct EvidenceClient {
    http: Arc<HttpTransport>,
}

impl EvidenceClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Build signed trust evidence from a trust decision.
    pub async fn build(&self, decision: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/trust-evidence", json!({ "decision": decision }))
            .await
    }

    /// Verify trust evidence without admin authentication.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http
            .public_post("/trust-evidence/verify", params)
            .await
    }
}
