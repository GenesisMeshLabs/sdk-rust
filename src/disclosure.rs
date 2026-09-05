use std::sync::Arc;

use serde_json::Value;

use crate::{client::HttpTransport, Result};

/// Selective capability disclosure client.
#[derive(Debug, Clone)]
pub struct DisclosureClient {
    http: Arc<HttpTransport>,
}

impl DisclosureClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Commit to a capability set.
    pub async fn commit(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/disclosure/commit", params)
            .await
    }

    /// Issue a one-time nullifier.
    pub async fn nullifier(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/disclosure/nullifier", params)
            .await
    }

    /// Generate a Merkle membership proof.
    pub async fn prove(&self, params: Value) -> Result<Value> {
        self.http.public_post("/disclosure/prove", params).await
    }

    /// Verify a capability proof without admin authentication.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http.public_post("/disclosure/verify", params).await
    }
}
