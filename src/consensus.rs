use std::sync::Arc;

use serde_json::Value;

use crate::{client::HttpTransport, Result};

/// Consensus voting and proof client.
#[derive(Debug, Clone)]
pub struct ConsensusClient {
    http: Arc<HttpTransport>,
}

impl ConsensusClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Cast a validator vote.
    pub async fn vote(&self, params: Value) -> Result<Value> {
        self.http.admin_post("/admin/consensus/vote", params).await
    }

    /// Assemble a consensus proof.
    pub async fn proof(&self, params: Value) -> Result<Value> {
        self.http.admin_post("/admin/consensus/proof", params).await
    }

    /// Verify a consensus proof without admin authentication.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http.public_post("/consensus/verify", params).await
    }
}
