use std::sync::Arc;

use serde_json::Value;

use crate::{client::HttpTransport, Result};

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

    /// Verify a boundary decision without admin authentication.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http.public_post("/boundary/verify", params).await
    }
}
