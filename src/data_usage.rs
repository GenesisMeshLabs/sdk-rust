use std::sync::Arc;

use serde_json::Value;

use crate::{client::HttpTransport, Result};

/// Data usage licensing and verification client.
#[derive(Debug, Clone)]
pub struct DataUsageClient {
    http: Arc<HttpTransport>,
}

impl DataUsageClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Create a data license policy.
    pub async fn create_policy(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/data-usage/policy", params)
            .await
    }

    /// Create a data access intent.
    pub async fn create_intent(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/data-usage/intent", params)
            .await
    }

    /// Get the active data usage policy.
    pub async fn get_policy(&self) -> Result<Value> {
        self.http.public_get("/data-usage/policy").await
    }

    /// Verify a data access intent against a policy.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http.public_post("/data-usage/verify", params).await
    }
}
