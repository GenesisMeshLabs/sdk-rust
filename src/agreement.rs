use std::sync::Arc;

use serde_json::Value;

use crate::{client::HttpTransport, Result};

/// Agreement lifecycle client: offer, counter, accept, verify.
#[derive(Debug, Clone)]
pub struct AgreementClient {
    http: Arc<HttpTransport>,
}

impl AgreementClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Create and sign a capability offer.
    pub async fn offer(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/agreements/offer", params)
            .await
    }

    /// Create and sign a counter-offer.
    pub async fn counter(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/agreements/counter", params)
            .await
    }

    /// Accept an offer or counter-offer.
    pub async fn accept(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/agreements/accept", params)
            .await
    }

    /// Verify agreement signatures without admin authentication.
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http.public_post("/agreements/verify", params).await
    }
}
