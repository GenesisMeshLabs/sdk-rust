use std::sync::Arc;

use serde_json::{json, Value};

use crate::{client::HttpTransport, errors::from_http_error, Result};

/// Liveness, readiness and health of the Network Authority (v0.60).
#[derive(Debug, Clone)]
pub struct HealthClient {
    http: Arc<HttpTransport>,
}

impl HealthClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Process liveness only (`GET /healthz`).
    pub async fn liveness(&self) -> Result<Value> {
        self.http.public_get("/healthz").await
    }

    /// Readiness (`GET /readyz`): database writable at the expected schema,
    /// key loaded, shared state in HA mode. A not-ready NA (503
    /// `service_not_ready`) is returned with `ready: false` and the failing
    /// checks, not as an error.
    pub async fn readiness(&self) -> Result<Value> {
        let (status, body) = self.http.public_get_status("/readyz").await?;
        let mut readiness = match status {
            200 => body,
            503 if body["error"]["code"] == "service_not_ready" => body["error"]["details"].clone(),
            _ => return Err(from_http_error(status, &body)),
        };
        if !readiness.is_object() {
            readiness = json!({});
        }
        let ready = status == 200;
        readiness["ready"] = json!(ready);
        readiness["status"] = json!(if ready { "ready" } else { "not_ready" });
        Ok(readiness)
    }

    /// Network, version, boundary policy health and evidence store mode (`GET /health`).
    pub async fn health(&self) -> Result<Value> {
        self.http.public_get("/health").await
    }
}
