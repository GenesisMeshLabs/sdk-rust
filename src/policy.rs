use std::sync::Arc;

use serde_json::{json, Value};

use crate::{
    client::{segment, HttpTransport},
    Result,
};

/// Declarative boundary policy lifecycle (v0.58).
#[derive(Debug, Clone)]
pub struct PolicyClient {
    http: Arc<HttpTransport>,
}

impl PolicyClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Dry-run validation of policy intent against the NA's gate registry (admin).
    pub async fn validate(&self, intent: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/boundary-policies/validate", intent)
            .await
    }

    /// Validate, sign and store a new inactive version (admin, privileged).
    /// Fails with `boundary_policy_invalid` when the intent does not validate.
    pub async fn publish(&self, intent: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/boundary-policies", intent)
            .await
    }

    /// Every stored version of every policy (admin).
    pub async fn list(&self) -> Result<Vec<Value>> {
        let mut body: Value = self.http.admin_get("/admin/boundary-policies", &[]).await?;
        Ok(match body["policies"].take() {
            Value::Array(policies) => policies,
            _ => Vec::new(),
        })
    }

    /// The active set, its health, and the enforcement mode (admin).
    pub async fn active(&self) -> Result<Value> {
        self.http
            .admin_get("/admin/boundary-policies/active", &[])
            .await
    }

    /// Every version of one policy, newest first, with the signed bodies (admin).
    pub async fn history(&self, policy_id: &str) -> Result<Value> {
        self.http
            .admin_get(
                &format!("/admin/boundary-policies/{}/history", segment(policy_id)?),
                &[],
            )
            .await
    }

    /// Activate a version; activating an older version is the rollback
    /// (admin, privileged).
    pub async fn activate(&self, policy_id: &str, version: u64) -> Result<Value> {
        self.http
            .admin_post(
                &format!("/admin/boundary-policies/{}/activate", segment(policy_id)?),
                json!({ "version": version }),
            )
            .await
    }

    /// Deactivate an active version (admin, privileged).
    pub async fn deactivate(&self, policy_id: &str, version: u64) -> Result<Value> {
        self.http
            .admin_post(
                &format!(
                    "/admin/boundary-policies/{}/deactivate",
                    segment(policy_id)?
                ),
                json!({ "version": version }),
            )
            .await
    }

    /// Verify a policy signature without admin authentication:
    /// `{"policy": ..., "issuer_public_keys": [...]}` (keys default to the NA's own).
    pub async fn verify(&self, params: Value) -> Result<Value> {
        self.http
            .public_post("/boundary-policies/verify", params)
            .await
    }
}
