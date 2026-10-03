use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    canonical::execution_digest,
    client::{query_pairs, resource_path, segment, HttpTransport},
    errors::{GenesisMeshError, Result},
    execution::ensure_metadata_only,
    verify::parse_export_lines,
};

/// Largest page the NA serves for search and export.
pub const MAX_PAGE: u64 = 1000;

/// The head of a resource chain: what the next record must link to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceHead {
    /// Sequence of the latest record of the resource.
    pub resource_sequence: u64,
    /// `ExecutionEvidence.digest()` of that record.
    pub record_digest: String,
}

/// The NA execution evidence store (v0.59): controller submission, operator
/// search, history, export, executor keys and retention.
#[derive(Debug, Clone)]
pub struct EvidenceStoreClient {
    http: Arc<HttpTransport>,
}

impl EvidenceStoreClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Submit one signed ExecutionEvidence record. Authenticated by the
    /// executor signature, not operator headers. An identical resubmission
    /// returns `status: "duplicate"`, so it is safe to retry.
    pub async fn submit(&self, evidence: Value) -> Result<Value> {
        ensure_metadata_only(
            evidence.get("execution_parameters").unwrap_or(&json!({})),
            evidence.get("outcome_detail").and_then(Value::as_str),
        )?;
        self.http
            .public_post("/evidence/execution", json!({ "evidence": evidence }))
            .await
    }

    /// Search stored entries (admin). Filters: `vendor_id`, `attestation_id`,
    /// `capability`, `resource_id`, `outcome`, `entry_kind`, `decision_id`,
    /// `since`, `until`, `after_sequence`, `limit` (1..1000). Use
    /// `next_after_sequence` as the next `after_sequence`.
    pub async fn search(&self, params: Value) -> Result<Value> {
        self.http
            .admin_get("/admin/evidence", &query_pairs(&params)?)
            .await
    }

    /// Every matching entry, following pages (admin).
    pub async fn search_all(&self, params: Value) -> Result<Vec<Value>> {
        let mut params = if params.is_null() { json!({}) } else { params };
        let mut after = 0_u64;
        let mut entries = Vec::new();
        loop {
            params["after_sequence"] = json!(after);
            let mut page = self.search(params.clone()).await?;
            if let Value::Array(items) = page["entries"].take() {
                entries.extend(items);
            }
            match page["next_after_sequence"].as_u64() {
                None if page["next_after_sequence"].is_null() => return Ok(entries),
                Some(next) if next > after => after = next,
                _ => {
                    return Err(GenesisMeshError::Verification(
                        "evidence search cursor did not advance".into(),
                    ))
                }
            }
        }
    }

    /// Store mode, size, last sequence and retention checkpoint (admin).
    pub async fn status(&self) -> Result<Value> {
        self.http.admin_get("/admin/evidence/status", &[]).await
    }

    /// Verify every stored entry, chain and signature on the NA (admin).
    pub async fn verify(&self) -> Result<Value> {
        self.http.admin_get("/admin/evidence/verify", &[]).await
    }

    /// One resource's history, decision to execution, verified by the NA
    /// (admin). `truncated: true` when cut at the NA's history limit.
    pub async fn resource_history(&self, resource_id: &str) -> Result<Value> {
        self.http
            .admin_get(
                &format!("/admin/evidence/resources/{}", resource_path(resource_id)?),
                &[],
            )
            .await
    }

    /// A vendor's decisions and the evidence under them, verified by the NA (admin).
    pub async fn vendor_history(&self, vendor_id: &str) -> Result<Value> {
        self.http
            .admin_get(
                &format!("/admin/evidence/vendors/{}", segment(vendor_id)?),
                &[],
            )
            .await
    }

    /// One page of `gm.evidence.event` JSON Lines, unparsed (admin).
    /// Parameters: `since_sequence` (default 0), `limit` (1..1000).
    pub async fn export_text(&self, params: Value) -> Result<String> {
        self.http
            .admin_get_text("/admin/evidence/export", &query_pairs(&params)?)
            .await
    }

    /// One page of export events, parsed (admin).
    pub async fn export(&self, params: Value) -> Result<Vec<Value>> {
        parse_export_lines(&self.export_text(params).await?)
    }

    /// Every event after `since_sequence`, following pages: an incremental
    /// SIEM pull (admin).
    pub async fn export_all(&self, since_sequence: u64, page_size: u64) -> Result<Vec<Value>> {
        if !(1..=MAX_PAGE).contains(&page_size) {
            return Err(GenesisMeshError::Configuration(
                "export page size must be between 1 and 1000".into(),
            ));
        }
        let mut since = since_sequence;
        let mut all = Vec::new();
        loop {
            let events = self
                .export(json!({"since_sequence": since, "limit": page_size}))
                .await?;
            let count = events.len() as u64;
            if let Some(last) = events.last() {
                let last_sequence = last["entry"]["store_sequence"].as_u64().unwrap_or_default();
                if last_sequence <= since {
                    return Err(GenesisMeshError::Verification(
                        "evidence export cursor did not advance".into(),
                    ));
                }
                since = last_sequence;
            }
            all.extend(events);
            if count < page_size {
                return Ok(all);
            }
        }
    }

    /// Registered executor keys, retired keys included (admin).
    pub async fn list_executor_keys(&self) -> Result<Vec<Value>> {
        let mut body: Value = self
            .http
            .admin_get("/admin/evidence/executor-keys", &[])
            .await?;
        Ok(match body["executor_keys"].take() {
            Value::Array(keys) => keys,
            _ => Vec::new(),
        })
    }

    /// Register a controller's executor signing key (admin, privileged):
    /// `key_id`, `public_key` (raw base64), `executor_sovereign_id`.
    pub async fn register_executor_key(&self, params: Value) -> Result<Value> {
        self.http
            .admin_post("/admin/evidence/executor-keys", params)
            .await
    }

    /// Retire an executor key: it still verifies old records and can sign no
    /// new ones (admin, privileged).
    pub async fn retire_executor_key(&self, key_id: &str) -> Result<Value> {
        self.http
            .admin_post(
                &format!("/admin/evidence/executor-keys/{}/retire", segment(key_id)?),
                json!({}),
            )
            .await
    }

    /// Remove entries older than `older_than_days` behind a signed checkpoint
    /// (admin, privileged).
    pub async fn apply_retention(&self, older_than_days: u32) -> Result<Value> {
        self.http
            .admin_post(
                "/admin/evidence/retention/apply",
                json!({ "older_than_days": older_than_days }),
            )
            .await
    }

    /// The most recent retention checkpoint in the store, if any (admin).
    pub async fn latest_checkpoint(&self) -> Result<Option<Value>> {
        let entries = self
            .search_all(json!({"entry_kind": "retention_checkpoint"}))
            .await?;
        Ok(entries.into_iter().last().map(|mut e| e["payload"].take()))
    }

    /// The head of a resource chain, or `None` for a resource with no history
    /// (admin). One indexed lookup on the NA (`/admin/evidence/resource-heads`,
    /// v0.63.1), which also covers chains whose records retention removed.
    /// Against an older NA it falls back to the resource history.
    pub async fn resource_head(&self, resource_id: &str) -> Result<Option<ResourceHead>> {
        let path = format!(
            "/admin/evidence/resource-heads/{}",
            resource_path(resource_id)?
        );
        match self.http.admin_get::<Value>(&path, &[]).await {
            Ok(head) => Ok(Some(serde_json::from_value(head)?)),
            Err(GenesisMeshError::NotFound { code, .. }) if code == "resource_not_found" => {
                Ok(None)
            }
            // Route missing: an NA older than v0.63.1.
            Err(GenesisMeshError::NotFound { .. }) => {
                self.resource_head_from_history(resource_id).await
            }
            Err(err) => Err(err),
        }
    }

    async fn resource_head_from_history(&self, resource_id: &str) -> Result<Option<ResourceHead>> {
        let history = match self.resource_history(resource_id).await {
            Ok(history) => history,
            Err(GenesisMeshError::NotFound { code, .. }) if code == "resource_not_found" => {
                let checkpoint = self.latest_checkpoint().await?;
                return Ok(checkpoint
                    .and_then(|c| c["resource_heads"].get(resource_id).cloned())
                    .map(serde_json::from_value)
                    .transpose()?);
            }
            Err(err) => return Err(err),
        };
        if history["verification"]["verified"].as_bool() != Some(true) {
            return Err(GenesisMeshError::Verification(
                "resource history did not verify".into(),
            ));
        }
        if history["truncated"].as_bool() == Some(true) {
            return Err(GenesisMeshError::Verification(
                "resource history is truncated; upgrade the NA to read the resource head".into(),
            ));
        }
        let mut head: Option<ResourceHead> = None;
        for event in history["entries"].as_array().into_iter().flatten() {
            if event["entry"]["entry_kind"] != "execution" {
                continue;
            }
            let record = &event["payload"];
            let Some(sequence) = record["resource_sequence"].as_u64() else {
                continue;
            };
            if record["resource_id"] != resource_id {
                continue;
            }
            if head.as_ref().is_none_or(|h| sequence > h.resource_sequence) {
                head = Some(ResourceHead {
                    resource_sequence: sequence,
                    record_digest: execution_digest(record)?,
                });
            }
        }
        Ok(head)
    }
}
