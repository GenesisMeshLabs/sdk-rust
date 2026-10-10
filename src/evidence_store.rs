use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    canonical::execution_digest,
    client::{query_pairs, resource_path, segment, HttpTransport},
    errors::{GenesisMeshError, Result},
    execution::ensure_metadata_only,
    outbox::{
        classify_submission_error, retry_delay, timestamp, Delivery, EvidenceOutbox, FlushReport,
        OutboxEntry, OutboxState, SubmissionFailure, PREDECESSOR_DEAD_LETTERED,
    },
    verify::parse_export_lines,
};

/// Largest page the NA serves for search and export.
pub const MAX_PAGE: u64 = 1000;

/// Most pending records an action submits before its own (older ones wait
/// for `flush_pending`).
const MAX_INLINE_DRAIN: usize = 100;

/// The head of a resource chain: what the next record must link to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceHead {
    /// Sequence of the latest record of the resource.
    pub resource_sequence: u64,
    /// `ExecutionEvidence.digest()` of that record.
    pub record_digest: String,
}

/// Options for [`EvidenceStoreClient::flush_pending`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FlushOptions {
    /// Retry entries whose backoff has not expired (e.g. right after the NA
    /// is back).
    pub ignore_backoff: bool,
}

/// The records a signed record chains from: its predecessor under the
/// decision and on the resource.
fn predecessors(evidence: &Value) -> Vec<String> {
    ["prev_evidence_digest", "prev_resource_digest"]
        .iter()
        .filter_map(|k| evidence[*k].as_str().map(str::to_owned))
        .collect()
}

fn outbox_error(err: std::io::Error) -> GenesisMeshError {
    GenesisMeshError::Outbox(err)
}

fn predecessor_refused() -> SubmissionFailure {
    SubmissionFailure {
        status: 0,
        code: PREDECESSOR_DEAD_LETTERED.into(),
        message: "a record this one chains from was refused".into(),
    }
}

/// Clears the flush flag when a run ends, however it ends.
struct Flushing<'a>(&'a AtomicBool);

impl Drop for Flushing<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The NA execution evidence store (v0.59): controller submission, operator
/// search, history, export, executor keys and retention.
#[derive(Debug, Clone)]
pub struct EvidenceStoreClient {
    http: Arc<HttpTransport>,
    outbox: Option<Arc<dyn EvidenceOutbox>>,
    flushing: Arc<AtomicBool>,
}

impl EvidenceStoreClient {
    pub(crate) fn new(http: Arc<HttpTransport>, outbox: Option<Arc<dyn EvidenceOutbox>>) -> Self {
        Self {
            http,
            outbox,
            flushing: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The configured evidence outbox (v1.2.0).
    pub fn outbox(&self) -> Option<&Arc<dyn EvidenceOutbox>> {
        self.outbox.as_ref()
    }

    fn require_outbox(&self) -> Result<&dyn EvidenceOutbox> {
        self.outbox
            .as_deref()
            .ok_or(GenesisMeshError::OutboxRequired)
    }

    /// Keep a signed record in the outbox and submit it (v1.2.0). Pending
    /// records it chains from are submitted first, oldest first (up to 100;
    /// older ones wait for [`flush_pending`](Self::flush_pending)). A failed
    /// submission is not an error: a transient one leaves the record pending,
    /// and a refusal no retry can overcome keeps it as a dead letter with the
    /// NA's code, as does a predecessor's refusal. Fails only when the outbox
    /// cannot store the record. Passing a record already in the outbox
    /// submits it again.
    pub async fn enqueue(&self, evidence: Value) -> Result<Delivery> {
        let outbox = self.require_outbox()?;
        let mut entries = outbox.list().await.map_err(outbox_error)?;
        let digest = execution_digest(&evidence)?;
        let id = evidence["evidence_id"].as_str().unwrap_or_default();
        let entry = match entries.iter().find(|e| e.id == id) {
            Some(found) if execution_digest(&found.evidence)? != digest => {
                return Err(GenesisMeshError::Outbox(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("a different record with evidence_id {id} is in the outbox"),
                )))
            }
            Some(found) => found.clone(),
            None => {
                let entry = OutboxEntry::new(evidence);
                outbox.add(&entry).await.map_err(outbox_error)?;
                entries.push(entry.clone());
                entry
            }
        };
        if entry.state == OutboxState::DeadLetter {
            return Ok(Delivery::queued(entry));
        }
        let (dead, pending) = chain_of(&entries, &entry)?;
        if dead {
            let refused = dead_letter(outbox, &mut entries, entry, predecessor_refused()).await?;
            return Ok(Delivery::queued(refused));
        }
        if pending.is_empty() {
            return self.attempt(outbox, &mut entries, entry).await;
        }
        if pending.len() > MAX_INLINE_DRAIN || self.flushing.swap(true, Ordering::AcqRel) {
            return Ok(Delivery::queued(entry));
        }
        let _flushing = Flushing(&self.flushing);
        let mut only: HashSet<String> = pending.into_iter().collect();
        only.insert(entry.id.clone());
        let (_, mut outcomes) = self
            .flush(
                outbox,
                FlushOptions {
                    ignore_backoff: true,
                },
                Some(&only),
            )
            .await?;
        Ok(outcomes
            .remove(&entry.id)
            .unwrap_or_else(|| Delivery::queued(entry)))
    }

    /// Submit the outbox's pending records in the order they were added
    /// (v1.2.0). A record waits while one it chains from is pending, and is
    /// dead-lettered (`evidence_predecessor_dead_lettered`) when that one was
    /// refused. Records in backoff are skipped unless `ignore_backoff`; a
    /// transient error ends the run, leaving the rest for the next one. Run
    /// it at startup and on a timer, one run at a time per client: a call
    /// while another runs returns [`GenesisMeshError::FlushInProgress`].
    pub async fn flush_pending(&self, options: FlushOptions) -> Result<FlushReport> {
        let outbox = self.require_outbox()?;
        if self.flushing.swap(true, Ordering::AcqRel) {
            return Err(GenesisMeshError::FlushInProgress);
        }
        let _flushing = Flushing(&self.flushing);
        Ok(self.flush(outbox, options, None).await?.0)
    }

    /// The newest pending record in the outbox for a resource that can still
    /// be admitted, or `None` (v1.2.0). [`governed_action`](crate::governed_action)
    /// chains from it, not from the NA's head, while it waits.
    pub async fn pending_head(&self, resource_id: &str) -> Result<Option<Value>> {
        let entries = self.require_outbox()?.list().await.map_err(outbox_error)?;
        let dead = dead_digests(&entries)?;
        for entry in entries.iter().rev() {
            if entry.state == OutboxState::Pending
                && entry.evidence["resource_id"] == resource_id
                && !dead.contains(&execution_digest(&entry.evidence)?)
            {
                return Ok(Some(entry.evidence.clone()));
            }
        }
        Ok(None)
    }

    async fn attempt(
        &self,
        outbox: &dyn EvidenceOutbox,
        entries: &mut [OutboxEntry],
        entry: OutboxEntry,
    ) -> Result<Delivery> {
        match self.submit(entry.evidence.clone()).await {
            Ok(ack) => {
                // The NA holds the record even if this fails: the next flush
                // resubmits it, gets a duplicate and removes it.
                let _ = outbox.remove(&entry.id).await;
                Ok(Delivery::admitted(ack))
            }
            Err(err) => {
                let (failure, transient) = classify_submission_error(&err);
                let attempts = entry.attempts + 1;
                if !transient {
                    let refused = OutboxEntry { attempts, ..entry };
                    return Ok(Delivery::queued(
                        dead_letter(outbox, entries, refused, failure).await?,
                    ));
                }
                let retry = chrono::Duration::from_std(retry_delay(attempts))
                    .unwrap_or(chrono::Duration::MAX);
                let failed = OutboxEntry {
                    attempts,
                    next_attempt_at: Some(timestamp(Utc::now() + retry)),
                    last_error: Some(failure),
                    ..entry
                };
                keep(outbox, &failed).await;
                if let Some(slot) = entries.iter_mut().find(|e| e.id == failed.id) {
                    *slot = failed.clone();
                }
                Ok(Delivery::queued(failed))
            }
        }
    }

    async fn flush(
        &self,
        outbox: &dyn EvidenceOutbox,
        options: FlushOptions,
        only: Option<&HashSet<String>>,
    ) -> Result<(FlushReport, HashMap<String, Delivery>)> {
        let mut report = FlushReport::default();
        let mut outcomes = HashMap::new();
        let mut entries = outbox.list().await.map_err(outbox_error)?;
        let mut waiting = HashSet::new();
        let mut stopped = false;
        let mut index = 0;
        while index < entries.len() {
            let entry = entries[index].clone();
            index += 1;
            if entry.state == OutboxState::DeadLetter {
                continue;
            }
            let digest = execution_digest(&entry.evidence)?;
            if only.is_some_and(|only| !only.contains(&entry.id)) {
                waiting.insert(digest);
                continue;
            }
            let after = predecessors(&entry.evidence);
            let due = options.ignore_backoff || entry.due(Utc::now());
            if stopped || !due || after.iter().any(|d| waiting.contains(d)) {
                waiting.insert(digest);
                outcomes.insert(entry.id.clone(), Delivery::queued(entry.clone()));
                report.pending.push(entry);
                continue;
            }
            let delivery = self.attempt(outbox, &mut entries, entry.clone()).await?;
            match &delivery.queued {
                None => report.admitted.push(entry.clone()),
                Some(refused) if refused.state == OutboxState::DeadLetter => {
                    report.dead_lettered.push(refused.clone());
                    // attempt() also dead-lettered the records chaining from it.
                    for later in &entries[index..] {
                        let follows = later.state == OutboxState::DeadLetter
                            && later
                                .last_error
                                .as_ref()
                                .is_some_and(|e| e.code == PREDECESSOR_DEAD_LETTERED)
                            && !report.dead_lettered.iter().any(|d| d.id == later.id);
                        if follows {
                            outcomes.insert(later.id.clone(), Delivery::queued(later.clone()));
                            report.dead_lettered.push(later.clone());
                        }
                    }
                }
                Some(failed) => {
                    waiting.insert(digest);
                    report.pending.push(failed.clone());
                    stopped = true;
                }
            }
            outcomes.insert(entry.id, delivery);
        }
        Ok((report, outcomes))
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

/// Store an entry's new state. Once the NA has answered, the answer stands
/// even if this fails: the entry keeps its previous state and the next flush
/// settles it.
async fn keep(outbox: &dyn EvidenceOutbox, entry: &OutboxEntry) {
    let _ = outbox.update(entry).await;
}

/// Digests of dead letters and of every record that chains from one.
fn dead_digests(entries: &[OutboxEntry]) -> Result<HashSet<String>> {
    let mut dead = HashSet::new();
    for entry in entries {
        if entry.state == OutboxState::DeadLetter
            || predecessors(&entry.evidence)
                .iter()
                .any(|d| dead.contains(d))
        {
            dead.insert(execution_digest(&entry.evidence)?);
        }
    }
    Ok(dead)
}

/// Whether `entry` chains from a dead letter, and the ids of the pending
/// records it chains from.
fn chain_of(entries: &[OutboxEntry], entry: &OutboxEntry) -> Result<(bool, Vec<String>)> {
    let mut by_digest = HashMap::new();
    for e in entries {
        by_digest.insert(execution_digest(&e.evidence)?, e);
    }
    let dead = dead_digests(entries)?;
    let mut pending = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = predecessors(&entry.evidence);
    while let Some(digest) = stack.pop() {
        let Some(before) = by_digest.get(&digest) else {
            continue;
        };
        if !seen.insert(digest) {
            continue;
        }
        if before.state == OutboxState::Pending {
            pending.push(before.id.clone());
        }
        stack.extend(predecessors(&before.evidence));
    }
    let chains_from_dead = predecessors(&entry.evidence)
        .iter()
        .any(|d| dead.contains(d));
    Ok((chains_from_dead, pending))
}

/// Dead-letter `entry` and every pending record after it that chains from
/// it.
async fn dead_letter(
    outbox: &dyn EvidenceOutbox,
    entries: &mut [OutboxEntry],
    entry: OutboxEntry,
    failure: SubmissionFailure,
) -> Result<OutboxEntry> {
    let refused = OutboxEntry {
        state: OutboxState::DeadLetter,
        next_attempt_at: None,
        last_error: Some(failure),
        ..entry
    };
    keep(outbox, &refused).await;
    let Some(position) = entries.iter().position(|e| e.id == refused.id) else {
        return Ok(refused);
    };
    entries[position] = refused.clone();
    let mut dead = HashSet::from([execution_digest(&refused.evidence)?]);
    for later in entries[position + 1..].iter_mut() {
        if later.state != OutboxState::Pending
            || !predecessors(&later.evidence)
                .iter()
                .any(|d| dead.contains(d))
        {
            continue;
        }
        dead.insert(execution_digest(&later.evidence)?);
        later.state = OutboxState::DeadLetter;
        later.next_attempt_at = None;
        later.last_error = Some(predecessor_refused());
        keep(outbox, later).await;
    }
    Ok(refused)
}
