use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, PoisonError,
    },
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    canonical::{execution_digest, out_of_band_digest},
    client::{query_pairs, resource_path, segment, HttpTransport},
    errors::{GenesisMeshError, Result},
    execution::ensure_metadata_only,
    outbox::{
        classify_record_submission_error, classify_submission_error, retry_delay, timestamp,
        Delivery, EvidenceOutbox, FlushReport, OutboxEntry, OutboxState, RecordDelivery,
        RecordFlushReport, RecordKind, RecordOutbox, RecordOutboxEntry, SubmissionFailure,
        PREDECESSOR_DEAD_LETTERED,
    },
    verify::parse_export_lines,
};

/// Largest page the NA serves for search and export.
pub const MAX_PAGE: u64 = 1000;

/// Most pending records an action submits before its own (older ones wait
/// for `flush_pending`).
const MAX_INLINE_DRAIN: usize = 100;

/// Most observations one batch request carries (v1.3.0).
const OBSERVATION_BATCH: usize = 100;

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

/// Ids of the records an `enqueue` call is submitting right now (v1.3.0): a
/// flush running meanwhile leaves them to it and reports them pending, so
/// one record is never submitted twice at once nor settled by two runs.
#[derive(Debug, Default)]
struct InFlight(Mutex<HashSet<String>>);

impl InFlight {
    fn ids(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn contains(&self, id: &str) -> bool {
        self.ids().contains(id)
    }

    /// Mark `id` in flight until the guard drops, however the call ends.
    fn hold(&self, id: &str) -> Holding<'_> {
        self.ids().insert(id.to_owned());
        Holding(self, id.to_owned())
    }
}

struct Holding<'a>(&'a InFlight, String);

impl Drop for Holding<'_> {
    fn drop(&mut self) {
        self.0.ids().remove(&self.1);
    }
}

/// The NA execution evidence store (v0.59): controller submission, operator
/// search, history, export, executor keys and retention; from v1.3.0 also
/// observations, break-glass records and their judgements.
#[derive(Debug, Clone)]
pub struct EvidenceStoreClient {
    http: Arc<HttpTransport>,
    outbox: Option<Arc<dyn EvidenceOutbox>>,
    flushing: Arc<AtomicBool>,
    in_flight: Arc<InFlight>,
    record_outbox: Option<Arc<dyn RecordOutbox>>,
    flushing_records: Arc<AtomicBool>,
    records_in_flight: Arc<InFlight>,
}

impl EvidenceStoreClient {
    pub(crate) fn new(
        http: Arc<HttpTransport>,
        outbox: Option<Arc<dyn EvidenceOutbox>>,
        record_outbox: Option<Arc<dyn RecordOutbox>>,
    ) -> Self {
        Self {
            http,
            outbox,
            flushing: Arc::new(AtomicBool::new(false)),
            in_flight: Arc::default(),
            record_outbox,
            flushing_records: Arc::new(AtomicBool::new(false)),
            records_in_flight: Arc::default(),
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
            let _holding = self.in_flight.hold(&entry.id);
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
    /// refused. Records in backoff are skipped unless `ignore_backoff`, as is
    /// a record an `enqueue` call is submitting (reported pending, v1.3.0); a
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
            if self.in_flight.contains(&entry.id) {
                // `enqueue` is submitting it: still pending as far as this run knows.
                waiting.insert(digest);
                outcomes.insert(entry.id.clone(), Delivery::queued(entry.clone()));
                report.pending.push(entry);
                continue;
            }
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
    /// v1.3.0: `unjudged_records`, when present, counts the observations and
    /// break-glass records not judged yet (they hold retention back).
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
    /// `key_id`, `public_key` (raw base64), `executor_sovereign_id`. v1.3.0:
    /// `role` is `executor` (the default), which signs execution evidence and
    /// break-glass records, or `observer`, which signs observations only;
    /// `resource_prefix` (or `null`) limits the key to resources whose id
    /// starts with it.
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

    // ── Changes outside the controlled path (v1.3.0) ─────────────────────────

    /// The configured record outbox (v1.3.0).
    pub fn record_outbox(&self) -> Option<&Arc<dyn RecordOutbox>> {
        self.record_outbox.as_ref()
    }

    fn require_record_outbox(&self) -> Result<&dyn RecordOutbox> {
        self.record_outbox
            .as_deref()
            .ok_or(GenesisMeshError::RecordOutboxRequired)
    }

    /// Submit one signed observation (v1.3.0). Authenticated by the observer
    /// key's signature, not operator headers. Idempotent per source event: a
    /// resubmission returns `status: "duplicate"`; `quarantined` means the NA
    /// kept an authentic record outside its time bounds, unjudged. The answer
    /// carries the `judgement` made at admission, when the NA judges then.
    pub async fn submit_observation(&self, observation: Value) -> Result<Value> {
        self.http
            .public_post(
                "/evidence/observations",
                json!({ "observation": observation }),
            )
            .await
    }

    /// Submit up to 100 signed observations in one request (v1.3.0); the NA
    /// admits them in order of their change times. One result per
    /// observation, with its `index` in the request: `recorded`, `duplicate`,
    /// `quarantined`, or `refused` with an `error` (`code`, `message`).
    pub async fn submit_observations(&self, observations: &[Value]) -> Result<Vec<Value>> {
        let mut body: Value = self
            .http
            .public_post(
                "/evidence/observations/batch",
                json!({ "observations": observations }),
            )
            .await?;
        Ok(match body["results"].take() {
            Value::Array(results) => results,
            _ => Vec::new(),
        })
    }

    /// Submit one signed break-glass record (v1.3.0), authenticated by the
    /// executor key's signature. A resubmission returns `status: "duplicate"`.
    pub async fn submit_break_glass(&self, record: Value) -> Result<Value> {
        self.http
            .public_post("/evidence/break-glass", json!({ "record": record }))
            .await
    }

    /// Keep a signed observation or break-glass record in the record outbox
    /// and submit it (v1.3.0). A failed submission is not an error: a
    /// transient one leaves the record pending for
    /// [`flush_records`](Self::flush_records), and a refusal no retry can
    /// overcome ([`RECORD_PERMANENT_REFUSALS`](crate::RECORD_PERMANENT_REFUSALS))
    /// keeps it as a dead letter. Fails only when the record outbox cannot
    /// store the record. Passing a record already in the outbox submits it
    /// again.
    pub async fn enqueue_record(&self, record: Value) -> Result<RecordDelivery> {
        let outbox = self.require_record_outbox()?;
        let fresh = RecordOutboxEntry::new(record);
        if fresh.id.is_empty() {
            return Err(GenesisMeshError::Configuration(
                "a record needs an observation_id or a break_glass_id".into(),
            ));
        }
        let entries = outbox.list().await.map_err(outbox_error)?;
        let entry = match entries.into_iter().find(|e| e.id == fresh.id) {
            Some(found)
                if out_of_band_digest(&found.record)? != out_of_band_digest(&fresh.record)? =>
            {
                return Err(GenesisMeshError::Outbox(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "a different record with id {} is in the record outbox",
                        fresh.id
                    ),
                )))
            }
            Some(found) => found,
            None => {
                outbox.add(&fresh).await.map_err(outbox_error)?;
                fresh
            }
        };
        if entry.state == OutboxState::DeadLetter {
            return Ok(RecordDelivery::queued(entry));
        }
        let _holding = self.records_in_flight.hold(&entry.id);
        Ok(self.attempt_record(outbox, entry).await)
    }

    /// Submit the record outbox's pending records in the order they were
    /// added (v1.3.0), consecutive observations up to 100 per request and
    /// break-glass records one at a time. Records in backoff are skipped
    /// unless `ignore_backoff`, as are records an `enqueue_record` call is
    /// submitting (reported pending); a transient error ends the run. A record the
    /// NA keeps as a quarantine entry is admitted and also listed in
    /// `quarantined`. One run at a time per client: a call while another
    /// runs returns [`GenesisMeshError::FlushInProgress`].
    pub async fn flush_records(&self, options: FlushOptions) -> Result<RecordFlushReport> {
        let outbox = self.require_record_outbox()?;
        if self.flushing_records.swap(true, Ordering::AcqRel) {
            return Err(GenesisMeshError::FlushInProgress);
        }
        let _flushing = Flushing(&self.flushing_records);
        let entries: Vec<RecordOutboxEntry> = outbox
            .list()
            .await
            .map_err(outbox_error)?
            .into_iter()
            .filter(|e| e.state == OutboxState::Pending)
            .collect();
        // A record `enqueue_record` is submitting is left to it, as pending.
        let due = |e: &RecordOutboxEntry| {
            !self.records_in_flight.contains(&e.id) && (options.ignore_backoff || e.due(Utc::now()))
        };
        let mut report = RecordFlushReport::default();
        let mut stopped = false;
        let mut index = 0;
        while index < entries.len() {
            let entry = &entries[index];
            if stopped || !due(entry) {
                report.pending.push(entry.clone());
                index += 1;
                continue;
            }
            if entry.kind == RecordKind::BreakGlass {
                let delivery = self.attempt_record(outbox, entry.clone()).await;
                stopped = !settle(&mut report, entry, delivery);
                index += 1;
                continue;
            }
            let start = index;
            while index < entries.len()
                && index - start < OBSERVATION_BATCH
                && entries[index].kind == RecordKind::Observation
                && due(&entries[index])
            {
                index += 1;
            }
            let batch = &entries[start..index];
            let records: Vec<Value> = batch.iter().map(|e| e.record.clone()).collect();
            let results = match self.submit_observations(&records).await {
                Ok(results) => results,
                Err(err) if classify_record_submission_error(&err).1 => {
                    for e in batch {
                        let failed = record_failed(outbox, e.clone(), &err).await;
                        settle(&mut report, e, RecordDelivery::queued(failed));
                    }
                    stopped = true;
                    continue;
                }
                Err(_) => {
                    // The batch itself was refused: each observation is tried alone.
                    for e in batch {
                        if stopped {
                            report.pending.push(e.clone());
                        } else {
                            let delivery = self.attempt_record(outbox, e.clone()).await;
                            stopped = !settle(&mut report, e, delivery);
                        }
                    }
                    continue;
                }
            };
            for (position, e) in batch.iter().enumerate() {
                match results
                    .iter()
                    .find(|r| r["index"].as_u64() == Some(position as u64))
                {
                    None => report.pending.push(e.clone()),
                    Some(answer) if answer["status"] == "refused" => {
                        let refusal = batch_refusal(&answer["error"]);
                        let failed = record_failed(outbox, e.clone(), &refusal).await;
                        settle(&mut report, e, RecordDelivery::queued(failed));
                    }
                    Some(answer) => {
                        // The NA holds the record even if this fails: the next
                        // flush resubmits it, gets a duplicate and removes it.
                        let _ = outbox.remove(&e.id).await;
                        settle(&mut report, e, RecordDelivery::admitted(answer.clone()));
                    }
                }
            }
        }
        Ok(report)
    }

    async fn attempt_record(
        &self,
        outbox: &dyn RecordOutbox,
        entry: RecordOutboxEntry,
    ) -> RecordDelivery {
        let submitted = match entry.kind {
            RecordKind::Observation => self.submit_observation(entry.record.clone()).await,
            RecordKind::BreakGlass => self.submit_break_glass(entry.record.clone()).await,
        };
        match submitted {
            Ok(ack) => {
                // The NA holds the record even if this fails: the next flush
                // resubmits it, gets a duplicate and removes it.
                let _ = outbox.remove(&entry.id).await;
                RecordDelivery::admitted(ack)
            }
            Err(err) => RecordDelivery::queued(record_failed(outbox, entry, &err).await),
        }
    }

    /// Judge an observation once (admin, v1.3.0): `status` `judged`, or
    /// `existing` with the judgement made before.
    pub async fn judge_observation(&self, observation_id: &str) -> Result<Value> {
        self.http
            .admin_post(
                &format!(
                    "/admin/evidence/observations/{}/judge",
                    segment(observation_id)?
                ),
                json!({}),
            )
            .await
    }

    /// Judge a break-glass record once (admin, v1.3.0): `status` `judged`,
    /// or `existing` with the judgement made before.
    pub async fn judge_break_glass(&self, break_glass_id: &str) -> Result<Value> {
        self.http
            .admin_post(
                &format!(
                    "/admin/evidence/break-glass/{}/judge",
                    segment(break_glass_id)?
                ),
                json!({}),
            )
            .await
    }

    /// Every change to a resource, oldest first, with how it was governed
    /// (`prior_decision` or `after_the_fact`) and its state (`recorded`,
    /// `matched`, `judged_allowed`, `judged_denied`, `indeterminate`,
    /// `observed`, `quarantined`) (admin, v1.3.0). `truncated: true` when
    /// the resource has more changes than one response holds.
    pub async fn resource_changes(&self, resource_id: &str) -> Result<Value> {
        self.http
            .admin_get(
                &format!("/admin/evidence/changes/{}", resource_path(resource_id)?),
                &[],
            )
            .await
    }

    /// Operator key holders as the evidence store records them (admin,
    /// v1.3.0).
    pub async fn operator_holders(&self) -> Result<Vec<Value>> {
        let mut body: Value = self
            .http
            .admin_get("/admin/evidence/operator-holders", &[])
            .await?;
        Ok(match body["holders"].take() {
            Value::Array(holders) => holders,
            _ => Vec::new(),
        })
    }

    /// Propose a new holder for an operator key (admin, privileged, v1.3.0);
    /// a privileged key of another holder approves it.
    pub async fn propose_holder(&self, key_id: &str, holder: &str) -> Result<Value> {
        self.http
            .admin_post(
                &format!("/admin/operator-keys/{}/holder", segment(key_id)?),
                json!({ "holder": holder }),
            )
            .await
    }

    /// Approve a holder change with a privileged key of a different holder
    /// (admin, privileged, v1.3.0).
    pub async fn approve_holder(&self, proposal_id: &str) -> Result<Value> {
        self.http
            .admin_post(
                &format!(
                    "/admin/operator-keys/holder-changes/{}/approve",
                    segment(proposal_id)?
                ),
                json!({}),
            )
            .await
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

/// A record outbox entry after a failed submission: pending with a backoff,
/// or a dead letter. Once the NA has answered, the answer stands even if the
/// outbox cannot store it: the entry keeps its previous state and the next
/// flush settles it.
async fn record_failed(
    outbox: &dyn RecordOutbox,
    entry: RecordOutboxEntry,
    err: &GenesisMeshError,
) -> RecordOutboxEntry {
    let (failure, transient) = classify_record_submission_error(err);
    let attempts = entry.attempts + 1;
    let next = if transient {
        let retry =
            chrono::Duration::from_std(retry_delay(attempts)).unwrap_or(chrono::Duration::MAX);
        RecordOutboxEntry {
            attempts,
            next_attempt_at: Some(timestamp(Utc::now() + retry)),
            last_error: Some(failure),
            ..entry
        }
    } else {
        RecordOutboxEntry {
            attempts,
            state: OutboxState::DeadLetter,
            next_attempt_at: None,
            last_error: Some(failure),
            ..entry
        }
    };
    let _ = outbox.update(&next).await;
    next
}

/// One refused result of a batch, as the error its single submission gives.
fn batch_refusal(error: &Value) -> GenesisMeshError {
    let code = error["code"].as_str().unwrap_or("unknown").to_owned();
    let message = error["message"]
        .as_str()
        .map_or_else(|| code.clone(), str::to_owned);
    if code.ends_with("_conflict") {
        GenesisMeshError::Http {
            status: 409,
            message,
            code,
        }
    } else {
        GenesisMeshError::Validation { message, code }
    }
}

/// File an entry's delivery in the report; true unless it stays pending.
fn settle(
    report: &mut RecordFlushReport,
    entry: &RecordOutboxEntry,
    delivery: RecordDelivery,
) -> bool {
    if let Some(ack) = delivery.submission {
        report.admitted.push(entry.clone());
        if ack["status"] == "quarantined" {
            report.quarantined.push(entry.clone());
        }
        return true;
    }
    match delivery.queued {
        Some(queued) if queued.state == OutboxState::DeadLetter => {
            report.dead_lettered.push(queued);
            true
        }
        Some(queued) => {
            report.pending.push(queued);
            false
        }
        None => false,
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
