//! Changes made outside the controlled path (Genesis Mesh 1.3.0).
//!
//! A governed change has a decision before it and execution evidence after
//! it. Other changes still happen: someone changes a secret in the cloud
//! console, or a controller acts while the Network Authority (NA) cannot be
//! reached. These records bring them into the evidence store:
//!
//! * `ObservationRecord`: a change an observer saw at its source, signed by
//!   an observer key ([`ObservationRecorder`]);
//! * `BreakGlassRecord`: a change a controller made while evaluation failed
//!   transiently, with its caller's justification, signed by the executor
//!   key ([`ExecutionRecorder::sign_break_glass`](crate::ExecutionRecorder::sign_break_glass),
//!   [`governed_action_with_break_glass`](crate::governed_action_with_break_glass));
//! * `JudgementRecord`, `QuarantineRecord`, `RegistryRecord`: signed by the NA.
//!
//! Records are JSON values, as execution evidence is. Each signs every field
//! but `signature`; an absent optional field is left out, never `null`
//! ([`out_of_band_canonical`](crate::canonical::out_of_band_canonical)). The
//! forms are frozen from 1.3.0 on and match the Python reference byte for
//! byte (conformance suite `out_of_band`).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    auth::{canonical_digest, load_signing_key, sha256_hex, sign_canonical},
    canonical::{out_of_band_canonical, python_timestamp},
    errors::{GenesisMeshError, Result},
    execution::check_metadata_only,
};

/// Why a controller broke the glass: an evaluation failure a later attempt
/// can overcome. A DENY is never one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationFailure {
    /// No response arrived (connection refused, reset, DNS).
    NetworkError,
    /// The request timed out.
    Timeout,
    /// HTTP `5xx`.
    ServerError,
    /// HTTP `429`.
    RateLimited,
}

impl EvaluationFailure {
    /// The wire name, e.g. `network_error`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetworkError => "network_error",
            Self::Timeout => "timeout",
            Self::ServerError => "server_error",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// The error for a record that would be refused, with the NA's code.
pub(crate) fn refused(code: &str, message: impl Into<String>) -> GenesisMeshError {
    GenesisMeshError::OutOfBandRecord {
        code: code.to_owned(),
        message: message.into(),
    }
}

/// Sign a record's canonical form and add the signature.
fn signed(mut record: Map<String, Value>, key_id: &str, key: &SigningKey) -> Result<Value> {
    let canonical = out_of_band_canonical(&Value::Object(record.clone()))?;
    record.insert("signature".into(), sign_canonical(&canonical, key_id, key));
    Ok(Value::Object(record))
}

fn insert_some(record: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        record.insert(key.into(), value);
    }
}

fn time(value: Option<DateTime<Utc>>) -> Option<Value> {
    value.map(|at| json!(python_timestamp(at)))
}

// ── Observations ─────────────────────────────────────────────────────────────

/// A change an observer saw, as [`ObservationRecorder::record`] signs it.
#[derive(Debug, Clone, Default)]
pub struct ObservationInput {
    /// The resource changed, e.g. `kv:<vault>/<secret>`.
    pub resource_id: String,
    /// `create`, `rotate`, `revoke`, `update` or `delete`.
    pub action: String,
    /// The capability the change exercises, as a governed action would
    /// request it.
    pub capability: String,
    /// When the source says the change happened. Give this, or both bounds
    /// of the window below.
    pub changed_at: Option<DateTime<Utc>>,
    /// The change happened after this (a reconciliation finding).
    pub changed_not_before: Option<DateTime<Utc>>,
    /// The change happened before this.
    pub changed_not_after: Option<DateTime<Utc>>,
    /// When the observer saw it. Defaults to now.
    pub observed_at: Option<DateTime<Utc>>,
    /// Who made the change, as the source reported it; not authenticated. A
    /// pseudonymous identifier, never a credential.
    pub actor: Option<String>,
    /// Where the change was seen, e.g. `cloud-activity-log`.
    pub source: String,
    /// The source's event id: one observation per source event.
    pub source_event_id: String,
    /// The source's version after the change; the NA matches it with
    /// execution evidence naming `execution_parameters.version_id`.
    pub version_id: Option<String>,
    /// Identifiers, versions and times; never values. Defaults to `{}`.
    pub metadata: Option<Value>,
    /// Defaults to a new UUID.
    pub observation_id: Option<String>,
}

/// Builds and signs observations for one observer (v1.3.0). Submit them
/// with [`EvidenceStoreClient::submit_observation`](crate::EvidenceStoreClient::submit_observation)
/// or keep them in the record outbox
/// ([`EvidenceStoreClient::enqueue_record`](crate::EvidenceStoreClient::enqueue_record)).
#[derive(Clone)]
pub struct ObservationRecorder {
    observer_sovereign_id: String,
    key_id: String,
    signing_key: SigningKey,
}

impl std::fmt::Debug for ObservationRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservationRecorder")
            .field("observer_sovereign_id", &self.observer_sovereign_id)
            .field("key_id", &self.key_id)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl ObservationRecorder {
    /// A recorder for `observer_sovereign_id`, signing with the base64 seed
    /// of the key registered with the NA as `key_id` with `role: "observer"`.
    pub fn new(
        observer_sovereign_id: impl Into<String>,
        key_id: impl Into<String>,
        seed_base64: &str,
    ) -> Result<Self> {
        Ok(Self {
            observer_sovereign_id: observer_sovereign_id.into(),
            key_id: key_id.into(),
            signing_key: load_signing_key(seed_base64)?,
        })
    }

    /// The observer sovereign this recorder signs for.
    pub fn observer_sovereign_id(&self) -> &str {
        &self.observer_sovereign_id
    }

    /// The registered observer key id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Build and sign one observation. Refused before signing
    /// ([`GenesisMeshError::OutOfBandRecord`]) without exactly one change
    /// time (`observation_malformed`), or with secret material in its
    /// metadata (`observation_secret_material`).
    pub fn record(&self, input: ObservationInput) -> Result<Value> {
        let window = input.changed_not_before.is_some() || input.changed_not_after.is_some();
        if input.changed_at.is_some() && window {
            return Err(refused(
                "observation_malformed",
                "give changed_at, or the changed_not_before and changed_not_after window, not both",
            ));
        }
        match (
            input.changed_at,
            input.changed_not_before,
            input.changed_not_after,
        ) {
            (Some(_), ..) => {}
            (None, Some(from), Some(until)) if from <= until => {}
            (None, Some(_), Some(_)) => {
                return Err(refused(
                    "observation_malformed",
                    "changed_not_before is after changed_not_after",
                ))
            }
            _ => {
                return Err(refused(
                    "observation_malformed",
                    "changed_at, or both changed_not_before and changed_not_after, is required",
                ))
            }
        }
        let metadata = input.metadata.unwrap_or_else(|| json!({}));
        if !metadata.is_object() {
            return Err(refused(
                "observation_malformed",
                "metadata must be a JSON object",
            ));
        }
        if let Some(secret) = check_metadata_only(&metadata, None) {
            return Err(refused("observation_secret_material", secret));
        }
        let mut record = Map::new();
        record.insert(
            "observation_id".into(),
            json!(input
                .observation_id
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
        );
        record.insert(
            "observer_sovereign_id".into(),
            json!(self.observer_sovereign_id),
        );
        record.insert("resource_id".into(), json!(input.resource_id));
        record.insert("action".into(), json!(input.action));
        record.insert("capability".into(), json!(input.capability));
        insert_some(&mut record, "changed_at", time(input.changed_at));
        insert_some(
            &mut record,
            "changed_not_before",
            time(input.changed_not_before),
        );
        insert_some(
            &mut record,
            "changed_not_after",
            time(input.changed_not_after),
        );
        record.insert(
            "observed_at".into(),
            json!(python_timestamp(input.observed_at.unwrap_or_else(Utc::now))),
        );
        insert_some(&mut record, "actor", input.actor.map(Value::from));
        record.insert("source".into(), json!(input.source));
        record.insert("source_event_id".into(), json!(input.source_event_id));
        insert_some(&mut record, "version_id", input.version_id.map(Value::from));
        record.insert("metadata".into(), metadata);
        signed(record, &self.key_id, &self.signing_key)
    }
}

/// How [`observation_from_finding`] records a reconciliation finding.
#[derive(Debug, Clone)]
pub struct FindingObservationOptions {
    /// The capability the change exercises.
    pub capability: String,
    /// The scan before this one: the change happened after it.
    pub previous_scan_at: DateTime<Utc>,
    /// This scan: the change happened before it.
    pub scanned_at: DateTime<Utc>,
    /// Defaults to `reconciliation`.
    pub source: Option<String>,
    /// The action recorded for a status, overriding the defaults
    /// (`unmanaged` create, `drifted` and `present_after_revoke` update,
    /// `missing` delete).
    pub actions: BTreeMap<String, String>,
}

impl FindingObservationOptions {
    /// Options for a scan at `scanned_at` after one at `previous_scan_at`.
    pub fn new(
        capability: impl Into<String>,
        previous_scan_at: DateTime<Utc>,
        scanned_at: DateTime<Utc>,
    ) -> Self {
        Self {
            capability: capability.into(),
            previous_scan_at,
            scanned_at,
            source: None,
            actions: BTreeMap::new(),
        }
    }
}

/// A reconciliation finding as an observation input, or `None` for a
/// resource in sync. The finding is the JSON the other SDKs' reconciliation
/// returns: `resource_id`, `status` (`unmanaged`, `drifted`,
/// `present_after_revoke`, `missing` or `in_sync`) and `observed` with its
/// `version` and `metadata`. The change is known only within the window
/// between the two scans, so the NA judges it at both ends of the window.
/// The source event is the scan and the resource, so a repeated scan does
/// not record the finding twice.
pub fn observation_from_finding(
    finding: &Value,
    options: &FindingObservationOptions,
) -> Option<ObservationInput> {
    let status = finding["status"].as_str()?;
    let resource_id = finding["resource_id"].as_str()?;
    let action = match options.actions.get(status) {
        Some(action) => action.clone(),
        None => match status {
            "unmanaged" => "create",
            "drifted" | "present_after_revoke" => "update",
            "missing" => "delete",
            _ => return None,
        }
        .to_owned(),
    };
    let scanned = python_timestamp(options.scanned_at);
    let event = format!("{scanned}\u{0}{resource_id}\u{0}{status}");
    let mut metadata = Map::new();
    metadata.insert("status".into(), json!(status));
    if let Some(observed) = finding["observed"]["metadata"].as_object() {
        metadata.extend(observed.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    Some(ObservationInput {
        resource_id: resource_id.to_owned(),
        action,
        capability: options.capability.clone(),
        changed_not_before: Some(options.previous_scan_at),
        changed_not_after: Some(options.scanned_at),
        observed_at: Some(options.scanned_at),
        source: options
            .source
            .clone()
            .unwrap_or_else(|| "reconciliation".into()),
        source_event_id: sha256_hex(event.as_bytes()),
        version_id: finding["observed"]["version"].as_str().map(str::to_owned),
        metadata: Some(Value::Object(metadata)),
        ..ObservationInput::default()
    })
}

// ── Break-glass ──────────────────────────────────────────────────────────────

/// A change a controller made without a decision, as
/// [`ExecutionRecorder::sign_break_glass`](crate::ExecutionRecorder::sign_break_glass)
/// signs it.
#[derive(Debug, Clone)]
pub struct BreakGlassInput {
    /// The resource acted on.
    pub resource_id: String,
    /// `create`, `rotate`, `revoke`, `update` or `delete`.
    pub resource_action: String,
    /// The capability the evaluation requested.
    pub capability: String,
    /// The attestation the evaluation named, if any.
    pub attestation_id: Option<String>,
    /// The evaluation's request parameters. Defaults to `{}`.
    pub request_parameters: Option<Value>,
    /// The evaluation's attributes. Defaults to `{}`.
    pub attributes: Option<Value>,
    /// Why the change could not wait for the NA: 1 to 1024 characters, no
    /// secret values.
    pub justification: String,
    /// The evaluation request that failed; only its digest is recorded.
    pub evaluation_request: Value,
    /// How the evaluation failed.
    pub evaluation_failure: EvaluationFailure,
    /// Defaults to now.
    pub executed_at: Option<DateTime<Utc>>,
    /// Defaults to `success`.
    pub outcome: Option<String>,
    /// Short outcome detail.
    pub outcome_detail: Option<String>,
    /// Identifiers and versions only. Defaults to `{}`.
    pub execution_parameters: Option<Value>,
}

impl BreakGlassInput {
    /// The required fields; the others default.
    pub fn new(
        resource_id: impl Into<String>,
        resource_action: impl Into<String>,
        capability: impl Into<String>,
        justification: impl Into<String>,
        evaluation_request: Value,
        evaluation_failure: EvaluationFailure,
    ) -> Self {
        Self {
            resource_id: resource_id.into(),
            resource_action: resource_action.into(),
            capability: capability.into(),
            attestation_id: None,
            request_parameters: None,
            attributes: None,
            justification: justification.into(),
            evaluation_request,
            evaluation_failure,
            executed_at: None,
            outcome: None,
            outcome_detail: None,
            execution_parameters: None,
        }
    }
}

/// The justification's refusal, if any: 1 to 1024 characters
/// (`break_glass_malformed`), and no secret material
/// (`break_glass_secret_material`).
pub(crate) fn check_justification(justification: &str) -> Result<()> {
    if !(1..=1024).contains(&justification.chars().count()) {
        return Err(refused(
            "break_glass_malformed",
            "a justification of 1 to 1024 characters is required",
        ));
    }
    match check_metadata_only(&json!({}), Some(justification)) {
        Some(secret) => Err(refused("break_glass_secret_material", secret)),
        None => Ok(()),
    }
}

fn object_or_empty(value: Option<Value>, name: &str) -> Result<Value> {
    let value = value.unwrap_or_else(|| json!({}));
    if !value.is_object() {
        return Err(refused(
            "break_glass_malformed",
            format!("{name} must be a JSON object"),
        ));
    }
    Ok(value)
}

/// Build and sign a break-glass record with an executor's key.
pub(crate) fn sign_break_glass(
    executor_sovereign_id: &str,
    key_id: &str,
    signing_key: &SigningKey,
    input: BreakGlassInput,
) -> Result<Value> {
    check_justification(&input.justification)?;
    let request_parameters = object_or_empty(input.request_parameters, "request_parameters")?;
    let attributes = object_or_empty(input.attributes, "attributes")?;
    let execution_parameters = object_or_empty(input.execution_parameters, "execution_parameters")?;
    let reported = json!({
        "execution_parameters": execution_parameters,
        "request_parameters": request_parameters,
        "attributes": attributes,
    });
    if let Some(secret) = check_metadata_only(&reported, input.outcome_detail.as_deref()) {
        return Err(refused("break_glass_secret_material", secret));
    }
    let mut record = Map::new();
    record.insert("break_glass_id".into(), json!(Uuid::new_v4().to_string()));
    record.insert("executor_sovereign_id".into(), json!(executor_sovereign_id));
    record.insert("resource_id".into(), json!(input.resource_id));
    record.insert("resource_action".into(), json!(input.resource_action));
    record.insert("capability".into(), json!(input.capability));
    insert_some(
        &mut record,
        "attestation_id",
        input.attestation_id.map(Value::from),
    );
    record.insert("request_parameters".into(), request_parameters);
    record.insert("attributes".into(), attributes);
    record.insert("justification".into(), json!(input.justification));
    record.insert(
        "evaluation_request_digest".into(),
        json!(canonical_digest(&input.evaluation_request)?),
    );
    record.insert(
        "evaluation_failure".into(),
        json!(input.evaluation_failure.as_str()),
    );
    record.insert(
        "executed_at".into(),
        json!(python_timestamp(input.executed_at.unwrap_or_else(Utc::now))),
    );
    record.insert(
        "outcome".into(),
        json!(input.outcome.unwrap_or_else(|| "success".into())),
    );
    insert_some(
        &mut record,
        "outcome_detail",
        input.outcome_detail.map(Value::from),
    );
    record.insert("execution_parameters".into(), execution_parameters);
    signed(record, key_id, signing_key)
}
