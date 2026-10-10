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
    auth::{canonical_digest, canonical_json, load_signing_key, sha256_hex, sign_canonical},
    canonical::{out_of_band_canonical, python_timestamp},
    errors::{GenesisMeshError, Result},
    execution::{secret_material, MAX_METADATA_BYTES},
    strict::canonical_timestamp,
    strict_json::check_strict_json,
};

/// What a resource change does (`ResourceAction` in the reference).
pub(crate) const RESOURCE_ACTIONS: [&str; 5] = ["create", "rotate", "revoke", "update", "delete"];

/// The size of named values as the NA measures a record's metadata: their
/// canonical JSON, with text outside ASCII escaped and floats in Python's
/// form (1.3.1).
pub(crate) fn metadata_size(values: &[(&str, &Value)]) -> usize {
    let object: Map<String, Value> = values
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).clone()))
        .collect();
    canonical_json(&Value::Object(object)).map_or(usize::MAX, |text| text.len())
}

/// Why a record's metadata would be refused as secret material, or `None`:
/// the reference's `metadata_problem` (1.3.1). The NA applies it to an
/// observation's `metadata`, `actor`, `source_event_id` and `version_id`, and
/// to a break-glass record's parameters, attributes, outcome detail and
/// justification: together at most [`MAX_METADATA_BYTES`] as
/// [`metadata_size`] measures them, and no field named like a secret, PEM
/// block, key or token.
pub(crate) fn metadata_problem(values: &[(&str, &Value)]) -> Option<String> {
    let size = metadata_size(values);
    if size > MAX_METADATA_BYTES {
        return Some(format!(
            "metadata is {size} bytes, over the {MAX_METADATA_BYTES}-byte limit"
        ));
    }
    values.iter().find_map(|(name, value)| match value {
        Value::Object(_) | Value::Array(_) => secret_material(value, &format!("{name}.")),
        other => secret_material(&json!({ *name: other }), ""),
    })
}

/// Why a text field would be refused as malformed, or `None`: `min` to `max`
/// characters, counted as the reference counts them (1.3.1).
pub(crate) fn length_problem(name: &str, value: &str, min: usize, max: usize) -> Option<String> {
    let count = value.chars().count();
    (!(min..=max).contains(&count))
        .then(|| format!("{name} must be {min} to {max} characters, not {count}"))
}

/// Why a resource action would be refused as malformed, or `None` (1.3.1).
pub(crate) fn action_problem(name: &str, action: &str) -> Option<String> {
    (!RESOURCE_ACTIONS.contains(&action))
        .then(|| format!("{name} must be create, rotate, revoke, update or delete, not {action:?}"))
}

/// Why a time would be refused as malformed, or `None`: the reference reads
/// the years 1 to 9999 only (1.3.1).
pub(crate) fn time_problem(name: &str, at: Option<DateTime<Utc>>) -> Option<String> {
    at.filter(|at| !canonical_timestamp(&python_timestamp(*at)))
        .map(|_| format!("{name} must fall in the years 1 to 9999"))
}

/// Refuse a signed record no reader would take (1.3.1): its JSON nested
/// deeper than every implementation reads ([`GenesisMeshError::StrictJson`],
/// `invalid_json`), checked as deep as the record goes: in an outbox file,
/// and an observation in a batch request.
pub(crate) fn check_nesting(record: &Value) -> Result<()> {
    let carried = json!({"entry": {"record": record}});
    check_strict_json(&serde_json::to_string(&carried)?).map_err(|err| match err {
        GenesisMeshError::StrictJson { reason, detail } => GenesisMeshError::StrictJson {
            reason,
            detail: format!("the record as submitted: {detail}"),
        },
        other => other,
    })
}

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

/// Sign a record's canonical form and add the signature, unless no reader
/// would take it ([`check_nesting`]).
fn signed(record: Map<String, Value>, key_id: &str, key: &SigningKey) -> Result<Value> {
    let mut record = Value::Object(record);
    check_nesting(&record)?;
    let canonical = out_of_band_canonical(&record)?;
    record["signature"] = sign_canonical(&canonical, key_id, key);
    Ok(record)
}

/// The first problem found, as a refusal with `code`.
fn first_problem(code: &str, problems: impl IntoIterator<Item = Option<String>>) -> Result<()> {
    match problems.into_iter().flatten().next() {
        Some(problem) => Err(refused(code, problem)),
        None => Ok(()),
    }
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
    /// ([`GenesisMeshError::OutOfBandRecord`]) as the NA would refuse it:
    /// `observation_malformed` without exactly one change time, with an
    /// action other than `create`, `rotate`, `revoke`, `update` or `delete`,
    /// a field of the wrong length or a time outside the years 1 to 9999
    /// (1.3.1); `observation_secret_material` with secret material in its
    /// `metadata`, `actor`, `source_event_id` or `version_id`, or with those
    /// together over [`MAX_METADATA_BYTES`](crate::MAX_METADATA_BYTES) as the
    /// NA counts them (text outside ASCII escaped, 1.3.1). Metadata nested
    /// too deep for every reader is refused as
    /// [`GenesisMeshError::StrictJson`] (`invalid_json`, 1.3.1).
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
        let observed_at = input.observed_at.unwrap_or_else(Utc::now);
        first_problem(
            "observation_malformed",
            [
                length_problem("observer_sovereign_id", &self.observer_sovereign_id, 1, 256),
                input
                    .observation_id
                    .as_deref()
                    .and_then(|id| length_problem("observation_id", id, 1, 128)),
                length_problem("resource_id", &input.resource_id, 1, 256),
                action_problem("action", &input.action),
                length_problem("capability", &input.capability, 1, 256),
                input
                    .actor
                    .as_deref()
                    .and_then(|actor| length_problem("actor", actor, 1, 256)),
                length_problem("source", &input.source, 1, 128),
                length_problem("source_event_id", &input.source_event_id, 1, 256),
                input
                    .version_id
                    .as_deref()
                    .and_then(|version| length_problem("version_id", version, 1, 256)),
                time_problem("changed_at", input.changed_at),
                time_problem("changed_not_before", input.changed_not_before),
                time_problem("changed_not_after", input.changed_not_after),
                time_problem("observed_at", Some(observed_at)),
            ],
        )?;
        let metadata = input.metadata.unwrap_or_else(|| json!({}));
        if !metadata.is_object() {
            return Err(refused(
                "observation_malformed",
                "metadata must be a JSON object",
            ));
        }
        // The NA guards the source's own strings too: an actor is a pseudonym,
        // never a credential.
        let actor = input.actor.clone().map(Value::from);
        let source_event_id = json!(input.source_event_id);
        let version_id = input.version_id.clone().map(Value::from);
        let mut guarded = vec![("metadata", &metadata)];
        if let Some(actor) = &actor {
            guarded.push(("actor", actor));
        }
        guarded.push(("source_event_id", &source_event_id));
        if let Some(version_id) = &version_id {
            guarded.push(("version_id", version_id));
        }
        if let Some(secret) = metadata_problem(&guarded) {
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
        record.insert("observed_at".into(), json!(python_timestamp(observed_at)));
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
    match metadata_problem(&[("justification", &json!(justification))]) {
        Some(secret) => Err(refused("break_glass_secret_material", secret)),
        None => Ok(()),
    }
}

/// What the NA guards in a break-glass record, in its order (1.3.1): an
/// absent outcome detail counts as `""`.
pub(crate) fn break_glass_metadata<'a>(
    execution_parameters: &'a Value,
    request_parameters: &'a Value,
    attributes: &'a Value,
    outcome_detail: &'a Value,
    justification: &'a Value,
) -> [(&'static str, &'a Value); 5] {
    [
        ("execution_parameters", execution_parameters),
        ("request_parameters", request_parameters),
        ("attributes", attributes),
        ("outcome_detail", outcome_detail),
        ("justification", justification),
    ]
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
    let executed_at = input.executed_at.unwrap_or_else(Utc::now);
    first_problem(
        "break_glass_malformed",
        [
            length_problem("executor_sovereign_id", executor_sovereign_id, 1, 256),
            length_problem("resource_id", &input.resource_id, 1, 256),
            action_problem("resource_action", &input.resource_action),
            length_problem("capability", &input.capability, 1, 256),
            input
                .attestation_id
                .as_deref()
                .and_then(|id| length_problem("attestation_id", id, 1, 128)),
            input
                .outcome_detail
                .as_deref()
                .and_then(|detail| length_problem("outcome_detail", detail, 0, 1024)),
            time_problem("executed_at", Some(executed_at)),
        ],
    )?;
    let request_parameters = object_or_empty(input.request_parameters, "request_parameters")?;
    let attributes = object_or_empty(input.attributes, "attributes")?;
    let execution_parameters = object_or_empty(input.execution_parameters, "execution_parameters")?;
    if let Some(secret) = metadata_problem(&break_glass_metadata(
        &execution_parameters,
        &request_parameters,
        &attributes,
        &json!(input.outcome_detail.as_deref().unwrap_or_default()),
        &json!(input.justification),
    )) {
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
    record.insert("executed_at".into(), json!(python_timestamp(executed_at)));
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
