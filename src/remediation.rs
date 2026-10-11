//! Remediation, reviews and emergency changes (Genesis Mesh 1.4.0, Stage 3).
//!
//! A change judged DENY after the fact (1.3.0) is cancelled after a grace
//! window, without breaking what reads it, and its author is told; a second
//! person can review a judgement, or a decision made under a policy that
//! requires it, and uphold, deny or waive the change. The Network Authority
//! (NA) states the remediation; the controller performs it and records it.
//! Two records bring this into the evidence store:
//!
//! * `RemediationRecord` (entry kind `remediation`): what a controller did
//!   about a judged change, signed by the executor key that carried it out
//!   ([`ExecutionRecorder::sign_remediation`](crate::ExecutionRecorder::sign_remediation),
//!   [`rotate_forward_then_disable`](crate::rotate_forward_then_disable));
//! * `ReviewRecord` (entry kind `review`): a second person's verdict, signed by
//!   the NA, with the operators' signed admin requests embedded so the
//!   approval verifies offline ([`review_approval_problem`]).
//!
//! The rest of this module is the reference's pure rules
//! (`trust/remediation.py`), checked by the conformance suite `remediation`:
//! what a judged change leads to ([`remediation_plan`]), the state table
//! ([`next_state`]), due times after a review, and the review rules. Records
//! are JSON values, as the 1.3.0 records are; their signed forms are frozen
//! from 1.4.0 on.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    auth::{canonical_json, verify_canonical},
    canonical::{out_of_band_canonical, python_timestamp},
    errors::Result,
    out_of_band::{length_problem, record_metadata_problem, refused, signed, time_problem},
    strict::{non_canonical_fields, unknown_fields},
    verify::valid_remediation_record,
};

// ── The state table ──────────────────────────────────────────────────────────

/// The states in which something is still to happen: the due queue's default.
pub const OPEN_STATES: [&str; 4] = ["remediation_due", "overdue", "review_pending", "waived"];

/// The Stage 3 states a remediation state can hold (the due queue's `state`).
pub const STAGE3_STATES: [&str; 7] = [
    "remediation_due",
    "overdue",
    "remediated",
    "review_pending",
    "upheld",
    "waived",
    "review_denied",
];

const TRANSITIONS: [(&str, &str, &str); 25] = [
    ("judged_denied", "arm", "remediation_due"),
    ("indeterminate", "arm", "remediation_due"),
    ("review_denied", "arm", "remediation_due"),
    ("judged_denied", "open_review", "review_pending"),
    ("indeterminate", "open_review", "review_pending"),
    ("judged_allowed", "open_review", "review_pending"),
    ("matched", "open_review", "review_pending"),
    ("recorded", "open_review", "review_pending"),
    ("remediation_due", "open_review", "review_pending"),
    ("overdue", "open_review", "review_pending"),
    ("upheld", "open_review", "review_pending"),
    ("waived", "open_review", "review_pending"),
    ("remediation_due", "due_passed", "overdue"),
    ("remediation_due", "record_remediation", "remediated"),
    ("overdue", "record_remediation", "remediated"),
    ("review_pending", "record_remediation", "remediated"),
    ("waived", "record_remediation", "remediated"),
    ("review_denied", "record_remediation", "remediated"),
    ("review_pending", "uphold", "upheld"),
    ("review_pending", "deny", "review_denied"),
    ("review_pending", "waive", "waived"),
    // A review pending when the remediation was recorded is still decided; it
    // changes nothing.
    ("remediated", "uphold", "remediated"),
    ("remediated", "deny", "remediated"),
    ("waived", "waiver_expired", "remediation_due"),
    ("upheld", "lifetime_ended", "remediation_due"),
];

/// A transition the state table does not allow, named by a stable code:
/// `review_waiver_after_remediation`, `review_after_remediation`,
/// `remediation_already_recorded`, `review_not_pending`,
/// `review_already_pending`, `remediation_not_due` or `illegal_transition`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail} [{code}]")]
pub struct TransitionRefused {
    /// The refusal code, as the NA answers it.
    pub code: &'static str,
    /// What was refused.
    pub detail: String,
}

/// The state after `event` (`arm`, `open_review`, `due_passed`,
/// `record_remediation`, `uphold`, `deny`, `waive`, `waiver_expired`,
/// `lifetime_ended`) in `state`, as the NA moves a change; refused with a
/// stable code when the table does not allow it.
pub fn next_state(
    state: &str,
    event: &str,
) -> std::result::Result<&'static str, TransitionRefused> {
    TRANSITIONS
        .iter()
        .find(|(from, on, _)| *from == state && *on == event)
        .map(|(_, _, to)| *to)
        .ok_or_else(|| TransitionRefused {
            code: refusal(state, event),
            detail: format!("{event} is not allowed in state {state}"),
        })
}

fn refusal(state: &str, event: &str) -> &'static str {
    match (state, event) {
        ("remediated", "waive") => "review_waiver_after_remediation",
        ("remediated", "open_review") => "review_after_remediation",
        ("remediated", "record_remediation") => "remediation_already_recorded",
        (_, "uphold" | "deny" | "waive") => "review_not_pending",
        ("review_pending", "open_review") => "review_already_pending",
        (_, "record_remediation") => "remediation_not_due",
        _ => "illegal_transition",
    }
}

/// A judged change's Stage 2 state, where it enters the state table.
pub fn judgement_state(verdict: &str, governed_by: &str) -> &'static str {
    match (governed_by, verdict) {
        ("prior_decision", "deny") => "judged_denied",
        ("prior_decision", _) => "matched",
        (_, "allow") => "judged_allowed",
        (_, "deny") => "judged_denied",
        _ => "indeterminate",
    }
}

// ── Remediation plans ────────────────────────────────────────────────────────

/// The key of remediation guidance for every gate a policy does not name.
pub const ANY_GATE: &str = "*";

/// What applies when no policy gives guidance: the NA's
/// `NA_REMEDIATION_GRACE_SECONDS` and `NA_REMEDIATION_DEFAULT_MODE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationDefaults {
    /// Grace before a remediation is due. Default one day.
    pub grace_seconds: i64,
    /// `alert_only` (the default) or `cancel`.
    pub mode: String,
}

impl Default for RemediationDefaults {
    fn default() -> Self {
        Self {
            grace_seconds: 24 * 3600,
            mode: "alert_only".into(),
        }
    }
}

/// What a judged change leads to, as the NA states it in the remediation
/// state (`mode`, `steps`, `fallback`, `grace_seconds`, `guidance_source`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationPlan {
    /// `cancel` or `alert_only`.
    pub mode: String,
    /// `rotate_forward_then_disable`, `disable` or `none`.
    pub steps: String,
    /// Why a cancel fell back to `alert_only`: `not_versioned`,
    /// `not_rotatable`, `not_reversible` or `indeterminate`.
    pub fallback: Option<String>,
    /// The grace before the remediation is due.
    pub grace_seconds: i64,
    /// Where the guidance came from: `gate`, `policy` or `default`.
    pub source: String,
}

impl RemediationPlan {
    /// `remediation_due_at`: `at` (the judgement or review time) plus the grace.
    pub fn due_at(&self, at: DateTime<Utc>) -> DateTime<Utc> {
        at + Duration::seconds(self.grace_seconds)
    }
}

/// What the record of a change says about cancelling it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeFacts {
    /// `create`, `rotate`, `revoke`, `update` or `delete`.
    pub action: String,
    /// The version the change made, when the record names one.
    pub version_id: Option<String>,
    /// False only when the record says the resource cannot be rotated.
    pub rotatable: bool,
}

/// The facts of a stored change (`observation`, `break_glass` or
/// `execution`): an observation's `action`, `version_id` and
/// `metadata.rotatable`; a controller record's `resource_action`,
/// `execution_parameters.version_id` and `execution_parameters.rotatable`.
/// `rotatable` is false only when the record sets it to `false`.
pub fn change_facts(kind: &str, payload: &Value) -> ChangeFacts {
    let (extra, version, action) = if kind == "observation" {
        (
            &payload["metadata"],
            &payload["version_id"],
            &payload["action"],
        )
    } else {
        (
            &payload["execution_parameters"],
            &payload["execution_parameters"]["version_id"],
            &payload["resource_action"],
        )
    };
    ChangeFacts {
        action: action.as_str().unwrap_or_default().to_owned(),
        version_id: version
            .as_str()
            .filter(|v| !v.is_empty())
            .map(str::to_owned),
        rotatable: extra["rotatable"] != Value::Bool(false),
    }
}

/// One entry of remediation guidance, when it reads as one.
fn gate_guidance(entry: &Value) -> Option<(String, i64)> {
    Some((
        entry["mode"].as_str()?.to_owned(),
        entry["grace_seconds"].as_i64()?,
    ))
}

/// `(mode, grace_seconds, source)` for a judged change: the guidance of each
/// enforce-mode gate that failed (its own entry, or its policy's `"*"`);
/// without one, the `"*"` guidance of the policies that applied; without
/// that, the defaults. Among several, `cancel` wins over `alert_only`, and
/// the shortest grace of the winning mode applies. `policies` are the
/// applied `BoundaryPolicy` JSON, `evaluations` the decision's or
/// judgement's `policy_binding.gate_evaluations`.
pub fn guidance(
    policies: &[Value],
    evaluations: &[Value],
    defaults: &RemediationDefaults,
) -> (String, i64, &'static str) {
    let mut by_key: BTreeMap<(String, i64), &Value> = BTreeMap::new();
    for policy in policies {
        let id = policy["policy_id"].as_str().unwrap_or_default().to_owned();
        by_key.insert((id, policy["version"].as_i64().unwrap_or_default()), policy);
    }
    let guided = |policy: &Value| {
        policy["remediation"]
            .as_object()
            .filter(|map| !map.is_empty())
            .cloned()
    };
    let mut found: Vec<(String, i64)> = Vec::new();
    for evaluation in evaluations {
        if evaluation["mode"] != "enforce" || evaluation["passed"] == true {
            continue;
        }
        let key = (
            evaluation["policy_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            evaluation["policy_version"].as_i64().unwrap_or_default(),
        );
        let Some(guidance) = by_key.get(&key).and_then(|p| guided(p)) else {
            continue;
        };
        let gate = evaluation["gate_id"].as_str().unwrap_or_default();
        if let Some(entry) = guidance.get(gate).or_else(|| guidance.get(ANY_GATE)) {
            found.extend(gate_guidance(entry));
        }
    }
    let mut source = "gate";
    if found.is_empty() {
        source = "policy";
        found = by_key
            .values()
            .filter_map(|p| guided(p)?.get(ANY_GATE).and_then(gate_guidance))
            .collect();
    }
    if found.is_empty() {
        return (defaults.mode.clone(), defaults.grace_seconds, "default");
    }
    let mode = if found.iter().any(|(mode, _)| mode == "cancel") {
        "cancel"
    } else {
        "alert_only"
    };
    let grace = found
        .iter()
        .filter(|(m, _)| m == mode)
        .map(|(_, grace)| *grace)
        .min()
        .unwrap_or_default();
    (mode.to_owned(), grace, source)
}

/// `(steps, fallback)` for cancelling a change. A created resource nothing
/// reads yet is disabled (or deleted). A rotated or updated resource with a
/// version is rotated forward to a governed new version, then the denied
/// version is disabled, unless the record says it cannot be rotated.
/// Without a version, or for a revocation or deletion (cancelling it would
/// restore something), the cancel falls back to `alert_only`.
pub fn cancel_steps(
    action: &str,
    version_id: Option<&str>,
    rotatable: bool,
) -> (&'static str, Option<&'static str>) {
    match (action, version_id) {
        ("create", _) => ("disable", None),
        ("rotate" | "update", None) => ("none", Some("not_versioned")),
        ("rotate" | "update", Some(_)) if !rotatable => ("none", Some("not_rotatable")),
        ("rotate" | "update", Some(_)) => ("rotate_forward_then_disable", None),
        _ => ("none", Some("not_reversible")),
    }
}

/// What a change judged `verdict` (`allow`, `deny` or `indeterminate`)
/// leads to, from the applied policies' guidance and the change's facts. An
/// `indeterminate` judgement always alerts.
pub fn remediation_plan(
    verdict: &str,
    policies: &[Value],
    evaluations: &[Value],
    facts: &ChangeFacts,
    defaults: &RemediationDefaults,
) -> RemediationPlan {
    let (mode, grace_seconds, source) = guidance(policies, evaluations, defaults);
    let plan = |mode: &str, steps: &str, fallback: Option<&str>| RemediationPlan {
        mode: mode.to_owned(),
        steps: steps.to_owned(),
        fallback: fallback.map(str::to_owned),
        grace_seconds,
        source: source.to_owned(),
    };
    if verdict == "indeterminate" {
        let fallback = (mode == "cancel").then_some("indeterminate");
        return plan("alert_only", "none", fallback);
    }
    if mode != "cancel" {
        return plan("alert_only", "none", None);
    }
    let (steps, fallback) =
        cancel_steps(&facts.action, facts.version_id.as_deref(), facts.rotatable);
    plan(
        if fallback.is_some() {
            "alert_only"
        } else {
            "cancel"
        },
        steps,
        fallback,
    )
}

/// When a remediation a review denied is due: the grace from the decision,
/// never later than it was already due (a review holds a remediation, it
/// does not extend it).
pub fn due_after_denial(
    current_due: Option<DateTime<Utc>>,
    decided_at: DateTime<Utc>,
    grace_seconds: i64,
) -> DateTime<Utc> {
    let due = decided_at + Duration::seconds(grace_seconds);
    current_due.map_or(due, |current| current.min(due))
}

/// When a remediation is due once a waiver ends: its grace again, from the
/// waiver's end.
pub fn due_after_waiver(waived_until: DateTime<Utc>, grace_seconds: i64) -> DateTime<Utc> {
    waived_until + Duration::seconds(grace_seconds)
}

/// Why a remediation record does not carry out the plan the NA stated
/// (`mode`, `steps`), or `None`: the NA refuses it as
/// `remediation_steps_mismatch`. A `delete` carries out `disable`.
pub fn steps_problem(plan_mode: &str, plan_steps: &str, record: &Value) -> Option<String> {
    let outcome = record["outcome"].as_str().unwrap_or_default();
    let steps = record["steps"].as_str().unwrap_or_default();
    if plan_mode == "alert_only" {
        return (outcome != "alerted").then(|| {
            format!("the remediation is alert_only; the record says {outcome} ({steps})")
        });
    }
    if outcome != "cancelled" {
        return Some(format!(
            "the remediation is a cancel ({plan_steps}); the record only alerted"
        ));
    }
    if (plan_steps == "disable" && matches!(steps, "disable" | "delete")) || steps == plan_steps {
        return None;
    }
    Some(format!(
        "the remediation is {plan_steps}; the record says {steps}"
    ))
}

// ── Remediation records ──────────────────────────────────────────────────────

/// The NA's refusals of a remediation record that no retry can overcome
/// (1.4.0): a record outbox keeps such a record as a dead letter. Not
/// listed, so retried: `remediation_unknown_key` (the key may not be
/// registered yet), `remediation_subject_not_found` and
/// `remediation_rotation_missing` (the subject or the forward rotation's
/// evidence is not stored yet), and `remediation_disabled`.
pub const REMEDIATION_PERMANENT_REFUSALS: [&str; 12] = [
    "invalid_remediation",
    "remediation_malformed",
    "remediation_invalid_signature",
    "remediation_key_retired",
    "remediation_out_of_scope",
    "remediation_secret_material",
    "remediation_subject_mismatch",
    "remediation_steps_mismatch",
    "remediation_rotation_mismatch",
    "remediation_not_due",
    "remediation_already_recorded",
    "remediation_conflict",
];

/// The judged change a remediation is about, as the NA's remediation state
/// names it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RemediationSubject {
    /// `judgement` or `decision`.
    pub subject_kind: String,
    /// The judgement's (or decision's) id.
    pub subject_id: String,
    /// The record of the change: `observation`, `break_glass` or `execution`.
    pub change_kind: String,
    /// Its id.
    pub change_id: String,
    /// The resource changed.
    pub resource_id: String,
}

impl RemediationSubject {
    /// The subject of a remediation state from the due queue
    /// ([`EvidenceStoreClient::remediations`](crate::EvidenceStoreClient::remediations)),
    /// or `None` when it does not name all five (a decision before its
    /// execution evidence is known).
    pub fn from_state(state: &Value) -> Option<Self> {
        let text = |key: &str| state[key].as_str().map(str::to_owned);
        Some(Self {
            subject_kind: text("subject_kind")?,
            subject_id: text("subject_id")?,
            change_kind: text("change_kind")?,
            change_id: text("change_id")?,
            resource_id: text("resource_id")?,
        })
    }
}

/// What the controller did, and the versions involved: identifiers only,
/// never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemediationSteps {
    /// A new version issued under a governed decision first (its execution
    /// evidence `rotation_evidence_id`, issuing `version_id`), then the denied
    /// version disabled. Outcome `cancelled`.
    RotateForwardThenDisable {
        /// The forward rotation's `evidence_id`.
        rotation_evidence_id: String,
        /// The version the rotation issued.
        version_id: String,
        /// The denied version, disabled after it.
        disabled_version_id: String,
    },
    /// The resource disabled (nothing read it yet). Outcome `cancelled`.
    Disable {
        /// The version disabled, when it has one.
        disabled_version_id: Option<String>,
    },
    /// The resource deleted instead of disabled. Outcome `cancelled`.
    Delete {
        /// The version deleted, when it has one.
        disabled_version_id: Option<String>,
    },
    /// Nothing changed: the denial was recorded and its author told
    /// (`alert_only`). Outcome `alerted`.
    Alerted,
}

/// A remediation as
/// [`ExecutionRecorder::sign_remediation`](crate::ExecutionRecorder::sign_remediation)
/// signs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationInput {
    /// The judged change.
    pub subject: RemediationSubject,
    /// What was done.
    pub steps: RemediationSteps,
    /// A short note, 1 to 1024 characters, no secret values.
    pub detail: Option<String>,
    /// When it was done. Defaults to now.
    pub remediated_at: Option<DateTime<Utc>>,
    /// Defaults to a new UUID.
    pub remediation_id: Option<String>,
}

impl RemediationInput {
    /// A remediation of `subject` by `steps`, the others defaulted.
    pub fn new(subject: RemediationSubject, steps: RemediationSteps) -> Self {
        Self {
            subject,
            steps,
            detail: None,
            remediated_at: None,
            remediation_id: None,
        }
    }
}

const SUBJECT_KINDS: [&str; 2] = ["judgement", "decision"];
const CHANGE_KINDS: [&str; 3] = ["observation", "break_glass", "execution"];

fn one_of_problem(name: &str, value: &str, allowed: &[&str]) -> Option<String> {
    (!allowed.contains(&value)).then(|| format!("{name} must be one of {}", allowed.join(", ")))
}

/// The record's fields in the reference's order, before signing.
fn remediation_fields(
    executor_sovereign_id: &str,
    input: &RemediationInput,
    at: DateTime<Utc>,
) -> Map<String, Value> {
    let (outcome, steps, rotation, version, disabled) = match &input.steps {
        RemediationSteps::RotateForwardThenDisable {
            rotation_evidence_id,
            version_id,
            disabled_version_id,
        } => (
            "cancelled",
            "rotate_forward_then_disable",
            Some(rotation_evidence_id),
            Some(version_id),
            Some(disabled_version_id),
        ),
        RemediationSteps::Disable {
            disabled_version_id,
        } => (
            "cancelled",
            "disable",
            None,
            None,
            disabled_version_id.as_ref(),
        ),
        RemediationSteps::Delete {
            disabled_version_id,
        } => (
            "cancelled",
            "delete",
            None,
            None,
            disabled_version_id.as_ref(),
        ),
        RemediationSteps::Alerted => ("alerted", "none", None, None, None),
    };
    let subject = &input.subject;
    let mut record = Map::new();
    let mut put = |key: &str, value: Option<&String>| {
        if let Some(value) = value {
            record.insert(key.into(), json!(value));
        }
    };
    put(
        "remediation_id",
        Some(
            &input
                .remediation_id
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        ),
    );
    put(
        "executor_sovereign_id",
        Some(&executor_sovereign_id.to_owned()),
    );
    put("subject_kind", Some(&subject.subject_kind));
    put("subject_id", Some(&subject.subject_id));
    put("change_kind", Some(&subject.change_kind));
    put("change_id", Some(&subject.change_id));
    put("resource_id", Some(&subject.resource_id));
    put("outcome", Some(&outcome.to_owned()));
    put("steps", Some(&steps.to_owned()));
    put("rotation_evidence_id", rotation);
    put("version_id", version);
    put("disabled_version_id", disabled);
    put("remediated_at", Some(&python_timestamp(at)));
    put("detail", input.detail.as_ref());
    record
}

/// Why the NA would refuse a remediation as malformed
/// (`remediation_malformed`) or as secret material
/// (`remediation_secret_material`), before anything is signed.
pub(crate) fn remediation_input_problem(
    executor_sovereign_id: &str,
    input: &RemediationInput,
) -> Result<()> {
    let at = input.remediated_at.unwrap_or_else(Utc::now);
    let record = Value::Object(remediation_fields(executor_sovereign_id, input, at));
    let text = |key: &str| record[key].as_str().unwrap_or_default().to_owned();
    let optional = |key: &str, max: usize| {
        record[key]
            .as_str()
            .and_then(|value| length_problem(key, value, 1, max))
    };
    let rotated_onto_itself = matches!(
        &input.steps,
        RemediationSteps::RotateForwardThenDisable { version_id, disabled_version_id, .. }
            if version_id == disabled_version_id
    )
    .then(|| "the forward rotation issues another version than the one disabled".to_owned());
    let problem = [
        length_problem("executor_sovereign_id", executor_sovereign_id, 1, 256),
        length_problem("remediation_id", &text("remediation_id"), 1, 128),
        one_of_problem("subject_kind", &text("subject_kind"), &SUBJECT_KINDS),
        length_problem("subject_id", &text("subject_id"), 1, 128),
        one_of_problem("change_kind", &text("change_kind"), &CHANGE_KINDS),
        length_problem("change_id", &text("change_id"), 1, 128),
        length_problem("resource_id", &text("resource_id"), 1, 256),
        optional("rotation_evidence_id", 128),
        optional("version_id", 256),
        optional("disabled_version_id", 256),
        optional("detail", 1024),
        time_problem("remediated_at", Some(at)),
        rotated_onto_itself,
    ]
    .into_iter()
    .flatten()
    .next();
    if let Some(problem) = problem {
        return Err(refused("remediation_malformed", problem));
    }
    if let Some(secret) = record_metadata_problem("remediation", &record) {
        return Err(refused("remediation_secret_material", secret));
    }
    Ok(())
}

/// Build and sign a remediation record with an executor's key.
pub(crate) fn sign_remediation(
    executor_sovereign_id: &str,
    key_id: &str,
    signing_key: &SigningKey,
    input: RemediationInput,
) -> Result<Value> {
    let input = RemediationInput {
        remediated_at: Some(input.remediated_at.unwrap_or_else(Utc::now)),
        remediation_id: Some(
            input
                .remediation_id
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        ),
        ..input
    };
    remediation_input_problem(executor_sovereign_id, &input)?;
    let at = input.remediated_at.unwrap_or_else(Utc::now);
    signed(
        remediation_fields(executor_sovereign_id, &input, at),
        key_id,
        signing_key,
    )
}

/// Whether the NA would admit a signed remediation record's signature and
/// key, or the refusal it would answer (`code`, detail), as the reference's
/// `check_remediation` decides it (the 1.3.1 guards): a record in its exact
/// form (`remediation_malformed`), signed (`remediation_invalid_signature`)
/// by a registered key of its `executor_sovereign_id`
/// (`remediation_unknown_key`) whose signature verifies, that is not retired
/// (`remediation_key_retired`), is an executor key and covers the resource
/// (`remediation_out_of_scope`), with no secret material in its versions or
/// detail (`remediation_secret_material`). `key` is a registered key as
/// `GET /admin/evidence/executor-keys` lists it (`key_id`, `public_key`,
/// `executor_sovereign_id`, `role`, `resource_prefix`, `retired`). The role
/// and scope are checked only once the signature verifies. The NA checks the
/// subject, the plan and the state besides.
pub fn check_remediation(record: &Value, key: Option<&Value>) -> Option<(&'static str, String)> {
    let model = "RemediationRecord";
    if !valid_remediation_record(record)
        || !unknown_fields(model, record).is_empty()
        || !non_canonical_fields(model, record).is_empty()
    {
        return Some((
            "remediation_malformed",
            "record is not a RemediationRecord in its exact form".into(),
        ));
    }
    let Some(sig) = record["signature"]["sig"].as_str() else {
        return Some((
            "remediation_invalid_signature",
            "record is not signed".into(),
        ));
    };
    let sovereign = record["executor_sovereign_id"].as_str().unwrap_or_default();
    let Some(key) = key.filter(|k| k["executor_sovereign_id"].as_str() == Some(sovereign)) else {
        return Some((
            "remediation_unknown_key",
            format!("signing key is not registered for {sovereign:?}"),
        ));
    };
    let public_key = key["public_key"].as_str().unwrap_or_default().to_owned();
    let verified = out_of_band_canonical(record)
        .is_ok_and(|canonical| verify_canonical(&canonical, sig, &[public_key]));
    if !verified {
        return Some((
            "remediation_invalid_signature",
            "signature does not verify".into(),
        ));
    }
    if key["retired"] == true {
        return Some(("remediation_key_retired", "signing key is retired".into()));
    }
    let role = key["role"].as_str().unwrap_or("executor");
    if role != "executor" {
        return Some((
            "remediation_out_of_scope",
            format!("signing key is an {role} key, not an executor key"),
        ));
    }
    if let Some(prefix) = key["resource_prefix"].as_str() {
        if !record["resource_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with(prefix)
        {
            return Some((
                "remediation_out_of_scope",
                format!("signing key covers only resources starting with {prefix:?}"),
            ));
        }
    }
    record_metadata_problem("remediation", record)
        .map(|secret| ("remediation_secret_material", secret))
}

// ── Reviews ──────────────────────────────────────────────────────────────────

/// The route an operator requests a review on.
pub const REVIEW_REQUEST_PATH: &str = "/admin/evidence/reviews";

/// How far an embedded approval's timestamp may be from the time the NA
/// recorded (the NA refuses older admin requests when they arrive).
pub const APPROVAL_MAX_AGE_SECONDS: i64 = 300;

/// Longest a waiver may run, whatever the NA's configuration: 90 days.
pub const MAX_WAIVER_SECONDS: i64 = 90 * 24 * 3600;

const DECISION_FIELDS: [&str; 3] = ["verdict", "waive_until", "note"];

/// The route a review is decided on.
pub fn review_decision_path(review_id: &str) -> String {
    format!("{REVIEW_REQUEST_PATH}/{review_id}/decide")
}

/// Who requested, decided and made a reviewed change, as a review names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReviewHolders<'a> {
    /// The deciding operator key.
    pub decided_by: &'a str,
    /// Its holder.
    pub decider_holder: &'a str,
    /// The requesting operator key; `None` for a review the NA opened.
    pub requested_by: Option<&'a str>,
    /// Its holder.
    pub requester_holder: Option<&'a str>,
    /// The actor the source reported (not authenticated).
    pub actor: Option<&'a str>,
    /// The holder the NA mapped the actor to.
    pub actor_holder: Option<&'a str>,
}

impl<'a> ReviewHolders<'a> {
    /// The holders a `ReviewRecord` names.
    pub fn of(review: &'a Value) -> Self {
        let text = |key: &str| review[key].as_str();
        Self {
            decided_by: text("decided_by").unwrap_or_default(),
            decider_holder: text("decider_holder").unwrap_or_default(),
            requested_by: text("requested_by"),
            requester_holder: text("requester_holder"),
            actor: text("actor"),
            actor_holder: text("actor_holder"),
        }
    }
}

/// `(code, detail)` when the decider is not a second holder, or `None`. The
/// first rule that matches wins:
///
/// 1. `review_same_holder_as_requester`: there is a requester, and the
///    decider's key is the requester's or its holder is the requester's;
/// 2. `review_same_holder_as_actor`: there is an actor, and the decider's
///    holder is the actor's, or the actor is named like the decider's key or
///    holder.
pub fn review_holder_problem(holders: &ReviewHolders<'_>) -> Option<(&'static str, String)> {
    let decider = holders.decider_holder;
    if let Some(requested_by) = holders.requested_by {
        if holders.decided_by == requested_by || Some(decider) == holders.requester_holder {
            return Some((
                "review_same_holder_as_requester",
                format!("holder {decider:?} requested this review; another holder decides it"),
            ));
        }
    }
    if let Some(actor) = holders.actor {
        if Some(decider) == holders.actor_holder || actor == holders.decided_by || actor == decider
        {
            return Some((
                "review_same_holder_as_actor",
                format!(
                    "holder {decider:?} is the observed actor ({actor:?}); another holder decides"
                ),
            ));
        }
    }
    None
}

/// An instant as the reference reads one: ISO 8601, `Z` or an offset, or
/// none (UTC).
fn instant(value: &Value) -> Option<DateTime<Utc>> {
    let text = value.as_str()?;
    match DateTime::parse_from_rfc3339(text) {
        Ok(at) => Some(at.with_timezone(&Utc)),
        Err(_) => NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f")
            .ok()
            .map(|naive| naive.and_utc()),
    }
}

/// Whether an embedded admin request (`AdminApproval`: `key_id`,
/// `public_key`, `method`, `path`, `query`, `audience`, `body`, `timestamp`,
/// `nonce`, `admin_signature`) verifies: the operator's signature over the
/// version 2 admin payload rebuilt from it, under its public key.
pub fn admin_approval_valid(approval: &Value) -> bool {
    let text = |key: &str| approval[key].as_str();
    let (Some(method), Some(path), Some(signature), Some(public_key)) = (
        text("method"),
        text("path"),
        text("admin_signature"),
        text("public_key"),
    ) else {
        return false;
    };
    let query = match &approval["query"] {
        Value::Null => json!({}),
        Value::Object(query)
            if query
                .values()
                .all(|v| v.as_array().is_some_and(|a| a.iter().all(Value::is_string))) =>
        {
            Value::Object(query.clone())
        }
        _ => return false,
    };
    let body = match &approval["body"] {
        Value::Null => json!({}),
        body @ Value::Object(_) => body.clone(),
        _ => return false,
    };
    if !path.starts_with('/') {
        return false;
    }
    let payload = json!({
        "v": crate::auth::ADMIN_SIGNATURE_VERSION,
        "method": method.to_uppercase(),
        "path": path,
        "query": query,
        "audience": approval["audience"],
        "body": body,
        "key_id": approval["key_id"],
        "timestamp": approval["timestamp"],
        "nonce": approval["nonce"],
    });
    canonical_json(&payload)
        .is_ok_and(|canonical| verify_canonical(&canonical, signature, &[public_key.to_owned()]))
}

fn approval_problem(
    approval: &Value,
    who: &str,
    key_id: &str,
    path: &str,
    audiences: &[String],
    at: Option<DateTime<Utc>>,
) -> Option<String> {
    if !admin_approval_valid(approval) {
        return Some(format!(
            "the {who}'s signature does not verify over its request"
        ));
    }
    let signer = approval["key_id"].as_str().unwrap_or_default();
    if signer != key_id {
        return Some(format!(
            "the {who}'s request is signed by {signer}, not {key_id}"
        ));
    }
    let method = approval["method"].as_str().unwrap_or_default();
    let query_given = approval["query"].as_object().is_some_and(|q| !q.is_empty());
    if method != "POST" || approval["path"] != path || query_given {
        return Some(format!(
            "the {who}'s request is {method} {}, not POST {path}",
            approval["path"].as_str().unwrap_or_default()
        ));
    }
    let audience = approval["audience"].as_str().unwrap_or_default();
    if !audiences.iter().any(|a| a == audience) {
        return Some(format!(
            "the {who}'s request is for another Network Authority"
        ));
    }
    let signed_at = instant(&approval["timestamp"]);
    let fresh = matches!((signed_at, at), (Some(signed), Some(at))
        if (signed - at).num_microseconds().is_some_and(|d| d.abs() <= APPROVAL_MAX_AGE_SECONDS * 1_000_000));
    if !fresh {
        return Some(format!(
            "the {who}'s request was signed more than {APPROVAL_MAX_AGE_SECONDS}s from when it was recorded"
        ));
    }
    None
}

/// The value of a field, absent and `null` alike.
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// Why the requests embedded in a review do not prove it, or `None`: offline,
/// with the review alone and the NA's public keys (`audiences`). The decider
/// signed `POST /admin/evidence/reviews/<review_id>/decide`, without a
/// query, for one of the NA keys, as `decided_by`, with exactly the verdict,
/// waiver end and note the review records, within 300 seconds of
/// `decided_at`; a requester (`request_approval`) signed
/// `POST /admin/evidence/reviews` with exactly the subject and justification
/// it records, within 300 seconds of `requested_at`. Whether each public key
/// is the operator key's is checked against the holder registry
/// ([`verify_evidence_events`](crate::verify::verify_evidence_events),
/// `review_approval_key_mismatch`). An export verifier reports a problem as
/// `review_approval_invalid`.
pub fn review_approval_problem(review: &Value, audiences: &[String]) -> Option<String> {
    let approval = field(review, "approval");
    let review_id = review["review_id"].as_str().unwrap_or_default();
    if let Some(problem) = approval_problem(
        approval,
        "decider",
        review["decided_by"].as_str().unwrap_or_default(),
        &review_decision_path(review_id),
        audiences,
        instant(&review["decided_at"]),
    ) {
        return Some(problem);
    }
    let body = approval["body"].as_object().cloned().unwrap_or_default();
    if body.keys().any(|k| !DECISION_FIELDS.contains(&k.as_str())) {
        return Some("the decider's request carries fields the review does not record".into());
    }
    let given = |key: &str| body.get(key).unwrap_or(&Value::Null);
    if given("verdict") != field(review, "verdict") || given("note") != field(review, "note") {
        return Some("the decider's request gives another verdict or note".into());
    }
    let recorded = field(review, "waive_until");
    let signed = given("waive_until");
    if signed.is_null() != recorded.is_null()
        || (!signed.is_null() && instant(signed) != instant(recorded))
    {
        return Some("the decider's request gives another waiver time".into());
    }
    let request = field(review, "request_approval");
    if request.is_null() {
        return None;
    }
    if let Some(problem) = approval_problem(
        request,
        "requester",
        review["requested_by"].as_str().unwrap_or_default(),
        REVIEW_REQUEST_PATH,
        audiences,
        instant(&review["requested_at"]),
    ) {
        return Some(problem);
    }
    let expected = json!({
        "subject_kind": field(review, "subject_kind"),
        "subject_id": field(review, "subject_id"),
        "justification": field(review, "justification"),
    });
    (request["body"] != expected)
        .then(|| "the requester's request names another subject or justification".into())
}

// ── Policy sections ──────────────────────────────────────────────────────────

const MAX_GRACE_SECONDS: i64 = 30 * 24 * 3600;
const MAX_EMERGENCY_LIFETIME_SECONDS: i64 = 30 * 24 * 3600;

fn parameter_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn integer_in(value: &Value, min: i64, max: i64) -> bool {
    value.as_i64().is_some_and(|n| (min..=max).contains(&n))
}

/// The issues the NA names for a boundary policy's 1.4.0 sections, as
/// `(code, detail)`, before it is published: `invalid_remediation`
/// (guidance that names no gate, a gate the policy does not have, a mode
/// other than `cancel` or `alert_only`, or a grace outside 0 to 2,592,000
/// seconds), `invalid_emergency` (an emergency policy must select exactly
/// one capability by its exact id, other than the exact one it
/// `stands_for`; `justification_parameter` matches `[A-Za-z0-9_-]{1,64}`;
/// `max_lifetime_seconds` is 60 to 2,592,000) and
/// `emergency_justification_not_required` (no enforce-mode
/// `required_parameter.v1` gate requires
/// `request_parameters.<justification_parameter>`). `review_required` may
/// only be `true`. The NA checks the rest of the policy besides
/// ([`PolicyClient::validate`](crate::PolicyClient::validate)).
pub fn policy_section_issues(policy: &Value) -> Vec<(&'static str, String)> {
    let mut issues = Vec::new();
    let gates: HashSet<&str> = policy["gates"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|g| g["gate_id"].as_str())
        .collect();
    match field(policy, "remediation") {
        Value::Null => {}
        Value::Object(guidance) if guidance.is_empty() => issues.push((
            "invalid_remediation",
            "remediation guidance names no gate".into(),
        )),
        Value::Object(guidance) => {
            for (key, entry) in guidance {
                let readable = entry.as_object().is_some_and(|e| {
                    e.keys().all(|k| k == "mode" || k == "grace_seconds")
                        && matches!(
                            e.get("mode").and_then(Value::as_str),
                            Some("cancel" | "alert_only")
                        )
                        && e.get("grace_seconds")
                            .is_some_and(|g| integer_in(g, 0, MAX_GRACE_SECONDS))
                });
                if !readable {
                    issues.push((
                        "invalid_remediation",
                        format!("remediation for {key:?} needs mode cancel or alert_only and grace_seconds 0 to {MAX_GRACE_SECONDS}"),
                    ));
                }
            }
            for key in guidance.keys() {
                if key != ANY_GATE && !gates.contains(key.as_str()) {
                    issues.push((
                        "invalid_remediation",
                        format!("remediation names {key:?}, which is not a gate of the policy"),
                    ));
                }
            }
        }
        _ => issues.push((
            "invalid_remediation",
            "remediation must be an object".into(),
        )),
    }
    if !matches!(
        field(policy, "review_required"),
        Value::Null | Value::Bool(true)
    ) {
        issues.push((
            "invalid_remediation",
            "review_required may only be true".into(),
        ));
    }
    issues.extend(emergency_issues(policy));
    issues
}

fn emergency_issues(policy: &Value) -> Vec<(&'static str, String)> {
    let emergency = field(policy, "emergency");
    if emergency.is_null() {
        return Vec::new();
    }
    let invalid = |detail: &str| ("invalid_emergency", detail.to_owned());
    let Some(section) = emergency.as_object() else {
        return vec![invalid("emergency must be an object")];
    };
    let stands_for = section.get("stands_for").and_then(Value::as_str);
    let parameter = section
        .get("justification_parameter")
        .and_then(Value::as_str);
    let readable = section.keys().all(|k| {
        [
            "stands_for",
            "justification_parameter",
            "max_lifetime_seconds",
        ]
        .contains(&k.as_str())
    }) && stands_for.is_some_and(|s| (1..=256).contains(&s.chars().count()))
        && parameter.is_some_and(|p| (1..=64).contains(&p.chars().count()))
        && section
            .get("max_lifetime_seconds")
            .is_some_and(|m| integer_in(m, 60, MAX_EMERGENCY_LIFETIME_SECONDS));
    if !readable {
        return vec![invalid(
            "emergency needs stands_for (1 to 256 characters), justification_parameter (1 to 64) \
             and max_lifetime_seconds (60 to 2592000)",
        )];
    }
    let (stands_for, parameter) = (
        stands_for.unwrap_or_default(),
        parameter.unwrap_or_default(),
    );
    let mut issues = Vec::new();
    let capabilities: Vec<&str> = policy["selector"]["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if capabilities.len() != 1 || capabilities[0].ends_with(".*") {
        issues.push(invalid(
            "an emergency policy selects exactly one capability by its exact ID",
        ));
    } else if capabilities[0] == stands_for {
        issues.push(invalid(
            "the emergency capability must differ from the capability it stands for",
        ));
    }
    if stands_for.ends_with(".*") {
        issues.push(invalid("stands_for is an exact capability ID"));
    }
    if !parameter_name(parameter) {
        issues.push(invalid(
            "justification_parameter must match [A-Za-z0-9_-]{1,64}",
        ));
        return issues;
    }
    let path = format!("request_parameters.{parameter}");
    let required = policy["gates"].as_array().into_iter().flatten().any(|g| {
        g["gate_type"] == "required_parameter.v1"
            && g.get("mode").and_then(Value::as_str).unwrap_or("enforce") == "enforce"
            && g["config"]["path"] == path.as_str()
    });
    if !required {
        issues.push((
            "emergency_justification_not_required",
            format!(
                "an emergency policy requires {path} with an enforce-mode required_parameter.v1 gate"
            ),
        ));
    }
    issues
}
