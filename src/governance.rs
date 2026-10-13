//! Controller-side composition for governed resource lifecycles (e.g.
//! secrets): evaluate, act only on a verified ALLOW, and record the outcome on
//! the resource chain. With break-glass (v1.3.0), act when the NA cannot be
//! reached, and record that. Cancel a denied change by rotating forward,
//! then disabling (1.4.0).

use std::future::Future;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    boundary::BoundaryClient,
    errors::{ActionValue, GenesisMeshError, Result},
    evidence_store::EvidenceStoreClient,
    execution::{
        check_metadata_only, resource_problem, ExecutionRecorder, PriorResource, RecordExecution,
        MAX_METADATA_BYTES,
    },
    out_of_band::{
        break_glass_metadata, check_justification, check_nesting, length_problem, metadata_size,
        refused, BreakGlassInput, EvaluationFailure,
    },
    outbox::{OutboxEntry, RecordOutboxEntry},
    remediation::{
        next_state, remediation_input_problem, steps_problem, RemediationInput, RemediationSteps,
        RemediationSubject,
    },
    verify::{verify_boundary_decision, VerifyDecisionOptions},
};

/// One failed gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFailure {
    /// Gate name.
    pub gate: String,
    /// Why it failed.
    pub detail: String,
}

/// What a decision means for a controller and a reviewer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSummary {
    /// The decision id.
    pub decision_id: String,
    /// The action is allowed.
    pub authorized: bool,
    /// The NA's denial reason.
    pub denial_reason: Option<String>,
    /// Failed gates that deny the request.
    pub enforced_failures: Vec<GateFailure>,
    /// Observe-mode policy gates that failed: recorded, not enforced.
    pub observed_failures: Vec<GateFailure>,
    /// `<policy_id>@<version>` in resolution order.
    pub applied_policies: Vec<String>,
    /// The attestation the decision binds, if any.
    pub attestation_id: Option<String>,
}

const OBSERVE_PREFIX: &str = "[observe] ";

/// Summarize a decision: enforced and observed failures, applied policies.
pub fn summarize_decision(decision: &Value) -> DecisionSummary {
    let mut enforced_failures = Vec::new();
    let mut observed_failures = Vec::new();
    for gate in decision["gate_results"].as_array().into_iter().flatten() {
        if gate["passed"].as_bool() == Some(true) {
            continue;
        }
        let detail = gate["detail"].as_str().unwrap_or_default();
        let name = gate["gate_name"].as_str().unwrap_or_default().to_owned();
        match detail.strip_prefix(OBSERVE_PREFIX) {
            Some(rest) => observed_failures.push(GateFailure {
                gate: name,
                detail: rest.to_owned(),
            }),
            None => enforced_failures.push(GateFailure {
                gate: name,
                detail: detail.to_owned(),
            }),
        }
    }
    DecisionSummary {
        decision_id: decision["decision_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        authorized: decision["authorized"].as_bool() == Some(true),
        denial_reason: decision["denial_reason"].as_str().map(str::to_owned),
        enforced_failures,
        observed_failures,
        applied_policies: decision["policy_binding"]["policies"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| {
                format!(
                    "{}@{}",
                    p["policy_id"].as_str().unwrap_or_default(),
                    p["version"]
                )
            })
            .collect(),
        attestation_id: decision["attestation_binding"]["attestation_id"]
            .as_str()
            .map(str::to_owned),
    }
}

/// What a governed action reports back for the evidence record.
#[derive(Debug, Clone)]
pub struct ActionReport<T> {
    /// Returned to the caller; never recorded.
    pub value: Option<T>,
    /// Recorded in the evidence, e.g. `{"secret_version": "v3"}`.
    /// Identifiers and versions only.
    pub execution_parameters: Option<Value>,
    /// Defaults to `success`.
    pub outcome: Option<String>,
    /// Short outcome detail.
    pub outcome_detail: Option<String>,
}

impl<T> Default for ActionReport<T> {
    fn default() -> Self {
        Self {
            value: None,
            execution_parameters: None,
            outcome: None,
            outcome_detail: None,
        }
    }
}

/// How the decision must verify before the action runs.
#[derive(Debug, Clone, Default)]
pub struct GovernedVerification {
    /// NA keys that may sign decisions. Required.
    pub operator_public_keys: Vec<String>,
    /// Keys for an embedded freshness proof, when checked.
    pub freshness_proof_issuer_keys: Vec<String>,
    /// The decision must bind exactly these policy versions (may be empty).
    pub expected_policies: Vec<Value>,
    /// Required for an ALLOW under an attestation basis.
    pub expected_attestation: Option<Value>,
}

/// A governed action request.
#[derive(Debug, Clone, Default)]
pub struct GovernedActionParams {
    /// The `/admin/boundary/evaluate` body: `requested_capability`,
    /// `attestation_id` or `agreement`, and `context`.
    pub evaluate: Value,
    /// Resource acted on, e.g. `kv:<vault>/<secret>`.
    pub resource_id: Option<String>,
    /// `create`, `rotate`, `revoke`, `update` or `delete`; required with `resource_id`.
    pub resource_action: Option<String>,
    /// The resource's previous record. `None` reads the head from the NA;
    /// `Some(None)` asserts the resource has no history.
    pub prior_resource: Option<Option<PriorResource>>,
    /// Offline verification of the decision.
    pub verify: GovernedVerification,
}

/// Outcome of [`governed_action`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GovernedActionResult<T> {
    /// `{decision, justification}` from the NA.
    pub evaluation: Value,
    /// The action was allowed and ran.
    pub authorized: bool,
    /// The decision summary.
    pub summary: DecisionSummary,
    /// The action's value, when it ran.
    pub value: Option<T>,
    /// The signed execution evidence, when the action ran.
    pub evidence: Option<Value>,
    /// The NA's acknowledgement of the evidence, when it admitted it.
    pub submission: Option<Value>,
    /// With an outbox (v1.2.0): the outbox entry holding the evidence when
    /// the NA has not admitted it, pending for `flush_pending` or a dead
    /// letter when it was refused. A failed submission then is not an error.
    pub queued: Option<OutboxEntry>,
}

const GUARD_NOTE: &str = "secret guard dropped";

/// The note naming what the guard dropped: plain field names only, others
/// counted.
fn guard_note(dropped: &[String]) -> String {
    let nameable = |d: &String| {
        !d.is_empty()
            && d.len() <= 64
            && d.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    };
    let mut parts: Vec<String> = dropped.iter().filter(|d| nameable(d)).cloned().collect();
    let others = dropped.len() - parts.len();
    if others > 0 {
        parts.push(format!(
            "{others} other field{}",
            if others == 1 { "" } else { "s" }
        ));
    }
    format!("[{GUARD_NOTE}: {}]", parts.join(", "))
}

/// Reported metadata without the parts the secret guard refuses.
#[derive(Debug, Clone, PartialEq)]
pub struct RefusedMetadata {
    /// The accepted parameters.
    pub execution_parameters: Value,
    /// The accepted detail, with a note naming what was dropped.
    pub outcome_detail: String,
    /// The refused field names, sorted (`outcome_detail` for the detail).
    pub dropped: Vec<String>,
}

/// The reported metadata without the parts the secret guard refuses: each
/// top-level parameter is checked alone, and the outcome detail names what
/// was dropped. A parameter nested too deep for every reader is dropped too
/// (1.3.1). Everything is dropped when the rest is still refused (its size).
pub fn without_refused_metadata(
    execution_parameters: &Value,
    outcome_detail: Option<&str>,
) -> RefusedMetadata {
    let empty = serde_json::Map::new();
    let params = execution_parameters.as_object().unwrap_or(&empty);
    let mut kept = serde_json::Map::new();
    let mut dropped = Vec::new();
    for (key, value) in params {
        let alone = json!({ key: value });
        if check_metadata_only(&alone, None).is_none()
            && check_nesting(&json!({ "execution_parameters": alone })).is_ok()
        {
            kept.insert(key.clone(), value.clone());
        } else {
            dropped.push(key.clone());
        }
    }
    let outcome_detail_given = outcome_detail.is_some();
    let detail = outcome_detail.filter(|d| check_metadata_only(&json!({}), Some(d)).is_none());
    if outcome_detail.is_some() && detail.is_none() {
        dropped.push("outcome_detail".into());
    }
    if check_metadata_only(&Value::Object(kept.clone()), detail).is_some() {
        dropped = params.keys().cloned().collect();
        if outcome_detail.is_some() {
            dropped.push("outcome_detail".into());
        }
        kept.clear();
    }
    dropped.sort();
    let note = guard_note(&dropped);
    let outcome_detail = match detail {
        Some(detail) if !dropped.iter().any(|d| d == "outcome_detail") => {
            format!("{detail} {note}")
        }
        _ => note,
    };
    if check_metadata_only(&Value::Object(kept.clone()), Some(&outcome_detail)).is_some() {
        let mut all: Vec<String> = params.keys().cloned().collect();
        if outcome_detail_given {
            all.push("outcome_detail".into());
        }
        all.sort();
        return RefusedMetadata {
            execution_parameters: json!({}),
            outcome_detail: format!("[{GUARD_NOTE}]"),
            dropped: all,
        };
    }
    RefusedMetadata {
        execution_parameters: Value::Object(kept),
        outcome_detail,
        dropped,
    }
}

/// The error type an action returns.
pub type ActionError = Box<dyn std::error::Error + Send + Sync>;

/// Why signing refused what an action reported, or `None` for another error:
/// secret material or its size, or (1.3.1) values nested too deep for every
/// reader. The outcome is then recorded without the refused parts.
fn refused_report(err: &GenesisMeshError) -> Option<String> {
    match err {
        GenesisMeshError::SecretMaterial(reason) => Some(reason.clone()),
        GenesisMeshError::OutOfBandRecord { code, message }
            if code == "break_glass_secret_material" =>
        {
            Some(message.clone())
        }
        GenesisMeshError::StrictJson { detail, .. } => Some(detail.clone()),
        _ => None,
    }
}

fn check_decision(decision: &Value, params: &GovernedActionParams, context_id: &str) -> Result<()> {
    let attestation_id = params
        .evaluate
        .get("attestation_id")
        .and_then(Value::as_str);
    let reject = |reason: &str| Err(GenesisMeshError::DecisionVerification(reason.to_owned()));
    if decision["authorized"].as_bool() == Some(true)
        && attestation_id.is_some()
        && params.verify.expected_attestation.is_none()
    {
        return reject("attestation_expectation_required");
    }
    let check = verify_boundary_decision(
        decision,
        &VerifyDecisionOptions {
            operator_public_keys: params.verify.operator_public_keys.clone(),
            freshness_proof_issuer_keys: params.verify.freshness_proof_issuer_keys.clone(),
            now: Some(Utc::now()),
            expected_policies: Some(params.verify.expected_policies.clone()),
            expected_attestation: params.verify.expected_attestation.clone(),
            as_of_record_time: false,
        },
    );
    if !check.accepted {
        return reject(&check.reason);
    }
    if decision["context_id"].as_str() != Some(context_id) {
        return reject("context_binding_mismatch");
    }
    if attestation_id.is_some()
        && decision["attestation_binding"]["attestation_id"].as_str() != attestation_id
    {
        return reject("attestation_binding_mismatch");
    }
    if let Some(agreement) = params.evaluate.get("agreement").filter(|a| !a.is_null()) {
        if decision["agreement_id"] != agreement["agreement_id"] {
            return reject("agreement_binding_mismatch");
        }
    }
    Ok(())
}

/// Break-glass for [`governed_action_with_break_glass`] (v1.3.0).
#[derive(Debug, Clone)]
pub struct BreakGlassOptions {
    /// Why the change cannot wait for the NA: 1 to 1024 characters, no
    /// secret values. Recorded, and shown with the resource's changes.
    pub justification: String,
}

impl BreakGlassOptions {
    /// Break-glass with this justification.
    pub fn new(justification: impl Into<String>) -> Self {
        Self {
            justification: justification.into(),
        }
    }
}

/// The evaluation failed transiently and the action ran under break-glass
/// (v1.3.0). The NA judges the record after the fact, as the failed
/// evaluation would have gone.
#[derive(Debug)]
#[non_exhaustive]
pub struct BreakGlassResult<T> {
    /// How the evaluation failed.
    pub failure: EvaluationFailure,
    /// The evaluation's error.
    pub evaluation_error: GenesisMeshError,
    /// The action's value.
    pub value: Option<T>,
    /// The signed break-glass record.
    pub record: Value,
    /// The NA's answer, when it was reachable again by then.
    pub submission: Option<Value>,
    /// The record outbox entry holding the record otherwise, pending for
    /// [`EvidenceStoreClient::flush_records`] or a dead letter.
    pub queued: Option<RecordOutboxEntry>,
    /// Reported metadata the secret guard refused, left out of the record
    /// (named in its `outcome_detail`); empty when none was.
    pub dropped: Vec<String>,
}

/// What [`governed_action_with_break_glass`] did (v1.3.0).
#[derive(Debug)]
pub enum GovernedActionOutcome<T> {
    /// The NA answered: the action ran on a verified ALLOW, or did not run
    /// on a DENY, as with [`governed_action`].
    Evaluated(GovernedActionResult<T>),
    /// The evaluation failed transiently and the action ran without a
    /// decision.
    BrokeGlass(BreakGlassResult<T>),
}

/// Refusals that look transient but are not: the NA throttling a caller whose
/// operator signatures keep failing, an evaluation the NA computed (perhaps a
/// DENY) but could not store, and an answer whose body could not be read
/// (v1.3.0). None breaks the glass.
const NOT_BREAKABLE: [&str; 3] = [
    "admin_auth_throttled",
    "evidence_store_unavailable",
    "response_body_unreadable",
];

/// Room kept for the action's report within the metadata limit of a
/// break-glass record.
const RECORD_RESERVE: usize = 2048;

/// The longest outcome detail a break-glass record carries (the reference's
/// limit, in characters).
const MAX_OUTCOME_DETAIL: usize = 1024;

/// `text` cut to `max` characters, the last one an ellipsis when cut.
fn clip(text: Option<String>, max: usize) -> Option<String> {
    let text = text?;
    if text.chars().count() <= max {
        return Some(text);
    }
    let mut cut: String = text.chars().take(max - 1).collect();
    cut.push('\u{2026}');
    Some(cut)
}

/// The transient failure an evaluation error is (v1.3.0), or `None` for any
/// other error: a network error, a timeout, HTTP `5xx` or `429`, but not
/// `429 admin_auth_throttled` nor `503 evidence_store_unavailable`. A DENY is
/// not an error.
pub fn evaluation_failure(err: &GenesisMeshError) -> Option<EvaluationFailure> {
    if NOT_BREAKABLE.contains(&err.code()) {
        return None;
    }
    match err {
        // A request that could not be built never reached the NA's network.
        GenesisMeshError::Network(error) if error.is_builder() => None,
        GenesisMeshError::Network(error) if error.is_timeout() => Some(EvaluationFailure::Timeout),
        GenesisMeshError::Network(_) => Some(EvaluationFailure::NetworkError),
        GenesisMeshError::RateLimit { .. } | GenesisMeshError::Http { status: 429, .. } => {
            Some(EvaluationFailure::RateLimited)
        }
        GenesisMeshError::Http {
            status: 500..=599, ..
        } => Some(EvaluationFailure::ServerError),
        _ => None,
    }
}

/// Evaluate, run `action` only on a verified ALLOW, then sign and submit the
/// execution evidence linked to the resource chain. A DENY returns
/// `authorized: false` without running the action. If the action fails, a
/// `failure` record is submitted and [`GenesisMeshError::ActionFailed`] is
/// returned with the action's error.
///
/// With an outbox ([`ClientOptions::with_outbox`](crate::ClientOptions::with_outbox),
/// v1.2.0) every record is kept until the NA admits it, and a failed
/// submission is not an error: the result's `queued` is the outbox entry,
/// which [`EvidenceStoreClient::flush_pending`] submits later. A resource with
/// pending records chains from the newest of them, not from the NA's head. A
/// guard refusal after the action records the outcome without the refused
/// fields and returns [`GenesisMeshError::MetadataRefused`]; a failure to
/// keep the record returns [`GenesisMeshError::EvidenceNotKept`]. Both carry
/// the action's value.
pub async fn governed_action<T, F, Fut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: GovernedActionParams,
    action: F,
) -> Result<GovernedActionResult<T>>
where
    T: Send + 'static,
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
{
    // Without break-glass the action always gets a decision.
    let action = |decision: Option<Value>| action(decision.unwrap_or_default());
    match run(boundary, evidence_store, recorder, params, None, action).await? {
        GovernedActionOutcome::Evaluated(result) => Ok(result),
        GovernedActionOutcome::BrokeGlass(_) => unreachable!("break-glass is off"),
    }
}

/// [`governed_action`] that runs the action even when the NA cannot be
/// reached (v1.3.0). When the evaluation fails transiently (network error,
/// timeout, `5xx`, `429`; see [`evaluation_failure`]), the action runs with
/// no decision (`None`), and a break-glass record signed by the executor key,
/// with `break_glass.justification`, is kept in the record outbox and
/// submitted: the outcome is [`GovernedActionOutcome::BrokeGlass`]. A DENY,
/// a decision that fails verification, the NA throttling failed operator
/// signatures (`429 admin_auth_throttled`), an evaluation it could not store
/// (`503 evidence_store_unavailable`), or any other error never breaks the
/// glass: those go as with [`governed_action`]
/// ([`GovernedActionOutcome::Evaluated`] or the error).
///
/// Before anything is evaluated or run, it needs a record outbox
/// ([`ClientOptions::with_record_outbox`](crate::ClientOptions::with_record_outbox),
/// else [`GenesisMeshError::RecordOutboxRequired`]), `resource_id`, and an
/// attestation-based evaluation (`attestation_id`; an agreement-based one
/// cannot be judged after the fact: `break_glass_malformed`) naming its
/// `requested_capability`, with the context's `request_parameters` and
/// `attributes` objects that, with the justification, leave room for the
/// record; and checks the justification (1 to 1024 characters) and the
/// evaluation context against the secret guard
/// ([`GenesisMeshError::OutOfBandRecord`], `break_glass_malformed` or
/// `break_glass_secret_material`). If the action fails under break-glass, a
/// `failure` record is kept and [`GenesisMeshError::ActionFailed`] carries it
/// (`queued_record` while the NA has not admitted it). Once the action ran a
/// record is always signed: an outcome detail is cut to 1024 characters, and
/// reported metadata the guard refuses is left out of the record (`dropped`;
/// the whole report when the rest is still refused). A record that cannot be
/// kept returns [`GenesisMeshError::EvidenceNotKept`] with the
/// action's value.
pub async fn governed_action_with_break_glass<T, F, Fut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: GovernedActionParams,
    break_glass: BreakGlassOptions,
    action: F,
) -> Result<GovernedActionOutcome<T>>
where
    T: Send + 'static,
    F: FnOnce(Option<Value>) -> Fut,
    Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
{
    run(
        boundary,
        evidence_store,
        recorder,
        params,
        Some(&break_glass),
        action,
    )
    .await
}

/// Everything break-glass needs is checked before anything is evaluated or run.
async fn check_break_glass(
    store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: &GovernedActionParams,
    options: &BreakGlassOptions,
) -> Result<()> {
    let outbox = store
        .record_outbox()
        .ok_or(GenesisMeshError::RecordOutboxRequired)?;
    if params.resource_id.is_none() {
        return Err(GenesisMeshError::Configuration(
            "break-glass needs resource_id and resource_action".into(),
        ));
    }
    let named = |key: &str| {
        params.evaluate[key]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    };
    // An agreement-based evaluation rests on the agreement, which a
    // break-glass record does not carry: the NA could not judge it after the
    // fact.
    if !named("attestation_id") {
        return Err(refused(
            "break_glass_malformed",
            "break-glass needs an attestation-based evaluation (attestation_id)",
        ));
    }
    if !named("requested_capability") {
        return Err(refused(
            "break_glass_malformed",
            "break-glass needs requested_capability",
        ));
    }
    let text = |key: &str| params.evaluate[key].as_str().unwrap_or_default();
    if let Some(problem) = [
        length_problem(
            "executor_sovereign_id",
            recorder.executor_sovereign_id(),
            1,
            256,
        ),
        length_problem("attestation_id", text("attestation_id"), 1, 128),
        length_problem("requested_capability", text("requested_capability"), 1, 256),
    ]
    .into_iter()
    .flatten()
    .next()
    {
        return Err(refused("break_glass_malformed", problem));
    }
    check_justification(&options.justification)?;
    // Everything the record carries besides the action's report is checked
    // now, with room left for the report, so a record can always be kept once
    // the action has run.
    let context = params
        .evaluate
        .get("context")
        .filter(|c| !c.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut carried = serde_json::Map::new();
    for name in ["request_parameters", "attributes"] {
        let value = context.get(name).cloned().unwrap_or_else(|| json!({}));
        if !value.is_object() {
            return Err(refused(
                "break_glass_malformed",
                format!("context.{name} must be a JSON object"),
            ));
        }
        carried.insert(name.into(), value);
    }
    if let Some(secret) = check_metadata_only(&context, None) {
        return Err(refused("break_glass_secret_material", secret));
    }
    check_nesting(&Value::Object(carried.clone()))?;
    // Measured as the NA measures the record (1.3.1): with the justification,
    // an empty report, and text outside ASCII escaped.
    let size = metadata_size(&break_glass_metadata(
        &json!({}),
        &carried["request_parameters"],
        &carried["attributes"],
        &json!(""),
        &json!(options.justification),
    ));
    if size > MAX_METADATA_BYTES - RECORD_RESERVE {
        return Err(refused(
            "break_glass_malformed",
            format!(
                "the context and justification leave no room for the record within \
                 {MAX_METADATA_BYTES} bytes"
            ),
        ));
    }
    outbox.list().await.map_err(GenesisMeshError::Outbox)?;
    Ok(())
}

/// Run the action without a decision and keep its break-glass record.
async fn break_the_glass<T, F, Fut>(
    store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: &GovernedActionParams,
    justification: &str,
    request: Value,
    (failure, evaluation_error): (EvaluationFailure, GenesisMeshError),
    action: F,
) -> Result<BreakGlassResult<T>>
where
    T: Send + 'static,
    F: FnOnce(Option<Value>) -> Fut,
    Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
{
    let context = &request["context"];
    let present = |value: &Value| Some(value.clone()).filter(|v| !v.is_null());
    let sign = |outcome: Option<String>,
                execution_parameters: Option<Value>,
                outcome_detail: Option<String>| {
        recorder.sign_break_glass(BreakGlassInput {
            attestation_id: request["attestation_id"].as_str().map(str::to_owned),
            request_parameters: present(&context["request_parameters"]),
            attributes: present(&context["attributes"]),
            outcome,
            outcome_detail: clip(outcome_detail, MAX_OUTCOME_DETAIL),
            execution_parameters,
            ..BreakGlassInput::new(
                params.resource_id.clone().unwrap_or_default(),
                params.resource_action.clone().unwrap_or_default(),
                request["requested_capability"].as_str().unwrap_or_default(),
                justification,
                request.clone(),
                failure,
            )
        })
    };

    let report = match action(None).await {
        Ok(report) => report,
        Err(source) => {
            // The error text is not recorded: it may carry secret material.
            let record = match sign(Some("failure".into()), None, Some("action failed".into())) {
                Ok(record) => record,
                Err(evidence_error) => {
                    return Err(GenesisMeshError::ActionUnrecorded {
                        source,
                        evidence_error: Box::new(evidence_error),
                        evidence: None,
                    })
                }
            };
            return Err(match store.enqueue_record(record.clone()).await {
                Ok(delivery) => GenesisMeshError::ActionFailed {
                    source,
                    evidence: Some(Box::new(record)),
                    queued: None,
                    queued_record: delivery.queued.map(Box::new),
                },
                Err(evidence_error) => GenesisMeshError::ActionUnrecorded {
                    source,
                    evidence_error: Box::new(evidence_error),
                    evidence: Some(Box::new(record)),
                },
            });
        }
    };

    // The action ran: from here on its outcome is always recorded.
    let ActionReport {
        value,
        execution_parameters,
        outcome,
        outcome_detail,
    } = report;
    let not_kept = |source: GenesisMeshError, record: Option<Value>, value: Option<T>| {
        GenesisMeshError::EvidenceNotKept {
            source: Box::new(source),
            evidence: record.map(Box::new),
            value: ActionValue::new(value),
        }
    };
    let (record, dropped) = match sign(
        outcome.clone(),
        execution_parameters.clone(),
        outcome_detail.clone(),
    ) {
        Ok(record) => (record, Vec::new()),
        Err(err) if refused_report(&err).is_some() => {
            let cleaned = without_refused_metadata(
                execution_parameters.as_ref().unwrap_or(&json!({})),
                outcome_detail.as_deref(),
            );
            match sign(
                outcome.clone(),
                Some(cleaned.execution_parameters),
                Some(cleaned.outcome_detail),
            ) {
                Ok(record) => (record, cleaned.dropped),
                Err(err) if refused_report(&err).is_some() => {
                    // The report together with the context is still refused
                    // (its size): keep the outcome alone.
                    let mut all: Vec<String> = execution_parameters
                        .as_ref()
                        .and_then(Value::as_object)
                        .map(|p| p.keys().cloned().collect())
                        .unwrap_or_default();
                    if outcome_detail.is_some() {
                        all.push("outcome_detail".into());
                    }
                    all.sort();
                    let detail = "[secret guard dropped the report]".to_owned();
                    match sign(outcome, Some(json!({})), Some(detail)) {
                        Ok(record) => (record, all),
                        Err(err) => return Err(not_kept(err, None, value)),
                    }
                }
                Err(err) => return Err(not_kept(err, None, value)),
            }
        }
        Err(err) => return Err(not_kept(err, None, value)),
    };
    let delivery = match store.enqueue_record(record.clone()).await {
        Ok(delivery) => delivery,
        Err(err) => return Err(not_kept(err, Some(record), value)),
    };
    Ok(BreakGlassResult {
        failure,
        evaluation_error,
        value,
        record,
        submission: delivery.submission,
        queued: delivery.queued,
        dropped,
    })
}

/// [`governed_action`], with break-glass when `break_glass` is given.
async fn run<T, F, Fut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: GovernedActionParams,
    break_glass: Option<&BreakGlassOptions>,
    action: F,
) -> Result<GovernedActionOutcome<T>>
where
    T: Send + 'static,
    F: FnOnce(Option<Value>) -> Fut,
    Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
{
    match attempt(
        boundary,
        evidence_store,
        recorder,
        params,
        break_glass,
        false,
        action,
    )
    .await?
    {
        Attempt::Done(outcome) => Ok(outcome),
        Attempt::Denied(result, _) => Ok(GovernedActionOutcome::Evaluated(result)),
        Attempt::Unanswered(err, _) => Err(err),
    }
}

/// What one governed attempt did. With `hand_back` (1.4.0, for
/// [`urgent_action`]), a DENY or an evaluation that got no answer returns the
/// action, which did not run.
enum Attempt<T, F> {
    Done(GovernedActionOutcome<T>),
    Denied(GovernedActionResult<T>, F),
    Unanswered(GenesisMeshError, F),
}

/// [`run`], handing the action back when it did not run and `hand_back`.
async fn attempt<T, F, Fut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: GovernedActionParams,
    break_glass: Option<&BreakGlassOptions>,
    hand_back: bool,
    action: F,
) -> Result<Attempt<T, F>>
where
    T: Send + 'static,
    F: FnOnce(Option<Value>) -> Fut,
    Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
{
    if params.resource_id.is_some() != params.resource_action.is_some() {
        return Err(GenesisMeshError::Configuration(
            "resource_id and resource_action go together".into(),
        ));
    }
    // A record the NA would refuse is refused before the action runs (1.3.1).
    if let Some(problem) = resource_problem(
        params.resource_id.as_deref(),
        params.resource_action.as_deref(),
    ) {
        return Err(GenesisMeshError::Configuration(problem));
    }
    if params.verify.operator_public_keys.is_empty() {
        return Err(GenesisMeshError::DecisionVerification(
            "verification_keys_required".into(),
        ));
    }
    let outbox = evidence_store.outbox();
    if let Some(outbox) = outbox {
        // An outbox that cannot be read fails here, before anything is
        // evaluated or run.
        outbox.list().await.map_err(GenesisMeshError::Outbox)?;
    }
    if let Some(options) = break_glass {
        check_break_glass(evidence_store, recorder, &params, options).await?;
    }
    let mut request = params.evaluate.clone();
    if !request.is_object() {
        return Err(GenesisMeshError::Configuration(
            "evaluate must be a JSON object".into(),
        ));
    }
    let context_id = request["context"]["context_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map_or_else(|| Uuid::new_v4().to_string(), str::to_owned);
    if !request["context"].is_object() {
        request["context"] = json!({});
    }
    request["context"]["context_id"] = json!(context_id);

    let evaluation = match boundary.evaluate(request.clone()).await {
        Ok(evaluation) => evaluation,
        Err(err) => {
            if hand_back && evaluation_failure(&err).is_some() {
                return Ok(Attempt::Unanswered(err, action));
            }
            let (Some(options), Some(failure)) = (break_glass, evaluation_failure(&err)) else {
                return Err(err);
            };
            let failed = (failure, err);
            return break_the_glass(
                evidence_store,
                recorder,
                &params,
                &options.justification,
                request,
                failed,
                action,
            )
            .await
            .map(|result| Attempt::Done(GovernedActionOutcome::BrokeGlass(result)));
        }
    };
    let decision = evaluation["decision"].clone();
    check_decision(&decision, &params, &context_id)?;
    let summary = summarize_decision(&decision);
    if !summary.authorized {
        let denied = GovernedActionResult {
            evaluation,
            authorized: false,
            summary,
            value: None,
            evidence: None,
            submission: None,
            queued: None,
        };
        return Ok(if hand_back {
            Attempt::Denied(denied, action)
        } else {
            Attempt::Done(GovernedActionOutcome::Evaluated(denied))
        });
    }

    let prior = match (&params.resource_id, &params.prior_resource) {
        (None, _) => None,
        (Some(_), Some(prior)) => prior.clone(),
        (Some(resource_id), None) => match match outbox {
            Some(_) => evidence_store.pending_head(resource_id).await?,
            None => None,
        } {
            Some(pending) => Some(PriorResource::Record(pending)),
            None => evidence_store
                .resource_head(resource_id)
                .await?
                .map(PriorResource::Head),
        },
    };
    // Reading the head may outlast the decision's validity window.
    check_decision(&decision, &params, &context_id)?;

    let capability = params.evaluate["requested_capability"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let record = |outcome: Option<String>,
                  execution_parameters: Option<Value>,
                  outcome_detail: Option<String>| {
        recorder.record(RecordExecution {
            decision: decision.clone(),
            executed_capability: capability.clone(),
            outcome,
            execution_parameters,
            outcome_detail,
            resource_id: params.resource_id.clone(),
            resource_action: params.resource_action.clone(),
            prior_resource: prior.clone(),
            ..RecordExecution::default()
        })
    };

    let report = match action(Some(decision.clone())).await {
        Ok(report) => report,
        Err(source) => {
            // The error text is not recorded: it may carry secret material.
            let evidence = match record(Some("failure".into()), None, Some("action failed".into()))
            {
                Ok(evidence) => evidence,
                Err(evidence_error) => {
                    return Err(GenesisMeshError::ActionUnrecorded {
                        source,
                        evidence_error: Box::new(evidence_error),
                        evidence: None,
                    })
                }
            };
            let kept = match outbox {
                Some(_) => evidence_store
                    .enqueue(evidence.clone())
                    .await
                    .map(|d| d.queued),
                None => evidence_store.submit(evidence.clone()).await.map(|_| None),
            };
            return Err(match kept {
                Ok(queued) => GenesisMeshError::ActionFailed {
                    source,
                    evidence: Some(Box::new(evidence)),
                    queued: queued.map(Box::new),
                    queued_record: None,
                },
                Err(evidence_error) => GenesisMeshError::ActionUnrecorded {
                    source,
                    evidence_error: Box::new(evidence_error),
                    evidence: Some(Box::new(evidence)),
                },
            });
        }
    };

    let ActionReport {
        value,
        execution_parameters,
        outcome,
        outcome_detail,
    } = report;
    if outbox.is_none() {
        let evidence = record(outcome, execution_parameters, outcome_detail)?;
        let submission = evidence_store.submit(evidence.clone()).await?;
        return Ok(Attempt::Done(GovernedActionOutcome::Evaluated(
            GovernedActionResult {
                evaluation,
                authorized: true,
                summary,
                value,
                evidence: Some(evidence),
                submission: Some(submission),
                queued: None,
            },
        )));
    }

    // The action ran: from here on its outcome is always recorded.
    let not_kept = |source: GenesisMeshError, evidence: Option<Value>, value: Option<T>| {
        GenesisMeshError::EvidenceNotKept {
            source: Box::new(source),
            evidence: evidence.map(Box::new),
            value: ActionValue::new(value),
        }
    };
    let (evidence, refused) = match record(
        outcome.clone(),
        execution_parameters.clone(),
        outcome_detail.clone(),
    ) {
        Ok(evidence) => (evidence, None),
        Err(err) => {
            let Some(reason) = refused_report(&err) else {
                return Err(not_kept(err, None, value));
            };
            let cleaned = without_refused_metadata(
                execution_parameters.as_ref().unwrap_or(&json!({})),
                outcome_detail.as_deref(),
            );
            match record(
                outcome,
                Some(cleaned.execution_parameters),
                Some(cleaned.outcome_detail),
            ) {
                Ok(evidence) => (evidence, Some((reason, cleaned.dropped))),
                Err(err) => return Err(not_kept(err, None, value)),
            }
        }
    };
    let delivery = match evidence_store.enqueue(evidence.clone()).await {
        Ok(delivery) => delivery,
        Err(err) => return Err(not_kept(err, Some(evidence), value)),
    };
    if let Some((reason, dropped)) = refused {
        return Err(GenesisMeshError::MetadataRefused {
            reason,
            dropped,
            evidence: Box::new(evidence),
            submission: delivery.submission.map(Box::new),
            queued: delivery.queued.map(Box::new),
            value: ActionValue::new(value),
        });
    }
    Ok(Attempt::Done(GovernedActionOutcome::Evaluated(
        GovernedActionResult {
            evaluation,
            authorized: true,
            summary,
            value,
            evidence: Some(evidence),
            submission: delivery.submission,
            queued: delivery.queued,
        },
    )))
}

// ── Remediation by a forward rotation (1.4.0) ────────────────────────────────

/// What [`rotate_forward_then_disable`] remediates and how the rotation is
/// governed (1.4.0).
#[derive(Debug, Clone)]
pub struct RotateForwardParams {
    /// The rotation's governed action: its evaluation (a decision for the
    /// rotation, under the policy that applies to it), the resource, which
    /// must be the subject's, and the decision's verification.
    /// `resource_action` is `rotate` (the default) or `update`.
    pub governed: GovernedActionParams,
    /// The judged change, from the remediation state
    /// ([`RemediationSubject::from_state`]).
    pub subject: RemediationSubject,
    /// The remediation state from the due queue, when the caller has it: its
    /// plan (`mode`, `steps`), its `state` and the version the change made
    /// (`change_version_id`) are checked before anything runs.
    pub state: Option<Value>,
    /// The denied version, disabled once the new version is current.
    pub disabled_version_id: String,
    /// A short note for the remediation record, no secret values.
    pub detail: Option<String>,
}

/// The version a forward rotation issued, as the rotation action reports it.
#[derive(Debug, Clone)]
pub struct RotatedVersion<T> {
    /// The new version, recorded as `execution_parameters.version_id`.
    pub version_id: String,
    /// Returned to the caller; never recorded.
    pub value: Option<T>,
    /// Other identifiers for the execution evidence (never values).
    pub execution_parameters: serde_json::Map<String, Value>,
}

impl<T> RotatedVersion<T> {
    /// The new version, without other parameters.
    pub fn new(version_id: impl Into<String>) -> Self {
        Self {
            version_id: version_id.into(),
            value: None,
            execution_parameters: serde_json::Map::new(),
        }
    }
}

/// What [`rotate_forward_then_disable`] did (1.4.0).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RotateForwardResult<T> {
    /// The forward rotation's governed action. When it was not authorized,
    /// nothing else happened.
    pub rotation: GovernedActionResult<T>,
    /// The signed remediation record linking the rotation, when the denied
    /// version was disabled.
    pub record: Option<Value>,
    /// The NA's answer to the record, when it admitted it.
    pub submission: Option<Value>,
    /// With a record outbox, the entry holding the record otherwise: pending
    /// (for example until the rotation's evidence is admitted) or a dead
    /// letter.
    pub queued: Option<RecordOutboxEntry>,
}

/// Cancel a denied change to a versioned resource without breaking its
/// readers (1.4.0): rotate forward to a new version under a governed
/// decision, then disable the denied version, then record a remediation
/// linked to the rotation's execution evidence.
///
/// 1. `rotate` runs as a [`governed_action`] (a verified ALLOW only),
///    rotating the resource to a new version and making it current; the new
///    version is recorded in the evidence as `execution_parameters.version_id`.
///    A DENY returns the result with no record: nothing else ran.
/// 2. `disable` disables (or deletes) `disabled_version_id`.
/// 3. The remediation record (`rotate_forward_then_disable`, outcome
///    `cancelled`) names the rotation's `evidence_id`, the new version and
///    the disabled one; it is signed by `recorder`, kept in the record outbox
///    when there is one (submitted directly otherwise), and submitted. The
///    NA admits it once it holds the rotation's evidence: with a record
///    outbox it stays pending until then (`remediation_rotation_missing` is
///    retried); flush the evidence outbox first.
///
/// Before anything is evaluated or run, it needs a `resource_id` equal to
/// the subject's and a `rotate` or `update` action
/// ([`GenesisMeshError::Configuration`]), a remediation the NA would admit
/// ([`GenesisMeshError::OutOfBandRecord`], `remediation_malformed` or
/// `remediation_secret_material`), and a record outbox that can be read.
/// With the remediation `state`, the NA's refusals it already tells are
/// refused too ([`GenesisMeshError::OutOfBandRecord`]): a plan other than
/// `cancel` by `rotate_forward_then_disable` (`remediation_steps_mismatch`),
/// a state from which no remediation is recorded, only `remediation_due` and
/// `overdue` are (`remediation_not_due`, `remediation_already_recorded`),
/// and another denied version than the change made
/// (`remediation_subject_mismatch`).
/// Errors of the rotation are those of [`governed_action`]. Once the rotation
/// ran, a new version equal to the denied one (nothing is disabled), a
/// disable that fails, or a record that cannot be signed, submitted or kept
/// returns [`GenesisMeshError::RemediationNotRecorded`] with the rotation's
/// evidence, and the record when it was signed.
pub async fn rotate_forward_then_disable<T, R, RFut, D, DFut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: RotateForwardParams,
    rotate: R,
    disable: D,
) -> Result<RotateForwardResult<T>>
where
    T: Send + 'static,
    R: FnOnce(Value) -> RFut,
    RFut: Future<Output = std::result::Result<RotatedVersion<T>, ActionError>>,
    D: FnOnce(String) -> DFut,
    DFut: Future<Output = std::result::Result<(), ActionError>>,
{
    let RotateForwardParams {
        mut governed,
        subject,
        state,
        disabled_version_id,
        detail,
    } = params;
    if let Some(state) = &state {
        let planned = json!({"outcome": "cancelled", "steps": "rotate_forward_then_disable"});
        if let (Some(mode), Some(steps)) = (state["mode"].as_str(), state["steps"].as_str()) {
            if let Some(problem) = steps_problem(mode, steps, &planned) {
                return Err(refused("remediation_steps_mismatch", problem));
            }
        }
        if let Some(current) = state["state"].as_str() {
            let pending = state["review_pending"] == true;
            if let Err(refusal) = next_state(current, "record_remediation", pending) {
                return Err(refused(refusal.code, refusal.detail));
            }
        }
        if let Some(version) = state["change_version_id"].as_str() {
            if version != disabled_version_id {
                return Err(refused(
                    "remediation_subject_mismatch",
                    format!("the change made version {version}, not {disabled_version_id}"),
                ));
            }
        }
    }
    if governed.resource_id.as_deref() != Some(subject.resource_id.as_str()) {
        return Err(GenesisMeshError::Configuration(
            "the forward rotation's resource_id must be the remediated resource".into(),
        ));
    }
    let action = governed
        .resource_action
        .get_or_insert_with(|| "rotate".into());
    if !matches!(action.as_str(), "rotate" | "update") {
        return Err(GenesisMeshError::Configuration(
            "a forward rotation's resource_action is rotate or update".into(),
        ));
    }
    let input = |rotation_evidence_id: String, version_id: String| RemediationInput {
        detail: detail.clone(),
        ..RemediationInput::new(
            subject.clone(),
            RemediationSteps::RotateForwardThenDisable {
                rotation_evidence_id,
                version_id,
                disabled_version_id: disabled_version_id.clone(),
            },
        )
    };
    // Checked with placeholders for what the rotation will give: another
    // version than the denied one.
    let placeholder = if disabled_version_id == "v" { "w" } else { "v" };
    remediation_input_problem(
        recorder.executor_sovereign_id(),
        &input("rotation".into(), placeholder.into()),
    )?;
    if let Some(outbox) = evidence_store.record_outbox() {
        // A record outbox that cannot be read fails here, before anything runs.
        outbox.list().await.map_err(GenesisMeshError::Outbox)?;
    }

    let rotation = governed_action(
        boundary,
        evidence_store,
        recorder,
        governed,
        |decision| async move {
            let rotated = rotate(decision).await?;
            let mut parameters = rotated.execution_parameters;
            parameters.insert("version_id".into(), json!(rotated.version_id));
            Ok(ActionReport {
                value: Some((rotated.value, rotated.version_id)),
                execution_parameters: Some(Value::Object(parameters)),
                ..ActionReport::default()
            })
        },
    )
    .await?;
    let GovernedActionResult {
        evaluation,
        authorized,
        summary,
        value,
        evidence,
        submission,
        queued,
    } = rotation;
    let (value, version_id) = match value {
        Some((value, version_id)) => (value, Some(version_id)),
        None => (None, None),
    };
    let rotation = GovernedActionResult {
        evaluation,
        authorized,
        summary,
        value,
        evidence,
        submission,
        queued,
    };
    let (Some(evidence), Some(version_id)) = (rotation.evidence.clone(), version_id) else {
        return Ok(RotateForwardResult {
            rotation,
            record: None,
            submission: None,
            queued: None,
        });
    };
    let incomplete =
        |source: ActionError, record: Option<Value>| GenesisMeshError::RemediationNotRecorded {
            source,
            rotation: Box::new(evidence.clone()),
            record: record.map(Box::new),
        };
    if version_id == disabled_version_id {
        return Err(incomplete(
            "the forward rotation issued the version it was to replace; nothing was disabled"
                .into(),
            None,
        ));
    }
    if let Err(source) = disable(disabled_version_id.clone()).await {
        return Err(incomplete(source, None));
    }
    let evidence_id = evidence["evidence_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let record = recorder
        .sign_remediation(input(evidence_id, version_id))
        .map_err(|err| incomplete(Box::new(err), None))?;
    let (submission, queued) = if evidence_store.record_outbox().is_some() {
        let delivery = evidence_store
            .enqueue_record(record.clone())
            .await
            .map_err(|err| incomplete(Box::new(err), Some(record.clone())))?;
        (delivery.submission, delivery.queued)
    } else {
        let submission = evidence_store
            .submit_remediation(record.clone())
            .await
            .map_err(|err| incomplete(Box::new(err), Some(record.clone())))?;
        (Some(submission), None)
    };
    Ok(RotateForwardResult {
        rotation,
        record: Some(record),
        submission,
        queued,
    })
}

// ── Urgent changes (1.4.0) ───────────────────────────────────────────────────

/// The emergency capability an urgent change falls back to (1.4.0): a
/// capability of its own, selected by a policy with an `emergency` section.
#[derive(Debug, Clone)]
pub struct EmergencyOptions {
    /// The emergency capability.
    pub capability: String,
    /// Why the change cannot wait: 1 to 1024 characters, no secret values.
    /// Sent as the emergency policy's justification parameter, and recorded
    /// as a break-glass record's justification.
    pub justification: String,
    /// The emergency policy's `justification_parameter`; `None` for
    /// `justification`.
    pub justification_parameter: Option<String>,
    /// The policies the emergency capability's decision must bind
    /// (`verify.expected_policies` for it).
    pub expected_policies: Vec<Value>,
}

/// How an urgent change went (1.4.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrgentPath {
    /// The ordinary capability was allowed: the change ran under it.
    Ordinary,
    /// The ordinary capability was denied, or its evaluation got no answer,
    /// and the emergency capability was decided (the outcome says whether it
    /// was allowed).
    Emergency,
    /// The NA did not answer for the emergency capability either: the change
    /// ran under break-glass naming it.
    BreakGlass,
}

/// What [`urgent_action`] did (1.4.0).
#[derive(Debug)]
#[non_exhaustive]
pub struct UrgentActionResult<T> {
    /// Which path the change took.
    pub path: UrgentPath,
    /// The governed action's outcome on that path.
    pub outcome: GovernedActionOutcome<T>,
    /// The ordinary capability's DENY, when the emergency capability was
    /// requested after it.
    pub ordinary_denial: Option<GovernedActionResult<T>>,
}

/// An urgent change (1.4.0): never blocked, always governed and judged.
///
/// * The ordinary capability (`params`) is evaluated first, as
///   [`governed_action`] does; an ALLOW runs the action under it
///   ([`UrgentPath::Ordinary`]).
/// * On a DENY, or when that evaluation gets no answer (a network error, a
///   timeout, `5xx` or `429`; see [`evaluation_failure`]), the emergency
///   capability is requested with the justification in its justification
///   parameter; the NA decides it under the emergency policy before the
///   change and reviews it after ([`UrgentPath::Emergency`]; the outcome's
///   `authorized` is false when that is a DENY too).
/// * When the NA does not answer for the emergency capability either, the
///   action runs under break-glass naming the emergency capability, with the
///   justification parameter in its request parameters; the NA judges it
///   under the emergency policy once it is back ([`UrgentPath::BreakGlass`]).
///
/// The action gets the decision it runs under, or `None` under break-glass.
/// Everything break-glass needs is checked before anything is evaluated, as
/// [`governed_action_with_break_glass`] checks it: a record outbox, an
/// attestation-based evaluation and `resource_id`. The emergency
/// capability's decision is verified against `emergency.expected_policies`.
pub async fn urgent_action<T, F, Fut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: GovernedActionParams,
    emergency: EmergencyOptions,
    action: F,
) -> Result<UrgentActionResult<T>>
where
    T: Send + 'static,
    F: FnOnce(Option<Value>) -> Fut,
    Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
{
    let parameter = emergency
        .justification_parameter
        .as_deref()
        .unwrap_or("justification");
    let mut urgent = params.clone();
    if !urgent.evaluate.is_object() {
        return Err(GenesisMeshError::Configuration(
            "evaluate must be a JSON object".into(),
        ));
    }
    urgent.evaluate["requested_capability"] = json!(emergency.capability);
    let context = &mut urgent.evaluate["context"];
    if !context.is_object() {
        *context = json!({});
    }
    // Each attempt is a request of its own.
    if let Some(context) = context.as_object_mut() {
        context.remove("context_id");
    }
    let parameters = &mut context["request_parameters"];
    if parameters.is_null() {
        *parameters = json!({});
    }
    if !parameters.is_object() {
        return Err(GenesisMeshError::Configuration(
            "context.request_parameters must be a JSON object".into(),
        ));
    }
    parameters[parameter] = json!(emergency.justification);
    urgent.verify.expected_policies = emergency.expected_policies;
    let break_glass = BreakGlassOptions::new(emergency.justification);
    check_break_glass(evidence_store, recorder, &urgent, &break_glass).await?;

    let (ordinary_denial, action) = match attempt(
        boundary,
        evidence_store,
        recorder,
        params,
        None,
        true,
        action,
    )
    .await?
    {
        Attempt::Done(outcome) => {
            return Ok(UrgentActionResult {
                path: UrgentPath::Ordinary,
                outcome,
                ordinary_denial: None,
            })
        }
        Attempt::Denied(denied, action) => (Some(denied), action),
        Attempt::Unanswered(_, action) => (None, action),
    };
    let outcome = run(
        boundary,
        evidence_store,
        recorder,
        urgent,
        Some(&break_glass),
        action,
    )
    .await?;
    let path = match outcome {
        GovernedActionOutcome::Evaluated(_) => UrgentPath::Emergency,
        GovernedActionOutcome::BrokeGlass(_) => UrgentPath::BreakGlass,
    };
    Ok(UrgentActionResult {
        path,
        outcome,
        ordinary_denial,
    })
}
