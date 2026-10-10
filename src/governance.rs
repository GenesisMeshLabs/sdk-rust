//! Controller-side composition for governed resource lifecycles (e.g.
//! secrets): evaluate, act only on a verified ALLOW, and record the outcome on
//! the resource chain. With break-glass (v1.3.0), act when the NA cannot be
//! reached, and record that.

use std::future::Future;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    boundary::BoundaryClient,
    errors::{ActionValue, GenesisMeshError, Result},
    evidence_store::EvidenceStoreClient,
    execution::{check_metadata_only, ExecutionRecorder, PriorResource, RecordExecution},
    out_of_band::{check_justification, refused, BreakGlassInput, EvaluationFailure},
    outbox::{OutboxEntry, RecordOutboxEntry},
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
/// was dropped. Everything is dropped when the rest is still refused (its
/// size).
pub fn without_refused_metadata(
    execution_parameters: &Value,
    outcome_detail: Option<&str>,
) -> RefusedMetadata {
    let empty = serde_json::Map::new();
    let params = execution_parameters.as_object().unwrap_or(&empty);
    let mut kept = serde_json::Map::new();
    let mut dropped = Vec::new();
    for (key, value) in params {
        if check_metadata_only(&json!({ key: value }), None).is_none() {
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
/// operator signatures keep failing, and an evaluation the NA computed
/// (perhaps a DENY) but could not store. Neither breaks the glass.
const NOT_BREAKABLE: [&str; 2] = ["admin_auth_throttled", "evidence_store_unavailable"];

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
/// cannot be judged after the fact: `break_glass_malformed`), and
/// checks the justification (1 to 1024 characters) and the evaluation
/// context against the secret guard
/// ([`GenesisMeshError::OutOfBandRecord`], `break_glass_malformed` or
/// `break_glass_secret_material`). If the action fails under break-glass, a
/// `failure` record is kept and [`GenesisMeshError::ActionFailed`] carries it
/// (`queued_record` while the NA has not admitted it). Reported metadata the
/// guard refuses is left out of the record (`dropped`); a record that cannot
/// be signed or kept returns [`GenesisMeshError::EvidenceNotKept`] with the
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
    // An agreement-based evaluation rests on the agreement, which a
    // break-glass record does not carry: the NA could not judge it after the
    // fact.
    if params
        .evaluate
        .get("attestation_id")
        .is_none_or(Value::is_null)
    {
        return Err(refused(
            "break_glass_malformed",
            "break-glass needs an attestation-based evaluation (attestation_id)",
        ));
    }
    check_justification(&options.justification)?;
    let context = params
        .evaluate
        .get("context")
        .filter(|c| !c.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(secret) = check_metadata_only(&context, None) {
        return Err(refused("break_glass_secret_material", secret));
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
            outcome_detail,
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
        Err(GenesisMeshError::OutOfBandRecord { code, .. })
            if code == "break_glass_secret_material" =>
        {
            let cleaned = without_refused_metadata(
                execution_parameters.as_ref().unwrap_or(&json!({})),
                outcome_detail.as_deref(),
            );
            match sign(
                outcome,
                Some(cleaned.execution_parameters),
                Some(cleaned.outcome_detail),
            ) {
                Ok(record) => (record, cleaned.dropped),
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
    if params.resource_id.is_some() != params.resource_action.is_some() {
        return Err(GenesisMeshError::Configuration(
            "resource_id and resource_action go together".into(),
        ));
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
        check_break_glass(evidence_store, &params, options).await?;
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
            .map(GovernedActionOutcome::BrokeGlass);
        }
    };
    let decision = evaluation["decision"].clone();
    check_decision(&decision, &params, &context_id)?;
    let summary = summarize_decision(&decision);
    if !summary.authorized {
        return Ok(GovernedActionOutcome::Evaluated(GovernedActionResult {
            evaluation,
            authorized: false,
            summary,
            value: None,
            evidence: None,
            submission: None,
            queued: None,
        }));
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
        return Ok(GovernedActionOutcome::Evaluated(GovernedActionResult {
            evaluation,
            authorized: true,
            summary,
            value,
            evidence: Some(evidence),
            submission: Some(submission),
            queued: None,
        }));
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
        Err(GenesisMeshError::SecretMaterial(reason)) => {
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
        Err(err) => return Err(not_kept(err, None, value)),
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
    Ok(GovernedActionOutcome::Evaluated(GovernedActionResult {
        evaluation,
        authorized: true,
        summary,
        value,
        evidence: Some(evidence),
        submission: delivery.submission,
        queued: delivery.queued,
    }))
}
