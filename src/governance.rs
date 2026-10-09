//! Controller-side composition for governed resource lifecycles (e.g.
//! secrets): evaluate, act only on a verified ALLOW, and record the outcome on
//! the resource chain.

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
    outbox::OutboxEntry,
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

    let evaluation = boundary.evaluate(request).await?;
    let decision = evaluation["decision"].clone();
    check_decision(&decision, &params, &context_id)?;
    let summary = summarize_decision(&decision);
    if !summary.authorized {
        return Ok(GovernedActionResult {
            evaluation,
            authorized: false,
            summary,
            value: None,
            evidence: None,
            submission: None,
            queued: None,
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

    let report = match action(decision.clone()).await {
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
        return Ok(GovernedActionResult {
            evaluation,
            authorized: true,
            summary,
            value,
            evidence: Some(evidence),
            submission: Some(submission),
            queued: None,
        });
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
    Ok(GovernedActionResult {
        evaluation,
        authorized: true,
        summary,
        value,
        evidence: Some(evidence),
        submission: delivery.submission,
        queued: delivery.queued,
    })
}
