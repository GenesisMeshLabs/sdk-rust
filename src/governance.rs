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
    errors::{GenesisMeshError, Result},
    evidence_store::EvidenceStoreClient,
    execution::{ExecutionRecorder, PriorResource, RecordExecution},
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
    /// The NA's acknowledgement of the evidence.
    pub submission: Option<Value>,
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
pub async fn governed_action<T, F, Fut>(
    boundary: &BoundaryClient,
    evidence_store: &EvidenceStoreClient,
    recorder: &ExecutionRecorder,
    params: GovernedActionParams,
    action: F,
) -> Result<GovernedActionResult<T>>
where
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
        });
    }

    let prior = match (&params.resource_id, &params.prior_resource) {
        (None, _) => None,
        (Some(_), Some(prior)) => prior.clone(),
        (Some(resource_id), None) => evidence_store
            .resource_head(resource_id)
            .await?
            .map(PriorResource::Head),
    };
    // Reading the head may outlast the decision's validity window.
    check_decision(&decision, &params, &context_id)?;

    let capability = params.evaluate["requested_capability"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let record_and_submit = |outcome: Option<String>,
                             execution_parameters: Option<Value>,
                             outcome_detail: Option<String>| {
        let evidence = recorder.record(RecordExecution {
            decision: decision.clone(),
            executed_capability: capability.clone(),
            outcome,
            execution_parameters,
            outcome_detail,
            resource_id: params.resource_id.clone(),
            resource_action: params.resource_action.clone(),
            prior_resource: prior.clone(),
            ..RecordExecution::default()
        });
        async move {
            let evidence = evidence?;
            let submission = evidence_store.submit(evidence.clone()).await?;
            Ok::<_, GenesisMeshError>((evidence, submission))
        }
    };

    match action(decision.clone()).await {
        Ok(report) => {
            let (evidence, submission) = record_and_submit(
                report.outcome,
                report.execution_parameters,
                report.outcome_detail,
            )
            .await?;
            Ok(GovernedActionResult {
                evaluation,
                authorized: true,
                summary,
                value: report.value,
                evidence: Some(evidence),
                submission: Some(submission),
            })
        }
        Err(source) => {
            // The error text is not recorded: it may carry secret material.
            match record_and_submit(Some("failure".into()), None, Some("action failed".into()))
                .await
            {
                Ok(_) => Err(GenesisMeshError::ActionFailed { source }),
                Err(evidence_error) => Err(GenesisMeshError::ActionUnrecorded {
                    source,
                    evidence_error: Box::new(evidence_error),
                }),
            }
        }
    }
}
