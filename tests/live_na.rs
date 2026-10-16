//! The governed-action lifecycle against a live Python Network Authority,
//! using only SDK calls. Skipped unless `GM_E2E_PYTHON` names a Python with
//! the Genesis Mesh core installed (a disposable loopback NA is started from
//! `scripts/e2e_na.py`), or `GM_E2E_BASE_URL`, `GM_E2E_OPERATOR_SEED` and
//! `GM_E2E_NA_PUBLIC_KEY` name an existing NA. The changes outside the
//! controlled path (1.3.0) are exercised when the NA records them: the
//! loopback NA says so, and `GM_E2E_OUT_OF_BAND=1` says so of an existing one.
//! Remediation and reviews (1.4.0) are exercised when the loopback NA records
//! them, with a second operator key of another holder deciding reviews.
//! Pre-issued grants (1.6.0) are exercised when the loopback NA issues them
//! (`EVIDENCE_GRANTS=on`).
//!
//! The live test is `#[ignore]`d, so a plain `cargo test` reports it as
//! ignored rather than passed; run it with `--include-ignored`. With
//! `GM_E2E_REQUIRED=1` (set by CI) every skip is a failure: no NA, or an NA
//! that cannot exercise a part, fails the run instead of reporting `ok`.

use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use genesis_mesh_sdk::{
    audit_pack,
    canonical::execution_digest,
    governed_action, governed_action_with_break_glass, json, public_key_from_seed,
    remediation::review_approval_problem,
    rotate_forward_then_disable,
    verify::{
        verify_attestation_signature, verify_boundary_decision, verify_evidence_events,
        verify_justification_signature, verify_policy_signature, VerifyDecisionOptions,
        VerifyEvidenceOptions,
    },
    ActionError, ActionReport, BreakGlassOptions, ClientOptions, EvaluationFailure, EvidenceOutbox,
    ExecutionRecorder, FlushOptions, GenesisMeshClient, GenesisMeshError, GovernedActionOutcome,
    GovernedActionParams, GovernedVerification, GrantActionOutcome, GrantAuthority, GrantFallback,
    GrantHolder, GrantRequest, HttpTransport, MemoryOutbox, MemoryRecordOutbox, ObservationInput,
    ObservationRecorder, OutboxState, RecordExecution, RecordOutbox, RemediationSubject,
    ReviewDecision, RotateForwardParams, RotatedVersion, Value,
};
use uuid::Uuid;

struct LiveNa {
    client: GenesisMeshClient,
    options: ClientOptions,
    na_public_key: String,
    /// The NA records changes outside the controlled path (1.3.0).
    out_of_band: bool,
    /// With remediation and reviews (1.4.0): a privileged key of another
    /// holder, which decides reviews.
    reviewer: Option<GenesisMeshClient>,
    /// The NA issues pre-issued grants (1.6.0).
    grants: bool,
    child: Option<Child>,
}

impl Drop for LiveNa {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A part of the run that cannot happen here: reported on stderr, or a
/// failure when `GM_E2E_REQUIRED=1` says every part must run (CI), so a lost
/// NA or a missing feature can never pass as `ok`.
fn skip(reason: &str) {
    if std::env::var("GM_E2E_REQUIRED").is_ok_and(|v| v == "1") {
        panic!("GM_E2E_REQUIRED=1, but this part cannot run: {reason}");
    }
    eprintln!("skipped: {reason}");
}

fn live_na() -> Option<LiveNa> {
    let (config, child) = if let Ok(base_url) = std::env::var("GM_E2E_BASE_URL") {
        let config = json!({
            "baseUrl": base_url,
            "signingKeyBase64": std::env::var("GM_E2E_OPERATOR_SEED").expect("GM_E2E_OPERATOR_SEED"),
            "keyId": std::env::var("GM_E2E_OPERATOR_KEY_ID").unwrap_or_else(|_| "ops".into()),
            "naPublicKey": std::env::var("GM_E2E_NA_PUBLIC_KEY").expect("GM_E2E_NA_PUBLIC_KEY"),
            "outOfBand": std::env::var("GM_E2E_OUT_OF_BAND").is_ok_and(|v| v == "1"),
        });
        (config, None)
    } else {
        let python = std::env::var("GM_E2E_PYTHON").ok()?;
        let mut child = Command::new(python)
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/e2e_na.py"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the loopback NA");
        let stdout = child.stdout.take().unwrap();
        let line = BufReader::new(stdout)
            .lines()
            .map(Result::unwrap)
            .find(|line| line.starts_with('{'))
            .expect("NA printed its configuration");
        (serde_json::from_str::<Value>(&line).unwrap(), Some(child))
    };
    let options = ClientOptions::new(config["baseUrl"].as_str().unwrap())
        .with_signing_key(config["signingKeyBase64"].as_str().unwrap())
        .with_key_id(config["keyId"].as_str().unwrap());
    let client = GenesisMeshClient::new(options.clone()).unwrap();
    let reviewer = config["remediation"].as_bool().unwrap_or(false).then(|| {
        let options = ClientOptions::new(config["baseUrl"].as_str().unwrap())
            .with_signing_key(config["reviewerSigningKeyBase64"].as_str().unwrap())
            .with_key_id(config["reviewerKeyId"].as_str().unwrap());
        GenesisMeshClient::new(options).unwrap()
    });
    Some(LiveNa {
        client,
        options,
        na_public_key: config["naPublicKey"].as_str().unwrap().to_owned(),
        out_of_band: config["outOfBand"].as_bool().unwrap_or(false),
        reviewer,
        grants: config["grants"].as_bool().unwrap_or(false),
        child,
    })
}

fn executor(id: &str) -> (ExecutionRecorder, String) {
    let seed = STANDARD.encode(Uuid::new_v4().as_bytes().repeat(2));
    (
        ExecutionRecorder::new(id, id, &seed).unwrap(),
        public_key_from_seed(&seed).unwrap(),
    )
}

fn window() -> (String, String) {
    let now = Utc::now();
    (
        (now - Duration::minutes(1)).to_rfc3339(),
        (now + Duration::hours(1)).to_rfc3339(),
    )
}

#[tokio::test]
#[ignore = "needs a live NA (GM_E2E_PYTHON or GM_E2E_BASE_URL); run with --include-ignored"]
async fn governed_lifecycle_against_a_live_na() {
    let Some(na) = live_na() else {
        skip("no NA: set GM_E2E_PYTHON or GM_E2E_BASE_URL");
        return;
    };
    admit_decide_record_audit_and_offboard(&na).await;
    observe_enforce_rollback_failures_conflicts_and_retired_keys(&na).await;
    keep_evidence_while_the_na_is_unreachable_and_admit_it_in_order(&na).await;
    record_and_judge_changes_outside_the_controlled_path(&na).await;
    remediate_review_and_verify_offline(&na).await;
    act_within_grants_offline_and_upload_on_reconnect(&na).await;
}

/// Skipped is not green: the live test run with `GM_E2E_REQUIRED=1` and no
/// NA fails rather than reporting `ok`.
#[test]
fn a_required_live_run_without_an_na_fails() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--include-ignored",
            "--exact",
            "governed_lifecycle_against_a_live_na",
        ])
        .env("GM_E2E_REQUIRED", "1")
        .env_remove("GM_E2E_PYTHON")
        .env_remove("GM_E2E_BASE_URL")
        .output()
        .unwrap();
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{out}");
    assert!(out.contains("1 failed"), "{out}");
    assert!(out.contains("GM_E2E_REQUIRED=1, but"), "{out}");
}

/// v1.4.0: a denied change cancelled by a forward rotation and a disable,
/// recorded as two linked records; a second denied change reviewed by
/// another holder and waived; the export verifies offline, the review's
/// approvals with it.
async fn remediate_review_and_verify_offline(na: &LiveNa) {
    let Some(reviewer) = &na.reviewer else {
        skip("1.4.0: the NA does not record remediations and reviews");
        return;
    };
    let gm = &na.client;
    let keys = vec![na.na_public_key.clone()];
    let id = Uuid::new_v4().to_string();
    let capability = format!("sdk.rem.{id}");
    let emergency = format!("sdk.rem.{id}.emergency");
    let resource = format!("kv:rem-{id}/secret");
    let attestation = gm
        .attestation
        .issue(json!({"subject_id": id, "roles": ["role:client"],
                      "claims": {"capabilities": [capability, emergency]}}))
        .await
        .unwrap();
    let (valid_from, valid_until) = window();
    let policy = gm
        .policy
        .publish(json!({
            "policy_id": format!("rem-{id}"), "valid_from": valid_from, "valid_until": valid_until,
            "selector": {"capabilities": [capability]},
            "gates": [{"gate_id": "lifetime", "gate_type": "max_value.v1", "order": 0,
                       "config": {"path": "request_parameters.lifetime_days", "max": 90}}],
            "remediation": {"lifetime": {"mode": "cancel", "grace_seconds": 3600}},
        }))
        .await
        .unwrap();
    gm.policy
        .activate(
            policy["policy_id"].as_str().unwrap(),
            policy["version"].as_u64().unwrap(),
        )
        .await
        .unwrap();
    let observer_id = format!("observer-{id}");
    let observer_seed = STANDARD.encode(Uuid::new_v4().as_bytes().repeat(2));
    gm.evidence_store
        .register_executor_key(json!({
            "key_id": observer_id, "public_key": public_key_from_seed(&observer_seed).unwrap(),
            "executor_sovereign_id": observer_id, "role": "observer",
            "resource_prefix": format!("kv:rem-{id}/"),
        }))
        .await
        .unwrap();
    let (recorder, executor_key) = executor(&format!("executor-{id}"));
    gm.evidence_store
        .register_executor_key(
            json!({"key_id": recorder.key_id(), "public_key": executor_key,
                                      "executor_sovereign_id": recorder.executor_sovereign_id()}),
        )
        .await
        .unwrap();
    let observer = ObservationRecorder::new(&observer_id, &observer_id, &observer_seed).unwrap();
    let denied_change = |event: &str, version: &str| {
        observer
            .record(ObservationInput {
                resource_id: resource.clone(),
                action: "rotate".into(),
                capability: capability.clone(),
                changed_at: Some(Utc::now()),
                source: "cloud-activity-log".into(),
                source_event_id: format!("{id}-{event}"),
                actor: Some("principal-7f3a".into()),
                version_id: Some(version.into()),
                metadata: Some(json!({"lifetime_days": 400})),
                ..ObservationInput::default()
            })
            .unwrap()
    };

    // 1. A denied rotation arms a cancel: rotate forward, then disable.
    let denied = gm
        .evidence_store
        .submit_observation(denied_change("1", "v8"))
        .await
        .unwrap();
    let judgement_id = denied["judgement"]["payload"]["judgement_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let due = gm
        .evidence_store
        .remediations_all(Some("remediation_due"), 100)
        .await
        .unwrap();
    let state = due
        .iter()
        .find(|s| s["subject_id"] == judgement_id.as_str())
        .expect("the denied change is in the due queue");
    assert_eq!(
        (&state["mode"], &state["steps"]),
        (&json!("cancel"), &json!("rotate_forward_then_disable"))
    );
    let notified = gm
        .evidence_store
        .mark_notified(&judgement_id, Some("email"))
        .await
        .unwrap();
    assert!(notified["notified_at"].is_string());
    let records: Arc<dyn RecordOutbox> = Arc::new(MemoryRecordOutbox::default());
    let controller =
        GenesisMeshClient::new(na.options.clone().with_record_outbox(records)).unwrap();
    let result = rotate_forward_then_disable(
        &controller.boundary,
        &controller.evidence_store,
        &recorder,
        RotateForwardParams {
            governed: GovernedActionParams {
                evaluate: json!({"attestation_id": attestation["attestation_id"],
                                 "requested_capability": capability,
                                 "context": {"request_parameters": {"lifetime_days": 30}}}),
                resource_id: Some(resource.clone()),
                resource_action: None,
                prior_resource: None,
                verify: GovernedVerification {
                    operator_public_keys: keys.clone(),
                    expected_policies: vec![policy.clone()],
                    expected_attestation: Some(attestation.clone()),
                    ..GovernedVerification::default()
                },
            },
            subject: RemediationSubject::from_state(state).unwrap(),
            state: Some(state.clone()),
            disabled_version_id: "v8".into(),
            detail: None,
        },
        |_| async { Ok::<_, ActionError>(RotatedVersion::<()>::new("v9")) },
        |_| async { Ok::<_, ActionError>(()) },
    )
    .await
    .unwrap();
    let submission = result.submission.expect("the remediation was admitted");
    assert_eq!(submission["status"], "recorded");
    assert_eq!(submission["remediation"]["state"], "remediated");

    // 2. Another denied change, reviewed by a second holder and waived.
    let second = gm
        .evidence_store
        .submit_observation(denied_change("2", "v10"))
        .await
        .unwrap();
    let second_id = second["judgement"]["payload"]["judgement_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let opened = gm
        .evidence_store
        .request_review("judgement", &second_id, "Planned with the vendor")
        .await
        .unwrap();
    // A pending review is a flag beside the state: the remediation stays due.
    assert_eq!(opened["state"], "remediation_due");
    assert_eq!(opened["review_pending"], true);
    let review_id = opened["review_id"].as_str().unwrap().to_owned();
    let refused = gm
        .evidence_store
        .decide_review(&review_id, &ReviewDecision::Deny { note: None })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "review_same_holder_as_requester");
    let decided = reviewer
        .evidence_store
        .decide_review(
            &review_id,
            &ReviewDecision::WaiveUntil {
                until: Utc::now() + Duration::days(1),
                note: Some("rotated by the vendor on Friday".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(decided["state"], "waived");
    let review = gm.evidence_store.review(&review_id).await.unwrap();
    assert_eq!(
        review_approval_problem(&review["record"]["payload"], &keys),
        None
    );
    let held = gm.evidence_store.remediation(&second_id).await.unwrap();
    assert_eq!(held["state"], "waived");

    // 3. Urgent changes. With the NA up, an ordinary DENY; the emergency
    // capability, with its justification, is decided under its own policy
    // and its decision is reviewed. With the NA down, break-glass names the
    // emergency capability and is judged under the same policy.
    let urgent_policy = gm
        .policy
        .publish(json!({
            "policy_id": format!("rem-{id}-emergency"), "valid_from": valid_from,
            "valid_until": valid_until, "selector": {"capabilities": [emergency]},
            "gates": [
                {"gate_id": "justified", "gate_type": "required_parameter.v1", "order": 0,
                 "config": {"path": "request_parameters.justification"}},
                {"gate_id": "short-lived", "gate_type": "max_value.v1", "order": 1,
                 "config": {"path": "request_parameters.lifetime_days", "max": 1}}],
            "emergency": {"stands_for": capability, "justification_parameter": "justification",
                          "max_lifetime_seconds": 86400},
        }))
        .await
        .unwrap();
    gm.policy
        .activate(
            urgent_policy["policy_id"].as_str().unwrap(),
            urgent_policy["version"].as_u64().unwrap(),
        )
        .await
        .unwrap();
    let urgent = |capability: &str, lifetime: u32, expected: &Value| GovernedActionParams {
        evaluate: json!({"attestation_id": attestation["attestation_id"],
                         "requested_capability": capability,
                         "context": {"request_parameters": {
                             "lifetime_days": lifetime,
                             "justification": "key leaked in a public repository"}}}),
        resource_id: Some(resource.clone()),
        resource_action: Some("rotate".into()),
        prior_resource: None,
        verify: GovernedVerification {
            operator_public_keys: keys.clone(),
            expected_policies: vec![expected.clone()],
            expected_attestation: Some(attestation.clone()),
            ..GovernedVerification::default()
        },
    };
    let rotate_to_v11 = |_| async {
        Ok::<_, ActionError>(ActionReport {
            value: Some(()),
            execution_parameters: Some(json!({"version_id": "v11"})),
            ..ActionReport::default()
        })
    };
    let ordinary = governed_action(
        &controller.boundary,
        &controller.evidence_store,
        &recorder,
        urgent(&capability, 400, &policy),
        |_| async { panic!("ran under an ordinary DENY") },
    )
    .await
    .map(|r: genesis_mesh_sdk::GovernedActionResult<()>| r.authorized)
    .unwrap();
    assert!(!ordinary);
    let decided = governed_action(
        &controller.boundary,
        &controller.evidence_store,
        &recorder,
        urgent(&emergency, 1, &urgent_policy),
        rotate_to_v11,
    )
    .await
    .unwrap();
    assert!(decided.authorized);
    let decision_id = decided.summary.decision_id.clone();
    let reviewed = gm.evidence_store.remediation(&decision_id).await.unwrap();
    assert_eq!(reviewed["state"], "recorded");
    assert_eq!(reviewed["review_pending"], true);
    assert_eq!(reviewed["review"]["opened_for"], "review_required");
    assert!(reviewed["lifetime_ends_at"].is_string());
    let unreachable = GenesisMeshClient::new(ClientOptions {
        base_url: "http://127.0.0.1:9".into(),
        ..na.options.clone()
    })
    .unwrap();
    let outcome = governed_action_with_break_glass(
        &unreachable.boundary,
        &controller.evidence_store,
        &recorder,
        urgent(&emergency, 1, &urgent_policy),
        BreakGlassOptions::new("key leaked in a public repository; NA unreachable"),
        |decision| async move {
            assert!(decision.is_none());
            Ok::<_, ActionError>(ActionReport {
                value: Some(()),
                execution_parameters: Some(json!({"version_id": "v12"})),
                ..ActionReport::default()
            })
        },
    )
    .await
    .unwrap();
    let GovernedActionOutcome::BrokeGlass(glass) = outcome else {
        panic!("the glass was not broken");
    };
    let judged = glass
        .submission
        .expect("the break-glass record was admitted");
    assert_eq!(judged["judgement"]["payload"]["verdict"], "allow");
    assert_eq!(
        judged["judgement"]["payload"]["policy_binding"]["policies"][0]["policy_id"],
        urgent_policy["policy_id"]
    );
    let judgement = judged["judgement"]["payload"]["judgement_id"]
        .as_str()
        .unwrap();
    let held = gm.evidence_store.remediation(judgement).await.unwrap();
    assert_eq!(held["state"], "judged_allowed");
    assert_eq!(held["review_pending"], true);

    // 4. The export verifies offline, remediation and review included.
    let exported = gm.evidence_store.export_all(0, 1000).await.unwrap();
    let executor_keys = gm.evidence_store.list_executor_keys().await.unwrap();
    let verification =
        verify_evidence_events(&exported, &VerifyEvidenceOptions::new(keys, executor_keys));
    assert!(verification.failures.is_empty(), "{verification:?}");
    assert!(verification.remediations >= 1);
    assert!(verification.reviews >= 1);
}

/// v1.3.0: observations and a break-glass record, judged by the NA, and an
/// export that verifies offline.
async fn record_and_judge_changes_outside_the_controlled_path(na: &LiveNa) {
    if !na.out_of_band {
        skip("1.3.0: the NA does not record changes outside the controlled path");
        return;
    }
    let gm = &na.client;
    let keys = vec![na.na_public_key.clone()];
    let id = Uuid::new_v4().to_string();
    let capability = format!("sdk.oob.{id}");
    let resource = format!("kv:oob-{id}/secret");
    let attestation = gm
        .attestation
        .issue(json!({"subject_id": id, "roles": ["role:client"], "claims": {"capabilities": [capability]}}))
        .await
        .unwrap();
    let (valid_from, valid_until) = window();
    let policy = gm
        .policy
        .publish(json!({
            "policy_id": format!("oob-{id}"), "valid_from": valid_from, "valid_until": valid_until,
            "selector": {"capabilities": [capability]},
            "gates": [{"gate_id": "lifetime", "gate_type": "max_value.v1", "order": 0,
                       "config": {"path": "request_parameters.lifetime_days", "max": 90}}],
        }))
        .await
        .unwrap();
    gm.policy
        .activate(
            policy["policy_id"].as_str().unwrap(),
            policy["version"].as_u64().unwrap(),
        )
        .await
        .unwrap();

    let observer_id = format!("observer-{id}");
    let observer_seed = STANDARD.encode(Uuid::new_v4().as_bytes().repeat(2));
    gm.evidence_store
        .register_executor_key(json!({
            "key_id": observer_id, "public_key": public_key_from_seed(&observer_seed).unwrap(),
            "executor_sovereign_id": observer_id, "role": "observer",
            "resource_prefix": format!("kv:oob-{id}/"),
        }))
        .await
        .unwrap();
    let observer = ObservationRecorder::new(&observer_id, &observer_id, &observer_seed).unwrap();
    let observe = |lifetime: u32, event: String| {
        observer
            .record(ObservationInput {
                resource_id: resource.clone(),
                action: "rotate".into(),
                capability: capability.clone(),
                changed_at: Some(Utc::now()),
                source: "cloud-activity-log".into(),
                source_event_id: event,
                actor: Some("principal-7f3a".into()),
                metadata: Some(json!({"lifetime_days": lifetime})),
                ..ObservationInput::default()
            })
            .unwrap()
    };
    let denied = gm
        .evidence_store
        .submit_observation(observe(400, format!("{id}-1")))
        .await
        .unwrap();
    assert_eq!(denied["status"], "recorded");
    assert_eq!(denied["judgement"]["payload"]["verdict"], "deny");
    assert_eq!(
        denied["judgement"]["payload"]["governed_by"],
        "after_the_fact"
    );
    let allowed = gm
        .evidence_store
        .submit_observations(&[observe(30, format!("{id}-2"))])
        .await
        .unwrap();
    assert_eq!(allowed[0]["status"], "recorded");
    assert_eq!(allowed[0]["judgement"]["payload"]["verdict"], "allow");
    let again = gm
        .evidence_store
        .judge_observation(denied["payload"]["observation_id"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(again["status"], "existing");

    // Break-glass: the NA cannot be reached for the evaluation; the action
    // runs and its record is admitted and judged.
    let (recorder, executor_key) = executor(&format!("executor-{id}"));
    gm.evidence_store
        .register_executor_key(
            json!({"key_id": recorder.key_id(), "public_key": executor_key,
                                      "executor_sovereign_id": recorder.executor_sovereign_id()}),
        )
        .await
        .unwrap();
    let records: Arc<dyn RecordOutbox> = Arc::new(MemoryRecordOutbox::default());
    let live = GenesisMeshClient::new(na.options.clone().with_record_outbox(records)).unwrap();
    // Nothing listens on the discard port.
    let unreachable = GenesisMeshClient::new(ClientOptions {
        base_url: "http://127.0.0.1:9".into(),
        ..na.options.clone()
    })
    .unwrap();
    let outcome = governed_action_with_break_glass(
        &unreachable.boundary,
        &live.evidence_store,
        &recorder,
        GovernedActionParams {
            evaluate: json!({"attestation_id": attestation["attestation_id"], "requested_capability": capability,
                             "context": {"request_parameters": {"lifetime_days": 30}}}),
            resource_id: Some(resource.clone()),
            resource_action: Some("rotate".into()),
            prior_resource: None,
            verify: GovernedVerification {
                operator_public_keys: keys.clone(),
                expected_policies: vec![policy],
                expected_attestation: Some(attestation),
                ..GovernedVerification::default()
            },
        },
        BreakGlassOptions::new("incident drill: NA unreachable"),
        |decision| async move {
            Ok::<_, ActionError>(ActionReport {
                value: Some(decision.is_none()),
                execution_parameters: Some(json!({"version_id": "v2"})),
                ..ActionReport::default()
            })
        },
    )
    .await
    .unwrap();
    let GovernedActionOutcome::BrokeGlass(result) = outcome else {
        panic!("the glass was not broken");
    };
    assert_eq!(result.failure, EvaluationFailure::NetworkError);
    assert_eq!(result.value, Some(true));
    let submission = result.submission.unwrap();
    assert_eq!(submission["status"], "recorded");
    assert_eq!(submission["judgement"]["payload"]["verdict"], "allow");

    let changes = gm.evidence_store.resource_changes(&resource).await.unwrap();
    let states: Vec<(&str, &str)> = changes["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["kind"].as_str().unwrap(), c["state"].as_str().unwrap()))
        .collect();
    // With remediation on (1.4.0), the denial is due for remediation, and the
    // break-glass record, flagged for review, stays allowed with a review
    // pending: a flag beside its state.
    let denied_state = if na.reviewer.is_some() {
        "remediation_due"
    } else {
        "judged_denied"
    };
    let glass_state = "judged_allowed";
    if na.reviewer.is_some() {
        assert_eq!(changes["changes"][2]["remediation"]["review_pending"], true);
    }
    assert_eq!(
        states,
        [
            ("observation", denied_state),
            ("observation", "judged_allowed"),
            ("break_glass", glass_state)
        ]
    );
    assert_eq!(
        changes["changes"][2]["justification"],
        "incident drill: NA unreachable"
    );
    let operator = na.options.key_id.clone().unwrap_or_else(|| "ops".into());
    assert!(gm
        .evidence_store
        .operator_holders()
        .await
        .unwrap()
        .iter()
        .any(|h| h["key_id"] == operator.as_str()));

    let exported = gm.evidence_store.export_all(0, 1000).await.unwrap();
    let executor_keys = gm.evidence_store.list_executor_keys().await.unwrap();
    let verification =
        verify_evidence_events(&exported, &VerifyEvidenceOptions::new(keys, executor_keys));
    assert!(verification.failures.is_empty(), "{verification:?}");
    assert!(verification.observations >= 2);
    assert!(verification.break_glass >= 1);
    assert!(verification.judgements >= 3);
}

/// v1.2.0: evidence that cannot be submitted stays in the outbox, a second
/// change chains from it, and a flush admits both in order.
async fn keep_evidence_while_the_na_is_unreachable_and_admit_it_in_order(na: &LiveNa) {
    let gm = &na.client;
    let id = Uuid::new_v4().to_string();
    let attestation = gm
        .attestation
        .issue(json!({"subject_id": id, "roles": ["role:client"], "claims": {"capabilities": ["sdk.outbox"]}}))
        .await
        .unwrap();
    let (recorder, executor_key) = executor(&id);
    gm.evidence_store
        .register_executor_key(
            json!({"key_id": id, "public_key": executor_key, "executor_sovereign_id": id}),
        )
        .await
        .unwrap();
    let outbox: Arc<dyn EvidenceOutbox> = Arc::new(MemoryOutbox::default());
    let live = GenesisMeshClient::new(na.options.clone().with_outbox(Arc::clone(&outbox))).unwrap();
    // Nothing listens on the discard port: every submission fails to connect.
    let unreachable = GenesisMeshClient::new(
        ClientOptions::new("http://127.0.0.1:9").with_outbox(Arc::clone(&outbox)),
    )
    .unwrap();
    let resource = format!("sdk:{id}");
    let params = |prior| GovernedActionParams {
        evaluate: json!({"attestation_id": attestation["attestation_id"], "requested_capability": "sdk.outbox"}),
        resource_id: Some(resource.clone()),
        resource_action: Some("rotate".into()),
        prior_resource: prior,
        verify: GovernedVerification {
            operator_public_keys: vec![na.na_public_key.clone()],
            expected_attestation: Some(attestation.clone()),
            ..GovernedVerification::default()
        },
    };
    let mut evidence = Vec::new();
    for (prior, version) in [(Some(None), "v1"), (None, "v2")] {
        let result = governed_action(
            &live.boundary,
            &unreachable.evidence_store,
            &recorder,
            params(prior),
            |_| async move {
                Ok::<_, ActionError>(ActionReport {
                    value: Some(version),
                    execution_parameters: Some(json!({"secret_version": version})),
                    ..ActionReport::default()
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(result.value, Some(version));
        assert_eq!(result.queued.unwrap().state, OutboxState::Pending);
        evidence.push(result.evidence.unwrap());
    }
    assert_eq!(
        evidence[1]["prev_resource_digest"],
        execution_digest(&evidence[0]).unwrap()
    );

    let flushed = live
        .evidence_store
        .flush_pending(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    let admitted: Vec<Value> = flushed.admitted.into_iter().map(|e| e.evidence).collect();
    assert_eq!(admitted, evidence);
    assert!(outbox.list().await.unwrap().is_empty());
    let history = gm.evidence_store.resource_history(&resource).await.unwrap();
    assert_eq!(history["verification"]["verified"], true);

    // A guard refusal after the action: recorded without the refused field.
    let mut err = governed_action(
        &live.boundary,
        &live.evidence_store,
        &recorder,
        params(None),
        |_| async {
            Ok::<_, ActionError>(ActionReport {
                value: Some(3_u8),
                execution_parameters: Some(
                    json!({"secret_version": "v3", "client_secret": "not-for-evidence"}),
                ),
                ..ActionReport::default()
            })
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.take_action_value::<u8>(), Some(3));
    let GenesisMeshError::MetadataRefused {
        evidence,
        submission,
        ..
    } = err
    else {
        panic!("unexpected error");
    };
    assert_eq!(submission.unwrap()["status"], "recorded");
    assert_eq!(
        evidence["execution_parameters"],
        json!({"secret_version": "v3"})
    );
}

async fn admit_decide_record_audit_and_offboard(na: &LiveNa) {
    let gm = &na.client;
    let keys = vec![na.na_public_key.clone()];
    let id = Uuid::new_v4().to_string();
    let vendor = format!("rust-zoë-{id}");
    let resource = format!("kv:rust-{id}/zoë");
    let (recorder, executor_key) = executor(&format!("executor-{id}"));

    assert_eq!(gm.health.readiness().await.unwrap()["ready"], true);
    let attestation = gm
        .attestation
        .issue(json!({
            "subject_id": vendor, "roles": ["role:client"],
            "claims": {"capabilities": ["sp-secret.create", "sp-secret.rotate", "sp-secret.revoke"],
                       "apps": [format!("app-{id}")], "note": "Zoë 😀", "\u{E000}": 1, "😀": 2},
        }))
        .await
        .unwrap();
    assert!(verify_attestation_signature(&attestation, &keys));
    gm.attestation
        .save_policy(json!({"recognition_policy": {
            "local_sovereign_id": attestation["issuer_sovereign_id"],
            "recognized_issuers": [{"sovereign_id": attestation["issuer_sovereign_id"], "public_keys": keys,
                                    "allowed_roles": ["role:client"], "accepted_statuses": ["active"]}],
            "revoked_attestation_ids": [],
        }}))
        .await
        .unwrap();

    let (valid_from, valid_until) = window();
    let intent = json!({
        "policy_id": format!("rust-policy-{id}"), "description": "Rust policy Zoë 😀",
        "valid_from": valid_from, "valid_until": valid_until,
        "selector": {"parent_kinds": ["attestation"], "requester_sovereign_ids": [vendor], "capabilities": ["sp-secret.*"]},
        "gates": [
            {"gate_id": "app", "gate_type": "attestation_claim.v1", "order": 0, "config": {"path": "request_parameters.app_id", "claim": "apps"}},
            {"gate_id": "owner", "gate_type": "required_parameter.v1", "order": 1, "mode": "observe", "config": {"path": "attributes.owner"}},
            {"gate_id": "lifetime", "gate_type": "max_value.v1", "order": 2, "config": {"path": "request_parameters.lifetime_days", "max": 90}},
        ],
    });
    assert_eq!(
        gm.policy.validate(intent.clone()).await.unwrap()["valid"],
        true
    );
    let policy = gm.policy.publish(intent).await.unwrap();
    let policy_id = policy["policy_id"].as_str().unwrap();
    let version = policy["version"].as_u64().unwrap();
    assert!(verify_policy_signature(&policy, &keys));
    assert_eq!(
        gm.policy.verify(json!({"policy": policy})).await.unwrap()["valid"],
        true
    );
    assert_eq!(
        gm.policy.activate(policy_id, version).await.unwrap()["active"],
        true
    );
    assert!(gm.policy.active().await.unwrap()["active"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["policy_id"] == policy_id));
    assert!(gm
        .policy
        .list()
        .await
        .unwrap()
        .iter()
        .any(|p| p["policy_id"] == policy_id));
    gm.evidence_store
        .register_executor_key(
            json!({"key_id": recorder.key_id(), "public_key": executor_key,
                                      "executor_sovereign_id": recorder.executor_sovereign_id()}),
        )
        .await
        .unwrap();

    let verify = GovernedVerification {
        operator_public_keys: keys.clone(),
        expected_policies: vec![policy.clone()],
        expected_attestation: Some(attestation.clone()),
        ..GovernedVerification::default()
    };
    let context = json!({"request_parameters": {"app_id": format!("app-{id}"), "lifetime_days": 30},
                         "attributes": {"secret_store": "test-store"}});
    let mut last = None;
    for (sequence, action) in ["create", "rotate", "revoke"].into_iter().enumerate() {
        let sequence = sequence as u64 + 1;
        let result = governed_action(
            &gm.boundary,
            &gm.evidence_store,
            &recorder,
            GovernedActionParams {
                evaluate: json!({"attestation_id": attestation["attestation_id"],
                                 "requested_capability": format!("sp-secret.{action}"), "context": context}),
                resource_id: Some(resource.clone()),
                resource_action: Some(action.into()),
                prior_resource: None,
                verify: verify.clone(),
            },
            |_decision| async move {
                Ok::<_, ActionError>(ActionReport::<()> {
                    execution_parameters: Some(json!({"secret_version": format!("v{sequence}"), "owner": "Zoë"})),
                    ..ActionReport::default()
                })
            },
        )
        .await
        .unwrap();
        assert!(result.authorized);
        let evidence = result.evidence.unwrap();
        assert_eq!(evidence["resource_sequence"], sequence);
        assert_eq!(result.submission.unwrap()["status"], "recorded");
        assert_eq!(result.summary.observed_failures.len(), 1);
        assert!(verify_justification_signature(
            &result.evaluation["justification_proof"],
            &keys
        ));
        assert_eq!(
            gm.evidence_store.submit(evidence.clone()).await.unwrap()["status"],
            "duplicate"
        );
        last = Some(evidence);
    }
    let head = gm
        .evidence_store
        .resource_head(&resource)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.resource_sequence, 3);
    assert_eq!(
        head.record_digest,
        execution_digest(last.as_ref().unwrap()).unwrap()
    );
    assert_eq!(
        gm.evidence_store
            .resource_head(&format!("kv:rust-{id}/none"))
            .await
            .unwrap(),
        None
    );

    for request_parameters in [
        json!({"app_id": "wrong", "lifetime_days": 30}),
        json!({"app_id": format!("app-{id}"), "lifetime_days": 91}),
    ] {
        let result = governed_action(
            &gm.boundary,
            &gm.evidence_store,
            &recorder,
            GovernedActionParams {
                evaluate: json!({"attestation_id": attestation["attestation_id"], "requested_capability": "sp-secret.create",
                                 "context": {"request_parameters": request_parameters}}),
                verify: verify.clone(),
                ..GovernedActionParams::default()
            },
            |_| async { panic!("a denied action must not run") as Result<ActionReport<()>, ActionError> },
        )
        .await
        .unwrap();
        assert!(!result.authorized);
    }

    assert_eq!(
        gm.evidence_store.resource_history(&resource).await.unwrap()["verification"]["verified"],
        true
    );
    let vendor_history = gm.evidence_store.vendor_history(&vendor).await.unwrap();
    assert_eq!(vendor_history["verification"]["verified"], true);
    let executor_keys = gm.evidence_store.list_executor_keys().await.unwrap();
    let filtered = VerifyEvidenceOptions {
        contiguous: false,
        ..VerifyEvidenceOptions::new(keys.clone(), executor_keys.clone())
    };
    assert!(
        verify_evidence_events(vendor_history["entries"].as_array().unwrap(), &filtered).verified
    );

    gm.attestation
        .revoke(
            attestation["attestation_id"].as_str().unwrap(),
            Some(json!({"reason": "Rust SDK test complete"})),
        )
        .await
        .unwrap();
    let revoked = gm
        .boundary
        .evaluate(json!({"attestation_id": attestation["attestation_id"], "requested_capability": "sp-secret.create", "context": context}))
        .await
        .unwrap();
    let check = verify_boundary_decision(
        &revoked["decision"],
        &VerifyDecisionOptions {
            operator_public_keys: keys.clone(),
            expected_policies: Some(vec![policy.clone()]),
            expected_attestation: Some(attestation.clone()),
            ..VerifyDecisionOptions::default()
        },
    );
    assert!(check.accepted && !check.authorized, "{check:?}");
    let refused = recorder
        .record(RecordExecution {
            decision: revoked["decision"].clone(),
            executed_capability: "sp-secret.create".into(),
            ..RecordExecution::default()
        })
        .unwrap();
    let err = gm.evidence_store.submit(refused).await.unwrap_err();
    assert_eq!(err.code(), "evidence_decision_denied");

    assert_eq!(gm.evidence_store.verify().await.unwrap()["verified"], true);
    assert_eq!(
        gm.evidence_store.status().await.unwrap()["evidence_store"],
        "on"
    );
    let exported = gm.evidence_store.export_all(0, 5).await.unwrap();
    let full = VerifyEvidenceOptions::new(keys.clone(), executor_keys);
    let offline = verify_evidence_events(&exported, &full);
    assert!(offline.verified, "{offline:?}");
    assert_eq!(
        gm.evidence_store
            .export(json!({"limit": 1}))
            .await
            .unwrap()
            .len(),
        1
    );
    let searched = gm
        .evidence_store
        .search_all(json!({"vendor_id": vendor, "limit": 2}))
        .await
        .unwrap();
    assert!(searched.len() > 3);
    assert_eq!(
        gm.evidence_store.apply_retention(365).await.unwrap()["removed_count"],
        0
    );
    assert_eq!(gm.evidence_store.latest_checkpoint().await.unwrap(), None);
    assert_eq!(
        gm.evidence_store
            .retire_executor_key(recorder.key_id())
            .await
            .unwrap()["active"],
        false
    );
}

async fn observe_enforce_rollback_failures_conflicts_and_retired_keys(na: &LiveNa) {
    let gm = &na.client;
    let keys = vec![na.na_public_key.clone()];
    let id = Uuid::new_v4().to_string();
    let attestation = gm
        .attestation
        .issue(json!({"subject_id": id, "roles": ["role:client"], "claims": {"capabilities": ["sdk.run"]}}))
        .await
        .unwrap();
    let (valid_from, valid_until) = window();
    let gate = json!({"gate_id": "owner", "gate_type": "required_parameter.v1", "mode": "observe", "order": 0,
                      "config": {"path": "attributes.owner"}});
    let mut intent = json!({"policy_id": id, "valid_from": valid_from, "valid_until": valid_until,
                            "selector": {"requester_sovereign_ids": [id]}, "gates": [gate]});
    let first = gm.policy.publish(intent.clone()).await.unwrap();
    let first_version = first["version"].as_u64().unwrap();
    gm.policy.activate(&id, first_version).await.unwrap();
    intent["gates"][0]["mode"] = json!("enforce");
    let second = gm.policy.publish(intent).await.unwrap();
    gm.policy
        .activate(&id, second["version"].as_u64().unwrap())
        .await
        .unwrap();
    let request =
        json!({"attestation_id": attestation["attestation_id"], "requested_capability": "sdk.run"});
    assert_eq!(
        gm.boundary.evaluate(request.clone()).await.unwrap()["decision"]["authorized"],
        false
    );
    gm.policy.activate(&id, first_version).await.unwrap();
    assert_eq!(
        gm.policy.history(&id).await.unwrap()["versions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let (recorder, executor_key) = executor(&id);
    gm.evidence_store
        .register_executor_key(
            json!({"key_id": id, "public_key": executor_key, "executor_sovereign_id": id}),
        )
        .await
        .unwrap();
    let resource = format!("sdk:{id}");
    let params = GovernedActionParams {
        evaluate: request.clone(),
        resource_id: Some(resource.clone()),
        resource_action: Some("create".into()),
        prior_resource: None,
        verify: GovernedVerification {
            operator_public_keys: keys.clone(),
            expected_policies: vec![first.clone()],
            expected_attestation: Some(attestation.clone()),
            ..GovernedVerification::default()
        },
    };
    let err = governed_action(
        &gm.boundary,
        &gm.evidence_store,
        &recorder,
        params,
        |_| async { Err::<ActionReport<()>, ActionError>("local test failure".into()) },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, GenesisMeshError::ActionFailed { .. }),
        "{err}"
    );
    let history = gm.evidence_store.resource_history(&resource).await.unwrap();
    let execution = history["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["entry"]["entry_kind"] == "execution")
        .unwrap();
    assert_eq!(execution["payload"]["outcome"], "failure");

    let evaluation = gm.boundary.evaluate(request.clone()).await.unwrap();
    let bad_head = recorder
        .record(RecordExecution {
            decision: evaluation["decision"].clone(),
            executed_capability: "sdk.run".into(),
            resource_id: Some(resource.clone()),
            resource_action: Some("create".into()),
            ..RecordExecution::default()
        })
        .unwrap();
    let conflict = gm.evidence_store.submit(bad_head).await.unwrap_err();
    assert!(
        matches!(conflict, GenesisMeshError::Http { status: 409, .. }),
        "{conflict}"
    );

    gm.evidence_store.retire_executor_key(&id).await.unwrap();
    let retired = recorder
        .record(RecordExecution {
            decision: evaluation["decision"].clone(),
            executed_capability: "sdk.run".into(),
            ..RecordExecution::default()
        })
        .unwrap();
    // 1.3.0 names a retired key; a 1.2 core does not.
    let refusal = gm.evidence_store.submit(retired).await.unwrap_err();
    assert!(
        ["evidence_executor_key_retired", "evidence_unknown_executor"].contains(&refusal.code()),
        "{refusal}"
    );
    assert_eq!(
        gm.policy.deactivate(&id, first_version).await.unwrap()["active"],
        false
    );
    let after = gm.boundary.evaluate(request).await.unwrap();
    let check = verify_boundary_decision(
        &after["decision"],
        &VerifyDecisionOptions {
            operator_public_keys: keys,
            expected_policies: Some(vec![first]),
            expected_attestation: Some(attestation),
            ..VerifyDecisionOptions::default()
        },
    );
    assert_eq!(
        (check.accepted, check.reason.as_str()),
        (false, "policy_binding_mismatch")
    );
}

/// v1.6.0: a device acts within a pre-issued grant while the NA cannot be
/// reached, uploads its uses on reconnecting (every one admitted, at the
/// NA's resource positions), and execution evidence made online afterwards
/// follows them in the resource's chain; past a grant's end, with the NA
/// unreachable, it falls back to break-glass; a revoked grant is refused
/// once the feed says so; the export and an audit pack verify offline.
async fn act_within_grants_offline_and_upload_on_reconnect(na: &LiveNa) {
    if !na.grants {
        skip("1.6.0: the NA does not issue grants");
        return;
    }
    let gm = &na.client;
    let keys = vec![na.na_public_key.clone()];
    let id = Uuid::new_v4().to_string();
    let capability = format!("sdk.grant.{id}");
    let resource = format!("kv:grant-{id}/api-key");
    let attestation = gm
        .attestation
        .issue(json!({"subject_id": id, "roles": ["role:client"],
                      "claims": {"capabilities": [capability]}}))
        .await
        .unwrap();
    // A grant must lie within every policy that applies.
    let valid_from = (Utc::now() - Duration::minutes(1)).to_rfc3339();
    let valid_until = (Utc::now() + Duration::days(2)).to_rfc3339();
    let policy = gm
        .policy
        .publish(json!({
            "policy_id": format!("grant-{id}"), "valid_from": valid_from, "valid_until": valid_until,
            "selector": {"capabilities": [capability]},
            "gates": [{"gate_id": "lifetime", "gate_type": "max_value.v1", "order": 0,
                       "config": {"path": "request_parameters.lifetime_days", "max": 90}}],
        }))
        .await
        .unwrap();
    gm.policy
        .activate(
            policy["policy_id"].as_str().unwrap(),
            policy["version"].as_u64().unwrap(),
        )
        .await
        .unwrap();
    let (recorder, executor_key) = executor(&format!("device-{id}"));
    gm.evidence_store
        .register_executor_key(json!({
            "key_id": recorder.key_id(), "public_key": executor_key,
            "executor_sovereign_id": recorder.executor_sovereign_id(),
        }))
        .await
        .unwrap();
    let request = |valid_until: String, max_uses: u64| {
        json!({
            "bearer_key_id": recorder.key_id(), "capabilities": [capability],
            "attestation_id": attestation["attestation_id"], "valid_until": valid_until,
            "max_uses": max_uses, "max_uses_per_time_token": 2,
            "parameter_envelope": {"lifetime_days": {"number_range": {
                "number_type": "integer", "minimum": 1, "maximum": 60}}},
        })
    };
    // The NA decides the policy over the whole envelope; 1 to 400 days may be denied.
    let mut wide = request(
        genesis_mesh_sdk::canonical::python_timestamp(Utc::now() + Duration::hours(1)),
        3,
    );
    wide["parameter_envelope"]["lifetime_days"]["number_range"]["maximum"] = json!(400);
    let refused = gm.grants.issue(wide).await.unwrap_err();
    assert_eq!(refused.code(), "grant_gate_may_deny");
    let issued = gm
        .grants
        .issue(request(
            genesis_mesh_sdk::canonical::python_timestamp(Utc::now() + Duration::hours(1)),
            3,
        ))
        .await
        .unwrap();
    assert_eq!(issued["time_token"]["use_sequence"], 0);
    let mut holder = GrantHolder::from_issued(&issued, recorder.clone(), keys.clone()).unwrap();

    // Offline: the same record outbox, behind an NA that cannot be reached.
    let outbox = Arc::new(MemoryRecordOutbox::default());
    let online =
        GenesisMeshClient::new(na.options.clone().with_record_outbox(outbox.clone())).unwrap();
    let offline = GenesisMeshClient::new(
        ClientOptions {
            base_url: "http://127.0.0.1:9".into(),
            ..na.options.clone()
        }
        .with_audience(na.na_public_key.clone())
        .with_record_outbox(outbox.clone()),
    )
    .unwrap();
    let rotate = |lifetime: u64| {
        GrantRequest::new(capability.clone(), json!({"lifetime_days": lifetime}))
            .on(resource.clone(), "rotate")
    };
    let report = |version: &'static str| async move {
        Ok::<_, ActionError>(ActionReport {
            value: Some(version),
            execution_parameters: Some(json!({"version_id": version})),
            ..ActionReport::default()
        })
    };
    let mut uses = Vec::new();
    for version in ["v1", "v2"] {
        let GrantActionOutcome::Used(used) = holder
            .act(&offline, rotate(30), |_| report(version))
            .await
            .unwrap()
        else {
            panic!("not used under the grant");
        };
        assert!(used.submission.is_none());
        uses.push(used.record);
    }
    // The envelope is checked offline: nothing runs.
    let outside = holder
        .act(&offline, rotate(61), |_| report("x"))
        .await
        .unwrap_err();
    assert_eq!(outside.code(), "grant_envelope_mismatch");
    let state = serde_json::to_value(holder.state()).unwrap();

    // Reconnected: the feed, the uploads (every use admitted, in order), a new token.
    let sync = holder.sync(&online).await.unwrap();
    assert!(sync.feed_read && !sync.revoked);
    let uploads = sync.uploads.unwrap();
    assert_eq!(uploads.admitted.len(), 2, "{uploads:?}");
    assert!(uploads.dead_lettered.is_empty() && uploads.pending.is_empty());
    assert!(sync.time_token_refreshed);
    assert_eq!(holder.time_token()["use_sequence"], 2);
    let GrantActionOutcome::Used(third) = holder
        .act(&online, rotate(45), |_| report("v3"))
        .await
        .unwrap()
    else {
        panic!("not used under the grant");
    };
    let submission = third.submission.unwrap();
    assert_eq!(submission["status"], "recorded");
    assert_eq!(submission["resource_sequence"], 3);
    let held = gm.grants.get(holder.grant_id()).await.unwrap();
    assert_eq!(held["uses"], 3);
    assert_eq!(held["remaining_uses"], 0);
    assert_eq!(held["chain_length"], 3);
    // The use chain, newest first, page by page.
    let page = gm
        .grants
        .uses(holder.grant_id(), None, Some(2))
        .await
        .unwrap();
    let listed = page["uses"].as_array().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["use_sequence"], 3);
    assert_eq!(listed[0]["state"], "admitted");
    let rest = gm
        .grants
        .uses(holder.grant_id(), page["next_before"].as_u64(), Some(2))
        .await
        .unwrap();
    assert_eq!(rest["uses"][0]["use_sequence"], 1);
    // The resource's head is the last use; the grant's entries by its id.
    let head = gm
        .evidence_store
        .resource_head_entry(&resource)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head["entry_kind"], "grant_execution");
    assert_eq!(head["record_id"], third.record["use_id"]);
    let entries = gm
        .evidence_store
        .search_all(json!({"grant_id": holder.grant_id()}))
        .await
        .unwrap();
    assert_eq!(entries.len(), 3);
    // The budget is spent: refused offline, without a fallback.
    let spent = holder
        .act(&offline, rotate(30), |_| report("x"))
        .await
        .unwrap_err();
    assert_eq!(spent.code(), "grant_budget_exhausted");
    // The same use again is a duplicate.
    let again = gm.grants.submit_use(uses[0].clone()).await.unwrap();
    assert_eq!(again["status"], "duplicate");
    // A restored holder keeps its chain (here: its state before the upload).
    let restored = GrantHolder::restore(
        serde_json::from_value(state).unwrap(),
        recorder.clone(),
        keys.clone(),
    )
    .unwrap();
    assert_eq!(restored.uses(), 2);

    // Online, a decision's evidence on the same resource follows the uses.
    let verify = GovernedVerification {
        operator_public_keys: keys.clone(),
        expected_attestation: Some(attestation.clone()),
        expected_policies: vec![policy.clone()],
        ..GovernedVerification::default()
    };
    let decided = governed_action(
        &online.boundary,
        &online.evidence_store,
        &recorder,
        GovernedActionParams {
            evaluate: json!({"attestation_id": attestation["attestation_id"],
                             "requested_capability": capability,
                             "context": {"request_parameters": {"lifetime_days": 30}}}),
            resource_id: Some(resource.clone()),
            resource_action: Some("rotate".into()),
            prior_resource: None,
            verify: verify.clone(),
        },
        |_| report("v4"),
    )
    .await
    .unwrap();
    assert!(decided.authorized);
    assert_eq!(decided.evidence.as_ref().unwrap()["resource_sequence"], 4);
    assert_eq!(
        decided.evidence.as_ref().unwrap()["prev_resource_digest"],
        genesis_mesh_sdk::grants::use_digest(&third.record)
            .unwrap()
            .as_str()
    );

    // Past its end, the NA unreachable: break-glass naming the capability.
    let brief = gm
        .grants
        .issue(request(
            genesis_mesh_sdk::canonical::python_timestamp(Utc::now() + Duration::seconds(3)),
            2,
        ))
        .await
        .unwrap();
    let mut ended = GrantHolder::from_issued(&brief, recorder.clone(), keys.clone()).unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let fallback = GrantFallback::new("the credential must rotate now", verify.clone());
    let outcome = ended
        .act(
            &offline,
            rotate(30).with_fallback(fallback.clone()),
            |authority| async move {
                assert_eq!(authority, GrantAuthority::BreakGlass);
                report("v5").await
            },
        )
        .await
        .unwrap();
    let GrantActionOutcome::FellBack { unusable, outcome } = outcome else {
        panic!("did not fall back");
    };
    assert_eq!(unusable.code, "grant_expired");
    let GovernedActionOutcome::BrokeGlass(glass) = *outcome else {
        panic!("did not break the glass");
    };
    assert_eq!(glass.record["capability"], capability.as_str());
    // With the NA back, the fallback asks it, and its ALLOW runs.
    let outcome = ended
        .act(
            &online,
            rotate(30).with_fallback(fallback),
            |authority| async move {
                assert!(matches!(authority, GrantAuthority::Decision(_)));
                report("v6").await
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        GrantActionOutcome::FellBack { ref outcome, .. }
            if matches!(**outcome, GovernedActionOutcome::Evaluated(ref r) if r.authorized)
    ));
    // The fallback uploaded what was pending first: the break-glass record.
    assert!(outbox.list().await.unwrap().is_empty());

    // Revoked by an operator: the feed lists it, and the holder refuses it.
    let revocable = gm
        .grants
        .issue(request(
            genesis_mesh_sdk::canonical::python_timestamp(Utc::now() + Duration::hours(1)),
            2,
        ))
        .await
        .unwrap();
    let mut revoked = GrantHolder::from_issued(&revocable, recorder.clone(), keys.clone()).unwrap();
    let answer = gm
        .grants
        .revoke(revoked.grant_id(), Some("the device was lost"))
        .await
        .unwrap();
    assert_eq!(answer["status"], "revoked");
    assert!(revoked.refresh_feed(&gm.grants).await.unwrap());
    let refused = revoked
        .act(&offline, rotate(30), |_| report("x"))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "grant_revoked");

    // The whole store verifies offline, grants, uses and revocation with it.
    let events = gm.evidence_store.export_all(0, 1000).await.unwrap();
    let executor_keys = gm.evidence_store.list_executor_keys().await.unwrap();
    let verification = verify_evidence_events(
        &events,
        &VerifyEvidenceOptions::new(keys.clone(), executor_keys),
    );
    assert!(verification.verified, "{:?}", verification.failures);
    assert!(verification.grants >= 3);
    assert!(verification.grant_executions >= 3);
    assert!(verification.grant_revocations >= 1);

    // And so does an audit pack holding them.
    let transport = HttpTransport::new(na.options.clone()).unwrap();
    let _: Value = transport
        .admin_post("/admin/evidence/anchors", json!({}))
        .await
        .unwrap();
    let pack: Value = transport
        .admin_post("/admin/evidence/audit-pack", json!({}))
        .await
        .unwrap();
    let mut files: BTreeMap<String, Vec<u8>> = pack["files"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(path, text)| (path.clone(), text.as_str().unwrap().as_bytes().to_vec()))
        .collect();
    files.insert(
        "manifest.json".into(),
        audit_pack::pack_json_bytes(&pack["manifest"]),
    );
    let checked = audit_pack::verify_audit_pack(
        &files,
        &audit_pack::VerifyPackOptions::new(na.na_public_key.clone(), None),
    );
    assert!(checked.verified, "{:?}", checked.reasons());
    let report_md = String::from_utf8(files["report.md"].clone()).unwrap();
    assert!(report_md.contains("## Grants"));
    assert!(report_md.contains("## Grant revocations"));
}
