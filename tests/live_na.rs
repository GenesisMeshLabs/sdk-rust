//! The governed-action lifecycle against a live Python Network Authority,
//! using only SDK calls. Skipped unless `GM_E2E_PYTHON` names a Python with
//! the Genesis Mesh core installed (a disposable loopback NA is started from
//! `scripts/e2e_na.py`), or `GM_E2E_BASE_URL`, `GM_E2E_OPERATOR_SEED` and
//! `GM_E2E_NA_PUBLIC_KEY` name an existing NA.

use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use genesis_mesh_sdk::{
    canonical::execution_digest,
    governed_action, json, public_key_from_seed,
    verify::{
        verify_attestation_signature, verify_boundary_decision, verify_evidence_events,
        verify_justification_signature, verify_policy_signature, VerifyDecisionOptions,
        VerifyEvidenceOptions,
    },
    ActionError, ActionReport, ClientOptions, EvidenceOutbox, ExecutionRecorder, FlushOptions,
    GenesisMeshClient, GenesisMeshError, GovernedActionParams, GovernedVerification, MemoryOutbox,
    RecordExecution, Value,
};
use uuid::Uuid;

struct LiveNa {
    client: GenesisMeshClient,
    options: ClientOptions,
    na_public_key: String,
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

fn live_na() -> Option<LiveNa> {
    let (config, child) = if let Ok(base_url) = std::env::var("GM_E2E_BASE_URL") {
        let config = json!({
            "baseUrl": base_url,
            "signingKeyBase64": std::env::var("GM_E2E_OPERATOR_SEED").expect("GM_E2E_OPERATOR_SEED"),
            "keyId": std::env::var("GM_E2E_OPERATOR_KEY_ID").unwrap_or_else(|_| "ops".into()),
            "naPublicKey": std::env::var("GM_E2E_NA_PUBLIC_KEY").expect("GM_E2E_NA_PUBLIC_KEY"),
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
    let client = GenesisMeshClient::new(
        options
            .clone()
            .with_outbox(Arc::new(MemoryOutbox::default())),
    )
    .unwrap();
    Some(LiveNa {
        client,
        options,
        na_public_key: config["naPublicKey"].as_str().unwrap().to_owned(),
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
async fn governed_lifecycle_against_a_live_na() {
    let Some(na) = live_na() else {
        eprintln!("skipped: set GM_E2E_PYTHON or GM_E2E_BASE_URL");
        return;
    };
    admit_decide_record_audit_and_offboard(&na).await;
    observe_enforce_rollback_failures_conflicts_and_retired_keys(&na).await;
    keep_evidence_while_the_na_is_unreachable_and_admit_it_in_order(&na).await;
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
        assert_eq!(result.submission.unwrap().status(), "pending");
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
    assert!(outbox.list().unwrap().is_empty());
    let history = gm.evidence_store.resource_history(&resource).await.unwrap();
    assert_eq!(history["verification"]["verified"], true);

    // A guard refusal after the action: recorded without the refused field.
    let err = governed_action(
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
    assert_eq!(err.action_value::<u8>(), Some(&3));
    let GenesisMeshError::MetadataRefused {
        evidence,
        submission,
        ..
    } = err
    else {
        panic!("unexpected error");
    };
    assert_eq!(submission.status(), "recorded");
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
        assert_eq!(result.submission.unwrap().status(), "recorded");
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
    assert_eq!(
        gm.evidence_store.submit(retired).await.unwrap_err().code(),
        "evidence_unknown_executor"
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
