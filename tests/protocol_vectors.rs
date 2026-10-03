//! Offline verification and evidence signing against artifacts produced by
//! the Python reference (`tests/fixtures/python-vectors.json`, shared with
//! the TypeScript SDK).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::{
    canonical::{
        attestation_digest, entry_digest, execution_digest, parse_timestamp, payload_digest,
        policy_digest,
    },
    json, public_key_from_seed,
    verify::{
        parse_export_lines, verify_attestation_signature, verify_boundary_decision,
        verify_decision_signature, verify_evidence_events, verify_execution_signature,
        verify_justification_signature, verify_policy_signature, verify_retention_checkpoint,
        VerifyDecisionOptions, VerifyEvidenceOptions,
    },
    ExecutionRecorder, GenesisMeshError, PriorResource, RecordExecution, ResourceHead, Value,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/python-vectors.json")).unwrap()
}

fn keys(v: &Value) -> Vec<String> {
    vec![v["na_public_key"].as_str().unwrap().to_owned()]
}

fn executor_keys(v: &Value) -> Vec<Value> {
    v["executor_keys"].as_array().unwrap().clone()
}

fn decision_options(v: &Value) -> VerifyDecisionOptions {
    VerifyDecisionOptions {
        operator_public_keys: keys(v),
        now: Some(at(&v["allowed"]["decision"]["decision_made_at"])),
        expected_policies: Some(vec![v["policy"].clone()]),
        expected_attestation: Some(v["attestation"].clone()),
        ..VerifyDecisionOptions::default()
    }
}

fn at(value: &Value) -> DateTime<Utc> {
    parse_timestamp(value.as_str().unwrap()).unwrap()
}

fn with(mut value: Value, key: &str, replacement: Value) -> Value {
    value[key] = replacement;
    value
}

fn export_options(v: &Value) -> VerifyEvidenceOptions {
    VerifyEvidenceOptions::new(keys(v), executor_keys(v))
}

fn reasons(v: &Value, events: &[Value], options: &VerifyEvidenceOptions) -> Vec<String> {
    let _ = v;
    verify_evidence_events(events, options)
        .failures
        .into_iter()
        .map(|f| f.reason)
        .collect()
}

#[test]
fn matches_every_reference_digest() {
    let v = vectors();
    assert_eq!(
        attestation_digest(&v["attestation"]).unwrap(),
        v["attestation_digest"]
    );
    assert_eq!(policy_digest(&v["policy"]).unwrap(), v["policy_digest"]);
    let digests: Vec<Value> = v["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| json!(execution_digest(e).unwrap()))
        .collect();
    assert_eq!(Value::Array(digests), v["execution_digests"]);
}

#[test]
fn verifies_python_signatures_and_rejects_tampering() {
    let v = vectors();
    let k = keys(&v);
    let executor = v["executor_keys"][0]["public_key"].as_str().unwrap();
    let decision = &v["allowed"]["decision"];
    let proof = &v["allowed"]["justification_proof"];
    assert!(verify_attestation_signature(&v["attestation"], &k));
    assert!(!verify_attestation_signature(
        &with(v["attestation"].clone(), "subject_id", json!("changed")),
        &k
    ));
    assert!(verify_policy_signature(&v["policy"], &k));
    assert!(!verify_policy_signature(
        &with(v["policy"].clone(), "description", json!("changed")),
        &k
    ));
    assert!(verify_decision_signature(decision, &k));
    assert!(!verify_decision_signature(
        &with(decision.clone(), "authorized", json!(false)),
        &k
    ));
    assert!(verify_justification_signature(proof, &k));
    assert!(!verify_justification_signature(
        &with(proof.clone(), "proof_id", json!("changed")),
        &k
    ));
    assert!(verify_retention_checkpoint(&v["checkpoint"], &k));
    assert!(!verify_retention_checkpoint(
        &with(v["checkpoint"].clone(), "removed_count", json!(100)),
        &k
    ));
    assert!(verify_execution_signature(&v["executions"][0], executor));
    assert!(!verify_execution_signature(
        &with(v["executions"][0].clone(), "outcome", json!("failure")),
        executor
    ));
}

#[test]
fn verifies_allow_and_signed_policy_deny_with_expected_bindings() {
    let v = vectors();
    let options = decision_options(&v);
    let allowed = verify_boundary_decision(&v["allowed"]["decision"], &options);
    assert!(allowed.accepted && allowed.authorized, "{allowed:?}");
    assert_eq!(allowed.reason, "authorized");
    let denied = verify_boundary_decision(&v["denied"]["decision"], &options);
    assert!(denied.accepted && !denied.authorized);
    assert_eq!(denied.reason, "unauthorized_policy_gate_failure");
}

#[test]
fn rejects_unsigned_expired_tampered_and_mismatched_decisions() {
    let v = vectors();
    let decision = v["allowed"]["decision"].clone();
    let options = decision_options(&v);
    let cases = [
        (
            "missing_signature",
            with(decision.clone(), "signature", Value::Null),
            options.clone(),
        ),
        (
            "decision_expired",
            decision.clone(),
            VerifyDecisionOptions {
                now: Some(parse_timestamp("2100-01-01T00:00:00Z").unwrap()),
                ..options.clone()
            },
        ),
        (
            "invalid_signature",
            with(decision.clone(), "context_id", json!("changed")),
            options.clone(),
        ),
        (
            "attestation_binding_mismatch",
            decision.clone(),
            VerifyDecisionOptions {
                expected_attestation: Some(with(
                    v["attestation"].clone(),
                    "subject_id",
                    json!("changed"),
                )),
                ..options.clone()
            },
        ),
        (
            "policy_binding_mismatch",
            decision.clone(),
            VerifyDecisionOptions {
                expected_policies: Some(vec![]),
                ..options.clone()
            },
        ),
        (
            "payload_invalid",
            with(decision.clone(), "decision_valid_until", json!("invalid")),
            options.clone(),
        ),
        ("payload_invalid", Value::Null, options.clone()),
    ];
    for (reason, decision, options) in cases {
        let result = verify_boundary_decision(&decision, &options);
        assert!(!result.accepted, "{reason}");
        assert_eq!(result.reason, reason);
    }
}

#[test]
fn verifies_the_complete_python_export_like_the_na() {
    let v = vectors();
    let events = parse_export_lines(v["export"].as_str().unwrap()).unwrap();
    assert_eq!(events.len(), 8);
    let result = verify_evidence_events(&events, &export_options(&v));
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        v["server_verification"]
    );
    let padded = format!("\n{}\n", v["export"].as_str().unwrap());
    assert_eq!(parse_export_lines(&padded).unwrap().len(), 8);
}

#[test]
fn rejects_malformed_exports() {
    for text in [
        "null",
        "{}",
        r#"{"schema":"gm.evidence.event","schema_version":1}"#,
        r#"{"schema":"gm.evidence.event","schema_version":2}"#,
        "invalid",
    ] {
        assert!(parse_export_lines(text).is_err(), "{text}");
    }
    let v = vectors();
    let result = verify_evidence_events(&[json!({})], &export_options(&v));
    assert!(!result.verified);
    assert_eq!(result.failures[0].reason, "payload_invalid");
}

#[test]
fn rejects_unknown_executor_keys() {
    let v = vectors();
    let events = parse_export_lines(v["export"].as_str().unwrap()).unwrap();
    let options = VerifyEvidenceOptions::new(keys(&v), vec![]);
    let failures = verify_evidence_events(&events, &options).failures;
    assert!(failures
        .iter()
        .any(|f| f.reason == "invalid_signature" && f.detail == "execution"));
}

#[test]
fn detects_removed_and_reordered_entries_and_allows_filtered_gaps() {
    let v = vectors();
    let events = parse_export_lines(v["export"].as_str().unwrap()).unwrap();
    let options = export_options(&v);
    let mut removed = events.clone();
    removed.remove(1);
    let mut reversed = events.clone();
    reversed.reverse();
    for modified in [removed, reversed] {
        assert!(reasons(&v, &modified, &options).contains(&"store_sequence_gap".into()));
    }
    let decisions: Vec<Value> = events
        .iter()
        .filter(|e| e["entry"]["entry_kind"] == "decision")
        .cloned()
        .collect();
    let filtered = VerifyEvidenceOptions {
        contiguous: false,
        ..options
    };
    assert!(verify_evidence_events(&decisions, &filtered).verified);
}

#[test]
fn detects_a_changed_envelope_payload_and_resource_chain() {
    let v = vectors();
    let mut events = parse_export_lines(v["export"].as_str().unwrap()).unwrap();
    let ev = events
        .iter_mut()
        .find(|e| e["entry"]["entry_kind"] == "execution")
        .unwrap();
    ev["payload"]["resource_sequence"] = json!(7);
    ev["entry"]["vendor_id"] = json!("changed");
    let found = reasons(&v, &events, &export_options(&v));
    for reason in [
        "entry_digest_mismatch",
        "payload_digest_mismatch",
        "invalid_signature",
        "resource_chain_break",
    ] {
        assert!(found.contains(&reason.to_owned()), "{reason}: {found:?}");
    }
}

#[test]
fn rejects_invalid_execution_fields_without_panicking() {
    let v = vectors();
    for field in ["executed_at", "sequence_no", "signature"] {
        let mut events = parse_export_lines(v["export"].as_str().unwrap()).unwrap();
        let ev = events
            .iter_mut()
            .find(|e| e["entry"]["entry_kind"] == "execution")
            .unwrap();
        ev["payload"][field] = if field == "sequence_no" {
            json!(-1)
        } else {
            json!(42)
        };
        ev["entry"]["payload_digest"] = json!(payload_digest(&ev["payload"]).unwrap());
        ev["entry_digest"] = json!(entry_digest(&ev["entry"]).unwrap());
        assert!(
            reasons(&v, &events, &export_options(&v)).contains(&"payload_invalid".into()),
            "{field}"
        );
    }
}

#[test]
fn does_not_trust_an_unsigned_caller_supplied_checkpoint() {
    let v = vectors();
    let options = VerifyEvidenceOptions {
        checkpoint: Some(with(v["checkpoint"].clone(), "signature", Value::Null)),
        ..export_options(&v)
    };
    assert!(!verify_evidence_events(&[], &options).verified);
    let signed = VerifyEvidenceOptions {
        checkpoint: Some(v["checkpoint"].clone()),
        ..export_options(&v)
    };
    assert!(verify_evidence_events(&[], &signed).verified);
}

fn recorder() -> (ExecutionRecorder, String) {
    let seed = STANDARD.encode([5_u8; 32]);
    (
        ExecutionRecorder::new("secrets-controller", "ctrl-rust", &seed).unwrap(),
        public_key_from_seed(&seed).unwrap(),
    )
}

#[test]
fn signs_records_that_link_both_chains() {
    let v = vectors();
    let (recorder, public_key) = recorder();
    let decision = &v["allowed"]["decision"];
    let last = v["executions"].as_array().unwrap().last().unwrap().clone();

    let first = recorder
        .record(RecordExecution {
            decision: decision.clone(),
            executed_capability: "sp-secret.rotate".into(),
            execution_parameters: Some(json!({"secret_version": "v3", "owner": "Zoë", "ttl": 1.5})),
            resource_id: last["resource_id"].as_str().map(str::to_owned),
            resource_action: Some("rotate".into()),
            prior_resource: Some(PriorResource::Record(last.clone())),
            ..RecordExecution::default()
        })
        .unwrap();
    assert!(verify_execution_signature(&first, &public_key));
    assert_eq!(first["sequence_no"], 1);
    assert_eq!(first["prev_evidence_digest"], Value::Null);
    assert_eq!(
        first["resource_sequence"],
        last["resource_sequence"].as_u64().unwrap() + 1
    );
    assert_eq!(
        first["prev_resource_digest"],
        *v["execution_digests"].as_array().unwrap().last().unwrap()
    );
    assert_eq!(first["outcome"], "success");

    let second = recorder
        .record(RecordExecution {
            decision: decision.clone(),
            executed_capability: "sp-secret.rotate".into(),
            prior_record: Some(first.clone()),
            resource_id: last["resource_id"].as_str().map(str::to_owned),
            resource_action: Some("rotate".into()),
            prior_resource: Some(PriorResource::Head(ResourceHead {
                resource_sequence: first["resource_sequence"].as_u64().unwrap(),
                record_digest: execution_digest(&first).unwrap(),
            })),
            ..RecordExecution::default()
        })
        .unwrap();
    assert!(verify_execution_signature(&second, &public_key));
    assert_eq!(second["sequence_no"], 2);
    assert_eq!(
        second["prev_evidence_digest"],
        json!(execution_digest(&first).unwrap())
    );
    assert_eq!(
        second["prev_resource_digest"],
        json!(execution_digest(&first).unwrap())
    );

    let bare = recorder
        .record(RecordExecution {
            decision: decision.clone(),
            executed_capability: "sp-secret.rotate".into(),
            ..RecordExecution::default()
        })
        .unwrap();
    assert!(bare.get("resource_id").is_none());
    assert!(verify_execution_signature(&bare, &public_key));
}

#[test]
fn refuses_incomplete_resource_pairs_and_secret_material() {
    let v = vectors();
    let (recorder, _) = recorder();
    let incomplete = recorder.record(RecordExecution {
        decision: v["allowed"]["decision"].clone(),
        resource_id: Some("kv:v/s".into()),
        ..RecordExecution::default()
    });
    assert!(matches!(
        incomplete,
        Err(GenesisMeshError::Configuration(_))
    ));
    let secret = recorder.record(RecordExecution {
        decision: v["allowed"]["decision"].clone(),
        execution_parameters: Some(json!({"password": "hunter2"})),
        ..RecordExecution::default()
    });
    assert!(matches!(secret, Err(GenesisMeshError::SecretMaterial(_))));
    assert_eq!(secret.unwrap_err().code(), "evidence_secret_material");
}
