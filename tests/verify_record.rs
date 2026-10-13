//! One record verified as an export verifies it (1.5.0), and decisions
//! judged as of their own time.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use genesis_mesh_sdk::{
    canonical::{attestation_canonical, parse_timestamp, policy_canonical},
    json, load_signing_key, public_key_from_seed, sign_canonical,
    verify::{
        parse_export_lines, verify_boundary_decision, verify_evidence_events, verify_record,
        VerifyDecisionOptions, VerifyEvidenceOptions, VerifyRecordOptions, RECORD_KINDS,
    },
    Value,
};

fn suite(name: &str) -> Value {
    let text = match name {
        "out_of_band" => include_str!("fixtures/out_of_band.json"),
        "remediation" => include_str!("fixtures/remediation.json"),
        "python-vectors" => include_str!("fixtures/python-vectors.json"),
        other => panic!("no suite {other}"),
    };
    serde_json::from_str(text).unwrap()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

/// The reasons a record carries in itself, which need nothing else of the
/// store; the others (chains, subjects, envelopes, duplicates) are an
/// export's.
const OWN: [&str; 8] = [
    "unknown_field",
    "payload_invalid",
    "invalid_signature",
    "non_canonical_form",
    "quarantine_digest_mismatch",
    "retention_count_mismatch",
    "review_approval_invalid",
    "review_same_holder",
];

/// Every record of every export vector fails alone for exactly the reasons
/// of its own that the export names for its entry.
#[test]
fn a_record_alone_fails_for_the_reasons_an_export_gives_it() {
    let mut checked = 0;
    let mut failing = 0;
    for name in ["out_of_band", "remediation"] {
        for v in suite(name)["vectors"].as_array().unwrap() {
            if v["kind"] != "verify_export" {
                continue;
            }
            let input = &v["input"];
            let events = parse_export_lines(input["lines"].as_str().unwrap()).unwrap();
            let keys = strings(&input["na_public_keys"]);
            let executor_keys = input["executor_keys"].as_array().unwrap().clone();
            let export = verify_evidence_events(
                &events,
                &VerifyEvidenceOptions {
                    checkpoint: input.get("checkpoint").cloned(),
                    ..VerifyEvidenceOptions::new(keys.clone(), executor_keys.clone())
                },
            );
            let options = VerifyRecordOptions {
                na_public_keys: keys,
                executor_keys,
                ..VerifyRecordOptions::default()
            };
            for event in &events {
                let kind = event["entry"]["entry_kind"].as_str().unwrap();
                let payload = &event["payload"];
                let seq = event["entry"]["store_sequence"].as_i64();
                // A decision entry holds a decision and its context; a
                // checkpoint's count runs from the one before it.
                if kind == "decision"
                    || !RECORD_KINDS.contains(&kind)
                    || (kind == "retention_checkpoint"
                        && !payload["previous_checkpoint_id"].is_null())
                {
                    continue;
                }
                let alone: BTreeSet<String> = verify_record(kind, payload, &options)
                    .failures
                    .into_iter()
                    .map(|f| f.reason)
                    .collect();
                let in_export: BTreeSet<String> = export
                    .failures
                    .iter()
                    .filter(|f| f.store_sequence == seq && OWN.contains(&f.reason.as_str()))
                    .map(|f| f.reason.clone())
                    .collect();
                assert_eq!(alone, in_export, "{name}/{} #{seq:?} {kind}", v["id"]);
                checked += 1;
                failing += usize::from(!alone.is_empty());
            }
        }
    }
    assert!(
        checked > 300 && failing >= 10,
        "{checked} records, {failing} failing"
    );
}

fn reference() -> Value {
    suite("python-vectors")
}

fn at(value: &str) -> DateTime<Utc> {
    parse_timestamp(value).unwrap()
}

fn keys(v: &Value) -> Vec<String> {
    vec![v["na_public_key"].as_str().unwrap().to_owned()]
}

#[test]
fn a_decision_is_judged_as_of_its_own_time_when_asked() {
    let v = reference();
    let decision = &v["allowed"]["decision"];
    let later = at("2100-01-01T00:00:00Z");
    let options = VerifyDecisionOptions {
        operator_public_keys: keys(&v),
        now: Some(later),
        ..VerifyDecisionOptions::default()
    };
    // As before 1.5.0 by default: judged as of now, the decision expired.
    assert_eq!(
        verify_boundary_decision(decision, &options).reason,
        "decision_expired"
    );
    let archived = VerifyDecisionOptions {
        as_of_record_time: true,
        ..options.clone()
    };
    let result = verify_boundary_decision(decision, &archived);
    assert!(result.accepted && result.authorized, "{result:?}");
    // A decision that expired before it was made fails at its own time
    // (refused before its signature is checked, as the reference refuses it).
    let mut backwards = decision.clone();
    backwards["decision_valid_until"] = json!("2000-01-01T00:00:00Z");
    assert_eq!(
        verify_boundary_decision(&backwards, &archived).reason,
        "decision_expired"
    );
}

#[test]
fn a_decision_record_is_judged_as_of_its_own_time_unless_given_one() {
    let v = reference();
    let options = VerifyRecordOptions {
        na_public_keys: keys(&v),
        ..VerifyRecordOptions::default()
    };
    let allowed = verify_record("decision", &v["allowed"]["decision"], &options);
    assert!(allowed.verified, "{allowed:?}");
    assert_eq!(
        (allowed.reason.as_str(), allowed.authorized),
        ("authorized", Some(true))
    );
    let denied = verify_record("decision", &v["denied"]["decision"], &options);
    assert!(
        denied.verified && denied.authorized == Some(false),
        "{denied:?}"
    );
    assert!(denied.reason.starts_with("unauthorized_"));
    let late = VerifyRecordOptions {
        at: Some(at("2100-01-01T00:00:00Z")),
        ..options.clone()
    };
    let expired = verify_record("decision", &v["allowed"]["decision"], &late);
    assert!(!expired.verified);
    assert_eq!(expired.reason, "decision_expired");
    assert_eq!(expired.failures.len(), 1);
    // The bindings an auditor expects, from the policy and attestation it holds.
    let bound = VerifyRecordOptions {
        expected_policies: Some(vec![v["policy"].clone()]),
        expected_attestation: Some(v["attestation"].clone()),
        ..options.clone()
    };
    assert!(verify_record("decision", &v["allowed"]["decision"], &bound).verified);
    let mut other = v["policy"].clone();
    other["version"] = json!(2);
    let unbound = VerifyRecordOptions {
        expected_policies: Some(vec![other]),
        ..options
    };
    let result = verify_record("decision", &v["allowed"]["decision"], &unbound);
    assert_eq!(result.reason, "policy_binding_mismatch");
}

#[test]
fn records_of_each_kind_verify_under_their_signers_keys() {
    let v = reference();
    let na = VerifyRecordOptions {
        na_public_keys: keys(&v),
        ..VerifyRecordOptions::default()
    };
    let executor = VerifyRecordOptions {
        executor_keys: v["executor_keys"].as_array().unwrap().clone(),
        ..VerifyRecordOptions::default()
    };
    for (kind, record, options) in [
        ("justification", &v["allowed"]["justification_proof"], &na),
        ("retention_checkpoint", &v["checkpoint"], &na),
        ("policy", &v["policy"], &na),
        ("execution", &v["executions"][0], &executor),
        ("execution", &v["executions"][1], &executor),
    ] {
        let result = verify_record(kind, record, options);
        assert!(result.verified, "{kind}: {result:?}");
        assert_eq!(result.reason, "verified");
        assert!(result.record_id.is_some());
    }
    // Each under the other's keys fails by its signature.
    assert_eq!(
        verify_record("execution", &v["executions"][0], &na).reason,
        "invalid_signature"
    );
    assert_eq!(
        verify_record(
            "justification",
            &v["allowed"]["justification_proof"],
            &executor
        )
        .reason,
        "invalid_signature"
    );
    let mut changed = v["policy"].clone();
    changed["description"] = json!("changed");
    assert_eq!(
        verify_record("policy", &changed, &na).reason,
        "invalid_signature"
    );
    assert_eq!(
        verify_record("policy", &json!([1]), &na).reason,
        "payload_invalid"
    );
    let unknown = verify_record("anchor", &json!({}), &na);
    assert_eq!(
        (unknown.verified, unknown.reason.as_str()),
        (false, "unknown_entry_kind")
    );
}

#[test]
fn a_signed_field_this_crate_does_not_know_is_refused_by_name() {
    let seed = STANDARD.encode([7u8; 32]);
    let key = load_signing_key(&seed).unwrap();
    let options = VerifyRecordOptions {
        na_public_keys: vec![public_key_from_seed(&seed).unwrap()],
        ..VerifyRecordOptions::default()
    };
    let v = reference();
    let mut policy = v["policy"].clone();
    policy["later_section"] = json!({"x": 1});
    policy["signature"] = sign_canonical(&policy_canonical(&policy).unwrap(), "k", &key);
    let result = verify_record("policy", &policy, &options);
    assert_eq!(result.reason, "unknown_field", "{result:?}");
    assert_eq!(result.failures[0].detail, "later_section");

    let mut attestation = v["attestation"].clone();
    let signature = sign_canonical(&attestation_canonical(&attestation).unwrap(), "k", &key);
    attestation["signatures"] = json!([signature]);
    let result = verify_record("attestation", &attestation, &options);
    assert!(result.verified, "{result:?}");
    attestation["claims"]["note"] = json!("changed");
    assert_eq!(
        verify_record("attestation", &attestation, &options).reason,
        "invalid_signature"
    );
}
