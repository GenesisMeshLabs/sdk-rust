//! The boundary decision vectors of the shared conformance suite `interop`
//! (genesismesh/conformance/generate_vectors.py), copied unchanged: each
//! decision, verified with the expectations the vector gives, must be accepted
//! or refused for the reason the Python reference gives (1.10.0).

mod receipts;

use chrono::{DateTime, Utc};
use genesis_mesh_sdk::verify::{
    verify_boundary_decision_expecting, ExpectedBinding, VerifyDecisionOptions,
};
use serde_json::Value;

fn decision_vectors() -> Vec<Value> {
    let suite: Value = serde_json::from_str(include_str!("fixtures/interop.json")).unwrap();
    suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "boundary_decision")
        .cloned()
        .collect()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn verify(vector: &Value) -> (bool, String, bool) {
    let input = &vector["input"];
    let now: DateTime<Utc> = DateTime::parse_from_rfc3339(input["now"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    let options = VerifyDecisionOptions {
        operator_public_keys: strings(&input["operator_public_keys"]),
        now: Some(now),
        expected_policies: input
            .get("expected_policies")
            .map(|p| p.as_array().unwrap().clone()),
        expected_attestation: input.get("expected_attestation").cloned(),
        ..Default::default()
    };
    let mut expected = ExpectedBinding::new();
    if let Some(key_id) = input
        .get("expected_requester_key_id")
        .and_then(Value::as_str)
    {
        expected = expected.requester_key_id(key_id);
    }
    for policy_id in input
        .get("expected_policy_ids")
        .map(strings)
        .unwrap_or_default()
    {
        expected = expected.policy_id(policy_id);
    }
    let result = verify_boundary_decision_expecting(&input["decision"], &options, &expected);
    (result.accepted, result.reason, result.authorized)
}

#[test]
fn every_decision_vector_gets_the_references_answer() {
    let vectors = decision_vectors();
    assert!(vectors.len() >= 17, "the suite has its decision vectors");
    let mut receipt = receipts::Receipt::start(
        "interop",
        file!(),
        "every_decision_vector_gets_the_references_answer",
    );
    for vector in &vectors {
        let want = &vector["expected"];
        let want = (
            want["accepted"].as_bool().unwrap(),
            want["reason"].as_str().unwrap().to_owned(),
            want["authorized"].as_bool().unwrap(),
        );
        assert_eq!(
            verify(vector),
            want,
            "{}: {}",
            vector["id"],
            vector["description"]
        );
        receipt.ran(vector);
    }
    receipt.finish(&serde_json::from_str(include_str!("fixtures/interop.json")).unwrap());
}

#[test]
fn expected_policy_ids_refuse_the_allow_no_policy_covered() {
    let vector = decision_vectors()
        .into_iter()
        .find(|v| v["id"] == "bd-012")
        .unwrap();
    assert_eq!(
        verify(&vector),
        (false, "policy_binding_mismatch".to_owned(), true)
    );
}
