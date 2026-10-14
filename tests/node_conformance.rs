//! The core's `node` conformance suite (1.7.0): node request signatures, the
//! edge join co-signature, join certificates and CRLs. Ed25519 is
//! deterministic, so every payload and signature is reproduced exactly.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{
    canonical_json,
    node_auth::{
        executor_key_id, executor_proof_payload, node_signing_payload, sign_executor_proof,
        sign_node_request,
    },
    verify::{verify_crl, verify_join_certificate},
    verify_canonical, Value,
};

fn vectors() -> Vec<Value> {
    let suite: Value =
        serde_json::from_str(include_str!("fixtures/node.json")).expect("node.json parses");
    assert_eq!(suite["suite"], "node");
    suite["vectors"].as_array().unwrap().clone()
}

/// The conformance generator's fixed seeds: `a` is 00..1f, `b` 20..3f, `c`
/// 40..5f.
fn key(name: &str) -> SigningKey {
    let start = match name {
        "a" => 0,
        "b" => 32,
        "c" => 64,
        other => panic!("no seed {other}"),
    };
    let seed: [u8; 32] = std::array::from_fn(|i| (start + i) as u8);
    SigningKey::from_bytes(&seed)
}

fn public(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} missing"))
}

#[test]
fn reproduces_every_node_vector() {
    let mut seen = std::collections::BTreeSet::new();
    for case in vectors() {
        let id = text(&case, "id");
        let input = &case["input"];
        let expected = &case["expected"];
        match text(&case, "kind") {
            "node_request" => {
                let node = key(text(input, "node_key"));
                assert_eq!(public(&node), text(input, "node_public_key_b64"), "{id}");
                let body = input["body"].clone();
                assert_eq!(
                    node_signing_payload(&body).unwrap(),
                    text(expected, "payload"),
                    "{id}"
                );
                let signed = sign_node_request(
                    body.clone(),
                    &node,
                    text(&body, "timestamp"),
                    text(&body, "nonce"),
                )
                .unwrap();
                assert_eq!(
                    text(&signed, "signature"),
                    text(expected, "signature_b64"),
                    "{id}"
                );
            }
            "join_request" => {
                let node = key(text(input, "node_key"));
                let executor = key(text(input, "executor_key"));
                assert_eq!(public(&executor), text(input, "executor_public_key_b64"));
                let body = input["body"].clone();
                assert_eq!(
                    executor_proof_payload(&body).unwrap(),
                    text(expected, "executor_payload"),
                    "{id}"
                );
                let proved = sign_executor_proof(body.clone(), &executor).unwrap();
                assert_eq!(
                    text(&proved, "executor_signature"),
                    text(expected, "executor_signature_b64"),
                    "{id}"
                );
                assert_eq!(
                    executor_key_id(&public(&executor)).unwrap(),
                    text(expected, "executor_key_id"),
                    "{id}"
                );
                assert_eq!(
                    node_signing_payload(&proved).unwrap(),
                    text(expected, "payload"),
                    "{id}"
                );
                let signed = sign_node_request(
                    proved,
                    &node,
                    text(&body, "timestamp"),
                    text(&body, "nonce"),
                )
                .unwrap();
                assert_eq!(
                    text(&signed, "signature"),
                    text(expected, "signature_b64"),
                    "{id}"
                );
            }
            "node_request_tampered" => {
                let body = &input["body"];
                assert_eq!(
                    node_signing_payload(body).unwrap(),
                    text(expected, "payload"),
                    "{id}"
                );
                let verifies = verify_canonical(
                    &node_signing_payload(body).unwrap(),
                    text(input, "signature_b64"),
                    &[text(input, "node_public_key_b64").to_owned()],
                );
                assert_eq!(Some(verifies), expected["verifies"].as_bool(), "{id}");
            }
            "join_certificate" => {
                let certificate = &input["certificate"];
                let keys: Vec<String> =
                    serde_json::from_value(input["na_public_keys"].clone()).unwrap();
                assert_eq!(keys, [public(&key("c"))]);
                let mut signed = certificate.clone();
                let map = signed.as_object_mut().unwrap();
                map.remove("signatures");
                map.remove("edge");
                assert_eq!(
                    canonical_json(&signed).unwrap(),
                    text(expected, "payload"),
                    "{id}"
                );
                assert_eq!(
                    Some(verify_join_certificate(certificate, &keys)),
                    expected["verifies"].as_bool(),
                    "{id}"
                );
            }
            "crl" => {
                let crl = &input["crl"];
                let keys: Vec<String> =
                    serde_json::from_value(input["na_public_keys"].clone()).unwrap();
                let mut signed = crl.clone();
                signed.as_object_mut().unwrap().remove("signatures");
                assert_eq!(
                    canonical_json(&signed).unwrap(),
                    text(expected, "payload"),
                    "{id}"
                );
                assert_eq!(
                    Some(verify_crl(crl, &keys)),
                    expected["verifies"].as_bool(),
                    "{id}"
                );
            }
            other => panic!("{id}: unknown kind {other}"),
        }
        seen.insert(id.to_owned());
    }
    for id in [
        "node-001", "node-002", "node-003", "node-004", "node-005", "node-006", "node-007",
        "cert-001", "cert-002", "crl-001", "crl-002",
    ] {
        assert!(seen.contains(id), "{id} is missing from node.json");
    }
}

#[test]
fn a_certificate_or_crl_without_its_fields_does_not_verify() {
    let keys = [public(&key("c"))];
    for case in vectors() {
        match text(&case, "id") {
            "cert-001" => {
                let certificate = &case["input"]["certificate"];
                assert!(verify_join_certificate(certificate, &keys));
                // The edge block is not signed; the signed fields are.
                let mut without_edge = certificate.clone();
                without_edge.as_object_mut().unwrap().remove("edge");
                assert!(verify_join_certificate(&without_edge, &keys));
                for field in ["cert_id", "roles", "expires_at"] {
                    let mut missing = certificate.clone();
                    missing.as_object_mut().unwrap().remove(field);
                    assert!(!verify_join_certificate(&missing, &keys), "{field}");
                }
                assert!(!verify_join_certificate(certificate, &[public(&key("a"))]));
            }
            "crl-001" => {
                let crl = &case["input"]["crl"];
                assert!(verify_crl(crl, &keys));
                let mut later = crl.clone();
                later["sequence"] = serde_json::json!(8);
                assert!(!verify_crl(&later, &keys));
                assert!(!verify_crl(&serde_json::json!([]), &keys));
            }
            _ => {}
        }
    }
}
