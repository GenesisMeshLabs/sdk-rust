//! 1.9.2: `verify_boundary_decision_expecting` checks an expected attestation
//! ID or subject ID without the attestation itself.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{
    canonical::{decision_canonical, python_timestamp},
    sign_canonical,
    verify::{verify_boundary_decision_expecting, ExpectedBinding, VerifyDecisionOptions},
};
use serde_json::{json, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/python-vectors.json")).unwrap()
}

/// The reference's allowed or denied decision, re-signed now with a test NA
/// key (the vectors' decisions expire within minutes of generation).
fn decision(allowed: bool, with_binding: bool) -> (Value, VerifyDecisionOptions) {
    let na = SigningKey::from_bytes(&[7; 32]);
    let mut decision = vectors()[if allowed { "allowed" } else { "denied" }]["decision"].clone();
    if !with_binding {
        decision
            .as_object_mut()
            .unwrap()
            .remove("attestation_binding");
    }
    let now = chrono::Utc::now();
    decision["decision_made_at"] = json!(python_timestamp(now));
    decision["decision_valid_until"] = json!(python_timestamp(now + chrono::Duration::minutes(5)));
    let canonical = decision_canonical(&decision).unwrap();
    decision["signature"] = sign_canonical(&canonical, "na", &na);
    let options = VerifyDecisionOptions {
        operator_public_keys: vec![STANDARD.encode(na.verifying_key().to_bytes())],
        ..Default::default()
    };
    (decision, options)
}

fn bound(field: &str) -> String {
    vectors()["allowed"]["decision"]["attestation_binding"][field]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn expected_attestation_and_subject_ids() {
    let (attestation, subject) = (bound("attestation_id"), bound("subject_id"));
    let cases = [
        (ExpectedBinding::new(), true, "authorized"),
        (
            ExpectedBinding::new()
                .attestation_id(&attestation)
                .subject_id(&subject),
            true,
            "authorized",
        ),
        (
            ExpectedBinding::new().attestation_id(&attestation),
            true,
            "authorized",
        ),
        (
            ExpectedBinding::new().subject_id(&subject),
            true,
            "authorized",
        ),
        (
            ExpectedBinding::new().attestation_id("another"),
            false,
            "attestation_binding_mismatch",
        ),
        (
            ExpectedBinding::new().subject_id("vendor-other"),
            false,
            "attestation_binding_mismatch",
        ),
        (
            ExpectedBinding::new()
                .attestation_id(&attestation)
                .subject_id("vendor-other"),
            false,
            "attestation_binding_mismatch",
        ),
    ];
    let (decision, options) = decision(true, true);
    for (expected, accepted, reason) in cases {
        let r = verify_boundary_decision_expecting(&decision, &options, &expected);
        assert_eq!(
            (r.accepted, r.reason.as_str()),
            (accepted, reason),
            "{expected:?}"
        );
        assert!(r.authorized);
    }
}

#[test]
fn a_denial_for_another_subject_is_refused_and_stays_a_denial() {
    let (decision, options) = decision(false, true);
    let ok = verify_boundary_decision_expecting(&decision, &options, &ExpectedBinding::new());
    assert!(ok.accepted && !ok.authorized, "{ok:?}");
    let r = verify_boundary_decision_expecting(
        &decision,
        &options,
        &ExpectedBinding::new().subject_id("vendor-other"),
    );
    assert_eq!(
        (r.accepted, r.authorized, r.reason.as_str()),
        (false, false, "attestation_binding_mismatch")
    );
}

#[test]
fn an_expectation_needs_an_attestation_binding() {
    let (decision, options) = decision(true, false);
    assert!(
        verify_boundary_decision_expecting(&decision, &options, &ExpectedBinding::new()).accepted
    );
    for expected in [
        ExpectedBinding::new().attestation_id("a"),
        ExpectedBinding::new().subject_id("s"),
    ] {
        let r = verify_boundary_decision_expecting(&decision, &options, &expected);
        assert_eq!(
            (r.accepted, r.reason.as_str()),
            (false, "attestation_binding_missing")
        );
    }
}

#[test]
fn an_earlier_refusal_wins() {
    let (mut decision, options) = decision(true, true);
    decision["denial_reason"] = json!("edited after signing");
    let r = verify_boundary_decision_expecting(
        &decision,
        &options,
        &ExpectedBinding::new().subject_id("vendor-other"),
    );
    assert_eq!(r.reason, "invalid_signature");
}
