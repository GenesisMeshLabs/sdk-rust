use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer};
use genesis_mesh_sdk::{build_admin_headers, canonical_json, json, load_signing_key, Value};

#[test]
fn matches_python_canonical_json_fixtures() {
    let fixtures: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/python_canonical.json")).unwrap();
    for fixture in fixtures {
        assert_eq!(
            canonical_json(&fixture["value"]).unwrap(),
            fixture["canonical"].as_str().unwrap(),
            "value: {}",
            fixture["value"]
        );
    }
}

#[test]
fn matches_python_ed25519_signature() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/python_signature.json")).unwrap();
    let key =
        load_signing_key(&STANDARD.encode(std::array::from_fn::<_, 32, _>(|i| i as u8))).unwrap();
    let canonical = canonical_json(&fixture["payload"]).unwrap();
    assert_eq!(canonical, fixture["canonical"].as_str().unwrap());
    assert_eq!(
        STANDARD.encode(key.sign(canonical.as_bytes()).to_bytes()),
        fixture["signature"]
    );
}

#[test]
fn headers_verify_and_use_unique_nonces() {
    let key = load_signing_key(&STANDARD.encode([7; 32])).unwrap();
    let body = json!({"message": "Hej 世界", "weight": 1e-7});
    let headers = build_admin_headers(&body, "test-key", &key).unwrap();
    let second = build_admin_headers(&body, "test-key", &key).unwrap();
    assert_ne!(headers.nonce, second.nonce);
    assert_eq!(
        uuid::Uuid::parse_str(&headers.nonce)
            .unwrap()
            .get_version_num(),
        4
    );
    chrono::DateTime::parse_from_rfc3339(&headers.timestamp).unwrap();
    let payload = json!({"body": body, "key_id": headers.key_id, "nonce": headers.nonce, "timestamp": headers.timestamp});
    let signature = Signature::from_slice(&STANDARD.decode(&headers.signature).unwrap()).unwrap();
    key.verifying_key()
        .verify_strict(canonical_json(&payload).unwrap().as_bytes(), &signature)
        .unwrap();
    assert!(key
        .verifying_key()
        .verify_strict(b"tampered", &signature)
        .is_err());
}

#[test]
fn seed_loading_accepts_padding_and_rejects_invalid_input() {
    let encoded = STANDARD.encode([3; 32]);
    assert_eq!(load_signing_key(&encoded).unwrap().to_bytes(), [3; 32]);
    assert_eq!(
        load_signing_key(encoded.trim_end_matches('='))
            .unwrap()
            .to_bytes(),
        [3; 32]
    );
    for invalid in [
        "%%%".to_owned(),
        STANDARD.encode([0; 31]),
        STANDARD.encode([0; 64]),
    ] {
        assert!(load_signing_key(&invalid).is_err());
    }
}
