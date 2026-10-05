use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer};
use genesis_mesh_sdk::{
    admin_signing_payload, build_admin_headers, build_admin_headers_at, canonical_json, json,
    load_signing_key, AdminRequest, Value,
};

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
    let request = AdminRequest {
        method: "POST",
        path: "/admin/invite",
        query: &[],
        audience: "TEST",
        body: &body,
    };
    let headers = build_admin_headers(&request, "test-key", &key).unwrap();
    let second = build_admin_headers(&request, "test-key", &key).unwrap();
    assert_ne!(headers.nonce, second.nonce);
    assert_eq!(
        uuid::Uuid::parse_str(&headers.nonce)
            .unwrap()
            .get_version_num(),
        4
    );
    chrono::DateTime::parse_from_rfc3339(&headers.timestamp).unwrap();
    let payload = admin_signing_payload(
        &request,
        &headers.key_id,
        &headers.timestamp,
        &headers.nonce,
    )
    .unwrap();
    let signature = Signature::from_slice(&STANDARD.decode(&headers.signature).unwrap()).unwrap();
    key.verifying_key()
        .verify_strict(payload.as_bytes(), &signature)
        .unwrap();
    // The same signature must not verify for another method, path, query or audience.
    let query = [("limit".to_owned(), "1".to_owned())];
    for other in [
        AdminRequest {
            method: "PUT",
            ..request
        },
        AdminRequest {
            path: "/admin/revoke",
            ..request
        },
        AdminRequest {
            query: &query,
            ..request
        },
        AdminRequest {
            audience: "OTHER",
            ..request
        },
    ] {
        let other =
            admin_signing_payload(&other, &headers.key_id, &headers.timestamp, &headers.nonce)
                .unwrap();
        assert!(key
            .verifying_key()
            .verify_strict(other.as_bytes(), &signature)
            .is_err());
    }
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

/// Shared reference vectors (genesismesh conformance/vectors/admin_auth.json),
/// copied unchanged. Seed "a" of the reference suite is bytes 0..31.
#[test]
fn matches_admin_signature_conformance_vectors() {
    let suite: Value = serde_json::from_str(include_str!("fixtures/admin_auth.json")).unwrap();
    let key =
        load_signing_key(&STANDARD.encode(std::array::from_fn::<_, 32, _>(|i| i as u8))).unwrap();
    for vector in suite["vectors"].as_array().unwrap() {
        let input = &vector["input"];
        let mut query = Vec::new();
        for (name, values) in input["query"].as_object().unwrap() {
            for value in values.as_array().unwrap() {
                query.push((name.clone(), value.as_str().unwrap().to_owned()));
            }
        }
        let request = AdminRequest {
            method: input["method"].as_str().unwrap(),
            path: input["path"].as_str().unwrap(),
            query: &query,
            audience: input["audience"].as_str().unwrap(),
            body: &input["body"],
        };
        let (key_id, timestamp, nonce) = (
            input["key_id"].as_str().unwrap(),
            input["timestamp"].as_str().unwrap(),
            input["nonce"].as_str().unwrap(),
        );
        assert_eq!(
            admin_signing_payload(&request, key_id, timestamp, nonce).unwrap(),
            vector["expected"]["payload"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
        let headers = build_admin_headers_at(&request, key_id, &key, timestamp, nonce).unwrap();
        assert_eq!(
            headers.signature, vector["expected"]["signature_b64"],
            "{}",
            vector["id"]
        );
    }
}
