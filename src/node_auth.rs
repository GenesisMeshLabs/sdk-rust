//! Node request signatures (1.7.0, beta): how a node signs its requests to
//! the Network Authority (`/join`, `/heartbeat`, `/renew` and the node-scoped
//! routes `/node/*`), and how an edge node proves it holds its executor key
//! when it joins. Pure: no network.
//!
//! A node request is a JSON object signed by the node key. The signature is
//! Ed25519 over the canonical JSON of the body without its `signature`
//! ([`canonical_json`]: sorted keys, no spaces, ASCII escapes), encoded as
//! base64, and the body carries a `timestamp` (RFC 3339, UTC, within 300
//! seconds of the NA's clock) and a fresh `nonce` (UUID v4). Nothing in the
//! signature binds the route: the `/node/*` routes add a `purpose` naming
//! the route and an `audience` naming the NA's public key.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    auth::canonical_json,
    errors::{GenesisMeshError, Result},
};

/// The `purpose` of `POST /node/boundary/evaluate`.
pub const PURPOSE_BOUNDARY_EVALUATE: &str = "node_boundary_evaluate";
/// The `purpose` of `POST /node/state`.
pub const PURPOSE_STATE: &str = "node_state";
/// The `purpose` of `POST /node/evidence/resource-head`.
pub const PURPOSE_RESOURCE_HEAD: &str = "node_resource_head";

fn object(body: &Value) -> Result<&serde_json::Map<String, Value>> {
    body.as_object().ok_or_else(|| {
        GenesisMeshError::Configuration("a node request body must be a JSON object".into())
    })
}

fn without(body: &Value, fields: &[&str]) -> Result<String> {
    let mut map = object(body)?.clone();
    for field in fields {
        map.remove(*field);
    }
    canonical_json(&Value::Object(map))
}

/// The bytes a node signs: the canonical JSON of `body` without its
/// `signature`, exactly as the NA verifies it.
pub fn node_signing_payload(body: &Value) -> Result<String> {
    without(body, &["signature"])
}

/// The bytes the executor key signs at `/join`: the canonical JSON of `body`
/// without `signature` and `executor_signature`.
pub fn executor_proof_payload(body: &Value) -> Result<String> {
    without(body, &["signature", "executor_signature"])
}

fn signature(key: &SigningKey, payload: &str) -> String {
    STANDARD.encode(key.sign(payload.as_bytes()).to_bytes())
}

/// A node request timestamp, as the reference node writes it:
/// `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`.
pub fn node_timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, false)
}

/// `body` with `timestamp` and `nonce` set and signed by the node key
/// (`signature`, base64). Sign the executor proof first
/// ([`sign_executor_proof`]): this signature covers it.
pub fn sign_node_request(
    body: Value,
    node_key: &SigningKey,
    timestamp: &str,
    nonce: &str,
) -> Result<Value> {
    object(&body)?;
    let mut body = body;
    body["timestamp"] = json!(timestamp);
    body["nonce"] = json!(nonce);
    let signed = signature(node_key, &node_signing_payload(&body)?);
    body["signature"] = json!(signed);
    Ok(body)
}

/// `body` with `executor_signature` set: the executor key's signature over
/// [`executor_proof_payload`], its proof of possession at `/join`. The body
/// must already carry everything the node signs but `signature` (its
/// `timestamp` and `nonce` included); sign it with the node key afterwards
/// ([`sign_node_request`] with the same timestamp and nonce).
pub fn sign_executor_proof(body: Value, executor_key: &SigningKey) -> Result<Value> {
    let mut body = body;
    let signed = signature(executor_key, &executor_proof_payload(&body)?);
    body["executor_signature"] = json!(signed);
    Ok(body)
}

/// The executor key ID the NA registers for an edge node's executor key:
/// `edge-` and the first 32 hex characters of the SHA-256 of the raw 32-byte
/// public key (given as base64).
pub fn executor_key_id(public_key_b64: &str) -> Result<String> {
    let raw = STANDARD
        .decode(public_key_b64)
        .ok()
        .filter(|raw| raw.len() == 32)
        .ok_or_else(|| {
            GenesisMeshError::Configuration("an executor public key is 32 bytes of base64".into())
        })?;
    let digest = Sha256::digest(&raw);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("edge-{}", &hex[..32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verify_canonical;

    #[test]
    fn signs_everything_but_the_signature() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let public = STANDARD.encode(key.verifying_key().to_bytes());
        let body = json!({"cert_id": "c", "node_public_key": public, "purpose": PURPOSE_STATE});
        let nonce = uuid::Uuid::new_v4().to_string();
        let signed =
            sign_node_request(body, &key, "2026-10-14T12:00:00.000000+00:00", &nonce).unwrap();
        let payload = node_signing_payload(&signed).unwrap();
        assert!(!payload.contains("signature"));
        assert!(verify_canonical(
            &payload,
            signed["signature"].as_str().unwrap(),
            &[public]
        ));
    }

    #[test]
    fn an_executor_key_id_is_edge_and_32_hex_characters() {
        let id = executor_key_id(&STANDARD.encode([2; 32])).unwrap();
        assert!(id.starts_with("edge-"));
        assert_eq!(id.len(), 37);
        assert!(executor_key_id("AAAA").is_err());
    }

    #[test]
    fn a_node_timestamp_has_microseconds_and_an_offset() {
        let at = DateTime::parse_from_rfc3339("2026-10-14T12:00:00.5Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(node_timestamp(at), "2026-10-14T12:00:00.500000+00:00");
    }
}
