use std::collections::BTreeMap;

use base64::{engine::general_purpose, Engine as _};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::errors::{GenesisMeshError, Result};

/// The four X-Admin-* headers used to authenticate admin API requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminHeaders {
    /// Operator key identifier registered with the Network Authority.
    pub key_id: String,
    /// Base64 Ed25519 signature over the canonical admin payload.
    pub signature: String,
    /// UTC ISO 8601 timestamp with millisecond precision.
    pub timestamp: String,
    /// UUID v4 replay-protection nonce.
    pub nonce: String,
}

/// Decode a base64-encoded 32-byte Ed25519 seed into a signing key.
pub fn load_signing_key(seed_base64: &str) -> Result<SigningKey> {
    let seed = general_purpose::STANDARD
        .decode(seed_base64)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(seed_base64))
        .map_err(|err| {
            GenesisMeshError::SigningKey(format!("invalid signing key base64: {err}"))
        })?;

    let seed: [u8; 32] = seed.try_into().map_err(|bytes: Vec<u8>| {
        GenesisMeshError::SigningKey(format!("signing key must be 32 bytes, got {}", bytes.len()))
    })?;

    Ok(SigningKey::from_bytes(&seed))
}

/// Produce deterministic compact JSON matching Python
/// `json.dumps(value, sort_keys=True, separators=(",",":"))`.
pub fn canonical_json(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => canonical_object(map),
        Value::Array(values) => {
            let items = values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", items.join(",")))
        }
        _ => serde_json::to_string(value).map_err(GenesisMeshError::Json),
    }
}

fn canonical_object(map: &Map<String, Value>) -> Result<String> {
    let sorted = map.iter().collect::<BTreeMap<_, _>>();
    let mut parts = Vec::with_capacity(sorted.len());

    for (key, value) in sorted {
        let key_json = serde_json::to_string(key).map_err(GenesisMeshError::Json)?;
        parts.push(format!("{key_json}:{}", canonical_json(value)?));
    }

    Ok(format!("{{{}}}", parts.join(",")))
}

/// Build the four admin auth headers for an admin request body.
pub fn build_admin_headers(
    body: &Value,
    key_id: &str,
    signing_key: &SigningKey,
) -> Result<AdminHeaders> {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let nonce = Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "body": body,
        "key_id": key_id,
        "nonce": nonce,
        "timestamp": timestamp,
    });
    let canonical = canonical_json(&payload)?;
    let signature = signing_key.sign(canonical.as_bytes());

    Ok(AdminHeaders {
        key_id: key_id.to_owned(),
        signature: general_purpose::STANDARD.encode(signature.to_bytes()),
        timestamp,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys() {
        let value = json!({"z": 3, "a": 1, "m": 2});
        assert_eq!(canonical_json(&value).unwrap(), r#"{"a":1,"m":2,"z":3}"#);
    }

    #[test]
    fn canonical_json_sorts_nested_keys() {
        let value = json!({"body": {"foo": "bar"}, "timestamp": "t", "nonce": "n", "key_id": "k"});
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"body":{"foo":"bar"},"key_id":"k","nonce":"n","timestamp":"t"}"#
        );
    }

    #[test]
    fn load_signing_key_rejects_wrong_length() {
        let encoded = general_purpose::STANDARD.encode(b"too-short");
        assert!(load_signing_key(&encoded).is_err());
    }

    #[test]
    fn build_admin_headers_returns_required_fields() {
        let seed = general_purpose::STANDARD.encode([0_u8; 32]);
        let key = load_signing_key(&seed).unwrap();
        let headers = build_admin_headers(&json!({"foo": "bar"}), "operator-local", &key).unwrap();

        assert_eq!(headers.key_id, "operator-local");
        assert!(!headers.signature.is_empty());
        assert!(!headers.timestamp.is_empty());
        assert!(!headers.nonce.is_empty());
        assert_eq!(
            general_purpose::STANDARD
                .decode(headers.signature)
                .unwrap()
                .len(),
            64
        );
    }
}
