use std::fmt::Write;

use base64::{engine::general_purpose, Engine as _};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
    let mut output = String::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Object(map) => {
            output.push('{');
            // Sort explicitly even when a downstream crate enables preserve_order.
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_string(key, output)?;
                output.push(':');
                write_canonical(&map[key], output)?;
            }
            output.push('}');
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(value, output)?;
            }
            output.push(']');
        }
        Value::String(value) => write_string(value, output)?,
        Value::Number(number) if number.is_f64() => {
            output.push_str(&python_float(number.as_f64().expect("JSON float")));
        }
        _ => output.push_str(&serde_json::to_string(value)?),
    }
    Ok(())
}

fn write_string(value: &str, output: &mut String) -> Result<()> {
    // Python's default ensure_ascii=True also escapes DEL and uses UTF-16
    // surrogate pairs for characters outside the basic multilingual plane.
    for character in serde_json::to_string(value)?.chars() {
        if character >= '\u{7f}' {
            let mut units = [0; 2];
            for unit in character.encode_utf16(&mut units) {
                write!(output, "\\u{unit:04x}").expect("writing to String cannot fail");
            }
        } else {
            output.push(character);
        }
    }
    Ok(())
}

fn python_float(value: f64) -> String {
    // Rust's shortest float formatter supplies the digits. Python switches to
    // scientific notation below 1e-4 and at 1e16, and pads exponent digits.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific float");
    let exponent: i32 = exponent.parse().expect("float exponent");
    if !(-4..16).contains(&exponent) {
        format!("{mantissa}e{exponent:+03}")
    } else {
        let mut decimal = value.to_string();
        if !decimal.contains('.') {
            decimal.push_str(".0");
        }
        decimal
    }
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

/// Lowercase hex SHA-256 of a value's canonical JSON, as the Python models'
/// `digest()` methods compute it.
pub fn canonical_digest(value: &Value) -> Result<String> {
    Ok(sha256_hex(canonical_json(value)?.as_bytes()))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

/// Sign a canonical body: `{"key_id", "sig"}` as embedded in GM signed models.
pub fn sign_canonical(canonical: &str, key_id: &str, signing_key: &SigningKey) -> Value {
    let signature = signing_key.sign(canonical.as_bytes());
    json!({"key_id": key_id, "sig": general_purpose::STANDARD.encode(signature.to_bytes())})
}

/// True when `signature_base64` verifies `canonical` under any of the raw
/// base64 Ed25519 public keys. Malformed keys and signatures do not verify.
pub fn verify_canonical(canonical: &str, signature_base64: &str, public_keys: &[String]) -> bool {
    let Ok(signature) = general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|_| ())
        .and_then(|bytes| Signature::from_slice(&bytes).map_err(|_| ()))
    else {
        return false;
    };
    public_keys.iter().any(|key| {
        general_purpose::STANDARD
            .decode(key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .is_some_and(|key| key.verify_strict(canonical.as_bytes(), &signature).is_ok())
    })
}

/// Raw base64 Ed25519 public key for a base64 seed.
pub fn public_key_from_seed(seed_base64: &str) -> Result<String> {
    let key = load_signing_key(seed_base64)?;
    Ok(general_purpose::STANDARD.encode(key.verifying_key().to_bytes()))
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
    fn signs_and_verifies_canonical_bodies() {
        let seed = general_purpose::STANDARD.encode([9_u8; 32]);
        let key = load_signing_key(&seed).unwrap();
        let public = public_key_from_seed(&seed).unwrap();
        let signature = sign_canonical("{\"a\":1}", "k", &key);
        let sig = signature["sig"].as_str().unwrap();
        assert!(verify_canonical(
            "{\"a\":1}",
            sig,
            std::slice::from_ref(&public)
        ));
        assert!(!verify_canonical(
            "{\"a\":2}",
            sig,
            std::slice::from_ref(&public)
        ));
        assert!(!verify_canonical("{\"a\":1}", "not base64", &[public]));
        assert!(!verify_canonical("{\"a\":1}", sig, &["short".into()]));
    }

    #[test]
    fn digests_canonical_json() {
        assert_eq!(
            canonical_digest(&json!({"b": 1, "a": "é"})).unwrap(),
            sha256_hex(br#"{"a":"\u00e9","b":1}"#)
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
