//! Value rules the record modules share (a leaf: it imports nothing from
//! the crate): the metadata size limit, the secret-material guard and the
//! reference's number normalization. Kept here so the record, strict and
//! verification modules use them without importing one another.

use serde_json::{json, Value};

/// Limit on `execution_parameters` plus `outcome_detail`, as enforced by the
/// NA; for an observation or break-glass record (1.3.1), on the values its
/// guard covers, counted as the NA counts them.
pub const MAX_METADATA_BYTES: usize = 16 * 1024;

const SECRET_KEYS: [&str; 18] = [
    "value",
    "secret",
    "secretvalue",
    "password",
    "passwd",
    "passphrase",
    "token",
    "accesstoken",
    "refreshtoken",
    "bearer",
    "privatekey",
    "keymaterial",
    "credential",
    "credentials",
    "clientsecret",
    "apikey",
    "pem",
    "connectionstring",
];

fn normalise_key(key: &str) -> String {
    key.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn token_chars(part: &str) -> bool {
    part.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn looks_like_key_material(value: &str) -> bool {
    // The reference's patterns end in `$`, which also matches before a final
    // newline (1.3.1).
    let value = value.strip_suffix('\n').unwrap_or(value);
    let long_opaque = value.len() >= 120
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b));
    let jwt = value.strip_prefix("eyJ").is_some_and(|rest| {
        let parts: Vec<&str> = rest.split('.').collect();
        parts.len() == 3
            && !parts[0].is_empty()
            && !parts[1].is_empty()
            && parts.iter().all(|p| token_chars(p))
    });
    long_opaque || jwt
}

/// The reference's `_secret_material`: the first field named like a secret,
/// PEM block, key or token under `path`.
pub(crate) fn secret_material(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, item)| secret_material(item, &format!("{path}{i}."))),
        Value::Object(map) => map.iter().find_map(|(key, inner)| {
            if SECRET_KEYS.contains(&normalise_key(key).as_str()) {
                Some(format!(
                    "field '{path}{key}' is not allowed in evidence metadata"
                ))
            } else {
                secret_material(inner, &format!("{path}{key}."))
            }
        }),
        Value::String(text) => {
            let field = path.trim_end_matches('.');
            if text.contains("-----BEGIN") {
                Some(format!("field '{field}' contains a PEM block"))
            } else if looks_like_key_material(text) {
                Some(format!("field '{field}' looks like key or token material"))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A number as an envelope holds it (the reference's `normalize_number`):
/// an integral number as an integer (`5.0` is `5`), within 64 bits (from
/// -2^63 to 2^64 - 1); another number as it is. Refused: a boolean, any
/// other non-number, and an integer beyond 64 bits.
pub fn normalize_number(value: &Value) -> std::result::Result<Value, String> {
    let Value::Number(n) = value else {
        return Err("a number is expected".into());
    };
    if n.is_i64() || n.is_u64() {
        return Ok(value.clone());
    }
    let x = n
        .as_f64()
        .filter(|x| x.is_finite())
        .ok_or("numbers must be finite")?;
    if x.fract() != 0.0 {
        return Ok(value.clone());
    }
    // -2^63 <= x <= 2^64 - 1; the largest double below 2^64 is 2^64 - 2048.
    if (-9_223_372_036_854_775_808.0..18_446_744_073_709_551_616.0).contains(&x) {
        Ok(if x < 0.0 {
            json!(x as i64)
        } else {
            json!(x as u64)
        })
    } else {
        Err("integers must fit in 64 bits".into())
    }
}
