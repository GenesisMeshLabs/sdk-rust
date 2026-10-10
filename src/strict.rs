//! Strict verification (v1.2.0): every signed field of a record is known.
//!
//! Before 1.2.0 this crate copied every received field into the signed form,
//! so a field a newer signer covered verified here and could change what a
//! record means. The registry (`src/canonical_registry.json`, generated from
//! the Python reference and shipped in the shared conformance suite
//! `field_registry`) lists every field of every record this crate verifies.
//! Verifiers check the signature over the record as received first; a signed
//! field the registry does not list is then refused as `unknown_field`, and an
//! evidence export entry of another kind as `unknown_entry_kind`. A record
//! signed over a form the reference does not write is refused as
//! `non_canonical_form`; this crate checks the form of the timestamps the
//! registry marks (v1.2.0), and that no field the reference always writes is
//! left out (v1.3.0, [`non_canonical_fields`]). See the core's reference page
//! "Canonical Form of Signed Records".

use std::sync::LazyLock;

use serde_json::Value;

static REGISTRY: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("canonical_registry.json"))
        .expect("the embedded canonical registry is valid JSON")
});

/// The embedded registry, for the conformance tests. Regenerate it with
/// `python scripts/sync_canonical_registry.py` after copying a new suite.
#[doc(hidden)]
pub fn embedded_registry() -> &'static Value {
    &REGISTRY
}

#[derive(Clone)]
enum Step {
    Key(String),
    Index(usize),
}

fn render(prefix: &str, steps: &[Step]) -> String {
    let parts: Vec<String> = steps
        .iter()
        .map(|s| match s {
            Step::Key(k) => k.clone(),
            Step::Index(i) => i.to_string(),
        })
        .collect();
    format!("{prefix}{}", parts.join("."))
}

fn outside_projection(spec: &Value, key: &str) -> bool {
    spec["signature_field"].as_str() == Some(key)
        || spec["canonical_fields"]
            .as_array()
            .is_some_and(|fields| !fields.iter().any(|f| f.as_str() == Some(key)))
}

fn collect(model: &str, data: &Value, path: &[Step], projection: bool, found: &mut Vec<Vec<Step>>) {
    let spec = &REGISTRY["models"][model];
    let (Some(fields), Some(record)) = (spec["fields"].as_object(), data.as_object()) else {
        return;
    };
    for (key, value) in record {
        if projection && outside_projection(spec, key) {
            continue;
        }
        let mut here = path.to_vec();
        here.push(Step::Key(key.clone()));
        let Some(kind) = fields.get(key) else {
            found.push(here);
            continue;
        };
        if value.is_null() {
            continue;
        }
        if let Some(nested) = kind.get("object").and_then(Value::as_str) {
            collect(nested, value, &here, false, found);
        } else if let Some(nested) = kind.get("list").and_then(Value::as_str) {
            for (i, item) in value.as_array().into_iter().flatten().enumerate() {
                let mut at = here.clone();
                at.push(Step::Index(i));
                collect(nested, item, &at, false, found);
            }
        } else if let Some(nested) = kind.get("map").and_then(Value::as_str) {
            for (k, item) in value.as_object().into_iter().flatten() {
                let mut at = here.clone();
                at.push(Step::Key(k.clone()));
                collect(nested, item, &at, false, found);
            }
        }
    }
}

/// Dotted paths, sorted by code point, of the signed fields in `data` that
/// `model` does not define, at any depth (`policy_binding.policies.0.extra`).
/// Only the signed projection is checked (not the signature, not an
/// agreement's unsigned fields); free-form fields are not inspected; values
/// of the wrong type are left to validation.
pub fn unknown_fields(model: &str, data: &Value) -> Vec<String> {
    prefixed_unknown_fields(model, data, "")
}

pub(crate) fn prefixed_unknown_fields(model: &str, data: &Value, prefix: &str) -> Vec<String> {
    let mut found = Vec::new();
    collect(model, data, &[], true, &mut found);
    let mut paths: Vec<String> = found.iter().map(|steps| render(prefix, steps)).collect();
    // UTF-8 byte order is code point order, as every implementation sorts.
    paths.sort();
    paths
}

/// True when this crate knows the evidence entry kind.
pub fn is_known_entry_kind(kind: &str) -> bool {
    REGISTRY["entry_kinds"]
        .as_array()
        .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some(kind)))
}

/// A copy of `data` without its unknown signed fields: what the signer did sign.
pub(crate) fn without_unknown_fields(model: &str, data: &Value) -> Value {
    let mut copy = data.clone();
    let mut found = Vec::new();
    collect(model, data, &[], true, &mut found);
    for steps in found {
        let Some((last, parents)) = steps.split_last() else {
            continue;
        };
        let mut node = &mut copy;
        for step in parents {
            node = match step {
                Step::Key(k) => &mut node[k.as_str()],
                Step::Index(i) => &mut node[*i],
            };
        }
        if let (Step::Key(k), Some(object)) = (last, node.as_object_mut()) {
            object.remove(k);
        }
    }
    copy
}

/// A root's canonical rules, for the conformance tests.
#[doc(hidden)]
pub fn registry_list(model: &str, rule: &str) -> Vec<String> {
    REGISTRY["models"][model][rule]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// True when `value` is a timestamp in canonical form (v1.2.0): what the
/// reference writes, `YYYY-MM-DDTHH:MM:SS`, six digits of microseconds when
/// not all zero, then `Z` for UTC or `+HH:MM` / `-HH:MM` for another offset
/// (none for a timestamp without one), naming an instant that exists.
pub fn canonical_timestamp(value: &str) -> bool {
    let b = value.as_bytes();
    let digits = |from: usize, len: usize| -> Option<u32> {
        let part = b.get(from..from + len)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| std::str::from_utf8(part).ok()?.parse().ok())?
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0, 4),
        digits(5, 2),
        digits(8, 2),
        digits(11, 2),
        digits(14, 2),
        digits(17, 2),
    ) else {
        return false;
    };
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return false;
    }
    let mut at = 19;
    if b.get(at) == Some(&b'.') {
        match digits(at + 1, 6) {
            Some(0) | None => return false,
            Some(_) => at += 7,
        }
    }
    match &b[at..] {
        b"" | b"Z" => {}
        [sign @ (b'+' | b'-'), zone @ ..] if zone.len() == 5 && zone[2] == b':' => {
            let (Some(h), Some(m)) = (digits(at + 1, 2), digits(at + 4, 2)) else {
                return false;
            };
            if h > 23 || m > 59 || (h == 0 && m == 0) {
                let _ = sign;
                return false;
            }
        }
        _ => return false,
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days[month as usize - 1]
        && hour <= 23
        && minute <= 59
        && second <= 59
}

/// Dotted paths, sorted, of the timestamps in `data`'s signed projection
/// that are not in canonical form (v1.2.0). Values that are not strings are
/// left to validation.
pub fn non_canonical_timestamps(model: &str, data: &Value) -> Vec<String> {
    fn walk(model: &str, data: &Value, prefix: &str, projection: bool, found: &mut Vec<String>) {
        let spec = &REGISTRY["models"][model];
        let (Some(fields), Some(record)) = (spec["fields"].as_object(), data.as_object()) else {
            return;
        };
        for (key, value) in record {
            if projection && outside_projection(spec, key) || value.is_null() {
                continue;
            }
            let Some(kind) = fields.get(key) else {
                continue;
            };
            if kind == "timestamp" {
                let loose = match value {
                    Value::Array(items) => items
                        .iter()
                        .any(|i| i.as_str().is_some_and(|s| !canonical_timestamp(s))),
                    other => other.as_str().is_some_and(|s| !canonical_timestamp(s)),
                };
                if loose {
                    found.push(format!("{prefix}{key}"));
                }
            } else if let Some(nested) = kind.get("object").and_then(Value::as_str) {
                walk(nested, value, &format!("{prefix}{key}."), false, found);
            } else if let Some(nested) = kind.get("list").and_then(Value::as_str) {
                for (i, item) in value.as_array().into_iter().flatten().enumerate() {
                    walk(nested, item, &format!("{prefix}{key}.{i}."), false, found);
                }
            } else if let Some(nested) = kind.get("map").and_then(Value::as_str) {
                for (k, item) in value.as_object().into_iter().flatten() {
                    walk(nested, item, &format!("{prefix}{key}.{k}."), false, found);
                }
            }
        }
    }
    let mut found = Vec::new();
    walk(model, data, "", true, &mut found);
    found.sort();
    found
}

/// Dotted paths, sorted, where `data`'s signed projection differs from the
/// form the reference writes (v1.3.0): timestamps not in canonical form
/// ([`non_canonical_timestamps`]), and a field the reference always writes
/// left out, at any depth. A field the reference leaves out when absent
/// (`omit_when_none`) reads the same absent or `null`. A record signed over
/// such a form is refused as `non_canonical_form`, as the reference refuses
/// it.
pub fn non_canonical_fields(model: &str, data: &Value) -> Vec<String> {
    fn walk(model: &str, data: &Value, prefix: &str, projection: bool, found: &mut Vec<String>) {
        let spec = &REGISTRY["models"][model];
        let (Some(fields), Some(record)) = (spec["fields"].as_object(), data.as_object()) else {
            return;
        };
        let omitted = |key: &str| {
            spec["omit_when_none"]
                .as_array()
                .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(key)))
        };
        for (key, kind) in fields {
            if projection && outside_projection(spec, key) {
                continue;
            }
            let Some(value) = record.get(key) else {
                if !omitted(key) {
                    found.push(format!("{prefix}{key}"));
                }
                continue;
            };
            if value.is_null() {
                continue;
            }
            if let Some(nested) = kind.get("object").and_then(Value::as_str) {
                walk(nested, value, &format!("{prefix}{key}."), false, found);
            } else if let Some(nested) = kind.get("list").and_then(Value::as_str) {
                for (i, item) in value.as_array().into_iter().flatten().enumerate() {
                    walk(nested, item, &format!("{prefix}{key}.{i}."), false, found);
                }
            } else if let Some(nested) = kind.get("map").and_then(Value::as_str) {
                for (k, item) in value.as_object().into_iter().flatten() {
                    walk(nested, item, &format!("{prefix}{key}.{k}."), false, found);
                }
            }
        }
    }
    let mut found = non_canonical_timestamps(model, data);
    walk(model, data, "", true, &mut found);
    found.sort();
    found.dedup();
    found
}
