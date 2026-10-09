//! Strict verification (v1.2.0): every field of a signed record is known.
//!
//! A verifier that copies every received field into the signed form accepts a
//! field it does not understand whenever the signer covered it, so a field
//! added in a later release could change what a record means. The registry
//! (`src/canonical_registry.json`, generated from the Python reference and
//! shipped in the shared conformance suite `canonical`) lists every field of
//! every record this SDK verifies; anything else is refused as
//! `unknown_field`, and an evidence export entry of another kind as
//! `unknown_entry_kind`. See the core's reference page "Canonical Form of
//! Signed Records".

use std::sync::LazyLock;

use serde_json::Value;

/// The field registry of signed records. Regenerate with
/// `python scripts/sync_canonical_registry.py` after copying a new suite.
pub static CANONICAL_REGISTRY: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("canonical_registry.json"))
        .expect("the embedded canonical registry is valid JSON")
});

/// Dotted paths of the fields in `data` that `model` does not define, at any
/// depth (`policy_binding.policies.0.extra`). Free-form fields are not
/// inspected; values of the wrong type are left to validation.
pub fn unknown_fields(model: &str, data: &Value) -> Vec<String> {
    unknown_fields_in(&CANONICAL_REGISTRY, model, data, "")
}

/// [`unknown_fields`] against a given registry, with a path prefix.
pub fn unknown_fields_in(registry: &Value, model: &str, data: &Value, path: &str) -> Vec<String> {
    let (Some(fields), Some(record)) = (
        registry["models"][model]["fields"].as_object(),
        data.as_object(),
    ) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (key, value) in record {
        let Some(kind) = fields.get(key) else {
            found.push(format!("{path}{key}"));
            continue;
        };
        if value.is_null() {
            continue;
        }
        if let Some(nested) = kind.get("object").and_then(Value::as_str) {
            found.extend(unknown_fields_in(
                registry,
                nested,
                value,
                &format!("{path}{key}."),
            ));
        } else if let Some(nested) = kind.get("list").and_then(Value::as_str) {
            for (i, item) in value.as_array().into_iter().flatten().enumerate() {
                found.extend(unknown_fields_in(
                    registry,
                    nested,
                    item,
                    &format!("{path}{key}.{i}."),
                ));
            }
        } else if let Some(nested) = kind.get("map").and_then(Value::as_str) {
            for (k, item) in value.as_object().into_iter().flatten() {
                found.extend(unknown_fields_in(
                    registry,
                    nested,
                    item,
                    &format!("{path}{key}.{k}."),
                ));
            }
        }
    }
    found
}

/// True when the record has no field outside `model`.
pub fn known_fields_only(model: &str, data: &Value) -> bool {
    unknown_fields(model, data).is_empty()
}

/// True when this SDK knows the evidence entry kind.
pub fn is_known_entry_kind(kind: &str) -> bool {
    CANONICAL_REGISTRY["entry_kinds"]
        .as_array()
        .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some(kind)))
}

/// Unknown fields of an evidence export payload; a decision payload wraps a
/// decision and its context.
pub(crate) fn unknown_payload_fields(kind: &str, payload: &Value) -> Vec<String> {
    let registry: &Value = &CANONICAL_REGISTRY;
    match kind {
        "decision" => {
            let mut found: Vec<String> = payload
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, _)| k)
                .filter(|k| *k != "decision" && *k != "context")
                .cloned()
                .collect();
            found.extend(unknown_fields_in(
                registry,
                "BoundaryDecision",
                &payload["decision"],
                "decision.",
            ));
            found.extend(unknown_fields_in(
                registry,
                "ContextRecord",
                &payload["context"],
                "context.",
            ));
            found
        }
        "justification" => unknown_fields("JustificationProof", payload),
        "execution" => unknown_fields("ExecutionEvidence", payload),
        "retention_checkpoint" => unknown_fields("RetentionCheckpoint", payload),
        _ => Vec::new(),
    }
}
