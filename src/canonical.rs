//! Canonical signed bodies, digests and timestamps of GM protocol models,
//! derived from their wire JSON exactly as the Python models'
//! `to_canonical_json()` and `digest()` derive them. Pure functions; key
//! operations live in `auth.rs`.

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Timelike, Utc};
use serde_json::{Map, Value};

use crate::{
    auth::{canonical_digest, canonical_json},
    errors::{GenesisMeshError, Result},
};

/// Resource-chain fields (v0.59), omitted from the execution canonical form when absent.
/// Decision fields omitted from the signed form when absent (checked against
/// the field registry).
pub const DECISION_OMITTED_WHEN_ABSENT: [&str; 2] = ["policy_binding", "attestation_binding"];

pub const RESOURCE_CHAIN_FIELDS: [&str; 4] = [
    "resource_id",
    "resource_action",
    "resource_sequence",
    "prev_resource_digest",
];

fn without(model: &Value, always: &[&str], when_null: &[&str]) -> Value {
    let Some(object) = model.as_object() else {
        return model.clone();
    };
    let mut out = Map::new();
    for (key, value) in object {
        if always.contains(&key.as_str()) || (when_null.contains(&key.as_str()) && value.is_null())
        {
            continue;
        }
        out.insert(key.clone(), value.clone());
    }
    Value::Object(out)
}

/// `BoundaryDecision.to_canonical_json()`.
pub fn decision_canonical(decision: &Value) -> Result<String> {
    canonical_json(&without(
        decision,
        &["signature"],
        &DECISION_OMITTED_WHEN_ABSENT,
    ))
}

/// `ExecutionEvidence.to_canonical_json()`: the body the executor signs.
pub fn execution_canonical(evidence: &Value) -> Result<String> {
    canonical_json(&without(evidence, &["signature"], &RESOURCE_CHAIN_FIELDS))
}

/// `ExecutionEvidence.digest()`: links the per-decision and per-resource chains.
pub fn execution_digest(evidence: &Value) -> Result<String> {
    canonical_digest(&without(evidence, &["signature"], &RESOURCE_CHAIN_FIELDS))
}

/// `MembershipAttestation.to_canonical_json()`.
pub fn attestation_canonical(attestation: &Value) -> Result<String> {
    canonical_json(&without(attestation, &["signatures"], &[]))
}

/// `MembershipAttestation.digest()`: the value an attestation binding commits to.
pub fn attestation_digest(attestation: &Value) -> Result<String> {
    canonical_digest(&without(attestation, &["signatures"], &[]))
}

/// `BoundaryPolicy.to_canonical_json()`.
pub fn policy_canonical(policy: &Value) -> Result<String> {
    canonical_json(&without(policy, &["signature"], &[]))
}

/// `BoundaryPolicy.digest()`.
pub fn policy_digest(policy: &Value) -> Result<String> {
    canonical_digest(&without(policy, &["signature"], &[]))
}

/// Digest of the ordered applied-policy list carried in a policy binding.
pub fn policy_set_digest(applied: &[Value]) -> Result<String> {
    let triples: Vec<Value> = applied
        .iter()
        .map(|p| {
            Value::Array(vec![
                p.get("policy_id").cloned().unwrap_or(Value::Null),
                p.get("version").cloned().unwrap_or(Value::Null),
                p.get("policy_digest").cloned().unwrap_or(Value::Null),
            ])
        })
        .collect();
    canonical_digest(&Value::Array(triples))
}

/// `DecisionJustification.to_canonical_json()`.
pub fn justification_canonical(proof: &Value) -> Result<String> {
    canonical_json(&without(proof, &["signature"], &[]))
}

/// `FreshnessProof.to_canonical_json()`.
pub fn freshness_proof_canonical(proof: &Value) -> Result<String> {
    canonical_json(&without(proof, &["signature"], &[]))
}

/// Checkpoint fields omitted from the signed form when absent (v1.3.0;
/// checked against the field registry).
pub const CHECKPOINT_OMITTED_WHEN_ABSENT: [&str; 1] = ["observation_heads"];

/// `RetentionCheckpoint.to_canonical_json()`.
pub fn checkpoint_canonical(checkpoint: &Value) -> Result<String> {
    canonical_json(&without(
        checkpoint,
        &["signature"],
        &CHECKPOINT_OMITTED_WHEN_ABSENT,
    ))
}

/// Envelope fields left out of the entry digest when absent (v1.3.0; checked
/// against the field registry), so 1.2 digests hold. A `null` reads as absent.
pub const ENVELOPE_OMITTED_WHEN_ABSENT: [&str; 4] = [
    "record_id",
    "subject_id",
    "matched_evidence_id",
    "observation_sequence",
];

/// `EvidenceStoreEntry.digest()`: every envelope field.
pub fn entry_digest(entry: &Value) -> Result<String> {
    canonical_digest(&without(entry, &[], &ENVELOPE_OMITTED_WHEN_ABSENT))
}

/// A Stage 2 record's signed fields (v1.3.0): every field but `signature`,
/// with top-level fields that are absent or `null` left out. Nested values
/// keep their form.
fn out_of_band_fields(record: &Value) -> Value {
    let Some(object) = record.as_object() else {
        return record.clone();
    };
    Value::Object(
        object
            .iter()
            .filter(|(key, value)| *key != "signature" && !value.is_null())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// The signed form of a record of a change made outside the controlled path
/// (v1.3.0): an observation, break-glass, judgement, quarantine or registry
/// record. Every field but `signature`; an absent optional field is left
/// out, never `null`. Frozen from 1.3.0 on (`_SignedRecord.to_canonical_json()`).
pub fn out_of_band_canonical(record: &Value) -> Result<String> {
    canonical_json(&out_of_band_fields(record))
}

/// SHA-256 of [`out_of_band_canonical`] (`_SignedRecord.digest()`).
pub fn out_of_band_digest(record: &Value) -> Result<String> {
    canonical_digest(&out_of_band_fields(record))
}

/// SHA-256 of a stored payload's canonical JSON.
pub fn payload_digest(payload: &Value) -> Result<String> {
    canonical_digest(payload)
}

/// A UTC timestamp in the form Pydantic re-serialises unchanged: microsecond
/// precision, `Z` suffix, fraction omitted when zero. Any other form would
/// come back changed from the NA and break a signature over it.
pub fn python_timestamp(at: DateTime<Utc>) -> String {
    let micros = at.nanosecond() / 1_000 % 1_000_000;
    let at = at.with_nanosecond(micros * 1_000).unwrap_or(at);
    if micros == 0 {
        at.to_rfc3339_opts(SecondsFormat::Secs, true)
    } else {
        at.to_rfc3339_opts(SecondsFormat::Micros, true)
    }
}

/// Parse an ISO 8601 timestamp as the NA writes it (`Z`, an offset, or naive
/// UTC; up to six fractional digits).
pub fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    let invalid = || GenesisMeshError::Verification(format!("not an ISO 8601 timestamp: {value}"));
    let fraction_ok = value
        .split_once('T')
        .and_then(|(_, time)| time.get(8..))
        .map(|rest| {
            let rest = rest.trim_end_matches('Z');
            let rest = match rest.rfind(['+', '-']) {
                Some(i) => &rest[..i],
                None => rest,
            };
            rest.is_empty()
                || rest.strip_prefix('.').is_some_and(|d| {
                    (1..=6).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit())
                })
        })
        .unwrap_or(false);
    if !fraction_ok || value.len() < 19 || value.as_bytes().get(10) != Some(&b'T') {
        return Err(invalid());
    }
    if let Ok(at) = DateTime::parse_from_rfc3339(value) {
        return Ok(at.with_timezone(&Utc));
    }
    NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|naive| naive.and_utc())
        .map_err(|_| invalid())
}

/// Microseconds since the epoch, keeping Python's microsecond precision.
pub(crate) fn micros(value: &str) -> Result<i64> {
    Ok(parse_timestamp(value)?.timestamp_micros())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn formats_pydantic_timestamps() {
        let base = Utc.with_ymd_and_hms(2026, 10, 1, 9, 56, 14).unwrap();
        assert_eq!(python_timestamp(base), "2026-10-01T09:56:14Z");
        let fine = base.with_nanosecond(628_709_999).unwrap();
        assert_eq!(python_timestamp(fine), "2026-10-01T09:56:14.628709Z");
        let ms = base.with_nanosecond(561_000_000).unwrap();
        assert_eq!(python_timestamp(ms), "2026-10-01T09:56:14.561000Z");
    }

    #[test]
    fn parses_na_timestamps_and_rejects_invalid_ones() {
        assert_eq!(
            micros("2026-10-01T09:56:14.628709Z").unwrap()
                - micros("2026-10-01T09:56:14.628708Z").unwrap(),
            1
        );
        assert_eq!(
            micros("2026-10-01T09:56:14+00:00").unwrap(),
            micros("2026-10-01T09:56:14").unwrap()
        );
        for bad in [
            "bad",
            "2026-02-30T00:00:00Z",
            "2026-10-01T25:00:00Z",
            "2026-10-01T09:56:14.1234567Z",
        ] {
            assert!(parse_timestamp(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn omits_new_envelope_and_record_fields_only_when_absent() {
        let entry = json!({"store_sequence": 1, "record_id": null, "resource_id": null});
        assert_eq!(
            entry_digest(&entry).unwrap(),
            canonical_digest(&json!({"store_sequence": 1, "resource_id": null})).unwrap()
        );
        let checkpoint = json!({"a": 1, "observation_heads": null, "signature": null});
        assert_eq!(checkpoint_canonical(&checkpoint).unwrap(), r#"{"a":1}"#);
        let heads = json!({"a": 1, "observation_heads": {}});
        assert_eq!(
            checkpoint_canonical(&heads).unwrap(),
            r#"{"a":1,"observation_heads":{}}"#
        );
        let record = json!({"b": null, "nested": {"x": null}, "signature": {"sig": "s"}});
        assert_eq!(
            out_of_band_canonical(&record).unwrap(),
            r#"{"nested":{"x":null}}"#
        );
    }

    #[test]
    fn omits_resource_fields_only_when_absent() {
        let bare = json!({"a": 1, "signature": {"sig": "x"}, "resource_id": null});
        assert_eq!(execution_canonical(&bare).unwrap(), r#"{"a":1}"#);
        let linked = json!({"a": 1, "resource_id": "kv:v/s", "prev_resource_digest": null});
        assert_eq!(
            execution_canonical(&linked).unwrap(),
            r#"{"a":1,"resource_id":"kv:v/s"}"#
        );
    }
}
