//! The vouching horizon for NA-signed records (Genesis Mesh 1.8.0): a port
//! of the Python reference's `trust.key_succession.na_record_refusal`,
//! pinned by the `vouching` conformance suite.
//!
//! A record is placed at the time its kind names
//! ([`NA_VOUCHING_TIME_FIELDS`]), its signature checked over the record as
//! received with the NA keys valid then, and, when `now` is given, the
//! horizon applied: a record whose key ended more than the hand-over and the
//! grace before `now` no longer vouches for the present (`outlives_key`).
//! Without `now` the record is judged at its own time only, as audit packs
//! and exports judge it.

use serde_json::Value;

use crate::{
    canonical::parse_timestamp,
    grants::{signed_as_received, GRANT_CLOCK_SKEW_SECONDS, GRANT_MAX_VALIDITY_SECONDS},
    key_history::NaKeyHistory,
    strict::{non_canonical_fields, unknown_fields},
};

/// The record kinds the vouching horizon applies to, and the field each is
/// placed at (1.8.0).
pub const NA_VOUCHING_TIME_FIELDS: [(&str, &str); 4] = [
    ("CapabilityGrant", "issued_at"),
    ("MembershipAttestation", "issued_at"),
    ("RecognitionTreaty", "issued_at"),
    ("SovereignRevocationFeed", "issued_at"),
];

fn micros(record: &Value, field: &str) -> Option<i64> {
    let text = record.get(field)?.as_str()?;
    parse_timestamp(text).ok().map(|t| t.timestamp_micros())
}

/// Why a record must be refused for its form, given the key that signed it:
/// `unknown_field` or `non_canonical_form` when its signature covers what was
/// received, otherwise `invalid_signature`; `None` when the form is the
/// reference's.
fn form_refusal(model: &str, record: &Value, signers: &[String]) -> Option<&'static str> {
    let unknown = !unknown_fields(model, record).is_empty();
    if !unknown && non_canonical_fields(model, record).is_empty() {
        return None;
    }
    if !signed_as_received(model, record, signers) {
        return Some("invalid_signature");
    }
    Some(if unknown {
        "unknown_field"
    } else {
        "non_canonical_form"
    })
}

/// True when the reference model's time rules accept `record` as `model`
/// (1.8.0): a grant is valid for at most 24 hours and starts within 24 hours
/// of its issue (with the clock skew either side); an attestation or a
/// treaty expires after it starts and is not issued after it expires.
pub fn model_times_accepted(model: &str, record: &Value) -> bool {
    match model {
        "CapabilityGrant" => {
            let (Some(issued), Some(from), Some(until)) = (
                micros(record, "issued_at"),
                micros(record, "valid_from"),
                micros(record, "valid_until"),
            ) else {
                return false;
            };
            let max = GRANT_MAX_VALIDITY_SECONDS * 1_000_000;
            let skew = GRANT_CLOCK_SKEW_SECONDS * 1_000_000;
            from < until
                && until - from <= max
                && issued - skew <= from
                && from <= issued + max + skew
        }
        "MembershipAttestation" | "RecognitionTreaty" => {
            let (Some(issued), Some(from), Some(expires)) = (
                micros(record, "issued_at"),
                micros(record, "valid_from"),
                micros(record, "expires_at"),
            ) else {
                return false;
            };
            expires > from && issued <= expires
        }
        _ => true,
    }
}

/// Why an NA-signed record of `model` does not verify, or `None` (1.8.0).
/// Reasons, in order: `unknown_field` or `non_canonical_form`,
/// `na_key_not_valid_at_time`, `invalid_signature`, `record_malformed`
/// (signed, but refused by its kind's time rules, such as a grant that starts
/// more than 24 hours after its issue), `outlives_key` (only with `now`,
/// microseconds; its horizon with `grace_seconds`, from
/// [`vouching_grace`](crate::key_history::vouching_grace)). `None` too for a model the horizon does not apply to is not
/// possible: such a model is `Err`.
pub fn na_record_refusal(
    model: &str,
    record: &Value,
    history: &NaKeyHistory,
    now: Option<i64>,
    grace_seconds: i64,
) -> Result<Option<&'static str>, String> {
    let Some((_, field)) = NA_VOUCHING_TIME_FIELDS.iter().find(|(m, _)| *m == model) else {
        return Err(format!(
            "{model} is not a kind the vouching horizon applies to"
        ));
    };
    let Some(at) = record.is_object().then(|| micros(record, field)).flatten() else {
        return Ok(Some("invalid_signature"));
    };
    let keys = history.keys_at(at);
    let Some(signer) = keys
        .iter()
        .find(|k| signed_as_received(model, record, std::slice::from_ref(*k)))
        .cloned()
    else {
        let others: Vec<String> = history
            .all_keys()
            .into_iter()
            .filter(|k| !keys.contains(k))
            .collect();
        return Ok(Some(
            if !others.is_empty() && signed_as_received(model, record, &others) {
                "na_key_not_valid_at_time"
            } else {
                "invalid_signature"
            },
        ));
    };
    if let Some(refusal) = form_refusal(model, record, std::slice::from_ref(&signer)) {
        return Ok(Some(refusal));
    }
    if !model_times_accepted(model, record) {
        return Ok(Some("record_malformed"));
    }
    if now.is_some_and(|now| history.record_outlives_key(&signer, now, grace_seconds)) {
        return Ok(Some("outlives_key"));
    }
    Ok(None)
}
