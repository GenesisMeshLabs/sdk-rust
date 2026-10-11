//! Offline verification of NA-signed artifacts and evidence exports.
//! Direct ports of the Python reference, with the same reason codes:
//!
//! * [`verify_boundary_decision`]: `trust/context/decisions.py` `verify_boundary_decision`
//! * [`verify_evidence_events`]: `trust/evidence_store.py` `verify_evidence_events`
//! * the review checks (1.4.0): `trust/remediation.py`
//!
//! No network access; every key is supplied by the caller.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::OnceLock,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::strict::{
    is_known_entry_kind, non_canonical_fields, prefixed_unknown_fields, unknown_fields,
    without_unknown_fields,
};
use crate::{
    auth::verify_canonical,
    canonical::{
        attestation_digest, checkpoint_canonical, decision_canonical, entry_digest,
        execution_canonical, execution_digest, freshness_proof_canonical, justification_canonical,
        micros, out_of_band_canonical, parse_timestamp, payload_digest, policy_canonical,
        policy_digest, policy_set_digest,
    },
    errors::{GenesisMeshError, Result},
    evidence_store::ResourceHead,
    remediation::{review_approval_problem, review_holder_problem, ReviewHolders},
};

// ── Structural checks (no coercion or mutation of signed JSON) ───────────────

type Check = Box<dyn Fn(Option<&Value>) -> bool + Send + Sync>;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

fn string() -> Check {
    Box::new(|v| matches!(v, Some(Value::String(_))))
}
fn boolean() -> Check {
    Box::new(|v| matches!(v, Some(Value::Bool(_))))
}
fn int_where(predicate: fn(i64) -> bool) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_i64)
            .is_some_and(|n| n.abs() <= MAX_SAFE_INTEGER && predicate(n))
    })
}
fn integer() -> Check {
    int_where(|_| true)
}
fn positive() -> Check {
    int_where(|n| n > 0)
}
fn nonnegative() -> Check {
    int_where(|n| n >= 0)
}
fn object() -> Check {
    Box::new(|v| matches!(v, Some(Value::Object(_))))
}
fn timestamp() -> Check {
    Box::new(|v| {
        v.and_then(Value::as_str)
            .is_some_and(|s| parse_timestamp(s).is_ok())
    })
}
fn nullable(check: Check) -> Check {
    Box::new(move |v| matches!(v, Some(Value::Null)) || check(v))
}
fn optional(check: Check) -> Check {
    Box::new(move |v| v.is_none() || check(v))
}
fn array(check: Check) -> Check {
    Box::new(
        move |v| matches!(v, Some(Value::Array(items)) if items.iter().all(|i| check(Some(i)))),
    )
}
fn one_of(values: &'static [&'static str]) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_str)
            .is_some_and(|s| values.contains(&s))
    })
}
fn dictionary(check: Check) -> Check {
    Box::new(move |v| matches!(v, Some(Value::Object(map)) if map.values().all(|i| check(Some(i)))))
}
fn shape(fields: Vec<(&'static str, Check)>, exact: bool) -> Check {
    Box::new(move |v| {
        let Some(Value::Object(map)) = v else {
            return false;
        };
        fields.iter().all(|(key, check)| check(map.get(*key)))
            && (!exact || map.keys().all(|k| fields.iter().any(|(f, _)| f == k)))
    })
}
fn signature() -> Check {
    nullable(shape(vec![("key_id", string()), ("sig", string())], false))
}
/// Absent, `null` (read as absent) or valid. Since 1.3.1 also for a field
/// the reference always writes, `null` when it has no value: a record without
/// it is then refused by its signature or its form, as the reference refuses
/// it, not as `payload_invalid`.
fn absent(check: Check) -> Check {
    optional(nullable(check))
}
/// A string of `min..=max` characters.
fn bounded(max: usize, min: usize) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_str)
            .is_some_and(|s| (min..=max).contains(&s.chars().count()))
    })
}
fn sha256() -> Check {
    bounded(64, 64)
}
fn action() -> Check {
    one_of(&["create", "rotate", "revoke", "update", "delete"])
}
fn verdict() -> Check {
    one_of(&["allow", "deny", "indeterminate"])
}
/// v1.3.0 records' timestamps are UTC, as the reference requires.
fn utc_timestamp() -> Check {
    Box::new(|v| {
        v.and_then(Value::as_str).is_some_and(|s| {
            parse_timestamp(s).is_ok()
                && (s.ends_with('Z') || s.ends_with("+00:00") || s.ends_with("-00:00"))
        })
    })
}
/// A field the reference fills when absent: left out, the record is not in
/// the form the reference writes (`non_canonical_form`), not malformed.
fn filled(check: Check) -> Check {
    optional(check)
}
fn gate_result() -> Check {
    shape(
        vec![
            ("gate_name", string()),
            ("passed", boolean()),
            ("detail", string()),
        ],
        false,
    )
}
fn policy_binding() -> Check {
    shape(
        vec![
            (
                "policies",
                array(shape(
                    vec![
                        ("policy_id", string()),
                        ("version", positive()),
                        ("policy_digest", string()),
                        ("signed_by", string()),
                    ],
                    false,
                )),
            ),
            ("policy_set_digest", string()),
            (
                "gate_evaluations",
                array(shape(
                    vec![
                        ("policy_id", string()),
                        ("policy_version", positive()),
                        ("gate_id", string()),
                        ("gate_type", string()),
                        ("order", nonnegative()),
                        ("mode", one_of(&["observe", "enforce"])),
                        ("passed", boolean()),
                        (
                            "outcome",
                            one_of(&[
                                "pass",
                                "fail",
                                "missing_context",
                                "invalid_context",
                                "gate_error",
                            ]),
                        ),
                    ],
                    false,
                )),
            ),
            ("context_digest", string()),
            ("registry_gate_types", array(string())),
            ("resolution_status", one_of(&["resolved", "failed"])),
            ("resolution_failure", absent(string())),
        ],
        false,
    )
}

macro_rules! validator {
    ($name:ident, $build:expr) => {
        fn $name(value: Option<&Value>) -> bool {
            static CHECK: OnceLock<Check> = OnceLock::new();
            CHECK.get_or_init(|| $build)(value)
        }
    };
}

validator!(
    valid_decision,
    shape(
        vec![
            ("decision_id", string()),
            ("context_id", string()),
            ("agreement_id", string()),
            ("authorized", boolean()),
            // Absent is read as absent, so a decision whose signature covers a
            // null fails at the signature, as in every implementation.
            ("denial_reason", optional(nullable(string()))),
            ("gate_results", array(gate_result())),
            ("decision_made_at", timestamp()),
            ("decision_valid_until", timestamp()),
            ("operator_sovereign_id", string()),
            (
                "freshness_proof",
                optional(nullable(shape(
                    vec![
                        ("proof_id", string()),
                        ("feed_sovereign_id", string()),
                        ("feed_sequence", nonnegative()),
                        ("feed_digest", string()),
                        ("attested_at", timestamp()),
                        ("proof_valid_until", timestamp()),
                        ("issuer_sovereign_id", string()),
                        ("signature", optional(signature())),
                    ],
                    false
                )))
            ),
            ("policy_binding", optional(nullable(policy_binding()))),
            (
                "attestation_binding",
                optional(nullable(shape(
                    vec![
                        ("attestation_id", string()),
                        ("subject_id", absent(string())),
                        ("issuer_sovereign_id", absent(string())),
                        ("attestation_digest", absent(string())),
                        ("revocation_seq_checked", nonnegative()),
                    ],
                    false
                )))
            ),
            ("signature", optional(signature())),
        ],
        false
    )
);

validator!(
    valid_context,
    shape(
        vec![
            ("context_id", string()),
            ("agreement_id", string()),
            ("parent_kind", string()),
            ("requester_sovereign_id", string()),
            ("provider_sovereign_id", string()),
            ("requested_capability", string()),
            ("request_parameters", object()),
            ("requested_at", timestamp()),
            ("context_freshness_seq", nonnegative()),
            ("attributes", object()),
            ("attestation_id", optional(nullable(string()))),
        ],
        false
    )
);

validator!(
    valid_execution,
    shape(
        vec![
            ("evidence_id", string()),
            ("sequence_no", positive()),
            ("decision_id", string()),
            ("context_id", string()),
            ("agreement_id", string()),
            ("executor_sovereign_id", string()),
            ("executed_capability", string()),
            ("execution_parameters", object()),
            ("executed_at", timestamp()),
            ("outcome", string()),
            ("outcome_detail", absent(string())),
            ("prev_evidence_digest", absent(string())),
            (
                "resource_id",
                optional(nullable(Box::new(|v| v
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty() && s.chars().count() <= 256))))
            ),
            (
                "resource_action",
                optional(nullable(one_of(&[
                    "create", "rotate", "revoke", "update", "delete"
                ])))
            ),
            ("resource_sequence", optional(nullable(positive()))),
            ("prev_resource_digest", optional(nullable(string()))),
            ("signature", optional(signature())),
        ],
        false
    )
);

validator!(
    valid_justification,
    shape(
        vec![
            ("proof_id", string()),
            ("decision_id", string()),
            ("proof_issued_at", timestamp()),
            ("issuer_sovereign_id", string()),
            ("signature", optional(signature())),
            (
                "trace",
                shape(
                    vec![
                        ("trace_id", string()),
                        ("decision_id", string()),
                        ("agreement_id", string()),
                        ("operator_sovereign_id", string()),
                        ("traced_at", timestamp()),
                        (
                            "entries",
                            array(shape(
                                vec![
                                    ("gate_name", string()),
                                    ("gate_type", string()),
                                    ("evaluated_at", timestamp()),
                                    ("inputs", object()),
                                    ("result", boolean()),
                                    ("reason", string()),
                                    ("metadata", object()),
                                ],
                                false
                            ))
                        ),
                        ("short_circuited_at", absent(string())),
                        ("final_authorized", boolean()),
                    ],
                    false
                )
            ),
        ],
        false
    )
);

validator!(
    valid_checkpoint,
    shape(
        vec![
            ("checkpoint_id", string()),
            ("created_at", timestamp()),
            ("cutoff", timestamp()),
            ("removed_through_sequence", nonnegative()),
            ("last_removed_entry_digest", string()),
            ("removed_count", nonnegative()),
            ("previous_checkpoint_id", absent(string())),
            ("issued_by", string()),
            ("signature", optional(signature())),
            (
                "resource_heads",
                dictionary(shape(
                    vec![
                        ("resource_sequence", positive()),
                        ("record_digest", string())
                    ],
                    true
                ))
            ),
            // v1.3.0, left out when absent.
            ("observation_heads", absent(dictionary(nonnegative()))),
        ],
        false
    )
);

// v1.3.0: records of changes made outside the controlled path. An absent
// optional field is left out of the signed form; a null reads as absent.

/// Exactly one change time: `changed_at`, or both bounds of a window in order.
fn change_time(record: &Value) -> bool {
    let at = |key: &str| {
        record
            .get(key)
            .filter(|v| !v.is_null())
            .and_then(Value::as_str)
    };
    match (
        at("changed_at"),
        at("changed_not_before"),
        at("changed_not_after"),
    ) {
        (Some(_), None, None) => true,
        (None, Some(from), Some(until)) => {
            matches!((micros(from), micros(until)), (Ok(from), Ok(until)) if from <= until)
        }
        _ => false,
    }
}

validator!(valid_observation, {
    let fields = shape(
        vec![
            ("observation_id", bounded(128, 1)),
            ("observer_sovereign_id", bounded(256, 1)),
            ("resource_id", bounded(256, 1)),
            ("action", action()),
            ("capability", bounded(256, 1)),
            ("changed_at", absent(utc_timestamp())),
            ("changed_not_before", absent(utc_timestamp())),
            ("changed_not_after", absent(utc_timestamp())),
            ("observed_at", utc_timestamp()),
            ("actor", absent(bounded(256, 1))),
            ("source", bounded(128, 1)),
            ("source_event_id", bounded(256, 1)),
            ("version_id", absent(bounded(256, 1))),
            ("metadata", filled(object())),
            ("signature", optional(signature())),
        ],
        false,
    );
    Box::new(move |v| fields(v) && v.is_some_and(change_time))
});

validator!(
    valid_break_glass,
    shape(
        vec![
            ("break_glass_id", bounded(128, 1)),
            ("executor_sovereign_id", bounded(256, 1)),
            ("resource_id", bounded(256, 1)),
            ("resource_action", action()),
            ("capability", bounded(256, 1)),
            ("attestation_id", absent(bounded(128, 1))),
            ("request_parameters", filled(object())),
            ("attributes", filled(object())),
            ("justification", bounded(1024, 1)),
            ("evaluation_request_digest", sha256()),
            (
                "evaluation_failure",
                one_of(&["network_error", "timeout", "server_error", "rate_limited"])
            ),
            ("executed_at", utc_timestamp()),
            ("outcome", string()),
            ("outcome_detail", absent(bounded(1024, 0))),
            ("execution_parameters", filled(object())),
            ("signature", optional(signature())),
        ],
        false
    )
);

validator!(
    valid_judgement,
    shape(
        vec![
            ("judgement_id", bounded(128, 1)),
            ("subject_kind", one_of(&["observation", "break_glass"])),
            ("subject_id", bounded(128, 1)),
            ("subject_digest", sha256()),
            ("subject_store_sequence", positive()),
            ("resource_id", bounded(256, 1)),
            ("action", action()),
            ("capability", bounded(256, 1)),
            ("governed_by", one_of(&["prior_decision", "after_the_fact"])),
            ("verdict", verdict()),
            ("reason", absent(bounded(1024, 0))),
            ("evaluated_as_of", utc_timestamp()),
            ("evaluated_from", absent(utc_timestamp())),
            ("policy_binding", absent(policy_binding())),
            ("gate_results", filled(array(gate_result()))),
            ("current_verdict", absent(verdict())),
            ("current_policy_set_digest", absent(string())),
            ("flagged_for_review", absent(boolean())),
            ("matched_evidence_id", absent(string())),
            ("matched_decision_id", absent(string())),
            ("possible_match_evidence_id", absent(string())),
            ("judged_at", utc_timestamp()),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false
    )
);

validator!(
    valid_quarantine,
    shape(
        vec![
            ("quarantine_id", bounded(128, 1)),
            (
                "record_kind",
                // v1.4.0: also a refused remediation record.
                one_of(&["execution", "observation", "break_glass", "remediation"])
            ),
            ("record", object()),
            ("record_digest", sha256()),
            ("rejection_code", bounded(128, 1)),
            ("detail", filled(bounded(1024, 0))),
            ("resource_id", absent(bounded(256, 1))),
            ("quarantined_at", utc_timestamp()),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false
    )
);

validator!(
    valid_registry,
    shape(
        vec![
            ("registry_record_id", bounded(128, 1)),
            (
                "event",
                one_of(&[
                    "policy_history_started",
                    "policy_activated",
                    "policy_deactivated",
                    "executor_key_registered",
                    "executor_key_retired",
                    "operator_key_holder",
                ])
            ),
            ("effective_at", utc_timestamp()),
            ("reconstructed", absent(boolean())),
            ("policy_id", absent(string())),
            ("policy_version", absent(positive())),
            ("policy_digest", absent(string())),
            ("key_id", absent(string())),
            ("public_key", absent(string())),
            ("executor_sovereign_id", absent(string())),
            ("key_role", absent(one_of(&["executor", "observer"]))),
            ("resource_prefix", absent(string())),
            ("operator_tier", absent(string())),
            ("holder", absent(string())),
            ("approved_by", absent(string())),
            ("recorded_by", absent(string())),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false
    )
);

// v1.4.0: remediation and review records. An absent optional field is left
// out of the signed form; a null reads as absent.

fn present(record: &Value, key: &str) -> bool {
    record.get(key).is_some_and(|v| !v.is_null())
}

/// A remediation's outcome, steps and versions agree (the reference's model
/// rules): `alerted` exactly when nothing changed (`none`); a forward
/// rotation names its evidence, the version it issued and the one it
/// disabled, two different versions; nothing else names rotation evidence or
/// a new version; `none` disables nothing.
fn remediation_consistent(record: &Value) -> bool {
    let outcome = str_field(record, "outcome");
    let steps = str_field(record, "steps");
    let versions = if steps == Some("rotate_forward_then_disable") {
        present(record, "rotation_evidence_id")
            && present(record, "version_id")
            && present(record, "disabled_version_id")
            && record["version_id"] != record["disabled_version_id"]
    } else {
        !present(record, "rotation_evidence_id") && !present(record, "version_id")
    };
    (outcome == Some("alerted")) == (steps == Some("none"))
        && versions
        && !(steps == Some("none") && present(record, "disabled_version_id"))
}

validator!(valid_remediation, {
    let fields = shape(
        vec![
            ("remediation_id", bounded(128, 1)),
            ("executor_sovereign_id", bounded(256, 1)),
            ("subject_kind", one_of(&["judgement", "decision"])),
            ("subject_id", bounded(128, 1)),
            (
                "change_kind",
                one_of(&["observation", "break_glass", "execution"]),
            ),
            ("change_id", bounded(128, 1)),
            ("resource_id", bounded(256, 1)),
            ("outcome", one_of(&["cancelled", "alerted"])),
            (
                "steps",
                one_of(&["rotate_forward_then_disable", "disable", "delete", "none"]),
            ),
            ("rotation_evidence_id", absent(bounded(128, 1))),
            ("version_id", absent(bounded(256, 1))),
            ("disabled_version_id", absent(bounded(256, 1))),
            ("remediated_at", utc_timestamp()),
            ("detail", absent(bounded(1024, 1))),
            ("signature", optional(signature())),
        ],
        false,
    );
    Box::new(move |v| fields(v) && v.is_some_and(remediation_consistent))
});

/// Whether a remediation record is well formed (1.4.0), for the record checks.
pub(crate) fn valid_remediation_record(record: &Value) -> bool {
    valid_remediation(Some(record))
}

/// An operator's signed admin request, kept whole in a review (1.4.0).
fn admin_approval() -> Check {
    shape(
        vec![
            ("key_id", bounded(256, 1)),
            ("public_key", bounded(256, 1)),
            ("method", bounded(16, 1)),
            ("path", bounded(2048, 1)),
            ("query", filled(dictionary(array(string())))),
            ("audience", bounded(256, 1)),
            ("body", filled(object())),
            ("timestamp", bounded(256, 1)),
            ("nonce", bounded(256, 1)),
            ("admin_signature", bounded(256, 1)),
        ],
        false,
    )
}

/// The longest waiver a review may record, in microseconds (90 days).
const MAX_WAIVER_MICROS: i64 = crate::remediation::MAX_WAIVER_SECONDS * 1_000_000;

/// A review's verdict, waiver and request agree (the reference's model
/// rules): `waive_until` is present exactly for a waiver, after the decision
/// and within 90 days of it; a requested review names its requester, holder,
/// justification and request, and one the NA opened none of them.
fn review_consistent(record: &Value) -> bool {
    let waiver = str_field(record, "verdict") == Some("waive_until");
    if waiver != present(record, "waive_until") {
        return false;
    }
    if waiver {
        let at = |key: &str| micros(str_field(record, key).unwrap_or_default());
        let (Ok(decided), Ok(until)) = (at("decided_at"), at("waive_until")) else {
            return false;
        };
        if !(decided < until && until - decided <= MAX_WAIVER_MICROS) {
            return false;
        }
    }
    let requested = str_field(record, "opened_for") == Some("requested");
    let given = [
        "requested_by",
        "requester_holder",
        "justification",
        "request_approval",
    ]
    .map(|key| present(record, key));
    if requested {
        given.iter().all(|g| *g)
    } else {
        !given.iter().any(|g| *g)
    }
}

validator!(valid_review, {
    let fields = shape(
        vec![
            ("review_id", bounded(128, 1)),
            ("subject_kind", one_of(&["judgement", "decision"])),
            ("subject_id", bounded(128, 1)),
            ("subject_digest", sha256()),
            ("resource_id", absent(bounded(256, 1))),
            ("capability", absent(bounded(256, 1))),
            (
                "opened_for",
                one_of(&["requested", "flagged_for_review", "review_required"]),
            ),
            ("requested_by", absent(bounded(256, 1))),
            ("requester_holder", absent(bounded(128, 1))),
            ("justification", absent(bounded(1024, 1))),
            ("request_approval", absent(admin_approval())),
            ("requested_at", utc_timestamp()),
            ("actor", absent(bounded(256, 1))),
            ("actor_holder", absent(bounded(128, 1))),
            ("verdict", one_of(&["uphold", "deny", "waive_until"])),
            ("waive_until", absent(utc_timestamp())),
            ("note", absent(bounded(1024, 1))),
            ("decided_by", bounded(256, 1)),
            ("decider_holder", bounded(128, 1)),
            ("approval", admin_approval()),
            ("decided_at", utc_timestamp()),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false,
    );
    Box::new(move |v| fields(v) && v.is_some_and(review_consistent))
});

validator!(
    valid_event,
    shape(
        vec![
            ("schema", one_of(&["gm.evidence.event"])),
            ("schema_version", int_where(|n| n == 1)),
            (
                "entry",
                shape(
                    vec![
                        ("store_sequence", positive()),
                        ("entry_kind", string()),
                        ("recorded_at", timestamp()),
                        ("payload_digest", string()),
                        ("prev_entry_digest", nullable(string())),
                        ("decision_id", nullable(string())),
                        ("context_id", nullable(string())),
                        ("vendor_id", nullable(string())),
                        ("attestation_id", nullable(string())),
                        ("capability", nullable(string())),
                        ("outcome", nullable(string())),
                        ("evidence_id", nullable(string())),
                        ("executor_sovereign_id", nullable(string())),
                        ("exec_sequence_no", nullable(integer())),
                        ("resource_id", nullable(string())),
                        ("resource_action", nullable(string())),
                        ("resource_sequence", nullable(integer())),
                        // v1.3.0, left out when absent.
                        ("record_id", absent(string())),
                        ("subject_id", absent(string())),
                        ("matched_evidence_id", absent(string())),
                        ("observation_sequence", absent(positive())),
                    ],
                    true
                )
            ),
            ("entry_digest", string()),
            ("payload", object()),
        ],
        true
    )
);

// ── Signatures ────────────────────────────────────────────────────────────────

fn signed_by(canonical: Result<String>, signature: Option<&Value>, keys: &[String]) -> bool {
    let (Ok(canonical), Some(sig)) = (canonical, signature.and_then(|s| s.get("sig")?.as_str()))
    else {
        return false;
    };
    verify_canonical(&canonical, sig, keys)
}

fn any_signed(canonical: Result<String>, signatures: Option<&Value>, keys: &[String]) -> bool {
    let Ok(canonical) = canonical else {
        return false;
    };
    signatures.and_then(Value::as_array).is_some_and(|sigs| {
        sigs.iter().any(|s| {
            s.get("sig")
                .and_then(Value::as_str)
                .is_some_and(|sig| verify_canonical(&canonical, sig, keys))
        })
    })
}

fn decision_signed(decision: &Value, public_keys: &[String]) -> bool {
    signed_by(
        decision_canonical(decision),
        decision.get("signature"),
        public_keys,
    )
}

fn checkpoint_signed(checkpoint: &Value, public_keys: &[String]) -> bool {
    signed_by(
        checkpoint_canonical(checkpoint),
        checkpoint.get("signature"),
        public_keys,
    )
}

/// True when the decision signature verifies under any of the operator (NA) keys.
pub fn verify_decision_signature(decision: &Value, public_keys: &[String]) -> bool {
    signed_by(
        decision_canonical(decision),
        decision.get("signature"),
        public_keys,
    ) && unknown_fields("BoundaryDecision", decision).is_empty()
}

/// True when any attestation signature verifies under the issuer keys.
pub fn verify_attestation_signature(attestation: &Value, public_keys: &[String]) -> bool {
    any_signed(
        crate::canonical::attestation_canonical(attestation),
        attestation.get("signatures"),
        public_keys,
    ) && unknown_fields("MembershipAttestation", attestation).is_empty()
}

/// True when the policy signature verifies under the issuer keys.
pub fn verify_policy_signature(policy: &Value, public_keys: &[String]) -> bool {
    signed_by(
        policy_canonical(policy),
        policy.get("signature"),
        public_keys,
    ) && unknown_fields("BoundaryPolicy", policy).is_empty()
}

/// True when the justification proof signature verifies under the NA keys.
pub fn verify_justification_signature(proof: &Value, public_keys: &[String]) -> bool {
    signed_by(
        justification_canonical(proof),
        proof.get("signature"),
        public_keys,
    ) && unknown_fields("JustificationProof", proof).is_empty()
}

/// True when the retention checkpoint signature verifies under the NA keys.
pub fn verify_retention_checkpoint(checkpoint: &Value, public_keys: &[String]) -> bool {
    signed_by(
        checkpoint_canonical(checkpoint),
        checkpoint.get("signature"),
        public_keys,
    ) && unknown_fields("RetentionCheckpoint", checkpoint).is_empty()
}

/// True when the record's signature verifies under the executor's public key.
pub fn verify_execution_signature(evidence: &Value, executor_public_key: &str) -> bool {
    signed_by(
        execution_canonical(evidence),
        evidence.get("signature"),
        &[executor_public_key.to_owned()],
    ) && unknown_fields("ExecutionEvidence", evidence).is_empty()
}

type Validator = fn(Option<&Value>) -> bool;

/// v1.3.0: the id field, model and validator of each record of a change made
/// outside the controlled path; v1.4.0: and of a remediation or review.
const OUT_OF_BAND_IDS: [(&str, &str, Validator); 7] = [
    ("observation_id", "ObservationRecord", valid_observation),
    ("break_glass_id", "BreakGlassRecord", valid_break_glass),
    ("judgement_id", "JudgementRecord", valid_judgement),
    ("quarantine_id", "QuarantineRecord", valid_quarantine),
    ("registry_record_id", "RegistryRecord", valid_registry),
    ("remediation_id", "RemediationRecord", valid_remediation),
    ("review_id", "ReviewRecord", valid_review),
];

/// Whether a Stage 2 record's signature covers it as received under one of
/// the keys, with no signed field the registry does not list. Its form is
/// checked apart ([`non_canonical_fields`]).
fn out_of_band_verifies(model: &str, record: &Value, keys: &[String]) -> bool {
    signed_by(out_of_band_canonical(record), record.get("signature"), keys)
        && unknown_fields(model, record).is_empty()
}

/// True when a record of a change made outside the controlled path (v1.3.0:
/// an observation, break-glass, judgement, quarantine or registry record;
/// v1.4.0: a remediation or review record; told by its id field) is well
/// formed, its signature verifies under one of the keys over its form as
/// received, and it is in the form the reference writes with no signed field
/// this crate does not know, as [`verify_evidence_events`] checks a stored
/// one. A review's embedded approvals are checked apart
/// ([`review_approval_problem`](crate::remediation::review_approval_problem)).
pub fn verify_out_of_band_record(record: &Value, public_keys: &[String]) -> bool {
    OUT_OF_BAND_IDS
        .iter()
        .find(|(id, ..)| record.get(*id).is_some())
        .is_some_and(|(_, model, valid)| {
            valid(Some(record))
                && out_of_band_verifies(model, record, public_keys)
                && non_canonical_fields(model, record).is_empty()
        })
}

// ── Boundary decisions ────────────────────────────────────────────────────────

const ATTESTATION_GATE_NAMES: [&str; 2] = ["attestation_status", "attestation_validity"];
const BUILTIN_GATE_NAMES: [&str; 6] = [
    "capability_check",
    "validity_window",
    "freshness_check",
    "freshness_proof",
    "attestation_status",
    "attestation_validity",
];

/// What a decision must satisfy offline.
#[derive(Debug, Clone, Default)]
pub struct VerifyDecisionOptions {
    /// NA keys that may sign decisions.
    pub operator_public_keys: Vec<String>,
    /// When non-empty and the decision embeds a freshness proof, the proof
    /// must verify under these keys.
    pub freshness_proof_issuer_keys: Vec<String>,
    /// Verification time. Defaults to now.
    pub now: Option<DateTime<Utc>>,
    /// The decision must bind exactly these policy versions.
    pub expected_policies: Option<Vec<Value>>,
    /// The decision must bind this attestation: id, subject, issuer and digest.
    pub expected_attestation: Option<Value>,
}

/// Outcome of [`verify_boundary_decision`]. `accepted` means the decision is
/// genuine; `authorized` whether it allows the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionVerification {
    /// The decision is authentic, unexpired and bound as expected.
    pub accepted: bool,
    /// Reason code, identical to the Python reference.
    pub reason: String,
    /// The decision's id, when present.
    pub decision_id: Option<String>,
    /// The decision authorizes the action.
    pub authorized: bool,
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Verify a decision's signature, expiry and bindings offline.
pub fn verify_boundary_decision(
    decision: &Value,
    options: &VerifyDecisionOptions,
) -> DecisionVerification {
    let authorized = decision.get("authorized").and_then(Value::as_bool) == Some(true);
    let result = |accepted: bool, reason: &str, authorized: bool| DecisionVerification {
        accepted,
        reason: reason.to_owned(),
        decision_id: str_field(decision, "decision_id").map(str::to_owned),
        authorized,
    };
    let reject = |reason: &str| result(false, reason, authorized);

    if !valid_decision(Some(decision)) {
        return reject("payload_invalid");
    }
    if decision.get("signature").is_none_or(Value::is_null) {
        return reject("missing_signature");
    }
    let now = options.now.unwrap_or_else(Utc::now).timestamp_micros();
    let valid_until = micros(str_field(decision, "decision_valid_until").unwrap_or_default());
    if valid_until.is_ok_and(|until| now > until) {
        return reject("decision_expired");
    }
    if !decision_signed(decision, &options.operator_public_keys) {
        return reject("invalid_signature");
    }
    // v1.2.0: an authentic decision with a signed field this crate does not
    // know, or expected inputs it cannot read, is refused by name.
    let unknown_policy = options
        .expected_policies
        .iter()
        .flatten()
        .any(|p| !unknown_fields("BoundaryPolicy", p).is_empty());
    let unknown_attestation = options
        .expected_attestation
        .as_ref()
        .is_some_and(|a| !unknown_fields("MembershipAttestation", a).is_empty());
    if !unknown_fields("BoundaryDecision", decision).is_empty()
        || unknown_policy
        || unknown_attestation
    {
        return reject("unknown_field");
    }
    // v1.2.0: a decision signed over a form the reference does not write
    // (v1.3.0: also one that leaves out a field the reference always writes).
    if !non_canonical_fields("BoundaryDecision", decision).is_empty() {
        return reject("non_canonical_form");
    }

    let proof = decision.get("freshness_proof").filter(|p| !p.is_null());
    if let Some(proof) = proof {
        if !options.freshness_proof_issuer_keys.is_empty() {
            if !signed_by(
                freshness_proof_canonical(proof),
                proof.get("signature"),
                &options.freshness_proof_issuer_keys,
            ) {
                return reject("freshness_proof_invalid_signature");
            }
            let proof_until = micros(str_field(proof, "proof_valid_until").unwrap_or_default());
            let made_at = micros(str_field(decision, "decision_made_at").unwrap_or_default());
            if matches!((proof_until, made_at), (Ok(until), Ok(made)) if until < made) {
                return reject("freshness_proof_expired");
            }
        }
    }

    let binding = decision.get("policy_binding").filter(|b| !b.is_null());
    if let Some(expected) = &options.expected_policies {
        let Some(binding) = binding else {
            return reject("policy_binding_missing");
        };
        let mut sorted: Vec<&Value> = expected.iter().collect();
        sorted.sort_by(|a, b| {
            str_field(a, "policy_id")
                .cmp(&str_field(b, "policy_id"))
                .then(
                    a.get("version")
                        .and_then(Value::as_i64)
                        .cmp(&b.get("version").and_then(Value::as_i64)),
                )
        });
        let expected_triples: Vec<String> = sorted
            .iter()
            .map(|p| {
                format!(
                    "{}\u{0}{}\u{0}{}",
                    str_field(p, "policy_id").unwrap_or_default(),
                    p.get("version").and_then(Value::as_i64).unwrap_or_default(),
                    policy_digest(p).unwrap_or_default()
                )
            })
            .collect();
        let applied = binding["policies"].as_array().cloned().unwrap_or_default();
        let bound: Vec<String> = applied
            .iter()
            .map(|a| {
                format!(
                    "{}\u{0}{}\u{0}{}",
                    str_field(a, "policy_id").unwrap_or_default(),
                    a.get("version").and_then(Value::as_i64).unwrap_or_default(),
                    str_field(a, "policy_digest").unwrap_or_default()
                )
            })
            .collect();
        let set_matches = policy_set_digest(&applied)
            .is_ok_and(|digest| Some(digest.as_str()) == str_field(binding, "policy_set_digest"));
        if expected_triples != bound || !set_matches {
            return reject("policy_binding_mismatch");
        }
    }

    if let Some(expected) = &options.expected_attestation {
        let Some(bound) = decision.get("attestation_binding").filter(|b| !b.is_null()) else {
            return reject("attestation_binding_missing");
        };
        let digest = attestation_digest(expected).ok();
        if str_field(bound, "attestation_id") != str_field(expected, "attestation_id")
            || str_field(bound, "subject_id") != str_field(expected, "subject_id")
            || str_field(bound, "issuer_sovereign_id") != str_field(expected, "issuer_sovereign_id")
            || str_field(bound, "attestation_digest") != digest.as_deref()
        {
            return reject("attestation_binding_mismatch");
        }
    }

    if !authorized {
        let failed: Vec<&Value> = decision["gate_results"]
            .as_array()
            .map(|gates| {
                gates
                    .iter()
                    .filter(|g| g.get("passed").and_then(Value::as_bool) != Some(true))
                    .collect()
            })
            .unwrap_or_default();
        let gate_name = |g: &&Value| str_field(g, "gate_name").unwrap_or_default().to_owned();
        if failed
            .iter()
            .any(|g| ATTESTATION_GATE_NAMES.contains(&gate_name(g).as_str()))
        {
            return result(true, "unauthorized_attestation_basis", false);
        }
        let builtin_failed = failed
            .iter()
            .any(|g| BUILTIN_GATE_NAMES.contains(&gate_name(g).as_str()));
        if let Some(binding) = binding {
            let resolution_failed = str_field(binding, "resolution_status") == Some("failed");
            let enforced_failure = binding["gate_evaluations"].as_array().is_some_and(|evals| {
                evals.iter().any(|e| {
                    str_field(e, "mode") == Some("enforce")
                        && e.get("passed").and_then(Value::as_bool) != Some(true)
                })
            });
            if !builtin_failed && (resolution_failed || enforced_failure) {
                return result(
                    true,
                    if resolution_failed {
                        "unauthorized_policy_resolution_failed"
                    } else {
                        "unauthorized_policy_gate_failure"
                    },
                    false,
                );
            }
        }
        let denial = str_field(decision, "denial_reason").unwrap_or_default();
        let reason = if denial.contains("capability") {
            "unauthorized_capability_out_of_scope"
        } else if denial.contains("validity") || denial.contains("window") {
            "unauthorized_outside_validity_window"
        } else if denial.contains("freshness") {
            "unauthorized_insufficient_freshness"
        } else {
            "unauthorized_gate_failure"
        };
        return result(true, reason, false);
    }
    result(true, "authorized", true)
}

// ── Evidence store export ─────────────────────────────────────────────────────

/// One problem found while verifying evidence events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFailure {
    /// Store sequence of the failing entry, when known.
    pub store_sequence: Option<i64>,
    /// Reason code, identical to the Python reference.
    pub reason: String,
    /// Extra context.
    pub detail: String,
}

/// Outcome of [`verify_evidence_events`]; the same shape the NA returns from
/// `GET /admin/evidence/verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceVerification {
    /// No failures.
    pub verified: bool,
    /// Events checked.
    pub checked_entries: u64,
    /// Decision entries checked.
    pub decisions: u64,
    /// Execution entries checked.
    pub executions: u64,
    /// Observation entries checked (v1.3.0); left out of the JSON form when
    /// zero, as the NA leaves it out.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub observations: u64,
    /// Break-glass entries checked (v1.3.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub break_glass: u64,
    /// Judgement entries checked (v1.3.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub judgements: u64,
    /// Quarantine entries checked (v1.3.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub quarantined: u64,
    /// Remediation entries checked (v1.4.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub remediations: u64,
    /// Review entries checked (v1.4.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reviews: u64,
    /// Every failure, in order.
    pub failures: Vec<VerificationFailure>,
    /// Findings that do not fail verification (v1.2.0), such as
    /// `unsigned_field`: a field outside a stored record's signature.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<VerificationFailure>,
}

fn is_zero(count: &u64) -> bool {
    *count == 0
}

/// How to verify a run of evidence events.
#[derive(Debug, Clone)]
pub struct VerifyEvidenceOptions {
    /// NA keys that sign decisions, justification proofs and retention checkpoints.
    pub na_public_keys: Vec<String>,
    /// Executor keys as listed by `GET /admin/evidence/executor-keys`
    /// (`key_id`, `public_key`, `executor_sovereign_id`); retired keys still
    /// verify old records. v1.3.0: a key's `role` is `executor` (the default
    /// when absent), which signs execution evidence and break-glass records
    /// (v1.4.0: and remediation records), or `observer`, which signs
    /// observations only.
    pub executor_keys: Vec<Value>,
    /// True for an unbroken run of the store (an export or the whole store);
    /// false for a filtered history, where store links are checked only
    /// between adjacent positions.
    pub contiguous: bool,
    /// Resource heads for chains whose early records retention removed.
    pub checkpoint: Option<Value>,
}

impl VerifyEvidenceOptions {
    /// Options for a contiguous export with no checkpoint.
    pub fn new(na_public_keys: Vec<String>, executor_keys: Vec<Value>) -> Self {
        Self {
            na_public_keys,
            executor_keys,
            contiguous: true,
            checkpoint: None,
        }
    }
}

/// An export payload's unknown fields: signed ones are refused, unsigned ones
/// (stored before 1.1.1, or in a decision's wrapper) reported and removed.
struct CheckedPayload {
    signed: Vec<String>,
    unsigned: Vec<String>,
    payload: Value,
}

fn check_payload_fields(
    kind: &str,
    payload: &Value,
    options: &VerifyEvidenceOptions,
    executor_keys: &HashMap<&str, &Value>,
) -> CheckedPayload {
    let none = |payload: &Value| CheckedPayload {
        signed: Vec::new(),
        unsigned: Vec::new(),
        payload: payload.clone(),
    };
    if kind == "decision" {
        let decision = &payload["decision"];
        let mut unsigned: Vec<String> = payload
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k)
            .filter(|k| *k != "decision" && *k != "context")
            .cloned()
            .collect();
        unsigned.extend(prefixed_unknown_fields(
            "ContextRecord",
            &payload["context"],
            "context.",
        ));
        let found = prefixed_unknown_fields("BoundaryDecision", decision, "decision.");
        if !found.is_empty() && decision_signed(decision, &options.na_public_keys) {
            return CheckedPayload {
                signed: found,
                unsigned,
                payload: payload.clone(),
            };
        }
        unsigned.extend(found);
        let mut cleaned = serde_json::Map::new();
        cleaned.insert(
            "decision".into(),
            without_unknown_fields("BoundaryDecision", decision),
        );
        cleaned.insert(
            "context".into(),
            without_unknown_fields("ContextRecord", &payload["context"]),
        );
        return CheckedPayload {
            signed: Vec::new(),
            unsigned,
            payload: Value::Object(cleaned),
        };
    }
    let model = match kind {
        "justification" => "JustificationProof",
        "execution" => "ExecutionEvidence",
        "retention_checkpoint" => "RetentionCheckpoint",
        other => match out_of_band_model(other) {
            Some(model) => model,
            None => return none(payload),
        },
    };
    let found = unknown_fields(model, payload);
    if found.is_empty() {
        return none(payload);
    }
    let signed_as_received = match kind {
        "execution" => payload
            .get("signature")
            .and_then(|sig| str_field(sig, "key_id"))
            .and_then(|id| executor_keys.get(id))
            .is_some_and(|key| {
                signed_by(
                    execution_canonical(payload),
                    payload.get("signature"),
                    &[str_field(key, "public_key").unwrap_or_default().to_owned()],
                )
            }),
        "justification" => signed_by(
            justification_canonical(payload),
            payload.get("signature"),
            &options.na_public_keys,
        ),
        "retention_checkpoint" => checkpoint_signed(payload, &options.na_public_keys),
        // v1.3.0: the key the signature names, whatever its role or sovereign,
        // so an authentic record with a field this crate does not know is
        // refused by name first, as the reference refuses it.
        "observation" | "break_glass" | "remediation" => payload
            .get("signature")
            .and_then(|sig| str_field(sig, "key_id"))
            .and_then(|id| executor_keys.get(id))
            .is_some_and(|key| {
                signed_by(
                    out_of_band_canonical(payload),
                    payload.get("signature"),
                    &[str_field(key, "public_key").unwrap_or_default().to_owned()],
                )
            }),
        _ => signed_by(
            out_of_band_canonical(payload),
            payload.get("signature"),
            &options.na_public_keys,
        ),
    };
    if signed_as_received {
        CheckedPayload {
            signed: found,
            unsigned: Vec::new(),
            payload: payload.clone(),
        }
    } else {
        CheckedPayload {
            signed: Vec::new(),
            unsigned: found,
            payload: without_unknown_fields(model, payload),
        }
    }
}

/// v1.3.0: the model each Stage 2 entry kind holds (v1.4.0: and each
/// Stage 3 kind).
fn out_of_band_model(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "observation" => "ObservationRecord",
        "break_glass" => "BreakGlassRecord",
        "judgement" => "JudgementRecord",
        "quarantine" => "QuarantineRecord",
        "registry" => "RegistryRecord",
        "remediation" => "RemediationRecord",
        "review" => "ReviewRecord",
        _ => return None,
    })
}

/// What a registered key signs (v1.3.0): `executor` unless it says otherwise.
fn key_role(key: &Value) -> &str {
    str_field(key, "role").unwrap_or("executor")
}

/// The keys that may sign a Stage 2 record: the registered key it names, when
/// that key belongs to the record's sovereign and has the role its kind needs
/// (an observer key for an observation, an executor key for a break-glass
/// record or, v1.4.0, a remediation record), or the NA's for the kinds the NA
/// signs.
fn out_of_band_keys(
    kind: &str,
    payload: &Value,
    na_public_keys: &[String],
    executor_keys: &HashMap<&str, &Value>,
) -> Vec<String> {
    let (role, sovereign) = match kind {
        "observation" => ("observer", "observer_sovereign_id"),
        "break_glass" | "remediation" => ("executor", "executor_sovereign_id"),
        _ => return na_public_keys.to_vec(),
    };
    payload
        .get("signature")
        .and_then(|sig| str_field(sig, "key_id"))
        .and_then(|id| executor_keys.get(id))
        .filter(|key| {
            str_field(key, "executor_sovereign_id") == str_field(payload, sovereign)
                && key_role(key) == role
        })
        .map(|key| vec![str_field(key, "public_key").unwrap_or_default().to_owned()])
        .unwrap_or_default()
}

/// Parse `gm.evidence.event` JSON Lines (blank lines ignored).
pub fn parse_export_lines(text: &str) -> Result<Vec<Value>> {
    let mut events = Vec::new();
    // JSON whitespace only, as every implementation (`trim` also removes other spaces).
    let json_space = |c: char| matches!(c, ' ' | '\t' | '\r' | '\n');
    for line in text
        .lines()
        .map(|l| l.trim_matches(json_space))
        .filter(|l| !l.is_empty())
    {
        let event = crate::strict_json::parse_strict_json(line)?;
        if !valid_event(Some(&event)) {
            return Err(GenesisMeshError::Verification(
                "invalid evidence event envelope or unsupported schema".into(),
            ));
        }
        events.push(event);
    }
    Ok(events)
}

/// The model a Stage 2 entry kind holds (v1.3.0).
fn model_of(kind: &str) -> &'static str {
    out_of_band_model(kind).unwrap_or_default()
}

/// Whether a Stage 2 payload's signature covers it as received under the key
/// its kind allows (v1.3.0).
fn out_of_band_signed(
    kind: &str,
    payload: &Value,
    options: &VerifyEvidenceOptions,
    executor_keys: &HashMap<&str, &Value>,
) -> bool {
    out_of_band_model(kind).is_some_and(|model| {
        out_of_band_verifies(
            model,
            payload,
            &out_of_band_keys(kind, payload, &options.na_public_keys, executor_keys),
        )
    })
}

/// Whether an export payload of a known kind is well formed.
fn valid_payload(kind: &str, payload: &Value) -> bool {
    match kind {
        "decision" => valid_decision(payload.get("decision")),
        "justification" => valid_justification(Some(payload)),
        "execution" => valid_execution(Some(payload)),
        "retention_checkpoint" => valid_checkpoint(Some(payload)),
        "observation" => valid_observation(Some(payload)),
        "break_glass" => valid_break_glass(Some(payload)),
        "judgement" => valid_judgement(Some(payload)),
        "quarantine" => valid_quarantine(Some(payload)),
        "registry" => valid_registry(Some(payload)),
        "remediation" => valid_remediation(Some(payload)),
        "review" => valid_review(Some(payload)),
        _ => false,
    }
}

/// A record's id, which appears once per kind in a store (v1.3.1).
fn record_id_of(kind: &str, payload: &Value) -> String {
    let id = match kind {
        "decision" => &payload["decision"]["decision_id"],
        "justification" => &payload["proof_id"],
        "execution" => &payload["evidence_id"],
        "retention_checkpoint" => &payload["checkpoint_id"],
        "observation" => &payload["observation_id"],
        "break_glass" => &payload["break_glass_id"],
        "judgement" => &payload["judgement_id"],
        "quarantine" => &payload["quarantine_id"],
        "registry" => &payload["registry_record_id"],
        "remediation" => &payload["remediation_id"],
        "review" => &payload["review_id"],
        _ => &Value::Null,
    };
    id.as_str().unwrap_or_default().to_owned()
}

/// v1.3.1: the envelope fields a Stage 2 entry derives from its record, and
/// the record field each must equal (an absent field is null). The NA
/// searches and matches on them.
const ENVELOPE_FIELDS: [(&str, &[(&str, &str)]); 7] = [
    (
        "observation",
        &[
            ("record_id", "observation_id"),
            ("resource_id", "resource_id"),
            ("resource_action", "action"),
            ("capability", "capability"),
            ("executor_sovereign_id", "observer_sovereign_id"),
        ],
    ),
    (
        "break_glass",
        &[
            ("record_id", "break_glass_id"),
            ("resource_id", "resource_id"),
            ("resource_action", "resource_action"),
            ("capability", "capability"),
            ("executor_sovereign_id", "executor_sovereign_id"),
            ("attestation_id", "attestation_id"),
            ("outcome", "outcome"),
        ],
    ),
    (
        "judgement",
        &[
            ("record_id", "judgement_id"),
            ("subject_id", "subject_id"),
            ("resource_id", "resource_id"),
            ("resource_action", "action"),
            ("capability", "capability"),
            ("outcome", "verdict"),
            ("matched_evidence_id", "matched_evidence_id"),
        ],
    ),
    (
        "quarantine",
        &[
            ("record_id", "quarantine_id"),
            ("resource_id", "resource_id"),
            ("outcome", "rejection_code"),
        ],
    ),
    (
        "registry",
        &[("record_id", "registry_record_id"), ("outcome", "event")],
    ),
    // v1.4.0
    (
        "remediation",
        &[
            ("record_id", "remediation_id"),
            ("subject_id", "subject_id"),
            ("resource_id", "resource_id"),
            ("executor_sovereign_id", "executor_sovereign_id"),
            ("outcome", "outcome"),
        ],
    ),
    (
        "review",
        &[
            ("record_id", "review_id"),
            ("subject_id", "subject_id"),
            ("resource_id", "resource_id"),
            ("capability", "capability"),
            ("outcome", "verdict"),
        ],
    ),
];

/// The envelope fields of an entry that differ from what its record says.
fn envelope_mismatches(kind: &str, entry: &Value, payload: &Value) -> Vec<&'static str> {
    let null = Value::Null;
    ENVELOPE_FIELDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, fields)| {
            fields
                .iter()
                .filter(|(field, source)| {
                    entry.get(*field).unwrap_or(&null) != payload.get(*source).unwrap_or(&null)
                })
                .map(|(field, _)| *field)
                .collect()
        })
        .unwrap_or_default()
}

fn fail(result: &mut EvidenceVerification, seq: Option<i64>, reason: &str, detail: &str) {
    result.verified = false;
    result.failures.push(VerificationFailure {
        store_sequence: seq,
        reason: reason.to_owned(),
        detail: detail.to_owned(),
    });
}

/// Verify stored entries: envelopes, the store chain, every signature, and
/// the decision and resource chains. v1.3.0: also the records of changes
/// made outside the controlled path (observations, break-glass records,
/// judgements, quarantine and registry entries), each resource's observation
/// positions, one judgement per record that names it as stored, and
/// execution evidence matched once.
///
/// v1.3.1, as the reference verifies an export:
///
/// * a run that starts at entry 1, or right after the checkpoint, holds each
///   chain from its start; one that starts anywhere else takes the first
///   record it holds of a resource as that chain's start;
/// * a record's id appears once per kind (`duplicate_record`);
/// * a Stage 2 entry's envelope names what its record says, every field the
///   NA derives from it (`envelope_mismatch`, once per entry);
/// * a judgement's subject is keyed by its kind and id; its matched record is
///   in a run from entry 1 (`judgement_match_missing`);
/// * a retention checkpoint removed as many entries as positions, counted
///   from the checkpoint before it when the run holds that one
///   (`retention_count_mismatch`);
/// * a record with fields outside its signature is checked for its form as
///   the signer signed it.
///
/// v1.4.0, remediations and reviews, as the reference verifies them:
///
/// * one remediation per judgement or decision (`duplicate_remediation`); it
///   names its judgement's resource (`remediation_subject_mismatch`); in a
///   run from entry 1 its subject and its forward rotation's execution
///   evidence are held before it (`remediation_subject_missing`,
///   `remediation_rotation_missing`), and the rotation is of the same
///   resource (`remediation_rotation_mismatch`); a remediation record is
///   signed by an executor key of its sovereign;
/// * a review's embedded admin requests verify offline
///   (`review_approval_invalid`, see
///   [`review_approval_problem`](crate::remediation::review_approval_problem)),
///   with the public key and holder the holder registry records for each
///   operator key at the time, when the run holds a record for that key
///   (`review_approval_key_mismatch`); its decider is a second holder
///   (`review_same_holder`); it names its subject's payload digest
///   (`review_subject_mismatch`; `review_subject_missing` in a run from
///   entry 1); and no waiver follows a remediation of the same subject
///   (`review_waiver_after_remediation`);
/// * remediation and review ids are not decisions (`evidence_cites_judgement`).
pub fn verify_evidence_events<'a>(
    events: impl IntoIterator<Item = &'a Value>,
    options: &VerifyEvidenceOptions,
) -> EvidenceVerification {
    let mut result = EvidenceVerification {
        verified: true,
        checked_entries: 0,
        decisions: 0,
        executions: 0,
        observations: 0,
        break_glass: 0,
        judgements: 0,
        quarantined: 0,
        remediations: 0,
        reviews: 0,
        failures: Vec::new(),
        warnings: Vec::new(),
    };
    let executor_keys: HashMap<&str, &Value> = options
        .executor_keys
        .iter()
        .filter_map(|k| Some((str_field(k, "key_id")?, k)))
        .collect();
    let checkpoint = options.checkpoint.as_ref().filter(|c| !c.is_null());

    let mut decisions: HashMap<String, Value> = HashMap::new();
    let mut contexts: HashMap<String, Value> = HashMap::new();
    let mut last_exec: HashMap<String, Value> = HashMap::new();
    let mut resource_heads: BTreeMap<String, ResourceHead> = checkpoint
        .and_then(|c| c.get("resource_heads"))
        .and_then(|h| serde_json::from_value(h.clone()).ok())
        .unwrap_or_default();
    // v1.3.0: observation positions per resource, judged records, matched evidence.
    let mut observation_heads: HashMap<String, i64> = checkpoint
        .and_then(|c| c.get("observation_heads"))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(resource, position)| Some((resource.clone(), position.as_i64()?)))
        .collect();
    // v1.3.1: judgement subjects and judged records by kind and id.
    let mut subjects: HashMap<(String, String), (String, i64)> = HashMap::new();
    let mut judged: HashSet<(String, String)> = HashSet::new();
    let mut matched: HashSet<String> = HashSet::new();
    let mut not_decisions: HashSet<String> = HashSet::new();
    // v1.3.1: the record ids seen per kind, the records a judgement can
    // match, and each retention checkpoint's last removed position.
    let mut record_ids: HashSet<(String, String)> = HashSet::new();
    let mut matchable: HashSet<String> = HashSet::new();
    let mut checkpoints: HashMap<String, i64> = HashMap::new();
    // v1.4.0: judgements and decisions by id (payload digest, resource),
    // execution evidence's resources, remediated subjects, and operator keys
    // as the holder registry records them.
    let mut stage3 = Stage3::default();
    let mut first_sequence: Option<i64> = None;
    let mut from_start = false;
    let mut prev: Option<Value> = None;

    if let Some(checkpoint) = checkpoint {
        if !valid_checkpoint(Some(checkpoint))
            || !checkpoint_signed(checkpoint, &options.na_public_keys)
        {
            fail(
                &mut result,
                None,
                "invalid_signature",
                "retention_checkpoint",
            );
            return result;
        }
        let unknown = prefixed_unknown_fields("RetentionCheckpoint", checkpoint, "checkpoint.");
        if !unknown.is_empty() {
            fail(&mut result, None, "unknown_field", &unknown.join(", "));
            return result;
        }
    }

    for event in events {
        result.checked_entries += 1;
        if !valid_event(Some(event)) {
            fail(&mut result, None, "payload_invalid", "event envelope");
            continue;
        }
        let entry = &event["entry"];
        let seq = entry["store_sequence"].as_i64().unwrap_or_default();
        let s = Some(seq);
        if entry_digest(entry).ok().as_deref() != str_field(event, "entry_digest") {
            fail(&mut result, s, "entry_digest_mismatch", "");
        }
        if payload_digest(&event["payload"]).ok().as_deref() != str_field(entry, "payload_digest") {
            fail(&mut result, s, "payload_digest_mismatch", "");
        }
        let prev_seq = prev.as_ref().and_then(|p| p["store_sequence"].as_i64());
        match (&prev, prev_seq) {
            (Some(prev), Some(prev_seq)) if options.contiguous || seq == prev_seq + 1 => {
                if seq != prev_seq + 1 {
                    fail(&mut result, s, "store_sequence_gap", "");
                } else if str_field(entry, "prev_entry_digest")
                    != entry_digest(prev).ok().as_deref()
                {
                    fail(&mut result, s, "store_chain_break", "");
                }
            }
            (None, _) => {
                if let Some(checkpoint) = checkpoint {
                    if Some(seq)
                        == checkpoint["removed_through_sequence"]
                            .as_i64()
                            .map(|n| n + 1)
                        && str_field(entry, "prev_entry_digest")
                            != str_field(checkpoint, "last_removed_entry_digest")
                    {
                        fail(
                            &mut result,
                            s,
                            "store_chain_break",
                            "does not continue from the checkpoint",
                        );
                    }
                }
            }
            _ => {}
        }
        if first_sequence.is_none() {
            first_sequence = Some(seq);
            from_start = seq == 1
                || checkpoint.is_some_and(|c| {
                    c["removed_through_sequence"].as_i64().map(|n| n + 1) == Some(seq)
                });
        }
        prev = Some(entry.clone());

        let kind = str_field(entry, "entry_kind").unwrap_or_default();
        if !is_known_entry_kind(kind) {
            // v1.2.0: a kind from a later release; its envelope still chains.
            fail(&mut result, s, "unknown_entry_kind", kind);
            continue;
        }
        let checked = check_payload_fields(kind, &event["payload"], options, &executor_keys);
        if !checked.signed.is_empty() {
            fail(&mut result, s, "unknown_field", &checked.signed.join(", "));
            continue;
        }
        if !checked.unsigned.is_empty() {
            result.warnings.push(VerificationFailure {
                store_sequence: s,
                reason: "unsigned_field".to_owned(),
                detail: checked.unsigned.join(", "),
            });
            // v1.3.0: the reference stores these records exactly as signed; a
            // field outside the signature is no part of one (the reference
            // refuses it as it reads the record).
            if out_of_band_model(kind).is_some() {
                fail(
                    &mut result,
                    s,
                    "payload_invalid",
                    &checked.unsigned.join(", "),
                );
                continue;
            }
        }
        let payload = &checked.payload;
        // A record whose signature covers it as received, in a form the
        // reference does not write, is refused by name, as the reference
        // refuses it (v1.3.0); since 1.3.1 also one whose fields outside its
        // signature were set aside, checked as the signer signed it.
        let signature = |result: &mut EvidenceVerification,
                         signed: bool,
                         model: &str,
                         record: &Value,
                         detail: &str| {
            if !signed {
                fail(result, s, "invalid_signature", detail);
            } else if !non_canonical_fields(model, record).is_empty() {
                fail(result, s, "non_canonical_form", detail);
            }
        };
        if !valid_payload(kind, payload) {
            fail(&mut result, s, "payload_invalid", "");
            continue;
        }
        // v1.3.1: a record appears once per kind; a copied entry is a replay.
        let record_id = record_id_of(kind, payload);
        if !record_ids.insert((kind.to_owned(), record_id.clone())) {
            fail(
                &mut result,
                s,
                "duplicate_record",
                &format!("{kind} {record_id}"),
            );
        }
        // v1.3.1: the envelope names what the record says.
        let wrong = envelope_mismatches(kind, entry, payload);
        if !wrong.is_empty() {
            fail(
                &mut result,
                s,
                "envelope_mismatch",
                &format!("{kind}: {}", wrong.join(", ")),
            );
        }
        match kind {
            "decision" => {
                let decision = &payload["decision"];
                signature(
                    &mut result,
                    verify_decision_signature(decision, &options.na_public_keys),
                    "BoundaryDecision",
                    decision,
                    "decision",
                );
                result.decisions += 1;
                let id = str_field(decision, "decision_id")
                    .unwrap_or_default()
                    .to_owned();
                stage3.judged.insert(
                    id.clone(),
                    (
                        str_field(entry, "payload_digest")
                            .unwrap_or_default()
                            .to_owned(),
                        None,
                    ),
                );
                decisions.insert(id.clone(), decision.clone());
                if valid_context(payload.get("context")) {
                    contexts.insert(id, payload["context"].clone());
                } else {
                    fail(&mut result, s, "payload_invalid", "context");
                }
            }
            "justification" => {
                signature(
                    &mut result,
                    verify_justification_signature(payload, &options.na_public_keys),
                    "JustificationProof",
                    payload,
                    "justification",
                );
            }
            "execution" => {
                let ev = payload;
                let key = ev
                    .get("signature")
                    .and_then(|sig| str_field(sig, "key_id"))
                    .and_then(|id| executor_keys.get(id));
                // v1.3.0: only an executor key signs execution evidence.
                let signed = key.is_some_and(|key| {
                    str_field(key, "executor_sovereign_id")
                        == str_field(ev, "executor_sovereign_id")
                        && key_role(key) == "executor"
                        && verify_execution_signature(
                            ev,
                            str_field(key, "public_key").unwrap_or_default(),
                        )
                });
                signature(&mut result, signed, "ExecutionEvidence", ev, "execution");
                result.executions += 1;
                let decision_id = str_field(ev, "decision_id").unwrap_or_default().to_owned();
                let decision = decisions.get(&decision_id);
                if let Some(decision) = decision {
                    let at = micros(str_field(ev, "executed_at").unwrap_or_default())
                        .unwrap_or_default();
                    let made = micros(str_field(decision, "decision_made_at").unwrap_or_default())
                        .unwrap_or_default();
                    let until =
                        micros(str_field(decision, "decision_valid_until").unwrap_or_default())
                            .unwrap_or_default();
                    if decision.get("authorized").and_then(Value::as_bool) != Some(true) {
                        fail(&mut result, s, "evidence_decision_denied", "");
                    } else if at < made || at > until {
                        fail(&mut result, s, "evidence_outside_decision_window", "");
                    } else if contexts.get(&decision_id).is_some_and(|c| {
                        str_field(ev, "executed_capability") != str_field(c, "requested_capability")
                    }) {
                        fail(&mut result, s, "evidence_capability_mismatch", "");
                    }
                }
                // v1.3.0: execution evidence never rests on a judgement or a record of one.
                if not_decisions.contains(&decision_id) {
                    fail(&mut result, s, "evidence_cites_judgement", &decision_id);
                }
                let sequence_no = ev["sequence_no"].as_i64();
                let prev_digest = str_field(ev, "prev_evidence_digest");
                if let Some(prior) = last_exec.get(&decision_id) {
                    if sequence_no != prior["sequence_no"].as_i64().map(|n| n + 1)
                        || prev_digest != execution_digest(prior).ok().as_deref()
                    {
                        fail(&mut result, s, "evidence_chain_break", "");
                    }
                } else if decision.is_some() && (sequence_no != Some(1) || prev_digest.is_some()) {
                    fail(&mut result, s, "evidence_chain_break", "");
                }
                last_exec.insert(decision_id, ev.clone());
                matchable.insert(str_field(ev, "evidence_id").unwrap_or_default().to_owned());
                stage3.executed.insert(
                    str_field(ev, "evidence_id").unwrap_or_default().to_owned(),
                    str_field(ev, "resource_id").map(str::to_owned),
                );
                if let Some(resource_id) = str_field(ev, "resource_id") {
                    let head = resource_heads.get(resource_id);
                    let expected = head.map_or(1, |h| h.resource_sequence + 1);
                    let resource_sequence = ev.get("resource_sequence").and_then(Value::as_u64);
                    // v1.3.1: a run that starts after entry 1 and not right
                    // after the checkpoint takes the first record it holds of
                    // a resource as that chain's start.
                    if (head.is_some() || from_start)
                        && (resource_sequence != Some(expected)
                            || str_field(ev, "prev_resource_digest")
                                != head.map(|h| h.record_digest.as_str()))
                    {
                        fail(&mut result, s, "resource_chain_break", resource_id);
                    }
                    resource_heads.insert(
                        resource_id.to_owned(),
                        ResourceHead {
                            resource_sequence: resource_sequence.unwrap_or_default(),
                            record_digest: execution_digest(ev).unwrap_or_default(),
                        },
                    );
                }
            }
            "retention_checkpoint" => {
                signature(
                    &mut result,
                    verify_retention_checkpoint(payload, &options.na_public_keys),
                    "RetentionCheckpoint",
                    payload,
                    "retention_checkpoint",
                );
                // v1.3.1: a checkpoint removed as many entries as positions,
                // counted from the checkpoint before it when the run holds
                // that one, or from entry 1 when there is none.
                let through = payload["removed_through_sequence"]
                    .as_i64()
                    .unwrap_or_default();
                let start = match str_field(payload, "previous_checkpoint_id") {
                    None => Some(0),
                    Some(previous) => checkpoints.get(previous).copied(),
                };
                if let Some(start) = start {
                    if payload["removed_count"].as_i64() != Some(through - start) {
                        fail(
                            &mut result,
                            s,
                            "retention_count_mismatch",
                            &format!(
                                "removed {} of {} entries after #{start} through #{through}",
                                payload["removed_count"],
                                through - start
                            ),
                        );
                    }
                }
                checkpoints.insert(record_id, through);
            }
            "observation" | "break_glass" => {
                let observation = kind == "observation";
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                let resource = str_field(payload, "resource_id")
                    .unwrap_or_default()
                    .to_owned();
                let digest = str_field(entry, "payload_digest").unwrap_or_default();
                subjects.insert(
                    (kind.to_owned(), record_id.clone()),
                    (digest.to_owned(), seq),
                );
                not_decisions.insert(record_id.clone());
                if observation {
                    result.observations += 1;
                    let position = entry["observation_sequence"].as_i64();
                    let head = observation_heads.get(&resource).copied();
                    if (head.is_some() || from_start) && position != Some(head.unwrap_or(0) + 1) {
                        fail(&mut result, s, "observation_chain_break", &resource);
                    }
                    let next = position.filter(|&p| p != 0).unwrap_or(head.unwrap_or(0));
                    observation_heads.insert(resource, next);
                } else {
                    result.break_glass += 1;
                    matchable.insert(record_id);
                }
            }
            "judgement" => {
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                result.judgements += 1;
                stage3.judged.insert(
                    record_id.clone(),
                    (
                        str_field(entry, "payload_digest")
                            .unwrap_or_default()
                            .to_owned(),
                        str_field(payload, "resource_id").map(str::to_owned),
                    ),
                );
                not_decisions.insert(record_id);
                let subject_id = str_field(payload, "subject_id").unwrap_or_default();
                // v1.3.1: keyed by the subject's kind and id.
                let subject = (
                    str_field(payload, "subject_kind")
                        .unwrap_or_default()
                        .to_owned(),
                    subject_id.to_owned(),
                );
                if !judged.insert(subject.clone()) {
                    fail(&mut result, s, "duplicate_judgement", subject_id);
                }
                let subject_sequence = payload["subject_store_sequence"].as_i64();
                match subjects.get(&subject) {
                    Some((digest, sequence)) => {
                        if Some(digest.as_str()) != str_field(payload, "subject_digest")
                            || Some(*sequence) != subject_sequence
                        {
                            fail(&mut result, s, "judgement_subject_mismatch", subject_id);
                        }
                    }
                    None => {
                        if options.contiguous
                            && first_sequence.is_some_and(|first| subject_sequence >= Some(first))
                        {
                            fail(&mut result, s, "judgement_subject_missing", subject_id);
                        }
                    }
                }
                if let Some(evidence_id) = str_field(payload, "matched_evidence_id") {
                    if !matched.insert(evidence_id.to_owned()) {
                        fail(&mut result, s, "match_reused", evidence_id);
                    }
                    // v1.3.1: the NA matches a record it already holds, so a
                    // run from entry 1 holds it.
                    if options.contiguous
                        && first_sequence == Some(1)
                        && !matchable.contains(evidence_id)
                    {
                        fail(&mut result, s, "judgement_match_missing", evidence_id);
                    }
                }
            }
            "quarantine" => {
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                result.quarantined += 1;
                if payload_digest(&payload["record"]).ok().as_deref()
                    != str_field(payload, "record_digest")
                {
                    fail(&mut result, s, "quarantine_digest_mismatch", "");
                }
            }
            "registry" => {
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                // v1.4.0: the operator keys' public keys and holders over time.
                if let (Some("operator_key_holder"), Some(key_id)) =
                    (str_field(payload, "event"), str_field(payload, "key_id"))
                {
                    stage3
                        .operator_keys
                        .entry(key_id.to_owned())
                        .or_default()
                        .push((
                            micros(str_field(payload, "effective_at").unwrap_or_default())
                                .unwrap_or_default(),
                            str_field(payload, "public_key").map(str::to_owned),
                            str_field(payload, "holder").map(str::to_owned),
                        ));
                }
            }
            "remediation" => {
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                result.remediations += 1;
                not_decisions.insert(record_id);
                let held_from_start = options.contiguous && first_sequence == Some(1);
                for (reason, detail) in stage3.remediation(payload, held_from_start) {
                    fail(&mut result, s, reason, &detail);
                }
            }
            "review" => {
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                result.reviews += 1;
                not_decisions.insert(record_id);
                let held_from_start = options.contiguous && first_sequence == Some(1);
                for (reason, detail) in
                    stage3.review(payload, &options.na_public_keys, held_from_start)
                {
                    fail(&mut result, s, reason, &detail);
                }
            }
            other => fail(&mut result, s, "unknown_entry_kind", other),
        }
    }
    result
}

/// An operator key as the holder registry records it (v1.4.0): when (in
/// microseconds), its public key and its holder.
type HolderRecord = (i64, Option<String>, Option<String>);

/// What an export verifier keeps for the Stage 3 checks (v1.4.0).
#[derive(Default)]
struct Stage3 {
    /// Judgements and decisions by id: payload digest, and a judgement's resource.
    judged: HashMap<String, (String, Option<String>)>,
    /// Execution evidence by id: its resource.
    executed: HashMap<String, Option<String>>,
    /// Subjects a remediation was recorded for.
    remediated: HashSet<String>,
    /// Operator keys as the holder registry records them: when, public key, holder.
    operator_keys: HashMap<String, Vec<HolderRecord>>,
}

impl Stage3 {
    /// One remediation per subject, of its subject's resource, after its
    /// forward rotation.
    fn remediation(
        &mut self,
        record: &Value,
        held_from_start: bool,
    ) -> Vec<(&'static str, String)> {
        let mut failures = Vec::new();
        let subject_id = str_field(record, "subject_id").unwrap_or_default();
        let resource_id = str_field(record, "resource_id");
        if !self.remediated.insert(subject_id.to_owned()) {
            failures.push(("duplicate_remediation", subject_id.to_owned()));
        }
        match self.judged.get(subject_id) {
            None if held_from_start => {
                failures.push(("remediation_subject_missing", subject_id.to_owned()));
            }
            Some((_, judged_resource))
                if str_field(record, "subject_kind") == Some("judgement")
                    && judged_resource.as_deref() != resource_id =>
            {
                failures.push(("remediation_subject_mismatch", subject_id.to_owned()));
            }
            _ => {}
        }
        if let Some(rotation) = str_field(record, "rotation_evidence_id") {
            match self.executed.get(rotation) {
                Some(rotated) if rotated.as_deref() != resource_id => {
                    failures.push(("remediation_rotation_mismatch", rotation.to_owned()));
                }
                None if held_from_start => {
                    failures.push(("remediation_rotation_missing", rotation.to_owned()));
                }
                _ => {}
            }
        }
        failures
    }

    /// A review's approvals verify offline, from a second holder, on the
    /// subject it names.
    fn review(
        &self,
        record: &Value,
        na_public_keys: &[String],
        held_from_start: bool,
    ) -> Vec<(&'static str, String)> {
        let mut failures = Vec::new();
        if let Some(problem) = review_approval_problem(record, na_public_keys) {
            failures.push(("review_approval_invalid", problem));
        }
        for (key, approval, holder, at) in [
            ("decided_by", "approval", "decider_holder", "decided_at"),
            (
                "requested_by",
                "request_approval",
                "requester_holder",
                "requested_at",
            ),
        ] {
            let (Some(key_id), Some(approval)) = (
                str_field(record, key),
                record.get(approval).filter(|a| !a.is_null()),
            ) else {
                continue;
            };
            let Some(recorded) = self.operator_keys.get(key_id) else {
                continue;
            };
            let at = micros(str_field(record, at).unwrap_or_default()).unwrap_or_default();
            // The latest record at or before the time; the first of equals.
            let latest = recorded.iter().filter(|(when, ..)| *when <= at).fold(
                None,
                |latest: Option<&HolderRecord>, r| match latest {
                    Some(l) if l.0 >= r.0 => Some(l),
                    _ => Some(r),
                },
            );
            let matches = latest.is_some_and(|(_, public_key, recorded_holder)| {
                public_key.as_deref() == str_field(approval, "public_key")
                    && recorded_holder.as_deref() == str_field(record, holder)
            });
            if !matches {
                failures.push(("review_approval_key_mismatch", key_id.to_owned()));
            }
        }
        if review_holder_problem(&ReviewHolders::of(record)).is_some() {
            let decider = str_field(record, "decided_by").unwrap_or_default();
            failures.push(("review_same_holder", decider.to_owned()));
        }
        let subject_id = str_field(record, "subject_id").unwrap_or_default();
        match self.judged.get(subject_id) {
            None if held_from_start => {
                failures.push(("review_subject_missing", subject_id.to_owned()));
            }
            Some((digest, _)) if Some(digest.as_str()) != str_field(record, "subject_digest") => {
                failures.push(("review_subject_mismatch", subject_id.to_owned()));
            }
            _ => {}
        }
        if str_field(record, "verdict") == Some("waive_until")
            && self.remediated.contains(subject_id)
        {
            failures.push(("review_waiver_after_remediation", subject_id.to_owned()));
        }
        failures
    }
}
