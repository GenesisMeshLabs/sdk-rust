//! Offline verification of NA-signed artifacts and evidence exports.
//! Direct ports of the Python reference, with the same reason codes:
//!
//! * [`verify_boundary_decision`]: `trust/context/decisions.py` `verify_boundary_decision`
//! * [`verify_evidence_events`]: `trust/evidence_store.py` `verify_evidence_events`
//! * the review checks (1.4.0): `trust/remediation.py`
//! * [`verify_store_anchors`], [`check_events_against_anchors`] and
//!   [`export_checkpoint`] (1.5.0): `trust/evidence_store.py`
//!
//! [`verify_record`] (1.5.0) verifies one record as an export verifies it.
//! The `genesis-mesh-verify` binary is built on this module.
//!
//! No network access; every key is supplied by the caller.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::OnceLock,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::grants::{
    continues_chain, next_previous, token_signature_valid, use_problem, PreviousUse, UseContext,
};
use crate::key_history::{
    succession_form_refusal, succession_signed_by, NaKeyHistory, NaKeys,
    SUCCESSION_MIN_LEAD_SECONDS,
};
use crate::strict::{
    is_known_entry_kind, non_canonical_fields, prefixed_unknown_fields, unknown_fields,
    without_unknown_fields,
};
use crate::{
    auth::verify_canonical,
    canonical::{
        anchor_canonical, anchor_digest, attestation_digest, checkpoint_canonical,
        decision_canonical, entry_digest, execution_canonical, execution_digest,
        freshness_proof_canonical, justification_canonical, key_succession_digest, micros,
        out_of_band_canonical, parse_timestamp, payload_digest, policy_canonical, policy_digest,
        policy_set_digest,
    },
    errors::{GenesisMeshError, Result},
    execution::ResourceHead,
    remediation::{
        review_approval_problem, review_holder_problem, rotation_problem, ReviewHolders,
        RotationFacts,
    },
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
            // v1.6.0: `grant`, a change matched to a grant use.
            (
                "governed_by",
                one_of(&["prior_decision", "after_the_fact", "grant"])
            ),
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
                // v1.4.0: also a refused remediation record; v1.6.0: a
                // refused grant use.
                one_of(&[
                    "execution",
                    "observation",
                    "break_glass",
                    "remediation",
                    "grant_execution"
                ])
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

/// Whether a record reads as its model (1.5.0, for the audit pack checks):
/// well formed with no field the model does not define, as the reference's
/// models (which forbid unknown fields) read it.
pub(crate) fn reads_as(model: &str, record: &Value) -> bool {
    let valid = match model {
        "RetentionCheckpoint" => valid_checkpoint(Some(record)),
        "RegistryRecord" => valid_registry(Some(record)),
        "JudgementRecord" => valid_judgement(Some(record)),
        "BoundaryDecision" => valid_decision(Some(record)),
        // v1.6.0: a grant's policy binding and basis are checked as a decision's.
        "CapabilityGrant" => valid_grant(Some(record)),
        _ => false,
    };
    valid && unknown_fields(model, record).is_empty()
}

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

// v1.5.0: an archive record, signed by the NA.
validator!(
    valid_archive,
    shape(
        vec![
            ("archive_id", bounded(128, 1)),
            ("pack_id", bounded(128, 1)),
            ("from_sequence", positive()),
            ("through_sequence", positive()),
            ("through_entry_digest", sha256()),
            ("end_anchor_sequence", positive()),
            ("manifest_sha256", sha256()),
            ("location", bounded(1024, 1)),
            ("archived_at", utc_timestamp()),
            ("recorded_by", absent(string())),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false
    )
);

// v1.6.0: pre-issued grants, their time tokens, uses and revocations. An
// absent optional field is left out of the signed form; a null reads as
// absent.

/// A field's value when present and not `null`.
fn given<'a>(record: &'a Value, key: &str) -> Option<&'a Value> {
    record.get(key).filter(|v| !v.is_null())
}

/// A grant's capabilities: 1 to 16 exact capability ids of 1 to 256
/// characters, none twice.
fn grant_capabilities() -> Check {
    Box::new(|v| {
        let Some(Value::Array(items)) = v else {
            return false;
        };
        (1..=crate::grants::MAX_GRANT_CAPABILITIES).contains(&items.len())
            && items.iter().enumerate().all(|(i, item)| {
                item.as_str()
                    .is_some_and(|c| (1..=256).contains(&c.chars().count()) && !c.contains('*'))
                    && !items[..i].contains(item)
            })
    })
}

fn grant_policy_binding() -> Check {
    shape(
        vec![
            (
                "policies",
                filled(array(shape(
                    vec![
                        ("policy_id", string()),
                        ("version", integer()),
                        ("policy_digest", string()),
                        ("signed_by", string()),
                    ],
                    false,
                ))),
            ),
            ("policy_set_digest", string()),
            (
                "gate_outcomes",
                filled(array(shape(
                    vec![
                        ("capability", string()),
                        ("policy_id", string()),
                        ("policy_version", integer()),
                        ("gate_id", string()),
                        ("gate_type", string()),
                        ("mode", one_of(&["observe", "enforce"])),
                        ("outcome", one_of(&["pass", "may_fail", "undecidable"])),
                        ("detail", bounded(1024, 0)),
                    ],
                    false,
                ))),
            ),
            ("registry_gate_types", filled(array(string()))),
        ],
        false,
    )
}

/// A use sequence between `min` and the largest budget.
fn use_sequence(min: i64) -> Check {
    Box::new(move |v| {
        v.and_then(Value::as_i64)
            .is_some_and(|n| n >= min && n <= crate::grants::GRANT_MAX_USES as i64)
    })
}

/// `use_head_digest` is given exactly when `use_sequence` is 1 or more.
fn head_consistent(record: &Value) -> bool {
    (record["use_sequence"].as_i64() == Some(0)) == given(record, "use_head_digest").is_none()
}

validator!(valid_grant, {
    let fields = shape(
        vec![
            ("grant_id", bounded(128, 1)),
            ("bearer_key_id", bounded(256, 1)),
            ("bearer_public_key", bounded(256, 1)),
            ("bearer_sovereign_id", bounded(256, 1)),
            ("capabilities", grant_capabilities()),
            ("basis_kind", one_of(&["agreement", "attestation"])),
            ("basis_id", bounded(128, 1)),
            ("basis_digest", sha256()),
            ("requester_sovereign_id", bounded(256, 1)),
            ("provider_sovereign_id", bounded(256, 1)),
            ("valid_from", utc_timestamp()),
            ("valid_until", utc_timestamp()),
            (
                "max_uses",
                int_where(|n| (1..=crate::grants::GRANT_MAX_USES as i64).contains(&n)),
            ),
            (
                "max_uses_per_time_token",
                int_where(|n| {
                    (1..=crate::grants::GRANT_MAX_USES_PER_TIME_TOKEN as i64).contains(&n)
                }),
            ),
            (
                "parameter_envelope",
                filled(Box::new(|v| {
                    v.is_some_and(|e| crate::grants::envelope_form_problem(e).is_none())
                })),
            ),
            ("basis_checks", filled(array(gate_result()))),
            ("policy_binding", grant_policy_binding()),
            ("issued_at", utc_timestamp()),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false,
    );
    // At most 24 hours, ending after it starts.
    let validity = |record: &Value| {
        let at = |key: &str| micros(str_field(record, key).unwrap_or_default());
        matches!((at("valid_from"), at("valid_until")), (Ok(from), Ok(until))
            if from < until
                && until - from <= crate::grants::GRANT_MAX_VALIDITY_SECONDS * 1_000_000)
    };
    Box::new(move |v| fields(v) && v.is_some_and(validity))
});

validator!(valid_time_token, {
    let fields = shape(
        vec![
            ("time_token_id", bounded(128, 1)),
            ("grant_id", bounded(128, 1)),
            ("use_sequence", use_sequence(0)),
            ("use_head_digest", absent(sha256())),
            ("issued_at", utc_timestamp()),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false,
    );
    Box::new(move |v| fields(v) && v.is_some_and(head_consistent))
});

validator!(valid_time_token_request, {
    let fields = shape(
        vec![
            ("grant_id", bounded(128, 1)),
            ("use_sequence", use_sequence(0)),
            ("use_head_digest", absent(sha256())),
            ("requested_at", utc_timestamp()),
            ("signature", optional(signature())),
        ],
        false,
    );
    Box::new(move |v| fields(v) && v.is_some_and(head_consistent))
});

validator!(valid_grant_use, {
    let fields = shape(
        vec![
            (
                "use_id",
                Box::new(|v| {
                    v.and_then(Value::as_str)
                        .is_some_and(crate::grants::valid_use_id)
                }),
            ),
            ("grant_id", bounded(128, 1)),
            ("grant_digest", sha256()),
            ("use_sequence", use_sequence(1)),
            ("prev_use_digest", absent(sha256())),
            ("executor_sovereign_id", bounded(256, 1)),
            ("capability", bounded(256, 1)),
            ("request_parameters", filled(object())),
            ("resource_id", absent(bounded(256, 1))),
            ("resource_action", absent(action())),
            ("executed_at", utc_timestamp()),
            ("time_token", Box::new(valid_time_token)),
            ("outcome", one_of(&crate::grants::USE_OUTCOMES)),
            ("outcome_detail", absent(bounded(1024, 0))),
            ("execution_parameters", filled(object())),
            ("signature", optional(signature())),
        ],
        false,
    );
    // A resource and its action go together; `prev_use_digest` is given
    // exactly from the second use on.
    let consistent = |record: &Value| {
        given(record, "resource_id").is_some() == given(record, "resource_action").is_some()
            && (record["use_sequence"].as_i64() == Some(1))
                == given(record, "prev_use_digest").is_none()
    };
    Box::new(move |v| fields(v) && v.is_some_and(consistent))
});

validator!(
    valid_grant_revocation,
    shape(
        vec![
            ("revocation_id", bounded(128, 1)),
            ("grant_id", bounded(128, 1)),
            ("grant_digest", sha256()),
            ("reason", one_of(&crate::grants::REVOCATION_REASONS)),
            ("detail", absent(bounded(1024, 1))),
            ("revoked_by", absent(bounded(256, 1))),
            ("revoked_at", utc_timestamp()),
            ("issuer_sovereign_id", string()),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        false
    )
);

validator!(
    valid_feed,
    shape(
        vec![
            ("feed_id", string()),
            ("issuer_sovereign_id", string()),
            ("sequence", nonnegative()),
            ("issued_at", timestamp()),
            ("revoked_attestation_ids", filled(array(string()))),
            ("revocation_reasons", filled(dictionary(string()))),
            // v1.6.0: the revoked grants not yet past their end, with grants on.
            ("revoked_grant_ids", absent(array(string()))),
            ("issued_by", string()),
            (
                "signatures",
                filled(array(shape(
                    vec![("key_id", string()), ("sig", string())],
                    false
                )))
            ),
        ],
        false
    )
);

/// True when a sovereign revocation feed (`GET /sovereign-revocation-feed`)
/// is well formed, one of its signatures verifies under the issuer's keys
/// over the feed as received, and it carries no field this crate does not
/// know (1.6.0: it knows `revoked_grant_ids`, which an NA with grants on
/// lists; a 1.5 verifier refuses it). The revoked grants a holder must refuse
/// are its `revoked_grant_ids`.
pub fn verify_revocation_feed(feed: &Value, issuer_public_keys: &[String]) -> bool {
    valid_feed(Some(feed))
        && unknown_fields("SovereignRevocationFeed", feed).is_empty()
        && crate::grants::signed_as_received("SovereignRevocationFeed", feed, issuer_public_keys)
}

/// True when a grant record (a `CapabilityGrant`, `TimeToken`,
/// `TimeTokenRequest`, `GrantExecutionEvidence` or `GrantRevocationRecord`,
/// named by `model`) is well formed and carries no field this crate does
/// not know (1.6.0); its signature is checked apart.
pub fn valid_grant_record(model: &str, record: &Value) -> bool {
    let valid = match model {
        "CapabilityGrant" => valid_grant(Some(record)),
        "TimeToken" => valid_time_token(Some(record)),
        "TimeTokenRequest" => valid_time_token_request(Some(record)),
        "GrantExecutionEvidence" => valid_grant_use(Some(record)),
        "GrantRevocationRecord" => valid_grant_revocation(Some(record)),
        _ => false,
    };
    valid && unknown_fields(model, record).is_empty()
}

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

pub(crate) fn signed_by(
    canonical: Result<String>,
    signature: Option<&Value>,
    keys: &[String],
) -> bool {
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
const OUT_OF_BAND_IDS: [(&str, &str, Validator); 8] = [
    ("archive_id", "ArchiveRecord", valid_archive),
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
    // v1.6.0: a grant record is signed over its form as received, as the
    // field registry describes it (a nested time token keeps its form).
    let signed = if GRANT_MODELS.contains(&model) {
        crate::grants::signed_as_received(model, record, keys)
    } else {
        signed_by(out_of_band_canonical(record), record.get("signature"), keys)
    };
    signed && unknown_fields(model, record).is_empty()
}

/// The models of the grant records (v1.6.0) an export or a single record
/// holds.
const GRANT_MODELS: [&str; 4] = [
    "CapabilityGrant",
    "GrantExecutionEvidence",
    "GrantRevocationRecord",
    "TimeToken",
];

/// True when a record of a change made outside the controlled path (v1.3.0:
/// an observation, break-glass, judgement, quarantine or registry record;
/// v1.4.0: a remediation or review record; told by its id field) is well
/// formed, its signature verifies under one of the keys over its form as
/// received, and it is in the form the reference writes with no signed field
/// this crate does not know, as [`verify_evidence_events`] checks a stored
/// one. A review's embedded approvals are checked apart
/// ([`review_approval_problem`]).
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
    /// Judge the decision as of its own time, `decision_made_at`, not as of
    /// `now` (1.5.0; the reference's `at_record_time`), so an archived
    /// decision still verifies when it is audited years later; `now` is then
    /// ignored. Off by default: a decision about to be acted on is judged as
    /// of now.
    pub at_record_time: bool,
    /// The NA's key history (1.5.0): when given, the decision must be signed
    /// by the key valid at its `decision_made_at`
    /// (`na_key_not_valid_at_time` for another key of the history), and
    /// `operator_public_keys` is not used.
    pub key_history: Option<NaKeyHistory>,
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
    let made_at =
        micros(str_field(decision, "decision_made_at").unwrap_or_default()).unwrap_or_default();
    let now = if options.at_record_time {
        made_at
    } else {
        options.now.unwrap_or_else(Utc::now).timestamp_micros()
    };
    let valid_until = micros(str_field(decision, "decision_valid_until").unwrap_or_default());
    if valid_until.is_ok_and(|until| now > until) {
        return reject("decision_expired");
    }
    let keys = match &options.key_history {
        Some(history) => NaKeys::History(history.clone()),
        None => NaKeys::Any(options.operator_public_keys.clone()),
    };
    let valid_then = keys.at(Some(made_at));
    let Some(signer) = valid_then
        .iter()
        .find(|k| decision_signed(decision, std::slice::from_ref(k)))
    else {
        // v1.5.0: signed by a key of the history, but not the one valid then.
        return reject(if decision_signed(decision, &keys.not_at(made_at)) {
            "na_key_not_valid_at_time"
        } else {
            "invalid_signature"
        });
    };
    // 1.5.0 review fixes: a key with an end vouches for a decision only as
    // long as the longest lifetime the NA issues past that end.
    let until =
        micros(str_field(decision, "decision_valid_until").unwrap_or_default()).unwrap_or_default();
    if keys
        .history()
        .is_some_and(|history| history.decision_outlives_key(signer, until))
    {
        return reject("decision_outlives_key");
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
    /// Key succession entries checked (v1.5.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub key_successions: u64,
    /// Archive entries checked (v1.5.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub archives: u64,
    /// Grant entries checked (v1.6.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub grants: u64,
    /// Grant use entries checked (v1.6.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub grant_executions: u64,
    /// Grant revocation entries checked (v1.6.0); left out when zero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub grant_revocations: u64,
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

impl EvidenceVerification {
    pub(crate) fn empty() -> Self {
        EvidenceVerification {
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
            key_successions: 0,
            archives: 0,
            grants: 0,
            grant_executions: 0,
            grant_revocations: 0,
            failures: Vec::new(),
            warnings: Vec::new(),
        }
    }
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
    /// The NA's key history (1.5.0): when given, an NA signature must be made
    /// by the key valid at the entry's `recorded_at`
    /// (`na_key_not_valid_at_time` for another key of the history), a key
    /// succession entry must be one of its successions, and
    /// `na_public_keys` is not used.
    pub key_history: Option<NaKeyHistory>,
    /// An audit pack's cited records (1.5.0): records before the run that its
    /// records rest on, verified for authenticity (signatures, digests) but
    /// not as a run. The run then holds every chain from its start, and a
    /// record it cites that neither holds is `cited_record_missing`.
    pub prior: Option<Vec<Value>>,
}

impl VerifyEvidenceOptions {
    /// Options for a contiguous export with no checkpoint.
    pub fn new(na_public_keys: Vec<String>, executor_keys: Vec<Value>) -> Self {
        Self {
            na_public_keys,
            executor_keys,
            contiguous: true,
            checkpoint: None,
            key_history: None,
            prior: None,
        }
    }

    /// The NA keys these options name: the key history, or keys valid at
    /// every time.
    pub fn na_keys(&self) -> NaKeys {
        match &self.key_history {
            Some(history) => NaKeys::History(history.clone()),
            None => NaKeys::Any(self.na_public_keys.clone()),
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

/// `na` is every NA key (and, for a key succession, the root key): an
/// unknown field signed by any of them is refused by name.
fn check_payload_fields(
    kind: &str,
    payload: &Value,
    na: &[String],
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
        if !found.is_empty() && decision_signed(decision, na) {
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
            na,
        ),
        "retention_checkpoint" => checkpoint_signed(payload, na),
        // v1.5.0: signed by the root key and the outgoing NA key.
        "key_succession" => succession_signed_by(payload, na),
        // v1.3.0: the key the signature names, whatever its role or sovereign,
        // so an authentic record with a field this crate does not know is
        // refused by name first, as the reference refuses it (v1.6.0: also a
        // grant use, signed by its bearer key).
        "observation" | "break_glass" | "remediation" | "grant_execution" => payload
            .get("signature")
            .and_then(|sig| str_field(sig, "key_id"))
            .and_then(|id| executor_keys.get(id))
            .is_some_and(|key| {
                let keys = [str_field(key, "public_key").unwrap_or_default().to_owned()];
                if kind == "grant_execution" {
                    crate::grants::signed_as_received(model, payload, &keys)
                } else {
                    signed_by(
                        out_of_band_canonical(payload),
                        payload.get("signature"),
                        &keys,
                    )
                }
            }),
        _ if GRANT_MODELS.contains(&model) => crate::grants::signed_as_received(model, payload, na),
        _ => signed_by(out_of_band_canonical(payload), payload.get("signature"), na),
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
        // v1.5.0
        "key_succession" => "KeySuccessionRecord",
        "archive" => "ArchiveRecord",
        // v1.6.0; a time token is no entry kind, but verified as a record.
        "grant" => "CapabilityGrant",
        "grant_execution" => "GrantExecutionEvidence",
        "grant_revocation" => "GrantRevocationRecord",
        "time_token" => "TimeToken",
        _ => return None,
    })
}

/// Whether a record with a field outside its signature is no record of its
/// kind (the reference's model forbids unknown fields): every Stage 2, 3 and
/// 4 record, and (1.5.0, as the reference has since 0.59) a retention
/// checkpoint. A justification, execution evidence or a decision's wrapper
/// with such a field gets the warning `unsigned_field` and verifies the rest.
fn refuses_unsigned_fields(kind: &str) -> bool {
    kind == "retention_checkpoint" || out_of_band_model(kind).is_some()
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
        // v1.6.0: a grant use is signed by its grant's bearer key, an executor key.
        "break_glass" | "remediation" | "grant_execution" => ("executor", "executor_sovereign_id"),
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
    na: &[String],
    executor_keys: &HashMap<&str, &Value>,
) -> bool {
    out_of_band_model(kind).is_some_and(|model| {
        out_of_band_verifies(
            model,
            payload,
            &out_of_band_keys(kind, payload, na, executor_keys),
        )
    })
}

/// Whether a record of an export kind other than a decision is signed as its
/// kind requires, the same check for an export entry and for a single record
/// (1.5.0): a justification or retention checkpoint by the NA, execution
/// evidence by an executor key of its sovereign, and a Stage 2 or Stage 3
/// record by the key its kind allows. `na` are the NA keys that may have
/// signed it (since 1.5.0, those valid at its time).
fn record_signed(
    kind: &str,
    payload: &Value,
    na: &[String],
    executor_keys: &HashMap<&str, &Value>,
) -> bool {
    match kind {
        "justification" => verify_justification_signature(payload, na),
        "retention_checkpoint" => verify_retention_checkpoint(payload, na),
        // v1.3.0: only an executor key signs execution evidence.
        "execution" => payload
            .get("signature")
            .and_then(|sig| str_field(sig, "key_id"))
            .and_then(|id| executor_keys.get(id))
            .is_some_and(|key| {
                str_field(key, "executor_sovereign_id")
                    == str_field(payload, "executor_sovereign_id")
                    && key_role(key) == "executor"
                    && verify_execution_signature(
                        payload,
                        str_field(key, "public_key").unwrap_or_default(),
                    )
            }),
        other => out_of_band_signed(other, payload, na, executor_keys),
    }
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
        // v1.5.0
        "key_succession" => crate::key_history::valid_succession_record(payload),
        "archive" => valid_archive(Some(payload)),
        // v1.6.0
        "grant" => valid_grant(Some(payload)),
        "grant_execution" => valid_grant_use(Some(payload)),
        "grant_revocation" => valid_grant_revocation(Some(payload)),
        "time_token" => valid_time_token(Some(payload)),
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
        "key_succession" => &payload["succession_id"],
        "archive" => &payload["archive_id"],
        "grant" => &payload["grant_id"],
        "grant_execution" => &payload["use_id"],
        "grant_revocation" => &payload["revocation_id"],
        "time_token" => &payload["time_token_id"],
        _ => &Value::Null,
    };
    id.as_str().unwrap_or_default().to_owned()
}

/// v1.3.1: the envelope fields a Stage 2 entry derives from its record, and
/// the record field each must equal (an absent field is null). The NA
/// searches and matches on them.
const ENVELOPE_FIELDS: [(&str, &[(&str, &str)]); 12] = [
    // v1.5.0: a key succession or archive entry carries its record's id only.
    ("key_succession", &[("record_id", "succession_id")]),
    ("archive", &[("record_id", "archive_id")]),
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
    // v1.6.0: no new envelope field. A grant names its bearer's sovereign; a
    // use its grant (`subject_id`) and its place in the grant's chain
    // (`exec_sequence_no`); a revocation its grant and reason. A use's
    // `resource_sequence` is the NA's, outside the record.
    (
        "grant",
        &[
            ("record_id", "grant_id"),
            ("executor_sovereign_id", "bearer_sovereign_id"),
        ],
    ),
    (
        "grant_execution",
        &[
            ("record_id", "use_id"),
            ("subject_id", "grant_id"),
            ("resource_id", "resource_id"),
            ("resource_action", "resource_action"),
            ("capability", "capability"),
            ("executor_sovereign_id", "executor_sovereign_id"),
            ("outcome", "outcome"),
            ("exec_sequence_no", "use_sequence"),
        ],
    ),
    (
        "grant_revocation",
        &[
            ("record_id", "revocation_id"),
            ("subject_id", "grant_id"),
            ("outcome", "reason"),
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

/// v1.3.1: whether a retention checkpoint removed as many entries as
/// positions after `start` (the checkpoint before it, or 0).
fn checkpoint_count_problem(checkpoint: &Value, start: i64) -> Option<String> {
    let through = checkpoint["removed_through_sequence"]
        .as_i64()
        .unwrap_or_default();
    (checkpoint["removed_count"].as_i64() != Some(through - start)).then(|| {
        format!(
            "removed {} of {} entries after #{start} through #{through}",
            checkpoint["removed_count"],
            through - start
        )
    })
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
///   names its judgement's change, resource and the version that change made
///   (`remediation_subject_mismatch`); in a run from its start (entry 1, or
///   right after the checkpoint) its subject and its forward rotation's
///   execution evidence are held before it (`remediation_subject_missing`,
///   `remediation_rotation_missing`); the rotation is of the same resource
///   (`remediation_rotation_mismatch`), by the remediation's own executor
///   sovereign (`remediation_rotation_other_executor`), made after the change
///   (`remediation_rotation_before_change`) and cited by no earlier
///   remediation (`remediation_rotation_reused`); a remediation record is
///   signed by an executor key of its sovereign;
/// * a review's embedded admin requests verify offline
///   (`review_approval_invalid`, see
///   [`review_approval_problem`]),
///   with the public key and holder the holder registry records for each
///   operator key at the time, when the run holds a record the NA signed for
///   that key (`review_approval_key_mismatch`); its decider is a second
///   holder (`review_same_holder`); it names its subject's payload digest
///   (`review_subject_mismatch`; `review_subject_missing` in a run from its
///   start); and no waiver follows a remediation of the same subject
///   (`review_waiver_after_remediation`);
/// * remediation and review ids are not decisions (`evidence_cites_judgement`).
///
/// v1.6.0, pre-issued grants ([`crate::grants`]), as the reference verifies
/// them:
///
/// * a grant use (`grant_execution`) and a grant revocation name a grant the
///   run holds when it holds the store from its start (`grant_missing`; in a
///   pack `cited_record_missing`), with its digest (`grant_mismatch`); a use
///   is signed by the grant's bearer key (`grant_bearer_mismatch`), and a
///   grant is revoked once (`duplicate_grant_revocation`);
/// * the uses of a grant form a chain (`grant_use_chain_break`), and each use
///   is checked by [`use_problem`] with what the
///   run holds (envelope, budget, time token, times, revocation; its reason
///   codes);
/// * a use takes the next position of its resource's chain, assigned by the
///   NA in the envelope (`resource_sequence`; `resource_chain_break`), only
///   when it has a resource (`envelope_mismatch`), and the next record of
///   that resource links to the use's digest;
/// * a judgement may match a use (`governed_by: grant`), and a quarantine
///   entry may hold a refused one.
///
/// The 1.6.0 review fixes:
///
/// * a quarantined use (an authentic `quarantine` entry of `record_kind`
///   `grant_execution`, signed by the grant's bearer key) that continues its
///   grant's use chain is the chain's head: the next use may link to it, and a
///   time token may name it. The budget counts the admitted uses (when the
///   run holds the chain from its first use), and the order and time rules
///   compare a use with the last admitted one;
/// * a use signed by a bearer key with a `resource_prefix` is within it
///   (`grant_use_out_of_scope`);
/// * a use's `use_id` is not the id of execution evidence or a break-glass
///   record (`duplicate_record`, in either order);
/// * a grant whose signature fails is not held: its uses and revocation are
///   checked as for a grant the run does not hold.
pub fn verify_evidence_events<'a>(
    events: impl IntoIterator<Item = &'a Value>,
    options: &VerifyEvidenceOptions,
) -> EvidenceVerification {
    let mut main = EvidenceVerification::empty();
    let na = options.na_keys();
    let na_all = na.all();
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
    // v1.6.0: grants by id (the record and its digest as received; only an
    // authentic grant is held), when each was revoked, and the state of each
    // grant's use chain.
    let mut grants_held: HashMap<String, (Value, String)> = HashMap::new();
    let mut revoked: HashMap<String, i64> = HashMap::new();
    let mut chains = GrantChains::default();
    let mut first_sequence: Option<i64> = None;
    let mut from_start = false;
    let mut prev: Option<Value> = None;

    if let Some(checkpoint) = checkpoint {
        // v1.5.0: signed by the NA key valid at its `created_at`.
        let created = micros(str_field(checkpoint, "created_at").unwrap_or_default()).ok();
        if !valid_checkpoint(Some(checkpoint)) || !checkpoint_signed(checkpoint, &na.at(created)) {
            fail(&mut main, None, "invalid_signature", "retention_checkpoint");
            return main;
        }
        let unknown = prefixed_unknown_fields("RetentionCheckpoint", checkpoint, "checkpoint.");
        if !unknown.is_empty() {
            fail(&mut main, None, "unknown_field", &unknown.join(", "));
            return main;
        }
    }

    // v1.5.0: an audit pack's cited records come first, in store order, into
    // their own result: their failures fail the run, their counts do not
    // count. The run's chains then continue from the records they hold.
    let pack = options.prior.is_some();
    let mut cited: Vec<&Value> = options.prior.iter().flatten().collect();
    cited.sort_by_key(|e| e["entry"]["store_sequence"].as_i64());
    let run: Vec<&Value> = events.into_iter().collect();
    let mut cited_result = EvidenceVerification::empty();
    let mut merged = !pack;
    // 1.5.0 review fixes: the latest recorded_at so far in the run, and
    // whether the entries just visited are a block retention carried forward.
    let mut clock: Option<i64> = None;
    let mut carrying = false;
    let visits = cited
        .iter()
        .map(|e| (*e, true))
        .chain(run.iter().map(|e| (*e, false)));
    for (event, cited_run) in visits {
        if !cited_run && !merged {
            merge_cited(&mut main, &mut cited_result);
            prev = None;
            merged = true;
        }
        // Checks that need a record's predecessors in the run; a pack's
        // cited records are not a run.
        let chained = !cited_run;
        let result = if cited_run {
            &mut cited_result
        } else {
            &mut main
        };
        result.checked_entries += 1;
        if !valid_event(Some(event)) {
            fail(result, None, "payload_invalid", "event envelope");
            continue;
        }
        let entry = &event["entry"];
        let seq = entry["store_sequence"].as_i64().unwrap_or_default();
        let s = Some(seq);
        let recorded = micros(str_field(entry, "recorded_at").unwrap_or_default()).ok();
        // 1.5.0 review fixes: in a contiguous run, an entry is recorded no
        // more than the tolerance before an earlier one (entries retention
        // carried forward keep their first time); an NA-signed entry's key
        // must also be valid at the latest earlier time.
        let mut not_before: Option<i64> = None;
        if options.contiguous && chained {
            let kind = str_field(entry, "entry_kind").unwrap_or_default();
            let adjacent = prev
                .as_ref()
                .and_then(|p| p["store_sequence"].as_i64())
                .is_some_and(|p| seq == p + 1);
            let after_checkpoint = prev
                .as_ref()
                .is_some_and(|p| str_field(p, "entry_kind") == Some("retention_checkpoint"));
            carrying = CARRIED_KINDS.contains(&kind) && adjacent && (after_checkpoint || carrying);
            if !carrying {
                let at = recorded.unwrap_or_default();
                if clock.is_some_and(|clock| at < clock - RECORD_TIME_TOLERANCE_MICROS) {
                    let detail = format!(
                        "recorded at {}, after an entry recorded at {}",
                        iso_time(at),
                        iso_time(clock.unwrap_or_default())
                    );
                    fail(result, s, "recorded_at_out_of_order", &detail);
                }
                not_before = clock;
                clock = Some(clock.map_or(at, |clock| clock.max(at)));
            }
        }
        if entry_digest(entry).ok().as_deref() != str_field(event, "entry_digest") {
            fail(result, s, "entry_digest_mismatch", "");
        }
        if payload_digest(&event["payload"]).ok().as_deref() != str_field(entry, "payload_digest") {
            fail(result, s, "payload_digest_mismatch", "");
        }
        let prev_seq = prev.as_ref().and_then(|p| p["store_sequence"].as_i64());
        match (&prev, prev_seq) {
            (Some(prev), Some(prev_seq))
                if (options.contiguous && chained) || seq == prev_seq + 1 =>
            {
                if seq != prev_seq + 1 {
                    fail(result, s, "store_sequence_gap", "");
                } else if str_field(entry, "prev_entry_digest")
                    != entry_digest(prev).ok().as_deref()
                {
                    fail(result, s, "store_chain_break", "");
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
                            result,
                            s,
                            "store_chain_break",
                            "does not continue from the checkpoint",
                        );
                    }
                }
            }
            _ => {}
        }
        if first_sequence.is_none() && chained {
            first_sequence = Some(seq);
            from_start = pack
                || seq == 1
                || checkpoint.is_some_and(|c| {
                    c["removed_through_sequence"].as_i64().map(|n| n + 1) == Some(seq)
                });
        }
        prev = Some(entry.clone());

        let kind = str_field(entry, "entry_kind").unwrap_or_default();
        // v1.5.0: NA signatures by the key valid at the entry's time (1.5.0
        // review fixes: and at the latest earlier time).
        let mut na_now = na.at(recorded);
        if let (Some(before), Some(at)) = (not_before, recorded) {
            if before > at {
                let later = na.at(Some(before));
                na_now.retain(|k| later.contains(k));
            }
        }
        let na_other: Vec<String> = na_all
            .iter()
            .filter(|k| !na_now.contains(k))
            .cloned()
            .collect();
        if !is_known_entry_kind(kind) {
            // v1.2.0: a kind from a later release; its envelope still chains.
            fail(result, s, "unknown_entry_kind", kind);
            continue;
        }
        let mut signers = na_all.clone();
        if kind == "key_succession" {
            signers.extend(na.history().and_then(|h| h.root_public_key.clone()));
            signers.extend(str_field(&event["payload"], "new_public_key").map(str::to_owned));
        }
        let checked = check_payload_fields(kind, &event["payload"], &signers, &executor_keys);
        if !checked.signed.is_empty() {
            fail(result, s, "unknown_field", &checked.signed.join(", "));
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
            if refuses_unsigned_fields(kind) {
                fail(result, s, "payload_invalid", &checked.unsigned.join(", "));
                continue;
            }
        }
        let payload = &checked.payload;
        // A record whose signature covers it as received, in a form the
        // reference does not write, is refused by name, as the reference
        // refuses it (v1.3.0); since 1.3.1 also one whose fields outside its
        // signature were set aside, checked as the signer signed it.
        // v1.5.0: a record signed by another key of the NA's history than the
        // one valid at its time is `na_key_not_valid_at_time`; a form the
        // reference does not write is refused first, as the reference does.
        let signature = |result: &mut EvidenceVerification,
                         (signed, by_other): (bool, bool),
                         model: &str,
                         record: &Value,
                         detail: &str| {
            let canonical = non_canonical_fields(model, record).is_empty();
            if (signed || by_other) && !canonical {
                fail(result, s, "non_canonical_form", detail);
            } else if by_other && !signed {
                fail(result, s, "na_key_not_valid_at_time", detail);
            } else if !signed {
                fail(result, s, "invalid_signature", detail);
            }
        };
        let signed_now = |kind: &str, record: &Value| {
            let signed = record_signed(kind, record, &na_now, &executor_keys);
            let by_other = !signed && record_signed(kind, record, &na_other, &executor_keys);
            (signed, by_other)
        };
        // 1.5.0 review fixes: a registered key verifies only records after it
        // was registered and before it was retired, where the store placed it.
        let placed = |result: &mut EvidenceVerification, kind: &str, record: &Value| -> bool {
            let Some(key) = signing_key(kind, record, &executor_keys) else {
                return true;
            };
            match placement_problem(key, seq, recorded.unwrap_or_default()) {
                None => true,
                Some(reason) => {
                    let id = str_field(key, "key_id").unwrap_or("-");
                    fail(result, s, reason, &format!("{kind} signed by {id}"));
                    false
                }
            }
        };
        if !valid_payload(kind, payload) {
            fail(result, s, "payload_invalid", "");
            continue;
        }
        // v1.3.1: a record appears once per kind; a copied entry is a replay.
        let record_id = record_id_of(kind, payload);
        if !record_ids.insert((kind.to_owned(), record_id.clone())) {
            fail(
                result,
                s,
                "duplicate_record",
                &format!("{kind} {record_id}"),
            );
        }
        // v1.3.1: the envelope names what the record says.
        let wrong = envelope_mismatches(kind, entry, payload);
        if !wrong.is_empty() {
            fail(
                result,
                s,
                "envelope_mismatch",
                &format!("{kind}: {}", wrong.join(", ")),
            );
        }
        match kind {
            "decision" => {
                let decision = &payload["decision"];
                let signed = verify_decision_signature(decision, &na_now);
                let by_other = !signed && verify_decision_signature(decision, &na_other);
                signature(
                    result,
                    (signed, by_other),
                    "BoundaryDecision",
                    decision,
                    "decision",
                );
                // 1.5.0 review fixes: valid longer than its key may vouch for.
                if signed && non_canonical_fields("BoundaryDecision", decision).is_empty() {
                    let signer = na_now
                        .iter()
                        .find(|k| verify_decision_signature(decision, std::slice::from_ref(k)));
                    let until =
                        micros(str_field(decision, "decision_valid_until").unwrap_or_default())
                            .unwrap_or_default();
                    if let (Some(signer), Some(history)) = (signer, na.history()) {
                        if history.decision_outlives_key(signer, until) {
                            let id = str_field(decision, "decision_id").unwrap_or_default();
                            fail(result, s, "decision_outlives_key", id);
                        }
                    }
                }
                result.decisions += 1;
                let id = str_field(decision, "decision_id")
                    .unwrap_or_default()
                    .to_owned();
                stage3.judged.insert(
                    id.clone(),
                    Subject {
                        digest: str_field(entry, "payload_digest")
                            .unwrap_or_default()
                            .to_owned(),
                        ..Subject::default()
                    },
                );
                decisions.insert(id.clone(), decision.clone());
                if valid_context(payload.get("context")) {
                    contexts.insert(id, payload["context"].clone());
                } else {
                    fail(result, s, "payload_invalid", "context");
                }
            }
            "justification" => {
                signature(
                    result,
                    signed_now(kind, payload),
                    "JustificationProof",
                    payload,
                    "justification",
                );
            }
            "execution" => {
                let ev = payload;
                if placed(result, kind, ev) {
                    signature(
                        result,
                        signed_now(kind, ev),
                        "ExecutionEvidence",
                        ev,
                        "execution",
                    );
                }
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
                        fail(result, s, "evidence_decision_denied", "");
                    } else if at < made || at > until {
                        fail(result, s, "evidence_outside_decision_window", "");
                    } else if contexts.get(&decision_id).is_some_and(|c| {
                        str_field(ev, "executed_capability") != str_field(c, "requested_capability")
                    }) {
                        fail(result, s, "evidence_capability_mismatch", "");
                    }
                } else if pack && chained {
                    // v1.5.0: a pack holds the decision every execution in its range rests on.
                    let detail = format!("decision {decision_id}");
                    fail(result, s, "cited_record_missing", &detail);
                }
                // v1.3.0: execution evidence never rests on a judgement or a record of one.
                if not_decisions.contains(&decision_id) {
                    fail(result, s, "evidence_cites_judgement", &decision_id);
                }
                let sequence_no = ev["sequence_no"].as_i64();
                let prev_digest = str_field(ev, "prev_evidence_digest");
                match last_exec.get(&decision_id) {
                    Some(prior) if chained => {
                        if sequence_no != prior["sequence_no"].as_i64().map(|n| n + 1)
                            || prev_digest != execution_digest(prior).ok().as_deref()
                        {
                            fail(result, s, "evidence_chain_break", "");
                        }
                    }
                    None if chained
                        && decision.is_some()
                        && (sequence_no != Some(1) || prev_digest.is_some()) =>
                    {
                        fail(result, s, "evidence_chain_break", "");
                    }
                    _ => {}
                }
                last_exec.insert(decision_id, ev.clone());
                let evidence_id = str_field(ev, "evidence_id").unwrap_or_default().to_owned();
                // v1.6.0 review fixes: observations match a use and execution
                // evidence by id, so they never share one.
                if chains.use_ids.contains(&evidence_id) {
                    let detail = format!("execution {evidence_id} is a grant use's ID");
                    fail(result, s, "duplicate_record", &detail);
                }
                chains.other_ids.insert(evidence_id.clone());
                matchable.insert(evidence_id);
                stage3.executed.insert(
                    str_field(ev, "evidence_id").unwrap_or_default().to_owned(),
                    Execution {
                        resource_id: str_field(ev, "resource_id").map(str::to_owned),
                        store_sequence: seq,
                        executed_at: micros(str_field(ev, "executed_at").unwrap_or_default())
                            .unwrap_or_default(),
                        executor_sovereign_id: str_field(ev, "executor_sovereign_id")
                            .unwrap_or_default()
                            .to_owned(),
                        decision_id: str_field(ev, "decision_id").unwrap_or_default().to_owned(),
                    },
                );
                if let Some(resource_id) = str_field(ev, "resource_id") {
                    let head = resource_heads.get(resource_id);
                    let expected = head.map_or(1, |h| h.resource_sequence + 1);
                    let resource_sequence = ev.get("resource_sequence").and_then(Value::as_u64);
                    // v1.3.1: a run that starts after entry 1 and not right
                    // after the checkpoint takes the first record it holds of
                    // a resource as that chain's start.
                    if chained
                        && (head.is_some() || from_start)
                        && (resource_sequence != Some(expected)
                            || str_field(ev, "prev_resource_digest")
                                != head.map(|h| h.record_digest.as_str()))
                    {
                        fail(result, s, "resource_chain_break", resource_id);
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
                let failed_before = result.failures.len();
                signature(
                    result,
                    signed_now(kind, payload),
                    "RetentionCheckpoint",
                    payload,
                    "retention_checkpoint",
                );
                // 1.5.0 review fixes: the chains an authentic checkpoint
                // removed continue from its heads.
                if result.failures.len() == failed_before {
                    let heads: BTreeMap<String, ResourceHead> =
                        serde_json::from_value(payload["resource_heads"].clone())
                            .unwrap_or_default();
                    for (resource, head) in heads {
                        let behind = resource_heads
                            .get(&resource)
                            .is_none_or(|held| held.resource_sequence < head.resource_sequence);
                        if behind {
                            resource_heads.insert(resource, head);
                        }
                    }
                    for (resource, position) in payload["observation_heads"]
                        .as_object()
                        .into_iter()
                        .flatten()
                    {
                        let position = position.as_i64().unwrap_or_default();
                        if observation_heads.get(resource).copied().unwrap_or(0) < position {
                            observation_heads.insert(resource.clone(), position);
                        }
                    }
                }
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
                if let Some(problem) =
                    start.and_then(|start| checkpoint_count_problem(payload, start))
                {
                    fail(result, s, "retention_count_mismatch", &problem);
                }
                checkpoints.insert(record_id, through);
            }
            "observation" | "break_glass" => {
                let observation = kind == "observation";
                if placed(result, kind, payload) {
                    let signed = signed_now(kind, payload);
                    signature(result, signed, model_of(kind), payload, kind);
                }
                let resource = str_field(payload, "resource_id")
                    .unwrap_or_default()
                    .to_owned();
                let digest = str_field(entry, "payload_digest").unwrap_or_default();
                subjects.insert(
                    (kind.to_owned(), record_id.clone()),
                    (digest.to_owned(), seq),
                );
                // v1.4.0: the version the change made, for its remediation.
                let version = if observation {
                    &payload["version_id"]
                } else {
                    &payload["execution_parameters"]["version_id"]
                };
                stage3.versions.insert(
                    (kind.to_owned(), record_id.clone()),
                    version
                        .as_str()
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned),
                );
                not_decisions.insert(record_id.clone());
                if observation {
                    result.observations += 1;
                    let position = entry["observation_sequence"].as_i64();
                    let head = observation_heads.get(&resource).copied();
                    if chained
                        && (head.is_some() || from_start)
                        && position != Some(head.unwrap_or(0) + 1)
                    {
                        fail(result, s, "observation_chain_break", &resource);
                    }
                    let next = position.filter(|&p| p != 0).unwrap_or(head.unwrap_or(0));
                    observation_heads.insert(resource, next);
                } else {
                    result.break_glass += 1;
                    // v1.6.0 review fixes: nor a use and a break-glass record.
                    if chains.use_ids.contains(&record_id) {
                        let detail = format!("break_glass {record_id} is a grant use's ID");
                        fail(result, s, "duplicate_record", &detail);
                    }
                    chains.other_ids.insert(record_id.clone());
                    matchable.insert(record_id);
                }
            }
            "judgement" => {
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                result.judgements += 1;
                stage3.judged.insert(
                    record_id.clone(),
                    Subject {
                        digest: str_field(entry, "payload_digest")
                            .unwrap_or_default()
                            .to_owned(),
                        resource_id: str_field(payload, "resource_id").map(str::to_owned),
                        change_kind: str_field(payload, "subject_kind").map(str::to_owned),
                        change_id: str_field(payload, "subject_id").map(str::to_owned),
                        change_sequence: payload["subject_store_sequence"].as_i64(),
                        changed_at: str_field(payload, "evaluated_as_of")
                            .and_then(|at| micros(at).ok()),
                    },
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
                    fail(result, s, "duplicate_judgement", subject_id);
                }
                let subject_sequence = payload["subject_store_sequence"].as_i64();
                match subjects.get(&subject) {
                    Some((digest, sequence)) => {
                        if Some(digest.as_str()) != str_field(payload, "subject_digest")
                            || Some(*sequence) != subject_sequence
                        {
                            fail(result, s, "judgement_subject_mismatch", subject_id);
                        }
                    }
                    None => {
                        if chained
                            && options.contiguous
                            && first_sequence.is_some_and(|first| subject_sequence >= Some(first))
                        {
                            fail(result, s, "judgement_subject_missing", subject_id);
                        } else if pack && chained {
                            let detail = format!("{} {subject_id}", subject.0);
                            fail(result, s, "cited_record_missing", &detail);
                        }
                    }
                }
                if let Some(evidence_id) = str_field(payload, "matched_evidence_id") {
                    if !matched.insert(evidence_id.to_owned()) {
                        fail(result, s, "match_reused", evidence_id);
                    }
                    // v1.3.1: the NA matches a record it already holds, so a
                    // run from entry 1 holds it.
                    if chained
                        && options.contiguous
                        && first_sequence == Some(1)
                        && !matchable.contains(evidence_id)
                    {
                        fail(result, s, "judgement_match_missing", evidence_id);
                    } else if pack && chained && !matchable.contains(evidence_id) {
                        let detail = format!("matched record {evidence_id}");
                        fail(result, s, "cited_record_missing", &detail);
                    }
                }
            }
            "quarantine" => {
                let failed_before = result.failures.len();
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                let authentic = result.failures.len() == failed_before;
                result.quarantined += 1;
                if payload_digest(&payload["record"]).ok().as_deref()
                    != str_field(payload, "record_digest")
                {
                    fail(result, s, "quarantine_digest_mismatch", "");
                } else if authentic && str_field(payload, "record_kind") == Some("grant_execution")
                {
                    // v1.6.0 review fixes: a quarantined use that continues
                    // its grant's chain is the chain's head.
                    chains.quarantined(&payload["record"], &grants_held, from_start || pack);
                }
            }
            "registry" => {
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                // v1.4.0: the operator keys' public keys and holders over time,
                // from registry records the NA signed only.
                let authentic =
                    signed.0 && non_canonical_fields(model_of(kind), payload).is_empty();
                if let (true, Some("operator_key_holder"), Some(key_id)) = (
                    authentic,
                    str_field(payload, "event"),
                    str_field(payload, "key_id"),
                ) {
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
                if placed(result, kind, payload) {
                    let signed = signed_now(kind, payload);
                    signature(result, signed, model_of(kind), payload, kind);
                }
                result.remediations += 1;
                not_decisions.insert(record_id);
                // A run from its start: entry 1, or right after the checkpoint.
                let held_from_start = chained && options.contiguous && from_start;
                for (reason, detail) in stage3.remediation(payload, held_from_start) {
                    fail(result, s, reason, &detail);
                }
            }
            "review" => {
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                result.reviews += 1;
                not_decisions.insert(record_id);
                // A run from its start: entry 1, or right after the checkpoint.
                let held_from_start = chained && options.contiguous && from_start;
                for (reason, detail) in stage3.review(payload, &na_all, held_from_start) {
                    fail(result, s, reason, &detail);
                }
            }
            // v1.5.0: a key succession is signed by its outgoing key, an NA
            // key; given the NA's key history, it is one of the history's
            // successions and the root key signed it.
            "key_succession" => {
                result.key_successions += 1;
                let id = str_field(payload, "succession_id").unwrap_or_default();
                let previous = str_field(payload, "previous_public_key").unwrap_or_default();
                if let Some(refusal) = succession_form_refusal(payload, &signers) {
                    let reason = if refusal == "unknown_field" {
                        "invalid_signature"
                    } else {
                        refusal
                    };
                    fail(result, s, reason, kind);
                } else if !na_all.iter().any(|k| k == previous)
                    || !succession_signed_by(payload, &[previous.to_owned()])
                {
                    fail(result, s, "invalid_signature", kind);
                } else if let Some(reason) = succession_entry_problem(payload, &na, recorded) {
                    fail(result, s, reason, id);
                }
            }
            "archive" => {
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                result.archives += 1;
            }
            // v1.6.0: a grant, held for the uses and revocation that name it;
            // review fixes: only when authentic (one whose signature fails is
            // not held, so its uses are checked as a missing grant's).
            "grant" => {
                let failed_before = result.failures.len();
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                result.grants += 1;
                if result.failures.len() == failed_before {
                    let digest = crate::grants::grant_digest(payload).unwrap_or_default();
                    grants_held.insert(record_id, (payload.clone(), digest));
                }
            }
            "grant_revocation" => {
                let failed_before = result.failures.len();
                let signed = signed_now(kind, payload);
                signature(result, signed, model_of(kind), payload, kind);
                let authentic = result.failures.len() == failed_before;
                result.grant_revocations += 1;
                let grant_id = str_field(payload, "grant_id").unwrap_or_default();
                match grants_held.get(grant_id) {
                    // A pack holds (or cites) the grant of every revocation in its range.
                    None if pack && chained => {
                        fail(
                            result,
                            s,
                            "cited_record_missing",
                            &format!("grant {grant_id}"),
                        );
                    }
                    None if chained && options.contiguous && from_start => {
                        fail(result, s, "grant_missing", grant_id);
                    }
                    Some((_, digest))
                        if str_field(payload, "grant_digest") != Some(digest.as_str()) =>
                    {
                        fail(result, s, "grant_mismatch", grant_id);
                    }
                    _ => {}
                }
                if revoked.contains_key(grant_id) {
                    fail(result, s, "duplicate_grant_revocation", grant_id);
                } else if authentic {
                    let at = micros(str_field(payload, "revoked_at").unwrap_or_default());
                    revoked.insert(grant_id.to_owned(), at.unwrap_or_default());
                }
            }
            "grant_execution" => {
                if placed(result, kind, payload) {
                    let signed = signed_now(kind, payload);
                    signature(result, signed, model_of(kind), payload, kind);
                }
                result.grant_executions += 1;
                let received = crate::grants::use_digest(payload).unwrap_or_default();
                let grant_id = str_field(payload, "grant_id").unwrap_or_default();
                let key_id = payload["signature"]["key_id"].as_str();
                let signer = key_id.and_then(|id| executor_keys.get(id));
                // Its place in the chain first: after the head (an admitted
                // use, or a quarantined one that continued the chain).
                let expected = chains.head(grant_id, from_start);
                if chained
                    && expected.is_some_and(|(at, digest)| {
                        !continues_chain(payload, (at, digest.as_deref()))
                    })
                {
                    fail(result, s, "grant_use_chain_break", grant_id);
                }
                let held = grants_held.get(grant_id);
                match held {
                    // A pack holds (or cites) the grant of every use in its range.
                    None if pack && chained => {
                        fail(
                            result,
                            s,
                            "cited_record_missing",
                            &format!("grant {grant_id}"),
                        );
                    }
                    None if chained && options.contiguous && from_start => {
                        fail(result, s, "grant_missing", grant_id);
                    }
                    Some((grant, _))
                        if key_id.is_none()
                            || key_id != str_field(grant, "bearer_key_id")
                            || str_field(payload, "executor_sovereign_id")
                                != str_field(grant, "bearer_sovereign_id")
                            || signer.is_some_and(|b| {
                                str_field(b, "public_key") != str_field(grant, "bearer_public_key")
                            }) =>
                    {
                        fail(result, s, "grant_bearer_mismatch", &record_id);
                    }
                    _ => {}
                }
                // Review fixes: a bearer key with a resource prefix signs
                // within it, as for execution evidence.
                if let Some(prefix) = signer.and_then(|k| str_field(k, "resource_prefix")) {
                    let within = str_field(payload, "resource_id")
                        .is_some_and(|resource| resource.starts_with(prefix));
                    if !within {
                        let detail =
                            format!("signing key covers only resources starting with {prefix:?}");
                        fail(result, s, "grant_use_out_of_scope", &detail);
                    }
                }
                if held.is_some_and(|(_, digest)| {
                    str_field(payload, "grant_digest") != Some(digest.as_str())
                }) {
                    fail(result, s, "grant_mismatch", grant_id);
                }
                let sequence = payload["use_sequence"].as_u64().unwrap_or_default();
                if sequence == 1 {
                    chains.admitted.entry(grant_id.to_owned()).or_insert(0);
                }
                let token = &payload["time_token"];
                let token_keys = na.at(str_field(token, "issued_at").and_then(|t| micros(t).ok()));
                if chained {
                    let token_sequence = token["use_sequence"].as_u64().unwrap_or_default();
                    let named = chains
                        .positions
                        .get(&(grant_id.to_owned(), token_sequence))
                        .filter(|_| token_sequence != 0)
                        .and_then(|(digest, at)| {
                            Some((digest.as_str(), DateTime::from_timestamp_micros(*at)?))
                        });
                    let context = UseContext {
                        grant: held.map(|(grant, _)| grant),
                        previous: chains.last_admitted.get(grant_id),
                        admitted: chains.admitted.get(grant_id).copied(),
                        token_head: named,
                        token_keys: &token_keys,
                        revoked_at: revoked
                            .get(grant_id)
                            .and_then(|at| DateTime::from_timestamp_micros(*at)),
                        recorded_at: recorded.and_then(DateTime::from_timestamp_micros),
                    };
                    if let Some((reason, detail)) = use_problem(payload, &context) {
                        fail(result, s, reason, &detail);
                    }
                } else if !token_signature_valid(token, &token_keys) {
                    fail(result, s, "grant_time_token_invalid", &record_id);
                }
                chains.admit(grant_id, sequence, &received, payload);
                if chains.other_ids.contains(&record_id) {
                    let detail = format!("grant_execution {record_id} is another record's ID");
                    fail(result, s, "duplicate_record", &detail);
                }
                chains.use_ids.insert(record_id.clone());
                matchable.insert(record_id.clone());
                let position = entry["resource_sequence"].as_u64();
                if let Some(resource_id) = str_field(payload, "resource_id") {
                    let head = resource_heads.get(resource_id);
                    if chained
                        && (head.is_some() || from_start)
                        && position != Some(head.map_or(1, |h| h.resource_sequence + 1))
                    {
                        fail(result, s, "resource_chain_break", resource_id);
                    }
                    resource_heads.insert(
                        resource_id.to_owned(),
                        ResourceHead {
                            resource_sequence: position.unwrap_or_default(),
                            record_digest: received,
                        },
                    );
                } else if !entry["resource_sequence"].is_null() {
                    fail(
                        result,
                        s,
                        "envelope_mismatch",
                        "grant_execution: resource_sequence",
                    );
                }
            }
            other => fail(result, s, "unknown_entry_kind", other),
        }
    }
    if !merged {
        merge_cited(&mut main, &mut cited_result);
    }
    main
}

/// The use chains of an export's grants (1.6.0; the review fixes).
#[derive(Default)]
struct GrantChains {
    /// Each grant's chain head: its position and digest (an admitted use, or
    /// a quarantined one that continued the chain).
    heads: HashMap<String, (u64, String)>,
    /// Each grant's last admitted use: the order and time rules compare a use
    /// with it.
    last_admitted: HashMap<String, PreviousUse>,
    /// How many uses of each grant were admitted, when the run holds its
    /// chain from its first use.
    admitted: HashMap<String, u64>,
    /// Each chain use's digest and time (microseconds), by grant and
    /// position: what a time token names.
    positions: HashMap<(String, u64), (String, i64)>,
    /// The ids of the uses, and of the execution evidence and break-glass
    /// records observations also match by id.
    use_ids: HashSet<String>,
    other_ids: HashSet<String>,
}

impl GrantChains {
    /// The head a use must continue: the chain's, or its start when the run
    /// holds the store from its start; `None` when it cannot tell.
    fn head(&self, grant_id: &str, from_start: bool) -> Option<(u64, Option<String>)> {
        match self.heads.get(grant_id) {
            Some((at, digest)) => Some((*at, Some(digest.clone()))),
            None => from_start.then_some((0, None)),
        }
    }

    /// An admitted use: the chain's head and its last admitted use.
    fn admit(&mut self, grant_id: &str, sequence: u64, digest: &str, use_record: &Value) {
        let previous = next_previous(use_record);
        let executed = previous.executed_at.timestamp_micros();
        self.heads
            .insert(grant_id.to_owned(), (sequence, digest.to_owned()));
        self.last_admitted.insert(grant_id.to_owned(), previous);
        if let Some(count) = self.admitted.get_mut(grant_id) {
            *count += 1;
        }
        self.positions.insert(
            (grant_id.to_owned(), sequence),
            (digest.to_owned(), executed),
        );
    }

    /// A use the NA quarantined (the record an authentic quarantine entry
    /// holds): the chain's head when it continues the chain, signed by its
    /// grant's bearer key when the run holds the grant.
    fn quarantined(
        &mut self,
        record: &Value,
        grants_held: &HashMap<String, (Value, String)>,
        held_from_start: bool,
    ) {
        if !valid_grant_record("GrantExecutionEvidence", record) {
            return;
        }
        let grant_id = str_field(record, "grant_id").unwrap_or_default();
        if let Some((grant, _)) = grants_held.get(grant_id) {
            let bearer = str_field(grant, "bearer_public_key").unwrap_or_default();
            if record["signature"]["key_id"].as_str() != str_field(grant, "bearer_key_id")
                || !crate::grants::signed_as_received(
                    "GrantExecutionEvidence",
                    record,
                    &[bearer.to_owned()],
                )
            {
                return;
            }
        }
        let sequence = record["use_sequence"].as_u64().unwrap_or_default();
        let expected = self.head(grant_id, held_from_start || sequence == 1);
        let Some((at, digest)) = expected else {
            return;
        };
        if !continues_chain(record, (at, digest.as_deref())) {
            return;
        }
        let digest = crate::grants::use_digest(record).unwrap_or_default();
        let executed = str_field(record, "executed_at")
            .and_then(|t| micros(t).ok())
            .unwrap_or_default();
        self.heads
            .insert(grant_id.to_owned(), (sequence, digest.clone()));
        self.positions
            .insert((grant_id.to_owned(), sequence), (digest, executed));
        if sequence == 1 {
            self.admitted.entry(grant_id.to_owned()).or_insert(0);
        }
    }
}

/// What a key succession entry signed by its outgoing key still lacks (1.5.0;
/// review fixes in the order of the reference): the root key's signature
/// (given the key history), the new key's (`succession_invalid_new_key_signature`),
/// its place in the history (`succession_not_in_history`), and a lead of
/// [`SUCCESSION_MIN_LEAD_SECONDS`] after the time the store recorded it, or
/// issued no later than it takes effect (`succession_backdated`).
fn succession_entry_problem(
    payload: &Value,
    na: &NaKeys,
    recorded: Option<i64>,
) -> Option<&'static str> {
    let root = na.history().and_then(|h| h.root_public_key.clone());
    if let Some(root) = &root {
        if !succession_signed_by(payload, std::slice::from_ref(root)) {
            return Some("succession_invalid_root_signature");
        }
    }
    let new_key = str_field(payload, "new_public_key")
        .unwrap_or_default()
        .to_owned();
    if !succession_signed_by(payload, &[new_key]) {
        return Some("succession_invalid_new_key_signature");
    }
    let digest = key_succession_digest(payload).unwrap_or_default();
    if root.is_some()
        && na
            .history()
            .is_some_and(|h| !h.succession_digests.contains(&digest))
    {
        return Some("succession_not_in_history");
    }
    let time = |key: &str| micros(str_field(payload, key).unwrap_or_default()).unwrap_or_default();
    let effective = time("effective_at");
    let lead = SUCCESSION_MIN_LEAD_SECONDS * 1_000_000;
    if time("issued_at") > effective || recorded.is_some_and(|at| at + lead > effective) {
        return Some("succession_backdated");
    }
    None
}

/// 1.5.0 review fixes: the kinds retention appends again after its
/// checkpoint, each with the time it was first recorded.
pub const CARRIED_KINDS: [&str; 3] = ["registry", "key_succession", "archive"];

/// How far, in microseconds, an entry's `recorded_at` may fall behind an
/// earlier entry's in store order (clock skew between NA instances).
const RECORD_TIME_TOLERANCE_MICROS: i64 = 300 * 1_000_000;

/// The store positions of the entries retention carried forward: entries of
/// [`CARRIED_KINDS`] in an unbroken run of positions right after a retention
/// checkpoint entry (1.5.0 review fixes).
pub fn carried_sequences(events: &[&Value]) -> HashSet<i64> {
    let mut sorted: Vec<&&Value> = events.iter().collect();
    sorted.sort_by_key(|e| e["entry"]["store_sequence"].as_i64());
    let mut out = HashSet::new();
    let mut previous: Option<&Value> = None;
    let mut carrying = false;
    for event in sorted {
        let entry = &event["entry"];
        let seq = entry["store_sequence"].as_i64().unwrap_or_default();
        let adjacent = previous.is_some_and(|p| p["store_sequence"].as_i64() == Some(seq - 1));
        let after_checkpoint =
            previous.is_some_and(|p| str_field(p, "entry_kind") == Some("retention_checkpoint"));
        let kind = str_field(entry, "entry_kind").unwrap_or_default();
        carrying = CARRIED_KINDS.contains(&kind) && adjacent && (after_checkpoint || carrying);
        if carrying {
            out.insert(seq);
        }
        previous = Some(entry);
    }
    out
}

fn iso_time(at: i64) -> String {
    DateTime::from_timestamp_micros(at)
        .map(crate::canonical::python_timestamp)
        .unwrap_or_default()
}

/// The registered key a key-signed record names, when it belongs to the
/// record's sovereign and has the role its kind needs.
fn signing_key<'a>(
    kind: &str,
    record: &Value,
    executor_keys: &HashMap<&str, &'a Value>,
) -> Option<&'a Value> {
    let (role, sovereign) = match kind {
        "observation" => ("observer", "observer_sovereign_id"),
        "execution" | "break_glass" | "remediation" | "grant_execution" => {
            ("executor", "executor_sovereign_id")
        }
        _ => return None,
    };
    record
        .get("signature")
        .and_then(|sig| str_field(sig, "key_id"))
        .and_then(|id| executor_keys.get(id).copied())
        .filter(|key| {
            str_field(key, "executor_sovereign_id") == str_field(record, sovereign)
                && key_role(key) == role
        })
}

/// Why a record at this store position and time (microseconds) may not
/// carry this key's signature, or `None` (1.5.0 review fixes): a key placed
/// in the store (`registered_sequence` or `registered_at_time`, and
/// `retired_sequence` or `retired_at_time`) verifies only records after its
/// registration and before its retirement (`evidence_unknown_executor`,
/// `evidence_executor_key_retired`). A key with no place is not placed.
pub fn placement_problem(key: &Value, store_sequence: i64, at: i64) -> Option<&'static str> {
    let sequence = |field: &str| key[field].as_i64();
    let time = |field: &str| str_field(key, field).and_then(|s| micros(s).ok());
    let (registered_seq, registered_at) =
        (sequence("registered_sequence"), time("registered_at_time"));
    if registered_seq.is_none() && registered_at.is_none() {
        return None;
    }
    let registered = registered_seq.is_some_and(|r| r < store_sequence)
        || registered_at.is_some_and(|r| r <= at);
    if !registered {
        return Some("evidence_unknown_executor");
    }
    let retired = sequence("retired_sequence").is_some_and(|r| r < store_sequence)
        || time("retired_at_time").is_some_and(|r| r <= at);
    retired.then_some("evidence_executor_key_retired")
}

/// An audit pack's cited records' failures and warnings, folded into the
/// run's result (1.5.0): a cited record that fails fails the pack.
fn merge_cited(main: &mut EvidenceVerification, cited: &mut EvidenceVerification) {
    for failure in cited.failures.drain(..) {
        let detail = format!("cited {}", failure.detail).trim_end().to_owned();
        fail(main, failure.store_sequence, &failure.reason, &detail);
    }
    main.warnings.append(&mut cited.warnings);
}

/// An operator key as the holder registry records it (v1.4.0): when (in
/// microseconds), its public key and its holder.
type HolderRecord = (i64, Option<String>, Option<String>);

/// What a remediation or review checks of its judgement or decision (v1.4.0).
#[derive(Default)]
struct Subject {
    /// The subject entry's payload digest.
    digest: String,
    /// A judgement's resource.
    resource_id: Option<String>,
    /// A judgement's change: its kind, id and store position, and when it
    /// happened (microseconds).
    change_kind: Option<String>,
    change_id: Option<String>,
    change_sequence: Option<i64>,
    changed_at: Option<i64>,
}

/// What a remediation checks of execution evidence (v1.4.0).
struct Execution {
    resource_id: Option<String>,
    store_sequence: i64,
    /// Microseconds.
    executed_at: i64,
    executor_sovereign_id: String,
    decision_id: String,
}

/// What an export verifier keeps for the Stage 3 checks (v1.4.0).
#[derive(Default)]
struct Stage3 {
    /// Judgements and decisions by id.
    judged: HashMap<String, Subject>,
    /// Execution evidence by id.
    executed: HashMap<String, Execution>,
    /// The version each observation or break-glass record names, by kind and id.
    versions: HashMap<(String, String), Option<String>>,
    /// The forward rotations remediations already cite.
    cited: HashSet<String>,
    /// Subjects a remediation was recorded for.
    remediated: HashSet<String>,
    /// Operator keys as the holder registry records them: when, public key, holder.
    operator_keys: HashMap<String, Vec<HolderRecord>>,
}

impl Stage3 {
    /// One remediation per subject, of its subject's change and resource,
    /// after a forward rotation of its own made after the change and cited
    /// once.
    fn remediation(
        &mut self,
        record: &Value,
        held_from_start: bool,
    ) -> Vec<(&'static str, String)> {
        let mut failures = Vec::new();
        let text = |key: &str| str_field(record, key);
        let subject_id = text("subject_id").unwrap_or_default();
        let resource_id = text("resource_id");
        if !self.remediated.insert(subject_id.to_owned()) {
            failures.push(("duplicate_remediation", subject_id.to_owned()));
        }
        let (mut change_sequence, mut changed_at) = (None, None);
        let mismatch = match self.judged.get(subject_id) {
            None => {
                if held_from_start {
                    failures.push(("remediation_subject_missing", subject_id.to_owned()));
                }
                false
            }
            Some(subject) if text("subject_kind") == Some("judgement") => {
                let change = (
                    text("change_kind").unwrap_or_default().to_owned(),
                    text("change_id").unwrap_or_default().to_owned(),
                );
                let version = self.versions.get(&change).cloned().flatten();
                let disabled = text("disabled_version_id");
                change_sequence = subject.change_sequence;
                changed_at = subject.changed_at;
                subject.resource_id.as_deref() != resource_id
                    || (Some(change.0.as_str()), Some(change.1.as_str()))
                        != (subject.change_kind.as_deref(), subject.change_id.as_deref())
                    || matches!((disabled, &version), (Some(d), Some(v)) if d != v)
            }
            // A decision's change is its execution evidence (or, never
            // executed, the decision itself).
            Some(_) if text("change_id") != Some(subject_id) => {
                let change = self.executed.get(text("change_id").unwrap_or_default());
                let wrong = text("change_kind") != Some("execution")
                    || change.is_some_and(|c| {
                        c.decision_id != subject_id || c.resource_id.as_deref() != resource_id
                    });
                if let (false, Some(change)) = (wrong, change) {
                    change_sequence = Some(change.store_sequence);
                    changed_at = Some(change.executed_at);
                }
                wrong
            }
            Some(_) => false,
        };
        if mismatch {
            failures.push(("remediation_subject_mismatch", subject_id.to_owned()));
        }
        if let Some(rotation) = text("rotation_evidence_id") {
            match self.executed.get(rotation) {
                Some(held) => {
                    if held.resource_id.as_deref() != resource_id {
                        failures.push(("remediation_rotation_mismatch", rotation.to_owned()));
                    }
                    if let Some((code, _)) = rotation_problem(&RotationFacts {
                        rotation_executor: &held.executor_sovereign_id,
                        rotation_sequence: held.store_sequence,
                        rotation_executed_at: held.executed_at,
                        record_executor: text("executor_sovereign_id").unwrap_or_default(),
                        change_sequence,
                        changed_at,
                        already_cited: self.cited.contains(rotation),
                    }) {
                        failures.push((code, rotation.to_owned()));
                    }
                }
                None if held_from_start => {
                    failures.push(("remediation_rotation_missing", rotation.to_owned()));
                }
                None if self.cited.contains(rotation) => {
                    failures.push(("remediation_rotation_reused", rotation.to_owned()));
                }
                None => {}
            }
            self.cited.insert(rotation.to_owned());
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
            Some(subject)
                if Some(subject.digest.as_str()) != str_field(record, "subject_digest") =>
            {
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

// ── Single records (1.5.0) ────────────────────────────────────────────────────

/// The kinds [`verify_record`] verifies: each entry kind of an evidence
/// export, the policies and attestations a decision binds, and (1.6.0) a
/// grant's time token.
pub const RECORD_KINDS: [&str; 19] = [
    "key_succession",
    "archive",
    "decision",
    "justification",
    "execution",
    "retention_checkpoint",
    "observation",
    "break_glass",
    "judgement",
    "quarantine",
    "registry",
    "remediation",
    "review",
    "policy",
    "attestation",
    // v1.6.0
    "grant",
    "grant_execution",
    "grant_revocation",
    "time_token",
];

/// What a single record is verified against.
#[derive(Debug, Clone, Default)]
pub struct VerifyRecordOptions {
    /// The NA's keys: they sign decisions, justifications, retention
    /// checkpoints, judgement, quarantine, registry and review records,
    /// policies and attestations.
    pub na_public_keys: Vec<String>,
    /// Registered keys as `GET /admin/evidence/executor-keys` lists them
    /// (`key_id`, `public_key`, `executor_sovereign_id`, `role`): they sign
    /// execution evidence, break-glass and remediation records (executor
    /// keys; 1.6.0: and grant uses, by the grant's bearer key) and
    /// observations (observer keys).
    pub executor_keys: Vec<Value>,
    /// Judge a decision's expiry as of this time. `None`, the default: as of
    /// the decision's own time (`decision_made_at`).
    pub at: Option<DateTime<Utc>>,
    /// A decision only: as [`VerifyDecisionOptions::freshness_proof_issuer_keys`].
    pub freshness_proof_issuer_keys: Vec<String>,
    /// A decision only: as [`VerifyDecisionOptions::expected_policies`].
    pub expected_policies: Option<Vec<Value>>,
    /// A decision only: as [`VerifyDecisionOptions::expected_attestation`].
    pub expected_attestation: Option<Value>,
    /// The NA's key history (1.5.0): when given, `na_public_keys` is not
    /// used, and an NA signature must be made by the key valid at the
    /// record's own time where it has one (a decision's `decision_made_at`, a
    /// retention checkpoint's `created_at`, a policy's or an attestation's
    /// `issued_at`); another record read alone is accepted under any key of
    /// the history. A key succession must be one of its successions.
    pub key_history: Option<NaKeyHistory>,
}

/// The time an NA-signed record read on its own is placed at in the key
/// history (1.5.0 review fixes: the reference's `NA_RECORD_TIME_FIELDS`), in
/// microseconds.
fn own_time(kind: &str, record: &Value) -> Option<i64> {
    let model = match kind {
        "decision" => "BoundaryDecision",
        "policy" => "BoundaryPolicy",
        "attestation" => "MembershipAttestation",
        other => payload_model(other)?,
    };
    let field = crate::key_history::na_record_time_field(model)?;
    micros(str_field(record, field)?).ok()
}

/// Outcome of [`verify_record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordVerification {
    /// The kind the record was verified as.
    pub kind: String,
    /// The record's id, when it has one.
    pub record_id: Option<String>,
    /// The record is authentic, well formed and in the form the reference
    /// writes.
    pub verified: bool,
    /// The first failure's reason code; for a verified record `verified`,
    /// or for a decision the reference's reason (`authorized`,
    /// `unauthorized_...`).
    pub reason: String,
    /// Whether a decision authorizes its action; absent for other kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    /// Every failure, in order (`store_sequence` is always absent).
    pub failures: Vec<VerificationFailure>,
    /// Findings that do not fail verification, such as `unsigned_field`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<VerificationFailure>,
}

impl RecordVerification {
    fn fail(&mut self, reason: &str, detail: &str) {
        if self.verified {
            self.reason = reason.to_owned();
        }
        self.verified = false;
        self.failures.push(VerificationFailure {
            store_sequence: None,
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        });
    }
}

/// The model an export entry kind other than a decision holds.
fn payload_model(kind: &str) -> Option<&'static str> {
    match kind {
        "justification" => Some("JustificationProof"),
        "execution" => Some("ExecutionEvidence"),
        "retention_checkpoint" => Some("RetentionCheckpoint"),
        other => out_of_band_model(other),
    }
}

/// Verify one signed record offline, as [`verify_evidence_events`] verifies
/// it as an entry of an export, with the same reason codes in the same
/// order: `unknown_field`, `payload_invalid`, `invalid_signature`,
/// `non_canonical_form`, and the checks a record carries in itself
/// (`quarantine_digest_mismatch`, `retention_count_mismatch` for a first
/// checkpoint, `review_approval_invalid`, `review_same_holder`; 1.6.0: a
/// grant use's time token, `grant_time_token_invalid`,
/// `grant_time_token_mismatch`, `grant_use_before_time_token`). A grant, a
/// grant revocation and a time token are NA-signed, a grant use by its
/// grant's bearer key (an executor key). The checks
/// that need the rest of the store (chains, subjects, matches) are an
/// export's. A decision is verified by [`verify_boundary_decision`], its
/// expiry as of its own time unless [`VerifyRecordOptions::at`] says
/// otherwise; a policy or an attestation by its signature and fields.
pub fn verify_record(
    kind: &str,
    record: &Value,
    options: &VerifyRecordOptions,
) -> RecordVerification {
    let mut out = RecordVerification {
        kind: kind.to_owned(),
        record_id: None,
        verified: true,
        reason: "verified".to_owned(),
        authorized: None,
        failures: Vec::new(),
        warnings: Vec::new(),
    };
    let na = match &options.key_history {
        Some(history) => NaKeys::History(history.clone()),
        None => NaKeys::Any(options.na_public_keys.clone()),
    };
    let at = own_time(kind, record);
    let keys = &na.at(at);
    let other = at.map(|at| na.not_at(at)).unwrap_or_default();
    match kind {
        "decision" => {
            let check = verify_boundary_decision(
                record,
                &VerifyDecisionOptions {
                    operator_public_keys: options.na_public_keys.clone(),
                    freshness_proof_issuer_keys: options.freshness_proof_issuer_keys.clone(),
                    now: options.at,
                    expected_policies: options.expected_policies.clone(),
                    expected_attestation: options.expected_attestation.clone(),
                    at_record_time: options.at.is_none(),
                    key_history: options.key_history.clone(),
                },
            );
            out.record_id = check.decision_id;
            out.authorized = Some(check.authorized);
            if check.accepted {
                out.reason = check.reason;
            } else {
                out.fail(&check.reason, "");
            }
        }
        "policy" | "attestation" => {
            let signed_with = |keys: &[String]| {
                if kind == "policy" {
                    signed_by(policy_canonical(record), record.get("signature"), keys)
                } else {
                    let canonical = crate::canonical::attestation_canonical(record);
                    any_signed(canonical, record.get("signatures"), keys)
                }
            };
            let (model, id) = if kind == "policy" {
                ("BoundaryPolicy", "policy_id")
            } else {
                ("MembershipAttestation", "attestation_id")
            };
            let signed = signed_with(keys);
            out.record_id = str_field(record, id).map(str::to_owned);
            let unknown = unknown_fields(model, record);
            if !record.is_object() {
                out.fail("payload_invalid", "");
            } else if signed && !unknown.is_empty() {
                out.fail("unknown_field", &unknown.join(", "));
            } else if !signed && signed_with(&other) {
                out.fail("na_key_not_valid_at_time", kind);
            } else if !signed {
                out.fail("invalid_signature", kind);
            }
        }
        _ => {
            let Some(model) = payload_model(kind) else {
                out.fail("unknown_entry_kind", kind);
                return out;
            };
            let executor_keys: HashMap<&str, &Value> = options
                .executor_keys
                .iter()
                .filter_map(|k| Some((str_field(k, "key_id")?, k)))
                .collect();
            let root = na.history().and_then(|h| h.root_public_key.clone());
            let mut signers = na.all();
            if kind == "key_succession" {
                signers.extend(root.clone());
            }
            out.record_id = Some(record_id_of(kind, record)).filter(|id| !id.is_empty());
            let checked = check_payload_fields(kind, record, &signers, &executor_keys);
            if !checked.signed.is_empty() {
                out.fail("unknown_field", &checked.signed.join(", "));
                return out;
            }
            if !checked.unsigned.is_empty() {
                out.warnings.push(VerificationFailure {
                    store_sequence: None,
                    reason: "unsigned_field".to_owned(),
                    detail: checked.unsigned.join(", "),
                });
                if refuses_unsigned_fields(kind) {
                    out.fail("payload_invalid", &checked.unsigned.join(", "));
                    return out;
                }
            }
            let payload = &checked.payload;
            if !valid_payload(kind, payload) {
                out.fail("payload_invalid", "");
                return out;
            }
            if kind == "key_succession" {
                if let Some(reason) = succession_alone(payload, &na) {
                    out.fail(reason, kind);
                }
                return out;
            }
            let signed = record_signed(kind, payload, keys, &executor_keys);
            let by_other = !signed && record_signed(kind, payload, &other, &executor_keys);
            let canonical = non_canonical_fields(model, payload).is_empty();
            if (signed || by_other) && !canonical {
                out.fail("non_canonical_form", kind);
            } else if by_other {
                out.fail("na_key_not_valid_at_time", kind);
            } else if !signed {
                out.fail("invalid_signature", kind);
            }
            match kind {
                "retention_checkpoint"
                    if str_field(payload, "previous_checkpoint_id").is_none() =>
                {
                    if let Some(problem) = checkpoint_count_problem(payload, 0) {
                        out.fail("retention_count_mismatch", &problem);
                    }
                }
                "quarantine" => {
                    if payload_digest(&payload["record"]).ok().as_deref()
                        != str_field(payload, "record_digest")
                    {
                        out.fail("quarantine_digest_mismatch", "");
                    }
                }
                "review" => {
                    if let Some(problem) = review_approval_problem(payload, &na.all()) {
                        out.fail("review_approval_invalid", &problem);
                    }
                    if review_holder_problem(&ReviewHolders::of(payload)).is_some() {
                        let decider = str_field(payload, "decided_by").unwrap_or_default();
                        out.fail("review_same_holder", decider);
                    }
                }
                // v1.6.0: what a use carries in itself: a time token the NA
                // signed for its grant, issued before it, not after it was
                // made. The rest needs its grant and chain (an export's).
                "grant_execution" => {
                    let token = &payload["time_token"];
                    let issued = str_field(token, "issued_at").and_then(|t| micros(t).ok());
                    let token_keys = na.at(issued);
                    let context = UseContext {
                        token_keys: &token_keys,
                        ..UseContext::default()
                    };
                    if let Some((reason, detail)) = use_problem(payload, &context) {
                        out.fail(reason, &detail);
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Why a key succession read on its own is refused, or `None`, as an export
/// refuses its entry (1.5.0): its form under the NA keys and the root key,
/// a signature by its outgoing key (a key of the history), and, given the
/// key history, the root key's signature (`succession_invalid_root_signature`)
/// and its place in the history (`succession_not_in_history`).
fn succession_alone(payload: &Value, na: &NaKeys) -> Option<&'static str> {
    let all = na.all();
    let mut signers = all.clone();
    signers.extend(na.history().and_then(|h| h.root_public_key.clone()));
    signers.extend(str_field(payload, "new_public_key").map(str::to_owned));
    if let Some(refusal) = succession_form_refusal(payload, &signers) {
        return Some(if refusal == "unknown_field" {
            "invalid_signature"
        } else {
            refusal
        });
    }
    let previous = str_field(payload, "previous_public_key").unwrap_or_default();
    if !all.iter().any(|k| k == previous) || !succession_signed_by(payload, &[previous.to_owned()])
    {
        return Some("invalid_signature");
    }
    // Read alone it has no store time: its lead is not checked.
    succession_entry_problem(payload, na, None)
}

// ── Store anchors (1.5.0; the reference's since 1.2.0) ────────────────────────

validator!(
    valid_anchor,
    shape(
        vec![
            ("anchor_sequence", positive()),
            ("sovereign_id", string()),
            ("store_sequence", positive()),
            ("entry_digest", string()),
            ("anchored_at", utc_timestamp()),
            ("previous_anchor_digest", absent(string())),
            ("issued_by", string()),
            ("signature", optional(signature())),
        ],
        true
    )
);

/// Anchors from a JSON file as the reference reads held anchors
/// (`genesis-mesh evidence verify-export --known-anchors <file>`): a JSON
/// array, an object with `anchors`, one anchor, or JSON Lines, in strict
/// JSON. Each must be a `StoreAnchor` ([`check_anchors`]). Returned in
/// `anchor_sequence` order.
pub fn parse_anchors(text: &str) -> Result<Vec<Value>> {
    let json_space = |c: char| matches!(c, ' ' | '\t' | '\r' | '\n');
    let text = text.trim_matches(json_space);
    let data = if text.starts_with('[') || text.starts_with('{') {
        match crate::strict_json::parse_strict_json(text) {
            Ok(value) => value,
            Err(GenesisMeshError::StrictJson { reason, .. }) if reason == "invalid_json" => {
                let lines = text
                    .split('\n')
                    .filter(|line| !line.trim_matches(json_space).is_empty())
                    .map(crate::strict_json::parse_strict_json)
                    .collect::<Result<Vec<Value>>>()?;
                Value::Array(lines)
            }
            Err(other) => return Err(other),
        }
    } else {
        Value::Array(Vec::new())
    };
    let raw = match data {
        Value::Object(ref map) => map
            .get("anchors")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![data.clone()])),
        other => other,
    };
    let Value::Array(raw) = raw else {
        return Err(GenesisMeshError::Verification(
            "anchors must be a list".into(),
        ));
    };
    check_anchors(raw)
}

/// Check that each value is a `StoreAnchor` (exactly its fields, positions
/// from 1, `anchored_at` in UTC) and order them by `anchor_sequence`, as the
/// reference reads held anchors.
pub fn check_anchors(anchors: Vec<Value>) -> Result<Vec<Value>> {
    if let Some(bad) = anchors.iter().find(|a| !valid_anchor(Some(a))) {
        let at = bad.get("anchor_sequence").cloned().unwrap_or(Value::Null);
        return Err(GenesisMeshError::Verification(format!(
            "not a store anchor (anchor_sequence {at})"
        )));
    }
    let mut anchors = anchors;
    anchors.sort_by_key(|a| a["anchor_sequence"].as_i64());
    Ok(anchors)
}

/// One problem found in a run of anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorFailure {
    /// The anchor's position.
    pub anchor_sequence: Option<i64>,
    /// Reason code, identical to the Python reference.
    pub reason: String,
    /// Extra context.
    pub detail: String,
}

/// Outcome of [`verify_store_anchors`] (the reference's `AnchorVerification`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorVerification {
    /// No failures.
    pub verified: bool,
    /// Anchors checked.
    pub checked_anchors: u64,
    /// The first anchor's position.
    pub first_anchor_sequence: Option<i64>,
    /// The last anchor's position.
    pub last_anchor_sequence: Option<i64>,
    /// The highest store position the anchors name.
    pub anchored_through_sequence: Option<i64>,
    /// Every failure, in order.
    pub failures: Vec<AnchorFailure>,
}

/// Verify a run of anchors ordered by `anchor_sequence`, as the reference's
/// `verify_store_anchors`: each signed by one of the NA keys
/// (`anchor_invalid_signature`; `None` skips signatures; given the NA's key
/// history, by the key valid at its `anchored_at`, else
/// `na_key_not_valid_at_time`), of `sovereign_id`
/// when given (`anchor_sovereign_mismatch`), positions without gaps
/// (`anchor_sequence_gap`), each naming the digest of the one before and the
/// first at position 1 naming none (`anchor_chain_break`), store positions
/// and times increasing (`anchor_not_increasing`). The run need not start at
/// 1: an auditor may hold only recent anchors.
pub fn verify_store_anchors(
    anchors: &[Value],
    na_keys: Option<&NaKeys>,
    sovereign_id: Option<&str>,
) -> AnchorVerification {
    let mut result = AnchorVerification {
        verified: true,
        checked_anchors: 0,
        first_anchor_sequence: None,
        last_anchor_sequence: None,
        anchored_through_sequence: None,
        failures: Vec::new(),
    };
    let fail = |result: &mut AnchorVerification, n: i64, reason: &str, detail: &str| {
        result.verified = false;
        result.failures.push(AnchorFailure {
            anchor_sequence: Some(n),
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        });
    };
    let at = |a: &Value| micros(str_field(a, "anchored_at").unwrap_or_default()).ok();
    let mut prev: Option<&Value> = None;
    for anchor in anchors {
        let n = anchor["anchor_sequence"].as_i64().unwrap_or_default();
        let store_sequence = anchor["store_sequence"].as_i64().unwrap_or_default();
        result.checked_anchors += 1;
        result.first_anchor_sequence.get_or_insert(n);
        result.last_anchor_sequence = Some(n);
        if let Some(keys) = na_keys {
            // v1.5.0: by the NA key valid at its `anchored_at`.
            let signed = |keys: &[String]| {
                signed_by(anchor_canonical(anchor), anchor.get("signature"), keys)
            };
            if !signed(&keys.at(at(anchor))) {
                let late = at(anchor).is_some_and(|at| signed(&keys.not_at(at)));
                let reason = if late {
                    "na_key_not_valid_at_time"
                } else {
                    "anchor_invalid_signature"
                };
                fail(&mut result, n, reason, "");
            }
        }
        if let Some(sovereign) = sovereign_id {
            let named = str_field(anchor, "sovereign_id").unwrap_or_default();
            if named != sovereign {
                fail(&mut result, n, "anchor_sovereign_mismatch", named);
            }
        }
        let previous_digest = str_field(anchor, "previous_anchor_digest");
        match prev {
            None => {
                if n == 1 && previous_digest.is_some() {
                    fail(
                        &mut result,
                        n,
                        "anchor_chain_break",
                        "the first anchor names a previous anchor",
                    );
                }
            }
            Some(prev) => {
                let prev_n = prev["anchor_sequence"].as_i64().unwrap_or_default();
                if n != prev_n + 1 {
                    let detail = format!("after {prev_n}");
                    fail(&mut result, n, "anchor_sequence_gap", &detail);
                } else if previous_digest != anchor_digest(prev).ok().as_deref() {
                    fail(&mut result, n, "anchor_chain_break", "");
                }
                if store_sequence <= prev["store_sequence"].as_i64().unwrap_or_default()
                    || at(anchor) < at(prev)
                {
                    fail(&mut result, n, "anchor_not_increasing", "");
                }
            }
        }
        let through = result.anchored_through_sequence.unwrap_or_default();
        result.anchored_through_sequence = Some(through.max(store_sequence));
        prev = Some(anchor);
    }
    result
}

/// The retention checkpoint in a run that explains where the run starts at
/// `first`: one that removed every entry before it and names its link.
fn starting_checkpoint<'a>(events: &[&'a Value], first: &Value) -> Option<&'a Value> {
    let entry = &first["entry"];
    let first_sequence = entry["store_sequence"].as_i64()?;
    events.iter().find_map(|event| {
        let payload = &event["payload"];
        (str_field(&event["entry"], "entry_kind") == Some("retention_checkpoint")
            && valid_checkpoint(Some(payload))
            && unknown_fields("RetentionCheckpoint", payload).is_empty()
            && payload["removed_through_sequence"].as_i64() == Some(first_sequence - 1)
            && str_field(payload, "last_removed_entry_digest")
                == str_field(entry, "prev_entry_digest"))
        .then_some(payload)
    })
}

/// The retention checkpoint in an export that explains where it starts, or
/// `None` (the reference's `export_checkpoint`): an export of a store after
/// retention starts right after what was removed, and its chains continue
/// from the checkpoint's resource and observation positions, so pass it as
/// [`VerifyEvidenceOptions::checkpoint`]. The checkpoint is itself an entry
/// of the export, verified with the rest.
pub fn export_checkpoint(events: &[Value]) -> Option<Value> {
    let first = events
        .iter()
        .min_by_key(|e| e["entry"]["store_sequence"].as_i64())?;
    let all: Vec<&Value> = events.iter().collect();
    starting_checkpoint(&all, first).cloned()
}

/// How an export lines up with the anchors held (the reference's
/// `anchors` summary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCoverage {
    /// Anchors held.
    pub anchors_checked: u64,
    /// Anchors whose entry the export holds as anchored.
    pub anchors_matched: u64,
    /// Anchors before the export's first entry.
    pub anchors_before_export: u64,
    /// Anchors after the export's last entry.
    pub anchors_after_export: u64,
    /// The export starts at entry 1, right after a checkpoint it holds, or
    /// (with `from_anchor`) right after a held anchor.
    pub linked_start: bool,
    /// The highest position an anchor matched.
    pub anchored_through_sequence: Option<i64>,
    /// Entries after that position.
    pub unanchored_entries: u64,
}

/// Check a contiguous export against anchors held out of band, as the
/// reference's `check_events_against_anchors`, adding failures to `result`:
///
/// * each anchor inside the run names its entry's digest as received
///   (`anchor_mismatch`, `anchor_entry_missing`); entries are hash-linked, so
///   a match covers every earlier entry of the run;
/// * the run is tied at its start: entry 1, right after a retention
///   checkpoint it holds or, with `from_anchor`, right after a held anchor
///   its first entry links to (`export_not_linked_to_anchors`; an anchor
///   right before the run that its first entry does not link to is
///   `anchor_mismatch`);
/// * no anchor follows its last entry (`export_ends_before_anchor`).
///
/// `partial` accepts a deliberate slice and skips both ends.
pub fn check_events_against_anchors(
    events: &[Value],
    anchors: &[Value],
    result: &mut EvidenceVerification,
    partial: bool,
    from_anchor: bool,
) -> AnchorCoverage {
    let sequence = |e: &Value| e["entry"]["store_sequence"].as_i64().unwrap_or_default();
    let by_sequence: HashMap<i64, &Value> = events.iter().map(|e| (sequence(e), e)).collect();
    let mut ordered: Vec<&Value> = events.iter().collect();
    ordered.sort_by_key(|e| sequence(e));
    let first = ordered.first().copied();
    let first_seq = first.map(sequence);
    let last_seq = ordered.last().map(|e| sequence(e));
    let (mut matched, mut before, mut beyond) = (0u64, 0u64, 0u64);
    let mut anchored_through: Option<i64> = None;
    let mut linked_start = first.is_some_and(|first| {
        first_seq == Some(1) || starting_checkpoint(&ordered, first).is_some()
    });
    let mut after_anchor: Option<i64> = None;
    for anchor in anchors {
        let seq = anchor["store_sequence"].as_i64().unwrap_or_default();
        let number = anchor["anchor_sequence"].as_i64().unwrap_or_default();
        let anchored = str_field(anchor, "entry_digest");
        let (Some(first), Some(first_seq), Some(last_seq)) = (first, first_seq, last_seq) else {
            beyond += 1;
            continue;
        };
        if seq > last_seq {
            beyond += 1;
            continue;
        }
        if seq == first_seq - 1 {
            if str_field(&first["entry"], "prev_entry_digest") == anchored {
                after_anchor = Some(number);
                linked_start = linked_start || from_anchor;
                matched += 1;
                anchored_through = Some(anchored_through.unwrap_or_default().max(seq));
            } else {
                let detail = format!("the run does not continue from anchor {number}");
                fail(result, Some(first_seq), "anchor_mismatch", &detail);
            }
            continue;
        }
        if seq < first_seq {
            before += 1;
            continue;
        }
        let detail = format!("anchor {number}");
        match by_sequence.get(&seq) {
            None => fail(result, Some(seq), "anchor_entry_missing", &detail),
            Some(event) => {
                let received = entry_digest(&event["entry"]).ok();
                if str_field(event, "entry_digest") != anchored || received.as_deref() != anchored {
                    fail(result, Some(seq), "anchor_mismatch", &detail);
                } else {
                    matched += 1;
                    anchored_through = Some(anchored_through.unwrap_or_default().max(seq));
                }
            }
        }
    }
    // A held anchor commits to every entry before the one it names, so a run
    // not tied at its start leaves entries the anchors prove exist
    // unaccounted for.
    if let (false, Some(first_seq), false, false) =
        (anchors.is_empty(), first_seq, linked_start, partial)
    {
        let why = match after_anchor {
            Some(n) => format!(
                "the export starts right after held anchor {n}, which proves the entries before \
                 it existed, not that they are kept: export from entry 1 (with the retention \
                 checkpoint that removed entries, if any), or verify it as an export since that \
                 anchor (--from-anchor)"
            ),
            None => format!(
                "the export starts at entry {first_seq} and holds neither entry 1 nor the \
                 retention checkpoint that removed the entries before it ({before} held \
                 anchor(s) before it): export from entry 1, or include that checkpoint's entry"
            ),
        };
        fail(
            result,
            Some(first_seq),
            "export_not_linked_to_anchors",
            &why,
        );
    }
    if beyond > 0 && !partial {
        let detail = format!("{beyond} anchor(s) after the last entry");
        fail(result, last_seq, "export_ends_before_anchor", &detail);
    }
    let floor = anchored_through.unwrap_or_default();
    AnchorCoverage {
        anchors_checked: anchors.len() as u64,
        anchors_matched: matched,
        anchors_before_export: before,
        anchors_after_export: beyond,
        linked_start,
        anchored_through_sequence: anchored_through,
        unanchored_entries: by_sequence.keys().filter(|&&s| s > floor).count() as u64,
    }
}

// ── Node certificates and the CRL (1.7.0) ────────────────────────────────────

/// The fields a `JoinCertificate` signature covers, in its canonical form.
const JOIN_CERTIFICATE_FIELDS: [&str; 7] = [
    "cert_id",
    "node_public_key",
    "network_name",
    "roles",
    "issued_at",
    "expires_at",
    "issued_by",
];

/// True when one of a `JoinCertificate`'s `signatures` verifies under the
/// NA's keys (1.7.0, beta). The signature covers exactly `cert_id`,
/// `node_public_key`, `network_name`, `roles`, `issued_at`, `expires_at` and
/// `issued_by`, as received; what a response adds beside them (an edge
/// node's `edge` block) is not signed and is ignored. A field missing or of
/// the wrong type does not verify.
pub fn verify_join_certificate(certificate: &Value, na_public_keys: &[String]) -> bool {
    let mut signed = serde_json::Map::new();
    for field in JOIN_CERTIFICATE_FIELDS {
        let value = &certificate[field];
        let well_formed = match field {
            "roles" => value
                .as_array()
                .is_some_and(|roles| roles.iter().all(Value::is_string)),
            _ => value.is_string(),
        };
        if !well_formed {
            return false;
        }
        signed.insert(field.to_owned(), value.clone());
    }
    any_signed(
        crate::auth::canonical_json(&Value::Object(signed)),
        certificate.get("signatures"),
        na_public_keys,
    )
}

/// True when one of a certificate revocation list's (`GET /crl`)
/// `signatures` verifies under the NA's keys (1.7.0, beta), over the list as
/// received without its `signatures`. A list without `crl_id`, `sequence` or
/// `revoked_certificates` does not verify.
pub fn verify_crl(crl: &Value, na_public_keys: &[String]) -> bool {
    let Some(map) = crl.as_object() else {
        return false;
    };
    if !crl["crl_id"].is_string()
        || !crl["sequence"].is_u64()
        || !crl["revoked_certificates"].is_array()
    {
        return false;
    }
    let mut signed = map.clone();
    signed.remove("signatures");
    any_signed(
        crate::auth::canonical_json(&Value::Object(signed)),
        crl.get("signatures"),
        na_public_keys,
    )
}
