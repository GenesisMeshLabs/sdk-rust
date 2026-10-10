//! Offline verification of NA-signed artifacts and evidence exports.
//! Direct ports of the Python reference, with the same reason codes:
//!
//! * [`verify_boundary_decision`]: `trust/context/decisions.py` `verify_boundary_decision`
//! * [`verify_evidence_events`]: `trust/evidence_store.py` `verify_evidence_events`
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
/// Absent, `null` (read as absent) or valid.
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
                && (s.ends_with(['Z', 'z']) || s.ends_with("+00:00") || s.ends_with("-00:00"))
        })
    })
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
            ("resolution_failure", nullable(string())),
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
                        ("subject_id", nullable(string())),
                        ("issuer_sovereign_id", nullable(string())),
                        ("attestation_digest", nullable(string())),
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
            ("outcome_detail", nullable(string())),
            ("prev_evidence_digest", nullable(string())),
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
                        ("short_circuited_at", nullable(string())),
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
            ("previous_checkpoint_id", nullable(string())),
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
            ("metadata", object()),
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
            ("request_parameters", object()),
            ("attributes", object()),
            ("justification", bounded(1024, 1)),
            ("evaluation_request_digest", sha256()),
            (
                "evaluation_failure",
                one_of(&["network_error", "timeout", "server_error", "rate_limited"])
            ),
            ("executed_at", utc_timestamp()),
            ("outcome", string()),
            ("outcome_detail", absent(bounded(1024, 0))),
            ("execution_parameters", object()),
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
            ("gate_results", array(gate_result())),
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
                one_of(&["execution", "observation", "break_glass"])
            ),
            ("record", object()),
            ("record_digest", sha256()),
            ("rejection_code", bounded(128, 1)),
            ("detail", bounded(1024, 0)),
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

/// v1.3.0: the id field and model of each record of a change made outside
/// the controlled path.
const OUT_OF_BAND_IDS: [(&str, &str); 5] = [
    ("observation_id", "ObservationRecord"),
    ("break_glass_id", "BreakGlassRecord"),
    ("judgement_id", "JudgementRecord"),
    ("quarantine_id", "QuarantineRecord"),
    ("registry_record_id", "RegistryRecord"),
];

/// Whether a Stage 2 record's signature covers it as received under one of
/// the keys, with no signed field the registry does not list. Its form is
/// checked apart ([`non_canonical_fields`]).
fn out_of_band_verifies(model: &str, record: &Value, keys: &[String]) -> bool {
    signed_by(out_of_band_canonical(record), record.get("signature"), keys)
        && unknown_fields(model, record).is_empty()
}

/// True when the signature of a record of a change made outside the
/// controlled path (v1.3.0: an observation, break-glass, judgement,
/// quarantine or registry record, told by its id field) verifies under one of
/// the keys, over its form as received. A record with a signed field this
/// crate does not know, or not in the form the reference writes (a timestamp
/// in another spelling, a field it always writes left out), does not verify.
pub fn verify_out_of_band_record(record: &Value, public_keys: &[String]) -> bool {
    OUT_OF_BAND_IDS
        .iter()
        .find(|(id, _)| record.get(*id).is_some())
        .is_some_and(|(_, model)| {
            out_of_band_verifies(model, record, public_keys)
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
    /// when absent), which signs execution evidence and break-glass records,
    /// or `observer`, which signs observations only.
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
        _ => signed_by(
            out_of_band_canonical(payload),
            payload.get("signature"),
            &out_of_band_keys(kind, payload, &options.na_public_keys, executor_keys),
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

/// v1.3.0: the model each Stage 2 entry kind holds.
fn out_of_band_model(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "observation" => "ObservationRecord",
        "break_glass" => "BreakGlassRecord",
        "judgement" => "JudgementRecord",
        "quarantine" => "QuarantineRecord",
        "registry" => "RegistryRecord",
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
/// record), or the NA's for the kinds the NA signs.
fn out_of_band_keys(
    kind: &str,
    payload: &Value,
    na_public_keys: &[String],
    executor_keys: &HashMap<&str, &Value>,
) -> Vec<String> {
    let (role, sovereign) = match kind {
        "observation" => ("observer", "observer_sovereign_id"),
        "break_glass" => ("executor", "executor_sovereign_id"),
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
    let mut subjects: HashMap<String, (String, i64)> = HashMap::new();
    let mut judged: HashSet<String> = HashSet::new();
    let mut matched: HashSet<String> = HashSet::new();
    let mut not_decisions: HashSet<String> = HashSet::new();
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
        }
        let payload = &checked.payload;
        // v1.3.0: a record whose signature covers it as received, in a form
        // the reference does not write, is refused by name, as the reference
        // refuses it (checked when the whole record was signed, not after
        // unsigned fields were set aside).
        let whole = checked.unsigned.is_empty();
        let signature = |result: &mut EvidenceVerification,
                         signed: bool,
                         model: &str,
                         record: &Value,
                         detail: &str| {
            if !signed {
                fail(result, s, "invalid_signature", detail);
            } else if whole && !non_canonical_fields(model, record).is_empty() {
                fail(result, s, "non_canonical_form", detail);
            }
        };
        match kind {
            "decision" => {
                let decision = &payload["decision"];
                if !valid_decision(payload.get("decision")) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
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
                decisions.insert(id.clone(), decision.clone());
                if valid_context(payload.get("context")) {
                    contexts.insert(id, payload["context"].clone());
                } else {
                    fail(&mut result, s, "payload_invalid", "context");
                }
            }
            "justification" => {
                if !valid_justification(Some(payload)) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
                signature(
                    &mut result,
                    verify_justification_signature(payload, &options.na_public_keys),
                    "JustificationProof",
                    payload,
                    "justification",
                );
            }
            "execution" => {
                if !valid_execution(Some(payload)) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
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
                if let Some(resource_id) = str_field(ev, "resource_id") {
                    let head = resource_heads.get(resource_id);
                    let expected = head.map_or(1, |h| h.resource_sequence + 1);
                    let resource_sequence = ev.get("resource_sequence").and_then(Value::as_u64);
                    if resource_sequence != Some(expected)
                        || str_field(ev, "prev_resource_digest")
                            != head.map(|h| h.record_digest.as_str())
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
                if !valid_checkpoint(Some(payload)) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
                signature(
                    &mut result,
                    verify_retention_checkpoint(payload, &options.na_public_keys),
                    "RetentionCheckpoint",
                    payload,
                    "retention_checkpoint",
                );
            }
            "observation" | "break_glass" => {
                let observation = kind == "observation";
                let valid = if observation {
                    valid_observation(Some(payload))
                } else {
                    valid_break_glass(Some(payload))
                };
                if !valid {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                let id_field = if observation {
                    "observation_id"
                } else {
                    "break_glass_id"
                };
                let record_id = str_field(payload, id_field).unwrap_or_default().to_owned();
                let resource = str_field(payload, "resource_id")
                    .unwrap_or_default()
                    .to_owned();
                if str_field(entry, "record_id") != Some(record_id.as_str())
                    || str_field(entry, "resource_id") != Some(resource.as_str())
                {
                    fail(&mut result, s, "envelope_mismatch", kind);
                }
                let digest = str_field(entry, "payload_digest").unwrap_or_default();
                subjects.insert(record_id.clone(), (digest.to_owned(), seq));
                not_decisions.insert(record_id);
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
                }
            }
            "judgement" => {
                if !valid_judgement(Some(payload)) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
                result.judgements += 1;
                let judgement_id = str_field(payload, "judgement_id").unwrap_or_default();
                let subject_id = str_field(payload, "subject_id").unwrap_or_default();
                not_decisions.insert(judgement_id.to_owned());
                if str_field(entry, "subject_id") != Some(subject_id)
                    || str_field(entry, "record_id") != Some(judgement_id)
                {
                    fail(&mut result, s, "envelope_mismatch", "judgement");
                }
                if !judged.insert(subject_id.to_owned()) {
                    fail(&mut result, s, "duplicate_judgement", subject_id);
                }
                let subject_sequence = payload["subject_store_sequence"].as_i64();
                match subjects.get(subject_id) {
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
                }
            }
            "quarantine" => {
                if !valid_quarantine(Some(payload)) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
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
                if !valid_registry(Some(payload)) {
                    fail(&mut result, s, "payload_invalid", "");
                    continue;
                }
                let signed = out_of_band_signed(kind, payload, options, &executor_keys);
                signature(&mut result, signed, model_of(kind), payload, kind);
            }
            other => fail(&mut result, s, "unknown_entry_kind", other),
        }
    }
    result
}
