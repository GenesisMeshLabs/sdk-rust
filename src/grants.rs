//! Pre-issued grants (Genesis Mesh 1.6.0, Stage 5): the records, their
//! number rules, envelopes and the rules a use is checked by. Pure functions;
//! the holder that acts within a grant is [`GrantHolder`](crate::GrantHolder).
//!
//! Break-glass (1.3.0) records a change made while the Network Authority (NA)
//! cannot be reached and has it judged afterwards. A grant authorises the
//! change beforehand: the NA signs, in advance, a bounded authorisation one
//! holder may use while the NA is unreachable, after checking that every
//! policy that applies allows every request the grant permits. The records,
//! as JSON values:
//!
//! * `CapabilityGrant` (entry kind `grant`, NA-signed): one bearer key (a
//!   registered executor key), the capabilities, a basis, a validity of at
//!   most 24 hours, a budget of uses, the uses one time token may anchor, and
//!   a closed parameter envelope;
//! * `TimeToken` (NA-signed): a time the NA signed for a grant's holder,
//!   bound to the head of the holder's use chain when it asked;
//! * `TimeTokenRequest` (beta, signed by the bearer key): the holder's request
//!   for one;
//! * `GrantExecutionEvidence` (entry kind `grant_execution`, signed by the
//!   bearer key): one use of a grant, in the grant's use chain;
//! * `GrantRevocationRecord` (entry kind `grant_revocation`, NA-signed): the
//!   NA's revocation of a grant from `revoked_at`.
//!
//! Each signs every field but `signature`; an absent optional field is left
//! out ([`received_canonical`] with the
//! field registry). A time token's absent `use_head_digest` is left out of
//! every form, also when the token is nested in a use. The forms are frozen
//! from 1.6.0 on and match the Python reference byte for byte (conformance
//! suite `grants`).
//!
//! Numbers, as every verifier reads them: an integral number is an integer
//! (`5.0` is `5`); integers fit 64 bits; comparisons are exact; booleans are
//! never numbers; set membership is type-strict (`true` is not `1`, `"1"` is
//! not `1`, but `1` is `1.0`).

use std::cmp::Ordering;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use crate::{
    auth::{sha256_hex, verify_canonical},
    canonical::{micros, parse_timestamp, python_timestamp, received_canonical},
    errors::Result,
    strict::without_unknown_fields,
};

/// The longest a grant may be valid, in seconds, whatever the NA's
/// configuration.
pub const GRANT_MAX_VALIDITY_SECONDS: i64 = 86_400;

/// The largest budget a grant may carry.
pub const GRANT_MAX_USES: u64 = 10_000;

/// The most uses one time token may anchor.
pub const GRANT_MAX_USES_PER_TIME_TOKEN: u64 = 1_000;

/// How far, in seconds, a use may be dated after the time its entry is
/// recorded (clock skew between a holder and the NA). Fixed, so every
/// verifier applies one rule; a time token's head use may be dated this much
/// after the token too.
pub const GRANT_CLOCK_SKEW_SECONDS: i64 = 300;

/// The most capabilities one grant may name.
pub const MAX_GRANT_CAPABILITIES: usize = 16;

/// The most parameters one grant's envelope may hold.
pub const MAX_ENVELOPE_PARAMETERS: usize = 64;

/// The most values a `one_of` or `subset_of` may list.
pub const MAX_LIST_VALUES: usize = 256;

/// Why the NA revokes a grant.
pub const REVOCATION_REASONS: [&str; 6] = [
    "operator",
    "attestation_revoked",
    "policy_deactivated",
    "policy_activated",
    "bearer_key_retired",
    // The review fixes: an agreement basis no longer signed by parties the
    // NA trusts (a recognition treaty was revoked or has expired).
    "agreement_untrusted",
];

/// The outcomes a use records.
pub const USE_OUTCOMES: [&str; 3] = ["success", "failure", "partial"];

/// Why a use is refused, in the order the NA and every verifier check them
/// (the first that applies is the use's code): the use's form, its grant and
/// signature, secret material, its place in the chain, the bearer key, its
/// scope and the grant's digest, then [`use_problem`]. The refusals after
/// the signature keep the authentic use as a quarantine entry
/// ([`QUARANTINED_USE_CODES`]); the rest are not stored.
pub const USE_REJECTION_CODES: [&str; 24] = [
    "grant_use_malformed",
    "grant_not_found",
    "grant_use_invalid_signature",
    "grant_use_secret_material",
    "grant_use_conflict",
    "grant_use_chain_gap",
    "grant_use_chain_mismatch",
    "grant_bearer_mismatch",
    "grant_bearer_key_retired",
    "grant_use_out_of_scope",
    "grant_mismatch",
    "grant_capability_mismatch",
    "grant_envelope_mismatch",
    "grant_budget_exhausted",
    "grant_time_token_invalid",
    "grant_time_token_mismatch",
    "grant_time_token_regressed",
    "grant_time_token_exhausted",
    "grant_use_before_time_token",
    "grant_use_out_of_order",
    "grant_use_outside_validity",
    "grant_use_in_future",
    "grant_use_uploaded_late",
    "grant_revoked",
];

/// The refusals of an authentic use that no later attempt overcomes: the use
/// already happened, so the NA keeps it as a quarantine entry (the error
/// names its `quarantine_id`, the same on a re-upload). Not stored: secret
/// material, and a use the holder retries (`grant_use_chain_gap`, an earlier
/// use not uploaded yet; `grant_use_in_future`, until the NA's clock reaches
/// it). A quarantined use that continues the chain ([`continues_chain`]) is
/// its head, so the holder's later uses are judged on their own; a conflict
/// or a chain mismatch never continues it.
pub const QUARANTINED_USE_CODES: [&str; 18] = [
    "grant_use_conflict",
    "grant_use_chain_mismatch",
    "grant_bearer_mismatch",
    "grant_bearer_key_retired",
    "grant_use_out_of_scope",
    "grant_mismatch",
    "grant_capability_mismatch",
    "grant_envelope_mismatch",
    "grant_budget_exhausted",
    "grant_time_token_invalid",
    "grant_time_token_mismatch",
    "grant_time_token_regressed",
    "grant_time_token_exhausted",
    "grant_use_before_time_token",
    "grant_use_out_of_order",
    "grant_use_outside_validity",
    "grant_use_uploaded_late",
    "grant_revoked",
];

/// Whether a use's `use_id` is a UUID in its canonical lowercase form, as
/// the reference requires (observations match a use by it).
pub fn valid_use_id(use_id: &str) -> bool {
    let b = use_id.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

/// Why the NA refuses to issue a grant, in the order it checks
/// (`422 <code>` from `POST /admin/grants`, `error.details.problems` listing
/// them all). The SDK does not decide them: the NA does.
pub const ISSUANCE_REFUSALS: [&str; 13] = [
    "grant_basis_invalid",
    "grant_outlives_basis",
    "grant_capability_out_of_scope",
    "grant_basis_not_fresh",
    "grant_policy_resolution_failed",
    "grant_review_required",
    "grant_policy_scheduled",
    "grant_outlives_policy",
    "grant_undecidable_attributes",
    "grant_undecidable_freshness",
    "grant_undecidable_time",
    "grant_undecidable_gate_type",
    "grant_gate_may_deny",
];

// ── Numbers ──────────────────────────────────────────────────────────────────

/// Integral values below this magnitude are held as integers.
const INTEGRAL_LIMIT: f64 = 85_070_591_730_234_615_865_843_651_857_942_052_864.0; // 2^126

/// A JSON number, compared exactly: an integer (also an integral float), or
/// a float that is not one.
#[derive(Debug, Clone, Copy)]
enum Num {
    Int(i128),
    Float(f64),
}

impl Num {
    fn of(value: &Value) -> Option<Num> {
        let Value::Number(n) = value else {
            return None;
        };
        if let Some(i) = n.as_i64() {
            return Some(Num::Int(i128::from(i)));
        }
        if let Some(u) = n.as_u64() {
            return Some(Num::Int(i128::from(u)));
        }
        let x = n.as_f64()?;
        if !x.is_finite() {
            return None;
        }
        Some(if x.fract() == 0.0 && x.abs() < INTEGRAL_LIMIT {
            Num::Int(x as i128)
        } else {
            Num::Float(x)
        })
    }

    fn integral(self) -> bool {
        match self {
            Num::Int(_) => true,
            Num::Float(x) => x.fract() == 0.0,
        }
    }
}

/// `x` against the integer `n`, exactly.
fn float_against(x: f64, n: i128) -> Ordering {
    if x >= INTEGRAL_LIMIT {
        return Ordering::Greater;
    }
    if x <= -INTEGRAL_LIMIT {
        return Ordering::Less;
    }
    let floor = x.floor();
    let whole = floor as i128;
    match whole.cmp(&n) {
        Ordering::Equal if x == floor => Ordering::Equal,
        Ordering::Equal => Ordering::Greater,
        other => other,
    }
}

fn compare(a: Num, b: Num) -> Ordering {
    match (a, b) {
        (Num::Int(a), Num::Int(b)) => a.cmp(&b),
        (Num::Float(a), Num::Float(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
        (Num::Float(x), Num::Int(n)) => float_against(x, n),
        (Num::Int(n), Num::Float(x)) => float_against(x, n).reverse(),
    }
}

/// Whether two scalars are one value, type-strictly: `true` is not `1`,
/// `"1"` is not `1`, but `1` is `1.0` (the reference's `scalar_key`).
pub fn scalar_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(_), Value::Number(_)) => match (Num::of(a), Num::of(b)) {
            (Some(a), Some(b)) => compare(a, b) == Ordering::Equal,
            _ => false,
        },
        _ => false,
    }
}

fn is_scalar(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_)
    )
}

pub use crate::rules::normalize_number;

fn normalize_scalar(value: &Value) -> std::result::Result<Value, String> {
    match value {
        Value::Number(_) => normalize_number(value),
        other if is_scalar(other) => Ok(other.clone()),
        _ => Err("one_of holds scalars only".into()),
    }
}

// ── Envelopes ────────────────────────────────────────────────────────────────

fn flag(spec: &Map<String, Value>, key: &str, default: bool) -> std::result::Result<bool, String> {
    match spec.get(key) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

/// A numeric range as the reference reads it (`NumericRange`): its
/// normalized form, or why it is refused.
fn normalize_range(range: &Value) -> std::result::Result<Value, String> {
    let Value::Object(spec) = range else {
        return Err("number_range must be an object".into());
    };
    const FIELDS: [&str; 5] = [
        "number_type",
        "minimum",
        "maximum",
        "exclusive_minimum",
        "exclusive_maximum",
    ];
    if let Some(extra) = spec.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return Err(format!("number_range has an unknown field {extra}"));
    }
    let number_type = match spec.get("number_type").and_then(Value::as_str) {
        Some(t @ ("integer" | "number")) => t,
        _ => return Err("number_type must be integer or number".into()),
    };
    let bound = |key: &str| -> std::result::Result<Value, String> {
        normalize_number(spec.get(key).ok_or(format!("{key} is required"))?)
            .map_err(|e| format!("{key}: {e}"))
    };
    let (minimum, maximum) = (bound("minimum")?, bound("maximum")?);
    let exclusive_minimum = flag(spec, "exclusive_minimum", false)?;
    let exclusive_maximum = flag(spec, "exclusive_maximum", false)?;
    let normalized = json!({
        "number_type": number_type,
        "minimum": minimum,
        "maximum": maximum,
        "exclusive_minimum": exclusive_minimum,
        "exclusive_maximum": exclusive_maximum,
    });
    let integers = minimum.is_i64() || minimum.is_u64();
    let integers = integers && (maximum.is_i64() || maximum.is_u64());
    if number_type == "integer" && !integers {
        return Err("an integer range has integer bounds".into());
    }
    if range_bounds(&normalized).is_none() {
        return Err(format!("the range holds no {number_type}"));
    }
    Ok(normalized)
}

/// A range's lowest and highest values, and whether each is attained; an
/// integer range's ends are integers. `None` when it holds no value.
fn range_bounds(range: &Value) -> Option<(Num, bool, Num, bool)> {
    let low = Num::of(&range["minimum"])?;
    let high = Num::of(&range["maximum"])?;
    let exclusive_low = range["exclusive_minimum"] == true;
    let exclusive_high = range["exclusive_maximum"] == true;
    if range["number_type"] == "integer" {
        let (Num::Int(low), Num::Int(high)) = (low, high) else {
            return None;
        };
        let first = if exclusive_low { low + 1 } else { low };
        let last = if exclusive_high { high - 1 } else { high };
        return (first <= last).then_some((Num::Int(first), true, Num::Int(last), true));
    }
    match compare(low, high) {
        Ordering::Greater => None,
        Ordering::Equal if exclusive_low || exclusive_high => None,
        _ => Some((low, !exclusive_low, high, !exclusive_high)),
    }
}

/// Whether a value lies within a (normalized) range: a number, never a
/// boolean, integral for an integer range, within the bounds, exactly.
pub fn in_range(value: &Value, range: &Value) -> bool {
    let Some(v) = Num::of(value) else {
        return false;
    };
    if range["number_type"] == "integer" && !v.integral() {
        return false;
    }
    let Some((low, low_in, high, high_in)) = range_bounds(range) else {
        return false;
    };
    let above = match compare(v, low) {
        Ordering::Greater => true,
        Ordering::Equal => low_in,
        Ordering::Less => false,
    };
    let below = match compare(v, high) {
        Ordering::Less => true,
        Ordering::Equal => high_in,
        Ordering::Greater => false,
    };
    above && below
}

fn bounded_list<'a>(
    spec: &'a Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'a Vec<Value>>, String> {
    match spec.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) if (1..=MAX_LIST_VALUES).contains(&items.len()) => {
            Ok(Some(items))
        }
        Some(_) => Err(format!("{key} must list 1 to {MAX_LIST_VALUES} values")),
    }
}

/// One envelope parameter as the reference reads it (`EnvelopeParameter`):
/// its normalized form, or why it is refused. A parameter is `required`
/// (default `true`) and gives exactly one of `one_of` (a set of scalars,
/// numbers normalized, no value twice), `subset_of` (a set of strings) or
/// `number_range` (`integer` or `number`, with inclusive or exclusive
/// bounds, holding at least one value).
pub fn normalize_parameter(parameter: &Value) -> std::result::Result<Value, String> {
    let Value::Object(spec) = parameter else {
        return Err("an envelope parameter is an object".into());
    };
    const FIELDS: [&str; 4] = ["required", "one_of", "subset_of", "number_range"];
    if let Some(extra) = spec.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return Err(format!("unknown field {extra}"));
    }
    let required = flag(spec, "required", true)?;
    let one_of = match bounded_list(spec, "one_of")? {
        Some(items) => {
            let values = items
                .iter()
                .map(normalize_scalar)
                .collect::<std::result::Result<Vec<Value>, String>>()?;
            for (i, value) in values.iter().enumerate() {
                if values[..i].iter().any(|v| scalar_equal(v, value)) {
                    return Err("one_of repeats a value".into());
                }
            }
            Some(values)
        }
        None => None,
    };
    let subset_of = match bounded_list(spec, "subset_of")? {
        Some(items) => {
            if !items.iter().all(Value::is_string) {
                return Err("subset_of holds strings only".into());
            }
            for (i, value) in items.iter().enumerate() {
                if items[..i].contains(value) {
                    return Err("subset_of repeats a value".into());
                }
            }
            Some(items.clone())
        }
        None => None,
    };
    let number_range = match spec.get("number_range") {
        None | Some(Value::Null) => None,
        Some(range) => Some(normalize_range(range)?),
    };
    let given = [
        one_of.is_some(),
        subset_of.is_some(),
        number_range.is_some(),
    ];
    if given.iter().filter(|g| **g).count() != 1 {
        return Err("give exactly one of one_of, subset_of and number_range".into());
    }
    Ok(json!({
        "required": required,
        "one_of": one_of,
        "subset_of": subset_of,
        "number_range": number_range,
    }))
}

/// Whether an envelope parameter's name is one segment of
/// `request_parameters`: 1 to 64 of `A-Z a-z 0-9 _ -` (the reference's
/// pattern, whose `$` also matches before a final line feed).
pub fn valid_parameter_name(name: &str) -> bool {
    let name = name.strip_suffix('\n').unwrap_or(name);
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Why a whole envelope (a map of parameter names to parameters) is refused,
/// or `None`.
pub fn envelope_form_problem(envelope: &Value) -> Option<String> {
    let Value::Object(parameters) = envelope else {
        return Some("parameter_envelope must be an object".into());
    };
    if parameters.len() > MAX_ENVELOPE_PARAMETERS {
        return Some(format!(
            "at most {MAX_ENVELOPE_PARAMETERS} envelope parameters"
        ));
    }
    parameters.iter().find_map(|(name, spec)| {
        if !valid_parameter_name(name) {
            return Some("envelope parameter names match [A-Za-z0-9_-]{1,64}".into());
        }
        normalize_parameter(spec)
            .err()
            .map(|e| format!("parameter_envelope.{name}: {e}"))
    })
}

/// Why one parameter value is outside its (normalized) envelope parameter,
/// or `None`.
pub fn parameter_value_problem(name: &str, value: &Value, parameter: &Value) -> Option<String> {
    if let Some(values) = parameter["one_of"].as_array() {
        if !is_scalar(value) {
            return Some(format!("request_parameters.{name} is not a scalar"));
        }
        return (!values.iter().any(|v| scalar_equal(v, value)))
            .then(|| format!("request_parameters.{name} is not one of its values"));
    }
    if let Some(allowed) = parameter["subset_of"].as_array() {
        let Some(items) = value.as_array().filter(|i| i.iter().all(Value::is_string)) else {
            return Some(format!(
                "request_parameters.{name} is not a list of strings"
            ));
        };
        return (!items.iter().all(|item| allowed.contains(item)))
            .then(|| format!("request_parameters.{name} has an item outside its set"));
    }
    (!in_range(value, &parameter["number_range"]))
        .then(|| format!("request_parameters.{name} is outside its range"))
}

/// Why a use's `request_parameters` are outside a grant's closed envelope,
/// or `None` (`grant_envelope_mismatch` otherwise). The envelope is closed: a
/// parameter it does not name is refused; a required parameter must be
/// present; a present one must be inside its parameter. Parameters are read
/// as the reference reads them ([`normalize_parameter`]); an envelope that
/// does not read is a problem itself.
pub fn envelope_problem(envelope: &Value, request_parameters: &Value) -> Option<String> {
    let Some(parameters) = request_parameters.as_object() else {
        return Some("request_parameters is not an object".into());
    };
    let Some(envelope) = envelope.as_object() else {
        return Some("the grant's envelope is not an object".into());
    };
    let mut outside: Vec<&String> = parameters
        .keys()
        .filter(|k| !envelope.contains_key(*k))
        .collect();
    outside.sort();
    if let Some(first) = outside.first() {
        return Some(format!("request_parameters.{first} is not in the envelope"));
    }
    let mut names: Vec<&String> = envelope.keys().collect();
    names.sort();
    for name in names {
        let parameter = match normalize_parameter(&envelope[name]) {
            Ok(parameter) => parameter,
            Err(e) => return Some(format!("the envelope's {name} does not read: {e}")),
        };
        match parameters.get(name) {
            None if parameter["required"] == true => {
                return Some(format!("request_parameters.{name} is required"))
            }
            None => continue,
            Some(value) => {
                if let Some(problem) = parameter_value_problem(name, value, &parameter) {
                    return Some(problem);
                }
            }
        }
    }
    None
}

// ── Signatures and digests ───────────────────────────────────────────────────

/// Whether a signature on `record` verifies, under one of `keys`, over its
/// signed form as received (the reference's `signed_as_received`): nothing
/// unknown is dropped, so a field this crate does not know still verifies
/// here (and is refused by name elsewhere).
pub fn signed_as_received(model: &str, record: &Value, keys: &[String]) -> bool {
    let spec = crate::strict::model_spec(model);
    let Ok(canonical) = received_canonical(model, record) else {
        return false;
    };
    let field = spec["signature_field"].as_str().unwrap_or("signature");
    let signatures: Vec<&Value> = match record.get(field) {
        Some(Value::Array(items)) if field == "signatures" => items.iter().collect(),
        Some(sig @ Value::Object(_)) if field != "signatures" => vec![sig],
        _ => Vec::new(),
    };
    signatures.iter().any(|sig| {
        sig.get("sig")
            .and_then(Value::as_str)
            .is_some_and(|sig| verify_canonical(&canonical, sig, keys))
    })
}

/// SHA-256 of a record's signed form as received, unknown fields set aside
/// (the reference's `_received_digest`): what a use chain and a resource
/// chain link to, and a use's `grant_digest`; equal to the reference's
/// `digest()` for a record in the form it writes.
pub fn received_digest(model: &str, record: &Value) -> Result<String> {
    let known = without_unknown_fields(model, record);
    Ok(sha256_hex(received_canonical(model, &known)?.as_bytes()))
}

/// [`received_digest`] of a `CapabilityGrant`: the `grant_digest` its uses
/// and revocation name.
pub fn grant_digest(grant: &Value) -> Result<String> {
    received_digest("CapabilityGrant", grant)
}

/// [`received_digest`] of a `GrantExecutionEvidence`: what the next use
/// names as `prev_use_digest`, a time token names as `use_head_digest`, and
/// (once the NA placed it) the next record of its resource links to.
pub fn use_digest(use_record: &Value) -> Result<String> {
    received_digest("GrantExecutionEvidence", use_record)
}

/// Whether a time token, as received (inside a use or alone), carries a
/// signature by one of `keys` (the NA's keys valid at its `issued_at`).
pub fn token_signature_valid(raw_token: &Value, keys: &[String]) -> bool {
    raw_token.is_object() && signed_as_received("TimeToken", raw_token, keys)
}

// ── Uses ─────────────────────────────────────────────────────────────────────

/// The last admitted use of the grant before this one, as the NA or a
/// verifier holds it: the order and time rules compare a use with it (never
/// with a quarantined use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousUse {
    /// When it was executed.
    pub executed_at: DateTime<Utc>,
    /// Its time token's `issued_at`.
    pub time_token_issued_at: DateTime<Utc>,
}

/// Whether a use continues a grant's use chain whose head is
/// `(use_sequence, digest)` (`(0, None)` before the first use): the head is
/// the last use the chain holds, admitted, or quarantined after it continued
/// the chain.
pub fn continues_chain(use_record: &Value, head: (u64, Option<&str>)) -> bool {
    use_record["use_sequence"].as_u64() == Some(head.0 + 1)
        && use_record.get("prev_use_digest").and_then(Value::as_str) == head.1
}

/// What a use is checked against, as the caller holds it
/// ([`use_problem`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct UseContext<'a> {
    /// The grant; `None` skips the checks that need it (capability,
    /// envelope, budget, per-token limit, validity, late upload).
    pub grant: Option<&'a Value>,
    /// The last admitted use before it; `None` for none or when it is not
    /// held.
    pub previous: Option<&'a PreviousUse>,
    /// How many uses of the grant were admitted before it; `None` when the
    /// caller does not hold the chain from its first use (the budget is then
    /// not checked).
    pub admitted: Option<u64>,
    /// The digest and time of the use the time token names (admitted or
    /// quarantined), when held.
    pub token_head: Option<(&'a str, DateTime<Utc>)>,
    /// The NA keys valid at the time token's `issued_at`.
    pub token_keys: &'a [String],
    /// When the grant was revoked, by a revocation recorded before the use.
    pub revoked_at: Option<DateTime<Utc>>,
    /// The use's time in the store; `None` before it is stored.
    pub recorded_at: Option<DateTime<Utc>>,
}

fn time(record: &Value, key: &str) -> i64 {
    record
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| micros(s).ok())
        .unwrap_or_default()
}

fn iso(at: i64) -> String {
    DateTime::from_timestamp_micros(at)
        .map(python_timestamp)
        .unwrap_or_default()
}

const SKEW_MICROS: i64 = GRANT_CLOCK_SKEW_SECONDS * 1_000_000;

/// `(code, detail)` for the first rule a well-formed use breaks, or `None`
/// (the reference's `use_problem`, in its order). Run after the use's
/// signature, bearer key, grant digest and chain position are checked; the
/// NA and an export verifier run it with what each holds:
///
/// 1. with the grant: its capability (`grant_capability_mismatch`), the
///    envelope (`grant_envelope_mismatch`), the budget over the admitted uses
///    (`grant_budget_exhausted`);
/// 2. the time token is the NA's for this grant, not older than the grant
///    (`grant_time_token_invalid`), issued before this use
///    (`grant_time_token_mismatch`), naming the use the store holds at that
///    position, dated at most 300 s after it (`grant_time_token_mismatch`);
/// 3. no older token than the last admitted use's
///    (`grant_time_token_regressed`), and at most `max_uses_per_time_token`
///    uses after the use the token names (`grant_time_token_exhausted`);
/// 4. dated no more than 300 s before its token
///    (`grant_use_before_time_token`), not before the last admitted use
///    (`grant_use_out_of_order`), within the grant's validity
///    (`grant_use_outside_validity`);
/// 5. once recorded: not dated more than 300 s after it
///    (`grant_use_in_future`), nor uploaded later than the grant's validity
///    after it (`grant_use_uploaded_late`);
/// 6. not dated at or after the grant's revocation (`grant_revoked`).
pub fn use_problem(use_record: &Value, context: &UseContext<'_>) -> Option<(&'static str, String)> {
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let number = |value: &Value, key: &str| value.get(key).and_then(Value::as_u64).unwrap_or(0);
    let token = &use_record["time_token"];
    let sequence = number(use_record, "use_sequence");
    let executed = time(use_record, "executed_at");
    let capability = text(use_record, "capability").unwrap_or_default();
    if let Some(grant) = context.grant {
        let named = grant["capabilities"]
            .as_array()
            .is_some_and(|c| c.iter().any(|c| c.as_str() == Some(capability.as_str())));
        if !named {
            return Some((
                "grant_capability_mismatch",
                format!("{capability} is not one of the grant's capabilities"),
            ));
        }
        if let Some(problem) = envelope_problem(
            &grant["parameter_envelope"],
            &use_record["request_parameters"],
        ) {
            return Some(("grant_envelope_mismatch", problem));
        }
        let budget = number(grant, "max_uses");
        if let Some(admitted) = context.admitted.filter(|admitted| *admitted >= budget) {
            return Some((
                "grant_budget_exhausted",
                format!("{admitted} uses admitted of a budget of {budget}"),
            ));
        }
    }
    let token_issued = time(token, "issued_at");
    if text(token, "grant_id") != text(use_record, "grant_id")
        || !token_signature_valid(token, context.token_keys)
        || context
            .grant
            .is_some_and(|grant| token_issued < time(grant, "issued_at"))
    {
        return Some((
            "grant_time_token_invalid",
            "the time token is not the NA's for this grant".into(),
        ));
    }
    let token_sequence = number(token, "use_sequence");
    if token_sequence >= sequence {
        return Some((
            "grant_time_token_mismatch",
            format!(
                "the time token was issued after use {token_sequence}, not before use {sequence}"
            ),
        ));
    }
    if let Some((digest, at)) = context.token_head {
        if Some(digest) != token.get("use_head_digest").and_then(Value::as_str)
            || at.timestamp_micros() > token_issued + SKEW_MICROS
        {
            return Some((
                "grant_time_token_mismatch",
                format!("use {token_sequence} is not the one the time token names"),
            ));
        }
    }
    if context
        .previous
        .is_some_and(|p| token_issued < p.time_token_issued_at.timestamp_micros())
    {
        return Some((
            "grant_time_token_regressed",
            "the time token is older than the previous use's".into(),
        ));
    }
    if let Some(grant) = context.grant {
        // Stateless: at most this many uses follow the use the token names.
        let limit = number(grant, "max_uses_per_time_token");
        if sequence.saturating_sub(token_sequence) > limit {
            return Some((
                "grant_time_token_exhausted",
                format!(
                    "use {sequence} is more than {limit} uses after the time token's {token_sequence}"
                ),
            ));
        }
    }
    if executed < token_issued - SKEW_MICROS {
        return Some((
            "grant_use_before_time_token",
            format!(
                "executed at {}, more than {GRANT_CLOCK_SKEW_SECONDS} s before the time token's {}",
                iso(executed),
                iso(token_issued)
            ),
        ));
    }
    if context
        .previous
        .is_some_and(|p| executed < p.executed_at.timestamp_micros())
    {
        return Some((
            "grant_use_out_of_order",
            format!("executed at {}, before the previous use", iso(executed)),
        ));
    }
    let validity = context.grant.map(|g| {
        let (from, until) = (time(g, "valid_from"), time(g, "valid_until"));
        (from, until, until - from)
    });
    if let Some((from, until, _)) = validity {
        if !(from <= executed && executed <= until) {
            return Some((
                "grant_use_outside_validity",
                format!(
                    "executed at {}, outside [{}, {}]",
                    iso(executed),
                    iso(from),
                    iso(until)
                ),
            ));
        }
    }
    if let Some(recorded) = context.recorded_at.map(|r| r.timestamp_micros()) {
        if executed > recorded + SKEW_MICROS {
            return Some((
                "grant_use_in_future",
                format!(
                    "executed at {}, after it was recorded at {}",
                    iso(executed),
                    iso(recorded)
                ),
            ));
        }
        if let Some((_, _, length)) = validity {
            if recorded - executed > length {
                return Some((
                    "grant_use_uploaded_late",
                    format!(
                        "recorded at {}, longer after it was executed than the grant's validity \
                         ({} s)",
                        iso(recorded),
                        length / 1_000_000
                    ),
                ));
            }
        }
    }
    if let Some(revoked) = context.revoked_at.map(|r| r.timestamp_micros()) {
        if executed >= revoked {
            return Some((
                "grant_revoked",
                format!("the grant was revoked at {}", iso(revoked)),
            ));
        }
    }
    None
}

/// What the next use is checked against once this one is admitted.
pub fn next_previous(use_record: &Value) -> PreviousUse {
    let at = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| parse_timestamp(s).ok())
            .unwrap_or_default()
    };
    PreviousUse {
        executed_at: at(use_record, "executed_at"),
        time_token_issued_at: at(&use_record["time_token"], "issued_at"),
    }
}

/// Why a use may carry secret material, or `None`: the metadata guard over
/// its `execution_parameters`, `request_parameters` and `outcome_detail`
/// (absent: `""`), as the NA applies it (`grant_use_secret_material`; such a
/// use is never stored).
pub fn use_secret_problem(use_record: &Value) -> Option<String> {
    let object = |key: &str| {
        use_record
            .get(key)
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| json!({}))
    };
    let detail = use_record
        .get("outcome_detail")
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or_else(|| json!(""));
    let execution = object("execution_parameters");
    let request = object("request_parameters");
    crate::out_of_band::metadata_problem(&[
        ("execution_parameters", &execution),
        ("request_parameters", &request),
        ("outcome_detail", &detail),
    ])
}

/// The last time a use of the grant may still be admitted: its end, plus
/// the late-upload window (its validity), plus the clock skew.
pub fn grant_horizon(grant: &Value) -> Option<DateTime<Utc>> {
    let (from, until) = (time(grant, "valid_from"), time(grant, "valid_until"));
    DateTime::from_timestamp_micros(until + (until - from) + SKEW_MICROS)
}

// ── Signing (the bearer key's records) ───────────────────────────────────────

/// One use of a grant, as
/// [`ExecutionRecorder::sign_grant_use`](crate::ExecutionRecorder::sign_grant_use)
/// signs it with the grant's bearer key.
#[derive(Debug, Clone)]
pub struct GrantUseInput {
    /// The grant: its `grant_id` and digest are recorded.
    pub grant: Value,
    /// The latest time token the holder holds for the grant, as the NA
    /// signed it.
    pub time_token: Value,
    /// The use's place in the grant's chain, from 1.
    pub use_sequence: u64,
    /// The previous use's digest ([`use_digest`]); `None` for the first.
    pub prev_use_digest: Option<String>,
    /// The capability used, one of the grant's.
    pub capability: String,
    /// The request's parameters, inside the grant's envelope. Defaults to
    /// `{}`.
    pub request_parameters: Option<Value>,
    /// The resource acted on; with `resource_action`.
    pub resource_id: Option<String>,
    /// `create`, `rotate`, `revoke`, `update` or `delete`.
    pub resource_action: Option<String>,
    /// Defaults to now.
    pub executed_at: Option<DateTime<Utc>>,
    /// `success` (the default), `failure` or `partial`.
    pub outcome: Option<String>,
    /// Short outcome detail, at most 1024 characters.
    pub outcome_detail: Option<String>,
    /// Identifiers and versions only. Defaults to `{}`.
    pub execution_parameters: Option<Value>,
    /// Defaults to a random UUID; a UUID in its canonical lowercase form.
    pub use_id: Option<String>,
}

impl GrantUseInput {
    /// A use of `grant` under `time_token`, at `use_sequence` after
    /// `prev_use_digest`, of `capability`; the rest defaults.
    pub fn new(
        grant: Value,
        time_token: Value,
        use_sequence: u64,
        prev_use_digest: Option<String>,
        capability: impl Into<String>,
    ) -> Self {
        Self {
            grant,
            time_token,
            use_sequence,
            prev_use_digest,
            capability: capability.into(),
            request_parameters: None,
            resource_id: None,
            resource_action: None,
            executed_at: None,
            outcome: None,
            outcome_detail: None,
            execution_parameters: None,
            use_id: None,
        }
    }
}

fn object_or_empty(value: Option<Value>, name: &str) -> Result<Value> {
    let value = value.unwrap_or_else(|| json!({}));
    if value.is_object() {
        Ok(value)
    } else {
        Err(crate::out_of_band::refused(
            "grant_use_malformed",
            format!("{name} must be a JSON object"),
        ))
    }
}

/// Sign a record's signed form as received under `model` and add the
/// signature, unless no reader would take it.
fn sign_as(
    model: &str,
    mut record: Value,
    key_id: &str,
    key: &ed25519_dalek::SigningKey,
) -> Result<Value> {
    crate::out_of_band::check_nesting(&record)?;
    let canonical = received_canonical(model, &record)?;
    record["signature"] = crate::auth::sign_canonical(&canonical, key_id, key);
    Ok(record)
}

/// Build and sign a use with the bearer key.
pub(crate) fn sign_grant_use(
    executor_sovereign_id: &str,
    key_id: &str,
    key: &ed25519_dalek::SigningKey,
    input: GrantUseInput,
) -> Result<Value> {
    use crate::out_of_band::{action_problem, length_problem, refused, time_problem};
    let executed_at = input.executed_at.unwrap_or_else(Utc::now);
    let outcome = input.outcome.unwrap_or_else(|| "success".into());
    let grant_id = input.grant["grant_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let sequence_ok = (1..=GRANT_MAX_USES).contains(&input.use_sequence);
    let chain_ok = (input.use_sequence == 1) == input.prev_use_digest.is_none();
    let problem = [
        (!sequence_ok).then(|| format!("use_sequence must be 1 to {GRANT_MAX_USES}")),
        (!chain_ok).then(|| "prev_use_digest is given exactly from the second use on".into()),
        length_problem("grant_id", &grant_id, 1, 128),
        length_problem("executor_sovereign_id", executor_sovereign_id, 1, 256),
        length_problem("capability", &input.capability, 1, 256),
        (input.resource_id.is_some() != input.resource_action.is_some())
            .then(|| "resource_id and resource_action go together".into()),
        input
            .resource_id
            .as_deref()
            .and_then(|id| length_problem("resource_id", id, 1, 256)),
        input
            .resource_action
            .as_deref()
            .and_then(|action| action_problem("resource_action", action)),
        (!USE_OUTCOMES.contains(&outcome.as_str()))
            .then(|| format!("outcome must be success, failure or partial, not {outcome:?}")),
        input
            .outcome_detail
            .as_deref()
            .and_then(|detail| length_problem("outcome_detail", detail, 0, 1024)),
        time_problem("executed_at", Some(executed_at)),
        (!input.time_token.is_object()).then(|| "time_token must be the NA's token".into()),
        input
            .use_id
            .as_deref()
            .filter(|id| !valid_use_id(id))
            .map(|_| "use_id must be a UUID in its canonical lowercase form".into()),
    ]
    .into_iter()
    .flatten()
    .next();
    if let Some(problem) = problem {
        return Err(refused("grant_use_malformed", problem));
    }
    let request_parameters = object_or_empty(input.request_parameters, "request_parameters")?;
    let execution_parameters = object_or_empty(input.execution_parameters, "execution_parameters")?;
    let mut record = Map::new();
    record.insert(
        "use_id".into(),
        json!(input
            .use_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
    );
    record.insert("grant_id".into(), json!(grant_id));
    record.insert("grant_digest".into(), json!(grant_digest(&input.grant)?));
    record.insert("use_sequence".into(), json!(input.use_sequence));
    if let Some(prev) = input.prev_use_digest {
        record.insert("prev_use_digest".into(), json!(prev));
    }
    record.insert("executor_sovereign_id".into(), json!(executor_sovereign_id));
    record.insert("capability".into(), json!(input.capability));
    record.insert("request_parameters".into(), request_parameters);
    if let (Some(id), Some(action)) = (input.resource_id, input.resource_action) {
        record.insert("resource_id".into(), json!(id));
        record.insert("resource_action".into(), json!(action));
    }
    record.insert("executed_at".into(), json!(python_timestamp(executed_at)));
    record.insert("time_token".into(), input.time_token);
    record.insert("outcome".into(), json!(outcome));
    if let Some(detail) = input.outcome_detail {
        record.insert("outcome_detail".into(), json!(detail));
    }
    record.insert("execution_parameters".into(), execution_parameters);
    let record = Value::Object(record);
    // The NA refuses a use carrying secret material and never stores it:
    // it is refused before it is signed.
    if let Some(secret) = use_secret_problem(&record) {
        return Err(refused("grant_use_secret_material", secret));
    }
    sign_as("GrantExecutionEvidence", record, key_id, key)
}

/// Build and sign a time token request with the bearer key.
pub(crate) fn sign_time_token_request(
    key_id: &str,
    key: &ed25519_dalek::SigningKey,
    grant_id: &str,
    use_sequence: u64,
    use_head_digest: Option<&str>,
    requested_at: DateTime<Utc>,
) -> Result<Value> {
    use crate::out_of_band::{length_problem, refused};
    let problem = length_problem("grant_id", grant_id, 1, 128)
        .or_else(|| {
            (use_sequence > GRANT_MAX_USES)
                .then(|| format!("use_sequence must be 0 to {GRANT_MAX_USES}"))
        })
        .or_else(|| {
            ((use_sequence == 0) != use_head_digest.is_none())
                .then(|| "use_head_digest is given exactly when use_sequence is 1 or more".into())
        });
    if let Some(problem) = problem {
        return Err(refused("time_token_request_malformed", problem));
    }
    let mut record = Map::new();
    record.insert("grant_id".into(), json!(grant_id));
    record.insert("use_sequence".into(), json!(use_sequence));
    if let Some(head) = use_head_digest {
        record.insert("use_head_digest".into(), json!(head));
    }
    record.insert("requested_at".into(), json!(python_timestamp(requested_at)));
    sign_as("TimeTokenRequest", Value::Object(record), key_id, key)
}
