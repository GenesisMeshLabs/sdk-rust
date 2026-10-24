//! The Network Authority's key history (1.5.0): the genesis block and the key
//! successions after it, verified from the root key the verifier holds, and
//! which NA key is valid when. A direct port of the Python reference
//! (`trust/key_succession.py`, `models/key_succession.py`), with its reason
//! codes.
//!
//! A `KeySuccessionRecord` names the NA's next key, signed by the root key
//! (kept offline), by the new key (proof that it is held) and by the outgoing
//! NA key. Keys inside the records prove nothing alone: the history
//! is accepted only from the root key down, and nothing after the first
//! refused record is accepted.
//!
//! Each key is valid over a window ([`NaKey::accepts`]):
//!
//! * the genesis key from the start until the first succession takes effect
//!   (its `valid_to` is shown, not enforced: deployments before 1.5.0 wrote
//!   one 90 days out);
//! * a key a succession named from its `effective_at` until the next
//!   succession takes effect, and never at or after its own `new_valid_to`;
//! * a succeeded key stays valid for records dated up to
//!   [`SUCCESSION_HANDOVER_SECONDS`] after the next key took effect.
//!
//! An NA signature is accepted when it verifies with a key valid at the
//! record's own time; a signature by another key of the history is
//! `na_key_not_valid_at_time`. Pure functions; no network.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    auth::verify_canonical,
    canonical::{
        key_succession_canonical, key_succession_digest, micros, parse_timestamp, python_timestamp,
        received_canonical,
    },
    strict::{non_canonical_fields, unknown_fields, without_unknown_fields},
};

/// How long after a succession takes effect the outgoing key is still
/// accepted, in seconds: NA instances' clocks differ, and an entry signed
/// just before the hand-over may be stored just after it.
pub const SUCCESSION_HANDOVER_SECONDS: i64 = 300;

const HANDOVER_MICROS: i64 = SUCCESSION_HANDOVER_SECONDS * 1_000_000;

/// A succession takes effect at least this long, in seconds, after the store
/// records it (1.5.0 review fixes; `succession_backdated` otherwise).
pub const SUCCESSION_MIN_LEAD_SECONDS: i64 = 60;

/// The longest lifetime of a decision the NA issues, in seconds (1.5.0
/// review fixes): a decision signed by a key with an end stays valid no
/// longer than that end, the hand-over and this lifetime
/// (`decision_outlives_key`).
pub const MAX_DECISION_LIFETIME_SECONDS: i64 = 300;

/// The vouching horizon's grace (1.8.0, seconds): how long past its end and
/// the hand-over a record of a key that has ended still vouches for the
/// present. Also the most a verifier allows: see [`vouching_grace`].
pub const SUCCESSION_VOUCHING_GRACE_SECONDS: i64 = 86_400;

/// The grace a verifier uses (1.8.0, seconds), given the NA's published
/// `vouching_grace_seconds` (`GET /na/key-history`). The value is unsigned,
/// so it may only shorten the grace: it is clamped to 0 to
/// [`SUCCESSION_VOUCHING_GRACE_SECONDS`], and `None` is the most. A
/// verifier that sets its own grace takes the smaller of the two.
pub fn vouching_grace(published: Option<i64>) -> i64 {
    published.map_or(SUCCESSION_VOUCHING_GRACE_SECONDS, |s| {
        s.clamp(0, SUCCESSION_VOUCHING_GRACE_SECONDS)
    })
}

/// The time an NA-signed record read on its own (outside the store) is
/// placed at in the key history, by model: the reference's
/// `NA_RECORD_TIME_FIELDS` (1.5.0 review fixes). In the store every entry is
/// placed at its `recorded_at`.
pub const NA_RECORD_TIME_FIELDS: [(&str, &str); 16] = [
    ("ArchiveRecord", "archived_at"),
    ("AuditPackManifest", "created_at"),
    ("BoundaryDecision", "decision_made_at"),
    ("BoundaryPolicy", "issued_at"),
    // v1.6.0: a grant, its revocation, and a time token (read alone, or
    // nested in a use).
    ("CapabilityGrant", "issued_at"),
    ("GrantRevocationRecord", "revoked_at"),
    ("JudgementRecord", "judged_at"),
    ("JustificationProof", "proof_issued_at"),
    ("MembershipAttestation", "issued_at"),
    ("QuarantineRecord", "quarantined_at"),
    ("RecognitionTreaty", "issued_at"),
    ("RegistryRecord", "effective_at"),
    ("RetentionCheckpoint", "created_at"),
    ("ReviewRecord", "decided_at"),
    ("StoreAnchor", "anchored_at"),
    ("TimeToken", "issued_at"),
];

/// The field an NA-signed record of `model` is placed at when read alone.
pub fn na_record_time_field(model: &str) -> Option<&'static str> {
    NA_RECORD_TIME_FIELDS
        .iter()
        .find(|(m, _)| *m == model)
        .map(|(_, field)| *field)
}

/// One key of the NA's history and the times it is valid at (microseconds
/// since the epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaKey {
    /// Its position in the history; the genesis key is 1.
    pub key_sequence: i64,
    /// Base64 Ed25519 public key.
    pub public_key: String,
    /// Its key ID, when the history names it.
    pub key_id: Option<String>,
    /// `None` for the genesis key: valid from the start of the network.
    pub valid_from: Option<i64>,
    /// The next succession's `effective_at`; `None` while the key is current.
    pub succeeded_at: Option<i64>,
    /// The declared end of validity (the genesis block's, or a succession's
    /// `new_valid_to`).
    pub valid_to: Option<i64>,
    /// `false` for the genesis key.
    pub valid_to_enforced: bool,
}

impl NaKey {
    /// True when a record dated `at` may carry this key's signature (with
    /// the hand-over).
    pub fn accepts(&self, at: i64) -> bool {
        !(self.valid_from.is_some_and(|from| at < from)
            || self
                .succeeded_at
                .is_some_and(|succeeded| at >= succeeded + HANDOVER_MICROS)
            || (self.valid_to_enforced && self.valid_to.is_some_and(|to| at >= to)))
    }

    /// The key's end (1.8.0): the earlier of its succession and its enforced
    /// `valid_to`; `None` for a key with neither.
    pub fn end(&self) -> Option<i64> {
        [
            self.succeeded_at,
            self.valid_to.filter(|_| self.valid_to_enforced),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// True when the NA may sign with this key at `at` (no hand-over).
    pub fn signs_at(&self, at: i64) -> bool {
        !(self.valid_from.is_some_and(|from| at < from)
            || self.succeeded_at.is_some_and(|succeeded| at >= succeeded)
            || (self.valid_to_enforced && self.valid_to.is_some_and(|to| at >= to)))
    }

    /// The reference's `NAKey.to_dict()`.
    pub fn to_json(&self) -> Value {
        let iso = |at: Option<i64>| {
            at.and_then(chrono::DateTime::from_timestamp_micros)
                .map(python_timestamp)
        };
        json!({
            "key_sequence": self.key_sequence,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "valid_from": iso(self.valid_from),
            "succeeded_at": iso(self.succeeded_at),
            "valid_to": iso(self.valid_to),
            "valid_to_enforced": self.valid_to_enforced,
        })
    }
}

/// The NA's keys in order, from a verified genesis block and successions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaKeyHistory {
    /// The genesis block's `network_name`.
    pub sovereign_id: String,
    /// The root key the history was verified from.
    pub root_public_key: Option<String>,
    /// Every key, the genesis key first.
    pub keys: Vec<NaKey>,
    /// The digest of each accepted succession, in order.
    pub succession_digests: Vec<String>,
}

impl NaKeyHistory {
    /// Every public key of the history.
    pub fn all_keys(&self) -> Vec<String> {
        self.keys.iter().map(|k| k.public_key.clone()).collect()
    }

    /// The public keys a record dated `at` (microseconds) may be signed with.
    pub fn keys_at(&self, at: i64) -> Vec<String> {
        self.keys
            .iter()
            .filter(|k| k.accepts(at))
            .map(|k| k.public_key.clone())
            .collect()
    }

    /// The key of the history with this public key.
    pub fn key_for(&self, public_key: &str) -> Option<&NaKey> {
        self.keys.iter().find(|k| k.public_key == public_key)
    }

    /// True when a decision signed by `public_key` stays valid
    /// (`valid_until`, microseconds) past what that key may vouch for (1.5.0
    /// review fixes): the key's end (its succession, or its enforced
    /// `valid_to`), the hand-over and [`MAX_DECISION_LIFETIME_SECONDS`].
    pub fn decision_outlives_key(&self, public_key: &str, valid_until: i64) -> bool {
        self.key_for(public_key)
            .and_then(NaKey::end)
            .is_some_and(|end| {
                valid_until > end + HANDOVER_MICROS + MAX_DECISION_LIFETIME_SECONDS * 1_000_000
            })
    }

    /// Until when a record signed by `public_key` vouches for the present
    /// (1.8.0, microseconds): its key's end, the hand-over and the grace
    /// (`grace_seconds`, from [`vouching_grace`]). `None` for a key with no
    /// end, or not in this history.
    pub fn vouches_until(&self, public_key: &str, grace_seconds: i64) -> Option<i64> {
        let end = self.key_for(public_key)?.end()?;
        Some(end + HANDOVER_MICROS + grace_seconds.max(0) * 1_000_000)
    }

    /// True when a record signed by `public_key` no longer vouches for the
    /// present at `now` (1.8.0, microseconds): its key ended more than the
    /// hand-over and the grace ago.
    pub fn record_outlives_key(&self, public_key: &str, now: i64, grace_seconds: i64) -> bool {
        self.vouches_until(public_key, grace_seconds)
            .is_some_and(|until| now >= until)
    }

    /// The public keys a record dated `at` may be signed with and that still
    /// vouch at `now` (1.8.0): [`NaKeyHistory::keys_at`] without the keys
    /// whose horizon has passed.
    pub fn keys_vouching_at(&self, at: i64, now: i64, grace_seconds: i64) -> Vec<String> {
        self.keys_at(at)
            .into_iter()
            .filter(|k| !self.record_outlives_key(k, now, grace_seconds))
            .collect()
    }

    /// The key the NA signs with at `at` (`None` in a gap after an enforced
    /// expiry).
    pub fn signing_key_at(&self, at: i64) -> Option<&NaKey> {
        self.keys.iter().find(|k| k.signs_at(at))
    }
}

/// One refused record of a key history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyHistoryFailure {
    /// The refused key's position (1 for the genesis block).
    pub key_sequence: Option<i64>,
    /// Reason code, identical to the Python reference.
    pub reason: String,
    /// Extra context.
    pub detail: String,
}

/// Outcome of [`verify_key_history`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHistoryVerification {
    /// No failure.
    pub verified: bool,
    /// The history, when it verified.
    pub history: Option<NaKeyHistory>,
    /// The failure that stopped it (at most one: nothing after it is read).
    pub failures: Vec<KeyHistoryFailure>,
}

impl KeyHistoryVerification {
    /// The reference's JSON form: `verified`, `failures` and, when it
    /// verified, `keys`.
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "verified": self.verified,
            "failures": self.failures,
        });
        if let Some(history) = &self.history {
            out["keys"] = Value::Array(history.keys.iter().map(NaKey::to_json).collect());
        }
        out
    }
}

/// True when `value` is a base64 Ed25519 public key (32 bytes).
pub fn valid_public_key(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|s| STANDARD.decode(s).ok())
        .is_some_and(|bytes| bytes.len() == 32)
}

fn text(value: &Value, min: usize, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| (min..=max).contains(&s.chars().count()))
}

fn timestamp(value: &Value) -> bool {
    value.as_str().is_some_and(|s| parse_timestamp(s).is_ok())
}

/// A UTC timestamp, as the reference's models require.
fn utc_timestamp(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        parse_timestamp(s).is_ok()
            && (s.ends_with('Z') || s.ends_with("+00:00") || s.ends_with("-00:00"))
    })
}

fn signatures(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => items.iter().all(|s| {
            s.get("key_id").is_some_and(Value::is_string)
                && s.get("sig").is_some_and(Value::is_string)
        }),
        Some(_) => false,
    }
}

/// Whether `raw` reads as a `GenesisBlock` (unknown fields are ignored, as
/// the reference ignores them).
fn valid_genesis(raw: &Value) -> bool {
    let strings = |v: Option<&Value>| match v {
        None | Some(Value::Null) => true,
        Some(Value::Array(items)) => items.iter().all(Value::is_string),
        Some(_) => false,
    };
    let na = &raw["network_authority"];
    let manifest = &raw["policy_manifest"];
    raw["network_name"].is_string()
        && raw["network_version"].is_string()
        && raw["root_public_key"].is_string()
        && na["public_key"].is_string()
        && timestamp(&na["valid_from"])
        && timestamp(&na["valid_to"])
        && manifest["hash"].is_string()
        && (manifest["url"].is_null() || manifest["url"].is_string())
        && strings(raw.get("allowed_crypto_suites"))
        && strings(raw.get("allowed_transports"))
        && match raw.get("bootstrap_anchors") {
            None | Some(Value::Null) => true,
            Some(Value::Array(items)) => items
                .iter()
                .all(|a| a["id"].is_string() && a["endpoint"].is_string()),
            Some(_) => false,
        }
        && signatures(raw.get("signatures"))
}

/// Whether `raw` reads as a `KeySuccessionRecord` (its unknown fields are
/// refused before this).
pub(crate) fn valid_succession_record(raw: &Value) -> bool {
    raw.is_object() && valid_succession(raw)
}

fn valid_succession(raw: &Value) -> bool {
    raw.get("succession_id").is_none_or(|v| text(v, 1, 128))
        && text(&raw["sovereign_id"], 1, 256)
        && raw["key_sequence"]
            .as_i64()
            .is_some_and(|n| (2..=9_007_199_254_740_991).contains(&n))
        && text(&raw["previous_key_id"], 1, 128)
        && text(&raw["previous_public_key"], 1, 128)
        && (raw["previous_succession_digest"].is_null()
            || text(&raw["previous_succession_digest"], 64, 64))
        && text(&raw["new_key_id"], 1, 128)
        && text(&raw["new_public_key"], 1, 128)
        && utc_timestamp(&raw["effective_at"])
        && utc_timestamp(&raw["new_valid_to"])
        && utc_timestamp(&raw["issued_at"])
        && signatures(raw.get("signatures"))
}

/// The signature values a record carries in its `signatures` list.
fn signature_values(raw: &Value) -> Vec<&str> {
    raw["signatures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.get("sig").and_then(Value::as_str))
        .collect()
}

/// True when one of a key succession's signatures verifies, over its signed
/// form as received, with one of `keys`.
pub fn succession_signed_by(raw: &Value, keys: &[String]) -> bool {
    let Ok(body) = key_succession_canonical(raw) else {
        return false;
    };
    signature_values(raw)
        .into_iter()
        .any(|sig| verify_canonical(&body, sig, keys))
}

fn genesis_signed_by(raw: &Value, key: &str) -> bool {
    let Ok(body) = received_canonical("GenesisBlock", raw) else {
        return false;
    };
    signature_values(raw)
        .into_iter()
        .any(|sig| verify_canonical(&body, sig, &[key.to_owned()]))
}

/// The reference's `strict_refusal` for a key succession: `None` when it has
/// no unknown field and is in canonical form; otherwise `unknown_field` or
/// `non_canonical_form` when a signature by one of `keys` covers it as
/// received, and `invalid_signature` when none does.
pub fn succession_form_refusal(raw: &Value, keys: &[String]) -> Option<&'static str> {
    let model = "KeySuccessionRecord";
    let unknown = !unknown_fields(model, raw).is_empty();
    if !unknown && non_canonical_fields(model, raw).is_empty() {
        return None;
    }
    Some(if !succession_signed_by(raw, keys) {
        "invalid_signature"
    } else if unknown {
        "unknown_field"
    } else {
        "non_canonical_form"
    })
}

/// Why a genesis block is refused, or `None`, in the reference's order:
/// `genesis_invalid`, `genesis_root_mismatch` (it does not name the root key
/// held; without one, its own is used), then (1.5.0 review fixes) a field
/// this crate does not know or a form the reference does not write, signed
/// by that key (`unknown_field`, `non_canonical_form`), and
/// `genesis_invalid_signature` (no signature by that key over the block as
/// received).
pub fn genesis_refusal(raw: &Value, root_public_key: Option<&str>) -> Option<&'static str> {
    if !raw.is_object() || !valid_genesis(raw) {
        return Some("genesis_invalid");
    }
    let named = raw["root_public_key"].as_str().unwrap_or_default();
    let root = root_public_key.unwrap_or(named);
    if named != root {
        return Some("genesis_root_mismatch");
    }
    // 1.5.0 review fixes: the trust anchor of the history is held to the
    // rules of every signed root: a field this crate does not know, or a form
    // the reference does not write, is refused by name when the root key
    // signed it.
    let model = "GenesisBlock";
    let unknown = !unknown_fields(model, raw).is_empty();
    let signed = genesis_signed_by(raw, root);
    if signed && unknown {
        return Some("unknown_field");
    }
    if signed && !non_canonical_fields(model, raw).is_empty() {
        return Some("non_canonical_form");
    }
    (!signed).then_some("genesis_invalid_signature")
}

/// What one succession must continue: the key it succeeds, the previous
/// succession's digest, the sovereign, the root key and every key held so
/// far.
pub struct SuccessionContext<'a> {
    /// The key the record must succeed.
    pub previous: &'a NaKey,
    /// The previous succession's digest (`None` for the first).
    pub previous_digest: Option<&'a str>,
    /// The genesis block's `network_name`.
    pub sovereign_id: &'a str,
    /// The root public key.
    pub root_public_key: &'a str,
    /// Every key the history held so far.
    pub held_keys: &'a [String],
}

/// Why one succession is refused, or `None`, in the reference's order:
/// `payload_invalid` (its unknown fields set aside), then its form
/// (`unknown_field` when one of its signers signed it, otherwise
/// `invalid_signature`; `non_canonical_form`),
/// `succession_sovereign_mismatch`, `succession_chain_break`,
/// `succession_key_reused` (a key the history held, or the root key),
/// `succession_backdated` (issued after it takes effect),
/// `succession_not_increasing`, `succession_after_expiry`,
/// `succession_invalid_root_signature`,
/// `succession_invalid_new_key_signature` (the new key's proof of
/// possession), `succession_invalid_previous_signature`. The second value is true when
/// the record read as a `KeySuccessionRecord` (its `key_sequence` names the
/// failure).
pub fn succession_refusal(raw: &Value, at: &SuccessionContext<'_>) -> (Option<&'static str>, bool) {
    // 1. It parses, its unknown fields set aside.
    if !raw.is_object() || !valid_succession(&without_unknown_fields("KeySuccessionRecord", raw)) {
        return (Some("payload_invalid"), false);
    }
    // 2. No unknown field (signed by one of its signers: `unknown_field`),
    //    the canonical form.
    let mut signers = vec![
        at.root_public_key.to_owned(),
        at.previous.public_key.clone(),
    ];
    if valid_public_key(&raw["new_public_key"]) {
        signers.extend(raw["new_public_key"].as_str().map(str::to_owned));
    }
    if let Some(form) = succession_form_refusal(raw, &signers) {
        return (Some(form), true);
    }
    let field = |key: &str| raw[key].as_str();
    let time = |key: &str| micros(field(key).unwrap_or_default()).unwrap_or_default();
    if field("sovereign_id") != Some(at.sovereign_id) {
        return (Some("succession_sovereign_mismatch"), true);
    }
    if raw["key_sequence"].as_i64() != Some(at.previous.key_sequence + 1)
        || field("previous_public_key") != Some(at.previous.public_key.as_str())
        || field("previous_succession_digest") != at.previous_digest
    {
        return (Some("succession_chain_break"), true);
    }
    // A key the history held, or the root key, is no new key.
    let new_key = field("new_public_key").unwrap_or_default();
    if !valid_public_key(&raw["new_public_key"])
        || at.held_keys.iter().any(|k| k == new_key)
        || new_key == at.root_public_key
    {
        return (Some("succession_key_reused"), true);
    }
    let effective = time("effective_at");
    if time("issued_at") > effective {
        return (Some("succession_backdated"), true);
    }
    if at.previous.valid_from.is_some_and(|from| effective <= from)
        || time("new_valid_to") <= effective
    {
        return (Some("succession_not_increasing"), true);
    }
    if at.previous.valid_to_enforced && at.previous.valid_to.is_some_and(|to| effective > to) {
        return (Some("succession_after_expiry"), true);
    }
    if !succession_signed_by(raw, &[at.root_public_key.to_owned()]) {
        return (Some("succession_invalid_root_signature"), true);
    }
    // 1.5.0 review fixes: the new key's own signature proves it is held.
    if !succession_signed_by(raw, &[new_key.to_owned()]) {
        return (Some("succession_invalid_new_key_signature"), true);
    }
    if !succession_signed_by(raw, std::slice::from_ref(&at.previous.public_key)) {
        return (Some("succession_invalid_previous_signature"), true);
    }
    (None, true)
}

/// Verify a genesis block and its successions, in order, and build the key
/// history (the reference's `verify_key_history`). `root_public_key` is the
/// root key the verifier holds out of band; without it the genesis block's
/// own is used. Nothing after the first refused record is accepted.
pub fn verify_key_history(
    genesis: &Value,
    successions: &[Value],
    root_public_key: Option<&str>,
) -> KeyHistoryVerification {
    let mut result = KeyHistoryVerification {
        verified: true,
        history: None,
        failures: Vec::new(),
    };
    let fail = |result: &mut KeyHistoryVerification, at: i64, reason: &str| {
        result.verified = false;
        result.failures.push(KeyHistoryFailure {
            key_sequence: Some(at),
            reason: reason.to_owned(),
            detail: String::new(),
        });
    };
    if let Some(reason) = genesis_refusal(genesis, root_public_key) {
        fail(&mut result, 1, reason);
        return result;
    }
    let sovereign = genesis["network_name"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let root = genesis["root_public_key"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let na = &genesis["network_authority"];
    let mut keys = vec![NaKey {
        key_sequence: 1,
        public_key: na["public_key"].as_str().unwrap_or_default().to_owned(),
        key_id: None,
        valid_from: None,
        succeeded_at: None,
        valid_to: micros(na["valid_to"].as_str().unwrap_or_default()).ok(),
        valid_to_enforced: false,
    }];
    let mut digests: Vec<String> = Vec::new();
    for raw in successions {
        let previous = keys.last().cloned().unwrap_or_else(|| keys[0].clone());
        let held: Vec<String> = keys.iter().map(|k| k.public_key.clone()).collect();
        let (refusal, parsed) = succession_refusal(
            raw,
            &SuccessionContext {
                previous: &previous,
                previous_digest: digests.last().map(String::as_str),
                sovereign_id: &sovereign,
                root_public_key: &root,
                held_keys: &held,
            },
        );
        if let Some(reason) = refusal {
            let position = if parsed {
                raw["key_sequence"]
                    .as_i64()
                    .unwrap_or(previous.key_sequence + 1)
            } else {
                previous.key_sequence + 1
            };
            fail(&mut result, position, reason);
            return result;
        }
        let effective =
            micros(raw["effective_at"].as_str().unwrap_or_default()).unwrap_or_default();
        if let Some(last) = keys.last_mut() {
            last.succeeded_at = Some(effective);
            if last.key_id.is_none() {
                last.key_id = raw["previous_key_id"].as_str().map(str::to_owned);
            }
        }
        keys.push(NaKey {
            key_sequence: raw["key_sequence"].as_i64().unwrap_or_default(),
            public_key: raw["new_public_key"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            key_id: raw["new_key_id"].as_str().map(str::to_owned),
            valid_from: Some(effective),
            succeeded_at: None,
            valid_to: micros(raw["new_valid_to"].as_str().unwrap_or_default()).ok(),
            valid_to_enforced: true,
        });
        digests.push(key_succession_digest(raw).unwrap_or_default());
    }
    result.history = Some(NaKeyHistory {
        sovereign_id: sovereign,
        root_public_key: Some(root),
        keys,
        succession_digests: digests,
    });
    result
}

/// The NA keys a verifier holds: keys valid at every time (what a list of
/// NA keys meant before 1.5.0), or the NA's key history (1.5.0), read at
/// each record's time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NaKeys {
    /// Keys valid at every time.
    Any(Vec<String>),
    /// The NA's key history.
    History(NaKeyHistory),
}

impl NaKeys {
    /// The keys a record dated `at` (microseconds) may be signed with; every
    /// key when `at` is `None`.
    pub fn at(&self, at: Option<i64>) -> Vec<String> {
        match (self, at) {
            (NaKeys::Any(keys), _) => keys.clone(),
            (NaKeys::History(history), Some(at)) => history.keys_at(at),
            (NaKeys::History(history), None) => history.all_keys(),
        }
    }

    /// Every key.
    pub fn all(&self) -> Vec<String> {
        self.at(None)
    }

    /// The other keys a record dated `at` was signed with, if not one valid
    /// then: for `na_key_not_valid_at_time`.
    pub fn not_at(&self, at: i64) -> Vec<String> {
        let valid = self.at(Some(at));
        self.all()
            .into_iter()
            .filter(|k| !valid.contains(k))
            .collect()
    }

    /// The history, when these keys are one.
    pub fn history(&self) -> Option<&NaKeyHistory> {
        match self {
            NaKeys::History(history) => Some(history),
            NaKeys::Any(_) => None,
        }
    }

    /// The keys a record dated `at` may be signed with and that still vouch
    /// at `now` (1.8.0, microseconds): [`NaKeys::at`] without the keys of
    /// the history whose horizon has passed. Keys valid at every time have no
    /// horizon.
    pub fn vouching_at(&self, at: Option<i64>, now: i64, grace_seconds: i64) -> Vec<String> {
        self.at(at)
            .into_iter()
            .filter(|k| !self.outlives(k, now, grace_seconds))
            .collect()
    }

    /// True when a record signed by `public_key` no longer vouches at `now`
    /// (1.8.0): its key of the history is past its horizon.
    pub fn outlives(&self, public_key: &str, now: i64, grace_seconds: i64) -> bool {
        self.history()
            .is_some_and(|h| h.record_outlives_key(public_key, now, grace_seconds))
    }

    /// The key sequence of `public_key` in the history (1.8.0); 0 for keys
    /// valid at every time, or a key outside the history.
    pub fn key_sequence(&self, public_key: &str) -> i64 {
        self.history()
            .and_then(|h| h.key_for(public_key))
            .map_or(0, |k| k.key_sequence)
    }
}

impl From<Vec<String>> for NaKeys {
    fn from(keys: Vec<String>) -> Self {
        NaKeys::Any(keys)
    }
}

impl From<NaKeyHistory> for NaKeys {
    fn from(history: NaKeyHistory) -> Self {
        NaKeys::History(history)
    }
}
