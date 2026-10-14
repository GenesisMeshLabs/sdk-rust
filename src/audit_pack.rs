//! Audit packs (1.5.0): offline verification, the completeness check and
//! the report, a direct port of the Python reference's `audit verify`
//! (`workflows/audit_pack.py`), with its reason codes. The normative page is
//! the core's `docs/reference/audit-pack-format.md`.
//!
//! A pack (format `gm.audit.pack`, version 1) holds one range of the
//! evidence store between two anchors, everything its records cite, the NA's
//! key history and a manifest the NA signs. [`verify_audit_pack`] checks it
//! from material the verifier holds itself, the root public key and its
//! copies of the anchors, in this order:
//!
//! 1. the manifest (`manifest_*`, `manifest_unknown_file`); a pack whose
//!    manifest fails is not checked further;
//! 2. the key history from the root key down (`genesis_*`, the succession
//!    reasons, `key_history_invalid`), then the manifest's signature as
//!    received, by the NA key valid at its `created_at`; a history that
//!    fails stops it;
//! 3. the anchors (the anchor reasons, `pack_end_anchor_mismatch`,
//!    `pack_end_anchor_not_held`, `pack_start_not_tied`, `manifest_backdated`,
//!    the range against the held anchors), and each cited entry against a
//!    prior pack or a held anchor (`cited_entry_mismatch`, warning
//!    `cited_entry_unanchored`);
//! 4. the entries (`entries_invalid`, `pack_range_mismatch`,
//!    `cited_out_of_range`, then every export reason with the cited records
//!    as predecessors, `cited_record_missing` among them), executor and
//!    observer keys placed by the registry records the NA signed;
//! 5. what the records rest on outside the store, checked as received
//!    (`cited_trust_invalid`, the `*_invalid_signature` reasons,
//!    `cited_policy_*`, `cited_attestation_*`);
//! 6. the report: `report.md` is what [`render_report`] writes from the pack's
//!    files (`report_mismatch`);
//! 7. the period: with one asked for, the pack covers it
//!    (`pack_period_not_covered`);
//! 8. with a changes file, the completeness check (`change_unmatched`;
//!    warnings `changes_outside_period`, `change_duplicate`).
//!
//! No network and no private key: every key comes from the caller.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    auth::{canonical_json, verify_canonical},
    canonical::{
        attestation_digest, entry_digest, micros, parse_timestamp, policy_digest,
        policy_set_digest, python_timestamp, received_canonical,
    },
    key_history::{verify_key_history, NaKeyHistory, NaKeys},
    strict::{non_canonical_fields, unknown_fields},
    strict_json::parse_strict_json,
    verify::{
        carried_sequences, check_anchors, check_events_against_anchors, parse_export_lines,
        reads_as, verify_boundary_decision, verify_evidence_events, verify_store_anchors,
        AnchorCoverage, EvidenceVerification, VerifyDecisionOptions, VerifyEvidenceOptions,
    },
};

/// The pack format this module reads.
pub const PACK_FORMAT: &str = "gm.audit.pack";
/// The signed manifest.
pub const MANIFEST_FILE: &str = "manifest.json";
/// The report for a reader.
pub const REPORT_FILE: &str = "report.md";
/// The NA's own verification of the pack.
pub const CHECKS_FILE: &str = "checks.json";
/// The signed genesis block.
pub const GENESIS_FILE: &str = "genesis.json";
/// Every key succession.
pub const KEY_HISTORY_FILE: &str = "keys/na-key-history.json";
/// The NA's executor and observer keys, for reference only.
pub const EXECUTOR_KEYS_FILE: &str = "keys/executor-keys.json";
/// The anchors around the range.
pub const ANCHORS_FILE: &str = "anchors.jsonl";
/// The range.
pub const ENTRIES_FILE: &str = "entries.jsonl";
/// What the range rests on from before it.
pub const CITED_FILE: &str = "cited.jsonl";
/// The policy versions the records were made under.
pub const POLICIES_FILE: &str = "policies.jsonl";
/// The NA's remediation states and notices at pack time (not signed).
pub const STATES_FILE: &str = "states.json";
/// The attestations the records name.
pub const ATTESTATIONS_FILE: &str = "trust/attestations.jsonl";
/// The treaties for those attestations' issuers.
pub const TREATIES_FILE: &str = "trust/treaties.jsonl";
/// The revocation feeds of those issuers.
pub const FEEDS_FILE: &str = "trust/feeds.jsonl";

/// Every file of a pack but the manifest (format version 1).
pub const PACK_FILES: [&str; 13] = [
    ANCHORS_FILE,
    CHECKS_FILE,
    CITED_FILE,
    ENTRIES_FILE,
    EXECUTOR_KEYS_FILE,
    GENESIS_FILE,
    KEY_HISTORY_FILE,
    POLICIES_FILE,
    REPORT_FILE,
    STATES_FILE,
    ATTESTATIONS_FILE,
    FEEDS_FILE,
    TREATIES_FILE,
];

/// The agreements a pack's grants rest on (1.6.0), each as received: held
/// only when the pack holds a grant under an agreement, so a pack without one
/// keeps the 1.5 file set.
pub const AGREEMENTS_FILE: &str = "trust/agreements.jsonl";

/// Files of the format a pack holds only when it has something to put in
/// them (1.6.0).
pub const OPTIONAL_PACK_FILES: [&str; 1] = [AGREEMENTS_FILE];

/// The completeness check's default tolerance, in seconds.
pub const DEFAULT_TOLERANCE_SECONDS: i64 = 300;

/// One failure or warning, with the file it was found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackFailure {
    /// The pack file (`known-anchors` and `changes` for the verifier's own
    /// inputs), when there is one.
    pub file: Option<String>,
    /// The store position, when there is one.
    pub store_sequence: Option<i64>,
    /// Reason code, identical to the Python reference.
    pub reason: String,
    /// Extra context.
    pub detail: String,
}

/// Outcome of [`verify_audit_pack`] (the reference's `PackVerification`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PackVerification {
    /// No failure.
    pub verified: bool,
    /// Every failure, in order.
    pub failures: Vec<PackFailure>,
    /// Findings that do not fail verification (`no_held_anchors`, ...).
    pub warnings: Vec<PackFailure>,
    /// The counts of the evidence verification of the range.
    pub counts: BTreeMap<String, u64>,
    /// The range as the entries hold it.
    pub range: Map<String, Value>,
    /// How the range lines up with the held anchors.
    pub anchors: Option<AnchorCoverage>,
    /// The key history, each key as the reference writes it.
    pub keys: Vec<Value>,
    /// The completeness check, with a changes file.
    pub completeness: Option<Value>,
    /// The period the pack covers (`from`, `until`), and the one it was
    /// asked for when it names one.
    pub period: Option<Map<String, Value>>,
    /// The lines where `report.md` differs from the report the pack renders
    /// to (`line`, `pack`, `verifier`).
    pub report_differences: Vec<Value>,
}

impl PackVerification {
    fn new() -> Self {
        PackVerification {
            verified: true,
            ..PackVerification::default()
        }
    }

    fn fail(&mut self, file: Option<&str>, seq: Option<i64>, reason: &str, detail: &str) {
        self.verified = false;
        self.failures.push(PackFailure {
            file: file.map(str::to_owned),
            store_sequence: seq,
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        });
    }

    fn warn(&mut self, file: Option<&str>, seq: Option<i64>, reason: &str, detail: &str) {
        self.warnings.push(PackFailure {
            file: file.map(str::to_owned),
            store_sequence: seq,
            reason: reason.to_owned(),
            detail: detail.to_owned(),
        });
    }

    /// The failure reason codes, sorted and once each: what two verifiers
    /// compare.
    pub fn reasons(&self) -> Vec<String> {
        let set: BTreeSet<&str> = self.failures.iter().map(|f| f.reason.as_str()).collect();
        set.into_iter().map(str::to_owned).collect()
    }

    /// The reference's JSON form (`audit verify --format json`, without
    /// `check_differences`).
    pub fn to_json(&self) -> Value {
        let mut out = json!({
            "verified": self.verified,
            "failures": self.failures,
            "warnings": self.warnings,
            "counts": self.counts,
            "range": self.range,
            "keys": self.keys,
        });
        if let Some(anchors) = &self.anchors {
            out["anchors"] = serde_json::to_value(anchors).unwrap_or_default();
        }
        if let Some(period) = &self.period {
            out["period"] = Value::Object(period.clone());
        }
        if !self.report_differences.is_empty() {
            out["report_differences"] = Value::Array(self.report_differences.clone());
        }
        if let Some(completeness) = &self.completeness {
            out["completeness"] = completeness.clone();
        }
        out
    }
}

/// What a pack is verified against.
#[derive(Debug, Clone)]
pub struct VerifyPackOptions {
    /// The root public key the verifier holds: the pack's keys prove nothing
    /// alone.
    pub root_public_key: String,
    /// The anchors the verifier holds. Without them a pack proves the
    /// integrity of what it holds, not that nothing was removed
    /// (`no_held_anchors`).
    pub held_anchors: Option<Vec<Value>>,
    /// Executor and observer keys the verifier supplies, for a store without
    /// registry records; a key the pack's registry records place wins.
    pub executor_keys: Vec<Value>,
    /// Changes from a log outside Genesis Mesh, for the completeness check.
    pub changes: Option<Vec<Change>>,
    /// How far apart a change and its record may be, in seconds.
    pub tolerance_seconds: i64,
    /// False verifies the files before a manifest exists (the NA writing
    /// `checks.json`).
    pub check_manifest: bool,
    /// A period the pack must cover (microseconds, from and until):
    /// `pack_period_not_covered` otherwise.
    pub period: Option<(i64, i64)>,
    /// The entries of packs verified before ([`pack_entry_digests`]): the
    /// entries this pack cites must equal them (`cited_entry_mismatch`).
    pub prior_entries: Option<HashMap<i64, String>>,
}

impl VerifyPackOptions {
    /// Options with the root key and the held anchors.
    pub fn new(root_public_key: impl Into<String>, held_anchors: Option<Vec<Value>>) -> Self {
        VerifyPackOptions {
            root_public_key: root_public_key.into(),
            held_anchors,
            executor_keys: Vec::new(),
            changes: None,
            tolerance_seconds: DEFAULT_TOLERANCE_SECONDS,
            check_manifest: true,
            period: None,
            prior_entries: None,
        }
    }
}

// ── Reading the files ────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

const JSON_SPACE: [char; 4] = [' ', '\t', '\r', '\n'];

fn read_json(data: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(data).map_err(|e| e.to_string())?;
    parse_strict_json(text.trim_matches(JSON_SPACE)).map_err(|e| e.to_string())
}

/// JSON Lines: one value per LF-separated line, blank lines ignored.
fn read_jsonl(data: &[u8]) -> Result<Vec<Value>, String> {
    let text = std::str::from_utf8(data).map_err(|e| e.to_string())?;
    text.split('\n')
        .filter(|line| !line.trim_matches([' ', '\t', '\r']).is_empty())
        .map(|line| parse_strict_json(line).map_err(|e| e.to_string()))
        .collect()
}

fn read_events(data: &[u8]) -> Result<Vec<Value>, String> {
    let text = std::str::from_utf8(data).map_err(|e| e.to_string())?;
    parse_export_lines(text).map_err(|e| e.to_string())
}

/// Canonical JSON with characters outside ASCII written as themselves, as a
/// pack's files hold it (`json.dumps(..., ensure_ascii=False)`).
fn pack_json(value: &Value) -> String {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                out.push('{');
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).unwrap_or_default());
                    out.push(':');
                    write(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap_or_default()),
            other => out.push_str(&canonical_json(other).unwrap_or_default()),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

/// A pack JSON file's bytes: canonical JSON (keys sorted, no whitespace,
/// characters outside ASCII written as themselves) and an LF.
pub fn pack_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = pack_json(value);
    out.push('\n');
    out.into_bytes()
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn seq_of(event: &Value) -> i64 {
    event["entry"]["store_sequence"]
        .as_i64()
        .unwrap_or_default()
}

/// A UTC time as the reference writes it (`Z`, microseconds when not zero).
fn iso(at: i64) -> String {
    chrono::DateTime::from_timestamp_micros(at)
        .map(python_timestamp)
        .unwrap_or_default()
}

/// A UTC time as Python's `datetime.isoformat()` writes it (`+00:00`).
fn isoformat(at: i64) -> String {
    let z = iso(at);
    match z.strip_suffix('Z') {
        Some(rest) => format!("{rest}+00:00"),
        None => z,
    }
}

fn time_of(value: &Value, key: &str) -> Option<i64> {
    micros(field(value, key)?).ok()
}

/// The entries a pack holds, by store position: their digests as received
/// (what [`VerifyPackOptions::prior_entries`] takes from packs verified
/// before).
pub fn pack_entry_digests(
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<HashMap<i64, String>, String> {
    let entries = read_events(files.get(ENTRIES_FILE).ok_or("entries.jsonl is missing")?)?;
    Ok(entries
        .iter()
        .map(|e| (seq_of(e), entry_digest(&e["entry"]).unwrap_or_default()))
        .collect())
}

// ── Signatures as received ───────────────────────────────────────────────────

/// The signature values a record of a registry root carries.
fn signature_values<'a>(model: &str, raw: &'a Value) -> Vec<&'a str> {
    let spec = crate::strict::model_spec(model);
    match spec["signature_field"].as_str() {
        Some("signatures") => raw["signatures"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| field(s, "sig"))
            .collect(),
        Some(name) => field(&raw[name], "sig").into_iter().collect(),
        None => Vec::new(),
    }
}

/// Whether a signature on `raw` verifies, over its signed form as received,
/// with one of `keys`.
fn signed_as_received(model: &str, raw: &Value, keys: &[String]) -> bool {
    let Ok(body) = received_canonical(model, raw) else {
        return false;
    };
    signature_values(model, raw)
        .into_iter()
        .any(|sig| verify_canonical(&body, sig, keys))
}

/// The form a signed record its signer signed must still pass: no unknown
/// field, the form the reference writes.
fn form_refusal(model: &str, raw: &Value) -> Option<&'static str> {
    if !unknown_fields(model, raw).is_empty() {
        Some("unknown_field")
    } else if !non_canonical_fields(model, raw).is_empty() {
        Some("non_canonical_form")
    } else {
        None
    }
}

/// `None` when a signature on `raw` verifies, over the record as received,
/// with the NA key valid at `at`; else why not: `unknown_field` or
/// `non_canonical_form` for a record its signer signed in another form,
/// `na_key_not_valid_at_time` for one signed by another key of the history,
/// `invalid_signature` otherwise (the reference's
/// `received_signature_reason`).
pub fn received_signature_reason(
    model: &str,
    raw: &Value,
    keys: &NaKeys,
    at: Option<i64>,
) -> Option<&'static str> {
    if !raw.is_object() {
        return Some("invalid_signature");
    }
    let valid = keys.at(at);
    if signed_as_received(model, raw, &valid) {
        return form_refusal(model, raw);
    }
    let others: Vec<String> = keys
        .all()
        .into_iter()
        .filter(|k| !valid.contains(k))
        .collect();
    if !others.is_empty() && signed_as_received(model, raw, &others) {
        return Some("na_key_not_valid_at_time");
    }
    Some("invalid_signature")
}

/// As [`received_signature_reason`], for keys with no time (a treaty's
/// subject keys).
fn received_by(model: &str, raw: &Value, keys: &[String]) -> Option<&'static str> {
    if !raw.is_object() || !signed_as_received(model, raw, keys) {
        return Some("invalid_signature");
    }
    form_refusal(model, raw)
}

// ── The manifest ─────────────────────────────────────────────────────────────

fn utc(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        parse_timestamp(s).is_ok()
            && (s.ends_with('Z') || s.ends_with("+00:00") || s.ends_with("-00:00"))
    })
}

fn text(value: &Value, min: usize, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|s| (min..=max).contains(&s.chars().count()))
}

fn at_least(value: &Value, min: i64) -> bool {
    value
        .as_i64()
        .is_some_and(|n| n >= min && n <= 9_007_199_254_740_991)
}

/// Whether a manifest reads as an `AuditPackManifest` (its unknown fields
/// are refused before this).
fn valid_manifest(m: &Value) -> bool {
    let optional = |key: &str, check: &dyn Fn(&Value) -> bool| {
        m.get(key).is_none_or(|v| v.is_null() || check(v))
    };
    m.is_object()
        && optional("format", &|v| v == PACK_FORMAT)
        && optional("format_version", &|v| v == 1)
        && optional("pack_id", &|v| text(v, 1, 128))
        && text(&m["sovereign_id"], 1, 256)
        && utc(&m["created_at"])
        && optional("requested_by", &|v| text(v, 1, 256))
        && at_least(&m["from_sequence"], 1)
        && at_least(&m["through_sequence"], 1)
        && optional("start_anchor_sequence", &|v| at_least(v, 1))
        && at_least(&m["end_anchor_sequence"], 1)
        && optional("period_from", &utc)
        && optional("period_until", &utc)
        && m["files"].as_array().is_some_and(|files| {
            files.iter().all(|f| {
                text(&f["path"], 1, 256) && text(&f["sha256"], 64, 64) && at_least(&f["bytes"], 0)
            })
        })
        && m["issued_by"].is_string()
        && optional("signature", &|v| {
            v["key_id"].is_string() && v["sig"].is_string()
        })
}

/// The bytes the reference writes for a manifest it reads: its fields (the
/// defaults filled), absent optional fields left out, times as Pydantic
/// writes them.
fn manifest_bytes(m: &Value) -> Option<Vec<u8>> {
    let mut wire = m.as_object()?.clone();
    wire.retain(|_, v| !v.is_null());
    for key in ["format", "format_version", "pack_id"] {
        if !wire.contains_key(key) {
            return None;
        }
    }
    for key in ["created_at", "period_from", "period_until"] {
        if let Some(at) = field(m, key) {
            let at = parse_timestamp(at).ok()?;
            wire.insert(key.into(), Value::String(python_timestamp(at)));
        }
    }
    Some(pack_json_bytes(&Value::Object(wire)))
}

fn check_manifest(
    files: &BTreeMap<String, Vec<u8>>,
    result: &mut PackVerification,
) -> Option<Value> {
    let m = Some(MANIFEST_FILE);
    let Some(raw) = files.get(MANIFEST_FILE) else {
        result.fail(m, None, "manifest_missing", "");
        return None;
    };
    let manifest = match read_json(raw) {
        Ok(data) if data.is_object() && !unknown_fields("AuditPackManifest", &data).is_empty() => {
            result.fail(m, None, "manifest_invalid", "unknown field");
            return None;
        }
        Ok(data) if valid_manifest(&data) => data,
        Ok(_) => {
            result.fail(m, None, "manifest_invalid", "not an AuditPackManifest");
            return None;
        }
        Err(e) => {
            result.fail(
                m,
                None,
                "manifest_invalid",
                &e.chars().take(200).collect::<String>(),
            );
            return None;
        }
    };
    if manifest_bytes(&manifest).as_deref() != Some(raw.as_slice()) {
        result.fail(m, None, "manifest_invalid", "not in canonical form");
    }
    let mut listed: BTreeMap<String, &Value> = BTreeMap::new();
    for item in manifest["files"].as_array().into_iter().flatten() {
        let path = field(item, "path").unwrap_or_default();
        if listed.contains_key(path) || path == MANIFEST_FILE {
            let detail = format!("lists {path} twice or itself");
            result.fail(m, None, "manifest_invalid", &detail);
        }
        listed.insert(path.to_owned(), item);
    }
    for path in PACK_FILES {
        if !listed.contains_key(path) {
            let detail = format!("{path} is not listed");
            result.fail(m, None, "manifest_file_missing", &detail);
        }
    }
    for (path, item) in &listed {
        if !PACK_FILES.contains(&path.as_str()) && !OPTIONAL_PACK_FILES.contains(&path.as_str()) {
            // A pack holds the files of its format and nothing else.
            let detail = format!("{path} is not a file of the format");
            result.fail(m, None, "manifest_unknown_file", &detail);
            continue;
        }
        match files.get(path) {
            None => result.fail(Some(path), None, "manifest_file_missing", ""),
            Some(data) => {
                if Some(sha256_hex(data).as_str()) != field(item, "sha256")
                    || Some(data.len() as i64) != item["bytes"].as_i64()
                {
                    result.fail(Some(path), None, "manifest_digest_mismatch", "");
                }
            }
        }
    }
    for path in files.keys() {
        if path != MANIFEST_FILE && !listed.contains_key(path) {
            result.fail(Some(path), None, "manifest_unlisted_file", "");
        }
    }
    Some(manifest)
}

/// Executor and observer keys from the registry records the NA signed (by
/// the key valid at the entry's time), each placed where the store
/// registered and retired it: by store position, or, for a record backfilled
/// at an upgrade (`reconstructed`) or carried past retention, by its
/// `effective_at` (`registered_sequence`, `registered_at_time`,
/// `retired_sequence`, `retired_at_time`). The reference's `_registry_keys`.
pub fn registry_keys(events: &[&Value], keys: &NaKeys) -> Vec<Value> {
    let mut ordered: Vec<&Value> = events.to_vec();
    ordered.sort_by_key(|e| seq_of(e));
    let carried = carried_sequences(&ordered);
    let mut placed: Vec<Value> = Vec::new();
    for event in ordered {
        let record = &event["payload"];
        if field(&event["entry"], "entry_kind") != Some("registry")
            || !reads_as("RegistryRecord", record)
        {
            continue;
        }
        let at = time_of(&event["entry"], "recorded_at");
        if received_signature_reason("RegistryRecord", record, keys, at).is_some() {
            continue;
        }
        let seq = seq_of(event);
        let by_time = record["reconstructed"] == true || carried.contains(&seq);
        let effective = field(record, "effective_at")
            .and_then(|s| parse_timestamp(s).ok())
            .map(python_timestamp);
        let named = |key: &str| field(record, key).filter(|v| !v.is_empty());
        let key_id = named("key_id");
        let position = placed.iter().position(|k| field(k, "key_id") == key_id);
        match (field(record, "event"), key_id) {
            (Some("executor_key_registered"), Some(key_id)) => {
                let (Some(public_key), Some(sovereign)) =
                    (named("public_key"), named("executor_sovereign_id"))
                else {
                    continue;
                };
                if position.is_some_and(|i| field(&placed[i], "public_key") == Some(public_key)) {
                    continue; // registered again: the first registration places it
                }
                let key = json!({
                    "key_id": key_id,
                    "public_key": public_key,
                    "executor_sovereign_id": sovereign,
                    "role": field(record, "key_role").unwrap_or("executor"),
                    "resource_prefix": record.get("resource_prefix").cloned().unwrap_or(Value::Null),
                    "registered_sequence": if by_time { Value::Null } else { json!(seq) },
                    "registered_at_time": if by_time { json!(effective) } else { Value::Null },
                    "retired_sequence": null,
                    "retired_at_time": null,
                });
                match position {
                    Some(i) => placed[i] = key,
                    None => placed.push(key),
                }
            }
            (Some("executor_key_retired"), Some(_)) => {
                if let Some(i) = position {
                    let held = &mut placed[i];
                    if held["retired_sequence"].is_null() && held["retired_at_time"].is_null() {
                        held["retired"] = json!(true);
                        if by_time {
                            held["retired_at_time"] = json!(effective);
                        } else {
                            held["retired_sequence"] = json!(seq);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    placed
}

fn file_of(seq: Option<i64>, from_sequence: i64) -> &'static str {
    match seq {
        Some(seq) if seq < from_sequence => CITED_FILE,
        _ => ENTRIES_FILE,
    }
}

/// An anchor as the reference writes it back (`StoreAnchor.to_wire()`).
fn anchor_wire(anchor: &Value) -> Value {
    let mut wire = anchor.as_object().cloned().unwrap_or_default();
    wire.retain(|_, v| !v.is_null());
    if let Some(at) = field(anchor, "anchored_at").and_then(|s| parse_timestamp(s).ok()) {
        wire.insert("anchored_at".into(), Value::String(python_timestamp(at)));
    }
    Value::Object(wire)
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Verify an audit pack offline: `files` maps each file's `/`-separated
/// path in the pack to its bytes. The module documentation lists the checks.
pub fn verify_audit_pack(
    files: &BTreeMap<String, Vec<u8>>,
    options: &VerifyPackOptions,
) -> PackVerification {
    let mut result = PackVerification::new();
    let manifest = if options.check_manifest {
        check_manifest(files, &mut result)
    } else {
        None
    };

    // 2. The key history, from the root key down.
    let history_files = (|| {
        let genesis = read_json(files.get(GENESIS_FILE).ok_or("genesis.json is missing")?)?;
        let history = read_json(
            files
                .get(KEY_HISTORY_FILE)
                .ok_or("the key history is missing")?,
        )?;
        let successions = match history.as_object() {
            Some(map) => map
                .get("successions")
                .cloned()
                .unwrap_or(Value::Array(Vec::new())),
            None => return Err("the key history is not an object".to_owned()),
        };
        Ok::<_, String>((genesis, successions))
    })();
    let (genesis, successions) = match history_files {
        Ok(read) => read,
        Err(e) => {
            let detail: String = e.chars().take(200).collect();
            result.fail(Some(KEY_HISTORY_FILE), None, "key_history_invalid", &detail);
            return result;
        }
    };
    let successions = successions.as_array().cloned().unwrap_or_default();
    let keyed = verify_key_history(&genesis, &successions, Some(&options.root_public_key));
    for failure in &keyed.failures {
        let n = failure.key_sequence.unwrap_or_default();
        let file = if n == 1 {
            GENESIS_FILE
        } else {
            KEY_HISTORY_FILE
        };
        result.fail(Some(file), None, &failure.reason, &format!("key {n}"));
    }
    let Some(history) = keyed.history.filter(|_| keyed.verified) else {
        return result;
    };
    result.keys = history.keys.iter().map(|k| k.to_json()).collect();
    let keys = NaKeys::History(history.clone());

    if let Some(m) = &manifest {
        if field(m, "sovereign_id") != Some(history.sovereign_id.as_str()) {
            result.fail(
                Some(MANIFEST_FILE),
                None,
                "manifest_invalid",
                "names another sovereign",
            );
        }
        // Over the manifest as received, not a form with its defaults filled in.
        if let Some(reason) =
            received_signature_reason("AuditPackManifest", m, &keys, time_of(m, "created_at"))
        {
            let reason = if reason == "invalid_signature" {
                "manifest_invalid_signature"
            } else {
                reason
            };
            result.fail(Some(MANIFEST_FILE), None, reason, "");
        }
    }
    if options.check_manifest && !result.verified {
        // Files that do not match a manifest the NA signed are not the pack.
        return result;
    }

    // 3 and 4. Anchors and entries.
    let read = (|| {
        let anchors = read_jsonl(files.get(ANCHORS_FILE).ok_or("anchors.jsonl is missing")?)?;
        let anchors = check_anchors(anchors).map_err(|e| e.to_string())?;
        let entries = read_events(files.get(ENTRIES_FILE).ok_or("entries.jsonl is missing")?)?;
        let cited = read_events(files.get(CITED_FILE).ok_or("cited.jsonl is missing")?)?;
        Ok::<_, String>((anchors, entries, cited))
    })();
    let (pack_anchors, entries, cited) = match read {
        Ok(read) => read,
        Err(e) => {
            let detail: String = e.chars().take(200).collect();
            result.fail(Some(ENTRIES_FILE), None, "entries_invalid", &detail);
            return result;
        }
    };
    let (Some(first_event), Some(last_event)) = (entries.first(), entries.last()) else {
        result.fail(
            Some(ENTRIES_FILE),
            None,
            "pack_range_mismatch",
            "the pack holds no entry",
        );
        return result;
    };
    let (first, last) = (seq_of(first_event), seq_of(last_event));
    let from_sequence = manifest
        .as_ref()
        .and_then(|m| m["from_sequence"].as_i64())
        .unwrap_or(first);
    let through = manifest
        .as_ref()
        .and_then(|m| m["through_sequence"].as_i64())
        .unwrap_or(last);
    let recorded = |e: &Value| time_of(&e["entry"], "recorded_at");
    result.range = json!({
        "from_sequence": first,
        "through_sequence": last,
        "entries": entries.len(),
        "first_recorded_at": recorded(first_event).map(isoformat).unwrap_or_default(),
        "last_recorded_at": recorded(last_event).map(isoformat).unwrap_or_default(),
    })
    .as_object()
    .cloned()
    .unwrap_or_default();
    if (first, last) != (from_sequence, through)
        || entries.len() as i64 != through - from_sequence + 1
    {
        let detail = format!(
            "the entries run {first}..{last}, the manifest says {from_sequence}..{through}"
        );
        result.fail(Some(ENTRIES_FILE), None, "pack_range_mismatch", &detail);
    }
    for event in &cited {
        if seq_of(event) >= from_sequence {
            result.fail(
                Some(CITED_FILE),
                Some(seq_of(event)),
                "cited_out_of_range",
                "",
            );
        }
    }

    let chain = verify_store_anchors(&pack_anchors, Some(&keys), Some(&history.sovereign_id));
    for failure in chain.failures {
        let detail = format!("anchor {}", failure.anchor_sequence.unwrap_or_default());
        result.fail(Some(ANCHORS_FILE), None, &failure.reason, &detail);
    }
    let number = |a: &Value| a["anchor_sequence"].as_i64().unwrap_or_default();
    let by_sequence: HashMap<i64, &Value> = pack_anchors.iter().map(|a| (number(a), a)).collect();
    let anchor_at =
        |m: &Value, key: &str| m[key].as_i64().and_then(|n| by_sequence.get(&n).copied());
    let end = match &manifest {
        Some(m) => anchor_at(m, "end_anchor_sequence"),
        None => pack_anchors.last(),
    };
    let last_digest = entry_digest(&last_event["entry"]).ok();
    if end.is_none_or(|end| {
        end["store_sequence"].as_i64() != Some(last)
            || field(end, "entry_digest") != last_digest.as_deref()
    }) {
        let detail = "no anchor of the pack names the range's last entry";
        result.fail(
            Some(ANCHORS_FILE),
            Some(last),
            "pack_end_anchor_mismatch",
            detail,
        );
    }
    let start_named = manifest
        .as_ref()
        .is_some_and(|m| m["start_anchor_sequence"].as_i64().is_some());
    let start_anchor = match &manifest {
        Some(m) => anchor_at(m, "start_anchor_sequence"),
        None => pack_anchors
            .iter()
            .rev()
            .find(|a| a["store_sequence"].as_i64() == Some(first - 1)),
    };
    let first_prev = field(&first_event["entry"], "prev_entry_digest");
    if start_named
        && start_anchor.is_none_or(|a| {
            a["store_sequence"].as_i64() != Some(first - 1)
                || field(a, "entry_digest") != first_prev
        })
    {
        let detail = "the start anchor does not name the entry before the range";
        result.fail(
            Some(ANCHORS_FILE),
            Some(first),
            "pack_start_not_tied",
            detail,
        );
    }
    if let Some(m) = &manifest {
        // The NA writes a pack after its end anchor and its last entry.
        let latest = recorded(last_event)
            .into_iter()
            .chain(end.and_then(|end| time_of(end, "anchored_at")))
            .max()
            .unwrap_or_default();
        let created = time_of(m, "created_at").unwrap_or_default();
        if created < latest {
            let detail = format!("created at {}, before {}", iso(created), iso(latest));
            result.fail(Some(MANIFEST_FILE), None, "manifest_backdated", &detail);
        }
    }

    // The start checkpoint: one (in the range or cited) that removed the
    // entries before the range; the last one found.
    let start_checkpoint = entries
        .iter()
        .chain(cited.iter())
        .filter(|e| field(&e["entry"], "entry_kind") == Some("retention_checkpoint"))
        .map(|e| &e["payload"])
        .rfind(|cp| {
            reads_as("RetentionCheckpoint", cp)
                && cp["removed_through_sequence"].as_i64() == Some(first - 1)
                && field(cp, "last_removed_entry_digest") == first_prev
        })
        .cloned();
    if first == 1 && first_prev.is_some() {
        result.fail(
            Some(ENTRIES_FILE),
            Some(1),
            "store_chain_break",
            "entry 1 names a previous entry",
        );
    }

    let held = options.held_anchors.as_deref().unwrap_or_default();
    let held_by: HashMap<i64, &Value> = held.iter().map(|a| (number(a), a)).collect();
    match &options.held_anchors {
        None => result.warn(
            None,
            None,
            "no_held_anchors",
            "verified without anchors held out of band: the pack's integrity, not that nothing was removed",
        ),
        Some(held) => {
            let held_chain = verify_store_anchors(held, Some(&keys), Some(&history.sovereign_id));
            for failure in held_chain.failures {
                let detail = format!("held anchor {}", failure.anchor_sequence.unwrap_or_default());
                result.fail(Some("known-anchors"), None, &failure.reason, &detail);
            }
            for anchor in &pack_anchors {
                let n = number(anchor);
                if held_by.get(&n).is_some_and(|mine| anchor_wire(mine) != anchor_wire(anchor)) {
                    let detail = format!("anchor {n} differs from the one held");
                    result.fail(Some(ANCHORS_FILE), anchor["store_sequence"].as_i64(), "anchor_mismatch", &detail);
                }
            }
            if let Some(end) = end.filter(|end| !held_by.contains_key(&number(end))) {
                let detail = format!("anchor {} is not among the anchors held", number(end));
                result.fail(Some(ANCHORS_FILE), Some(last), "pack_end_anchor_not_held", &detail);
            }
            let inside: Vec<Value> = held
                .iter()
                .filter(|a| a["store_sequence"].as_i64().is_some_and(|s| s <= last))
                .cloned()
                .collect();
            let mut tied = EvidenceVerification::empty();
            let coverage = check_events_against_anchors(&entries, &inside, &mut tied, false, true);
            for f in tied.failures {
                result.fail(Some(ENTRIES_FILE), f.store_sequence, &f.reason, &f.detail);
            }
            result.anchors = Some(coverage);
        }
    }

    // A cited entry is checked against what the verifier holds at its
    // position: an entry of a pack verified before, or an anchor naming that
    // very entry. Neither: a warning.
    let held_at: HashMap<i64, &Value> = held
        .iter()
        .map(|a| (a["store_sequence"].as_i64().unwrap_or_default(), a))
        .collect();
    for event in &cited {
        let seq = seq_of(event);
        let digest = entry_digest(&event["entry"]).unwrap_or_default();
        let known = options.prior_entries.as_ref().and_then(|p| p.get(&seq));
        let anchor = held_at.get(&seq);
        if known.is_some_and(|k| *k != digest) {
            let detail = "differs from the entry a prior pack holds";
            result.fail(Some(CITED_FILE), Some(seq), "cited_entry_mismatch", detail);
        } else if let Some(anchor) =
            anchor.filter(|a| field(a, "entry_digest") != Some(digest.as_str()))
        {
            let detail = format!("differs from held anchor {}", number(anchor));
            result.fail(Some(CITED_FILE), Some(seq), "cited_entry_mismatch", &detail);
        } else if known.is_none() && anchor.is_none() {
            let detail = "signed, but neither a prior pack nor a held anchor covers this entry";
            result.warn(
                Some(CITED_FILE),
                Some(seq),
                "cited_entry_unanchored",
                detail,
            );
        }
    }

    // 4. Executor keys: keys supplied out of band, then the registry records
    // the NA signed, which win.
    let all: Vec<&Value> = cited.iter().chain(entries.iter()).collect();
    let registered = registry_keys(&all, &keys);
    let mut executor_keys: Vec<Value> = options
        .executor_keys
        .iter()
        .filter(|k| {
            !registered
                .iter()
                .any(|r| field(r, "key_id") == field(k, "key_id"))
        })
        .cloned()
        .collect();
    executor_keys.extend(registered);
    let verification = verify_evidence_events(
        &entries,
        &VerifyEvidenceOptions {
            checkpoint: start_checkpoint.clone(),
            key_history: Some(history.clone()),
            prior: Some(cited.clone()),
            ..VerifyEvidenceOptions::new(Vec::new(), executor_keys)
        },
    );
    for f in &verification.failures {
        result.fail(
            Some(file_of(f.store_sequence, from_sequence)),
            f.store_sequence,
            &f.reason,
            &f.detail,
        );
    }
    for w in &verification.warnings {
        result.warn(
            Some(file_of(w.store_sequence, from_sequence)),
            w.store_sequence,
            &w.reason,
            &w.detail,
        );
    }
    result.counts = counts_of(&verification);

    // 5. What the records cite outside the store.
    check_cited_trust(files, &entries, &cited, &history, &keys, &mut result);

    // 6. The report renders from the pack's own files.
    if let Some(m) = &manifest {
        check_report(files, m, &entries, &mut result);
    }

    // 7. The period the pack covers: from its start anchor (or the retention
    // checkpoint it starts after, or its first entry) to its end anchor.
    let covered_from = start_anchor
        .and_then(|a| time_of(a, "anchored_at"))
        .or_else(|| {
            start_checkpoint
                .as_ref()
                .and_then(|cp| time_of(cp, "created_at"))
        })
        .or_else(|| recorded(first_event))
        .unwrap_or_default();
    let covered_until = end
        .and_then(|end| time_of(end, "anchored_at"))
        .or_else(|| recorded(last_event))
        .unwrap_or_default();
    let mut period = Map::new();
    period.insert("from".into(), json!(iso(covered_from)));
    period.insert("until".into(), json!(iso(covered_until)));
    if let Some(m) = &manifest {
        for (key, name) in [
            ("period_from", "requested_from"),
            ("period_until", "requested_until"),
        ] {
            if let Some(at) = time_of(m, key) {
                period.insert(name.into(), json!(iso(at)));
            }
        }
    }
    if let Some((wanted_from, wanted_until)) = options.period {
        period.insert("asked_from".into(), json!(iso(wanted_from)));
        period.insert("asked_until".into(), json!(iso(wanted_until)));
        if wanted_from < covered_from || wanted_until > covered_until {
            let detail = format!(
                "the pack covers {} to {}",
                iso(covered_from),
                iso(covered_until)
            );
            result.fail(None, None, "pack_period_not_covered", &detail);
        }
    }
    result.period = Some(period);

    // 8. Completeness.
    if let Some(changes) = &options.changes {
        let report = check_completeness(
            changes,
            &entries,
            &cited,
            (covered_from, covered_until),
            options.tolerance_seconds,
        );
        for item in report["unmatched_changes"].as_array().into_iter().flatten() {
            let text = |key: &str| item[key].as_str().unwrap_or("-").to_owned();
            let detail = format!(
                "{} {} {} {} {}",
                text("source"),
                text("source_event_id"),
                text("resource_id"),
                text("action"),
                text("changed_at")
            );
            result.fail(Some("changes"), None, "change_unmatched", &detail);
        }
        let outside = report["outside_period"].as_array().map_or(0, Vec::len);
        if outside > 0 {
            let detail = format!(
                "{outside} change(s) dated outside the period the pack covers ({} to {})",
                iso(covered_from),
                iso(covered_until)
            );
            result.warn(Some("changes"), None, "changes_outside_period", &detail);
        }
        for item in report["duplicate_changes"].as_array().into_iter().flatten() {
            let detail = format!(
                "change {} repeats {} {}",
                item["index"],
                item["source"].as_str().unwrap_or("None"),
                item["source_event_id"].as_str().unwrap_or("None")
            );
            result.warn(Some("changes"), None, "change_duplicate", &detail);
        }
        result.completeness = Some(report);
    }
    result
}

/// The counts of an evidence verification as the reference reports them:
/// every integer of its JSON form.
fn counts_of(verification: &EvidenceVerification) -> BTreeMap<String, u64> {
    serde_json::to_value(verification)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k, v.as_u64()?)))
        .collect()
}

fn check_report(
    files: &BTreeMap<String, Vec<u8>>,
    manifest: &Value,
    entries: &[Value],
    result: &mut PackVerification,
) {
    let read = (|| {
        let checks = read_json(files.get(CHECKS_FILE).ok_or("checks.json is missing")?)?;
        let states = read_json(files.get(STATES_FILE).ok_or("states.json is missing")?)?;
        let claimed = files.get(REPORT_FILE).ok_or("report.md is missing")?;
        let claimed = String::from_utf8(claimed.clone()).map_err(|e| e.to_string())?;
        Ok::<_, String>((checks, states, claimed))
    })();
    let (checks, states, claimed) = match read {
        Ok(read) => read,
        Err(e) => {
            let detail = format!(
                "cannot be rendered: {}",
                e.chars().take(160).collect::<String>()
            );
            result.fail(Some(REPORT_FILE), None, "report_mismatch", &detail);
            return;
        }
    };
    if !checks.is_object() || !states.is_object() {
        let detail = "checks.json and states.json are JSON objects";
        result.fail(Some(REPORT_FILE), None, "report_mismatch", detail);
        return;
    }
    let or_empty = |v: &Value| if truthy(v) { v.clone() } else { json!({}) };
    let expected = render_report(
        &report_header(manifest),
        entries,
        &checks,
        &or_empty(&states["states"]),
        &or_empty(&states["notices"]),
    );
    if expected == claimed {
        return;
    }
    let ours: Vec<&str> = expected.split('\n').collect();
    let theirs: Vec<&str> = claimed.split('\n').collect();
    for i in 0..ours.len().max(theirs.len()) {
        let (mine, pack) = (ours.get(i), theirs.get(i));
        if mine != pack {
            result
                .report_differences
                .push(json!({"line": i + 1, "pack": pack, "verifier": mine}));
        }
    }
    let detail = format!(
        "{} line(s) differ from the report the pack renders to",
        result.report_differences.len()
    );
    result.fail(Some(REPORT_FILE), None, "report_mismatch", &detail);
}

/// Whether the shapes of the trust files read as their models.
fn trust_shapes(
    policies: &[Value],
    attestations: &[Value],
    treaties: &[Value],
    feeds: &[Value],
) -> bool {
    let shaped = |items: &[Value], fields: &[&str], time: &str| {
        items.iter().all(|item| {
            item.is_object()
                && fields.iter().all(|f| item[*f].is_string())
                && field(item, time).is_some_and(|s| parse_timestamp(s).is_ok())
        })
    };
    let lists = |items: &[Value]| {
        items
            .iter()
            .all(|i| i.get("signatures").is_none_or(Value::is_array))
    };
    shaped(policies, &["policy_id"], "issued_at")
        && policies.iter().all(|p| p["version"].is_i64())
        && shaped(
            attestations,
            &["attestation_id", "issuer_sovereign_id"],
            "issued_at",
        )
        && lists(attestations)
        && shaped(
            treaties,
            &["treaty_id", "subject_sovereign_id"],
            "issued_at",
        )
        && treaties.iter().all(|t| {
            t.get("subject_public_keys")
                .is_none_or(|k| k.as_array().is_some_and(|a| a.iter().all(Value::is_string)))
        })
        && lists(treaties)
        && shaped(feeds, &["feed_id", "issuer_sovereign_id"], "issued_at")
        && lists(feeds)
}

fn check_cited_trust(
    files: &BTreeMap<String, Vec<u8>>,
    entries: &[Value],
    cited: &[Value],
    history: &NaKeyHistory,
    keys: &NaKeys,
    result: &mut PackVerification,
) {
    let read = |path: &str| {
        read_jsonl(
            files
                .get(path)
                .ok_or_else(|| format!("{path} is missing"))?,
        )
    };
    let read_all = (|| {
        Ok::<_, String>((
            read(POLICIES_FILE)?,
            read(ATTESTATIONS_FILE)?,
            read(TREATIES_FILE)?,
            read(FEEDS_FILE)?,
            // 1.6.0: only in a pack holding a grant under an agreement.
            match files.get(AGREEMENTS_FILE) {
                Some(_) => read(AGREEMENTS_FILE)?,
                None => Vec::new(),
            },
        ))
    })();
    let (policies, attestations, treaties, feeds, agreements) = match read_all {
        Ok(all) => all,
        Err(e) => {
            let detail: String = e.chars().take(200).collect();
            result.fail(Some(POLICIES_FILE), None, "cited_trust_invalid", &detail);
            return;
        }
    };
    if !trust_shapes(&policies, &attestations, &treaties, &feeds) {
        result.fail(
            Some(POLICIES_FILE),
            None,
            "cited_trust_invalid",
            "a record is not of its model",
        );
        return;
    }
    let named = |reason: &'static str, otherwise: &'static str| {
        if reason == "invalid_signature" {
            otherwise
        } else {
            reason
        }
    };

    let mut by_version: HashMap<(String, i64), &Value> = HashMap::new();
    for policy in &policies {
        let id = field(policy, "policy_id").unwrap_or_default();
        let version = policy["version"].as_i64().unwrap_or_default();
        if let Some(reason) =
            received_signature_reason("BoundaryPolicy", policy, keys, time_of(policy, "issued_at"))
        {
            let reason = named(reason, "policy_invalid_signature");
            result.fail(
                Some(POLICIES_FILE),
                None,
                reason,
                &format!("{id} v{version}"),
            );
        }
        by_version.insert((id.to_owned(), version), policy);
    }
    let own = history.sovereign_id.as_str();
    let own_sovereign = own.to_owned();
    let mut issuer_keys: HashMap<String, Vec<String>> = HashMap::new();
    for treaty in &treaties {
        let at = time_of(treaty, "issued_at");
        if let Some(reason) = received_signature_reason("RecognitionTreaty", treaty, keys, at) {
            let reason = named(reason, "treaty_invalid_signature");
            result.fail(
                Some(TREATIES_FILE),
                None,
                reason,
                field(treaty, "treaty_id").unwrap_or_default(),
            );
            continue;
        }
        issuer_keys
            .entry(
                field(treaty, "subject_sovereign_id")
                    .unwrap_or_default()
                    .to_owned(),
            )
            .or_default()
            .extend(
                treaty["subject_public_keys"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|k| k.as_str().map(str::to_owned)),
            );
    }
    let mut by_attestation: HashMap<&str, &Value> = HashMap::new();
    for attestation in &attestations {
        let issuer = field(attestation, "issuer_sovereign_id").unwrap_or_default();
        let model = "MembershipAttestation";
        let reason = if issuer == own {
            received_signature_reason(model, attestation, keys, time_of(attestation, "issued_at"))
        } else {
            received_by(
                model,
                attestation,
                issuer_keys
                    .get(issuer)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )
        };
        let id = field(attestation, "attestation_id").unwrap_or_default();
        if let Some(reason) = reason {
            let reason = named(reason, "attestation_invalid_signature");
            result.fail(Some(ATTESTATIONS_FILE), None, reason, id);
        }
        by_attestation.insert(id, attestation);
    }
    for feed in &feeds {
        let issuer = field(feed, "issuer_sovereign_id").unwrap_or_default();
        let k = issuer_keys
            .get(issuer)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if let Some(reason) = received_by("SovereignRevocationFeed", feed, k) {
            let reason = named(reason, "feed_invalid_signature");
            result.fail(
                Some(FEEDS_FILE),
                None,
                reason,
                field(feed, "feed_id").unwrap_or_default(),
            );
        }
    }

    let from_sequence = entries.first().map(seq_of).unwrap_or_default();
    for event in cited.iter().chain(entries.iter()) {
        let kind = field(&event["entry"], "entry_kind").unwrap_or_default();
        let seq = seq_of(event);
        let file = Some(file_of(Some(seq), from_sequence));
        let binding = match kind {
            "decision" => {
                let decision = &event["payload"]["decision"];
                if !reads_as("BoundaryDecision", decision) {
                    continue;
                }
                let bound = &decision["attestation_binding"];
                if field(bound, "attestation_digest").is_some_and(|d| !d.is_empty()) {
                    let id = field(bound, "attestation_id").unwrap_or_default();
                    match by_attestation.get(id) {
                        None => result.fail(file, Some(seq), "cited_attestation_missing", id),
                        Some(held) => {
                            // As of the decision's own time: its expiry since then says nothing against it.
                            let verdict = verify_boundary_decision(
                                decision,
                                &VerifyDecisionOptions {
                                    expected_attestation: Some((*held).clone()),
                                    at_record_time: true,
                                    key_history: Some(history.clone()),
                                    ..VerifyDecisionOptions::default()
                                },
                            );
                            if matches!(
                                verdict.reason.as_str(),
                                "attestation_binding_mismatch" | "attestation_binding_missing"
                            ) {
                                result.fail(file, Some(seq), "cited_attestation_mismatch", id);
                            }
                        }
                    }
                }
                &decision["policy_binding"]
            }
            "judgement" => {
                if !reads_as("JudgementRecord", &event["payload"]) {
                    continue;
                }
                &event["payload"]["policy_binding"]
            }
            // v1.6.0: the policy versions a grant is bound to, and the
            // attestation or (review fixes) agreement it rests on.
            "grant" => {
                let grant = &event["payload"];
                if !reads_as("CapabilityGrant", grant) {
                    continue;
                }
                let id = field(grant, "basis_id").unwrap_or_default();
                if field(grant, "basis_kind") == Some("attestation") {
                    match by_attestation.get(id) {
                        None => result.fail(file, Some(seq), "cited_attestation_missing", id),
                        Some(held) => {
                            if attestation_digest(held).ok().as_deref()
                                != field(grant, "basis_digest")
                            {
                                result.fail(file, Some(seq), "cited_attestation_mismatch", id);
                            }
                        }
                    }
                } else {
                    let held = agreements
                        .iter()
                        .find(|a| field(a, "agreement_id") == Some(id));
                    if let Some(problem) =
                        agreement_problem(grant, held, &own_sovereign, keys, &issuer_keys)
                    {
                        let at = if problem == "cited_agreement_missing" {
                            file
                        } else {
                            Some(AGREEMENTS_FILE)
                        };
                        result.fail(at, Some(seq), problem, id);
                    }
                }
                &grant["policy_binding"]
            }
            _ => continue,
        };
        if binding.is_null() {
            continue;
        }
        let applied = binding["policies"].as_array().cloned().unwrap_or_default();
        if policy_set_digest(&applied).ok().as_deref() != field(binding, "policy_set_digest") {
            result.fail(
                file,
                Some(seq),
                "cited_policy_mismatch",
                "policy_set_digest",
            );
        }
        for policy in &applied {
            let id = field(policy, "policy_id").unwrap_or_default();
            let version = policy["version"].as_i64().unwrap_or_default();
            let detail = format!("{id} v{version}");
            match by_version.get(&(id.to_owned(), version)) {
                None => result.fail(file, Some(seq), "cited_policy_missing", &detail),
                Some(held) => {
                    if policy_digest(held).ok().as_deref() != field(policy, "policy_digest") {
                        result.fail(file, Some(seq), "cited_policy_mismatch", &detail);
                    }
                }
            }
        }
    }
}

/// Why the agreement a grant rests on does not hold up in a pack, or `None`
/// (1.6.0 review fixes, the reference's `_agreement_problem`):
/// `cited_agreement_missing` when the pack does not hold it;
/// `cited_agreement_mismatch` when it is not the one the grant's
/// `basis_digest` names, or its parties are not the grant's (the responder is
/// the requester, the offerer the provider); `agreement_invalid_signature`
/// when its two parties did not sign it, as received, with keys the pack
/// vouches for (the NA's key valid at `agreed_terms.valid_from` for its own
/// sovereign, a treaty's subject keys for another; an agreement the NA
/// offered and accepted itself carries the NA's signature for both, which
/// holds only while the pack carries a treaty for the responder), or it is
/// not in the form the reference writes.
fn agreement_problem(
    grant: &Value,
    agreement: Option<&Value>,
    own: &str,
    keys: &NaKeys,
    treaty_keys: &HashMap<String, Vec<String>>,
) -> Option<&'static str> {
    let Some(agreement) = agreement else {
        return Some("cited_agreement_missing");
    };
    let valid_from = agreement["agreed_terms"]["valid_from"]
        .as_str()
        .and_then(|t| micros(t).ok());
    let readable = agreement.is_object()
        && [
            "agreement_id",
            "offerer_sovereign_id",
            "responder_sovereign_id",
        ]
        .iter()
        .all(|k| agreement[*k].is_string())
        && valid_from.is_some();
    if !readable {
        return Some("cited_agreement_mismatch");
    }
    let digest = received_canonical("AgreementRecord", agreement)
        .map(|body| sha256_hex(body.as_bytes()))
        .ok();
    if digest.as_deref() != field(grant, "basis_digest")
        || field(agreement, "responder_sovereign_id") != field(grant, "requester_sovereign_id")
        || field(agreement, "offerer_sovereign_id") != field(grant, "provider_sovereign_id")
    {
        return Some("cited_agreement_mismatch");
    }
    let na_keys = keys.at(valid_from);
    let party_keys = |party: &str| -> Vec<String> {
        if party == own {
            na_keys.clone()
        } else {
            treaty_keys
                .get(party)
                .into_iter()
                .flatten()
                .filter(|k| !na_keys.contains(k))
                .cloned()
                .collect()
        }
    };
    let offerer = field(agreement, "offerer_sovereign_id").unwrap_or_default();
    let responder = field(agreement, "responder_sovereign_id").unwrap_or_default();
    let mut pairs = vec![(party_keys(offerer), party_keys(responder))];
    // The NA-offered-and-accepted exception holds, as on the NA's routes,
    // only while the responder holds a treaty from this NA (one the pack
    // carries).
    let responder_trusted = treaty_keys.get(responder).is_some_and(|k| !k.is_empty());
    if offerer == own && responder_trusted {
        pairs.push((na_keys.clone(), na_keys.clone()));
    }
    let well_formed = unknown_fields("AgreementRecord", agreement).is_empty()
        && non_canonical_fields("AgreementRecord", agreement).is_empty();
    let signed = pairs.iter().any(|(offerer, responder)| {
        !offerer.is_empty()
            && !responder.is_empty()
            && signed_as_received("AgreementRecord", agreement, offerer)
            && signed_as_received("AgreementRecord", agreement, responder)
    });
    (!(signed && well_formed)).then_some("agreement_invalid_signature")
}

/// Where a verification differs from the checks the NA wrote into the pack
/// (`checks.json`): `verified`, the sorted reason codes, or a count. Not a
/// failure by itself (the NA's checks ran with the NA's anchors).
pub fn differences_from_pack_checks(
    result: &PackVerification,
    files: &BTreeMap<String, Vec<u8>>,
) -> Vec<Value> {
    let Some(claimed) = files.get(CHECKS_FILE).and_then(|data| read_json(data).ok()) else {
        return vec![json!({"field": CHECKS_FILE, "pack": null, "verifier": "unreadable"})];
    };
    let mut out = Vec::new();
    if claimed["verified"] != Value::Bool(result.verified) {
        out.push(
            json!({"field": "verified", "pack": claimed["verified"], "verifier": result.verified}),
        );
    }
    let reasons: BTreeSet<String> = claimed["failures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f.is_object())
        .map(|f| match &f["reason"] {
            Value::String(s) => s.clone(),
            Value::Null => "None".to_owned(),
            other => other.to_string(),
        })
        .collect();
    let reasons: Vec<String> = reasons.into_iter().collect();
    if reasons != result.reasons() {
        out.push(json!({"field": "failures", "pack": reasons, "verifier": result.reasons()}));
    }
    for (name, value) in &result.counts {
        let pack = claimed["counts"][name.as_str()].as_u64().unwrap_or(0);
        if pack != *value {
            out.push(json!({"field": format!("counts.{name}"), "pack": pack, "verifier": value}));
        }
    }
    out
}

// ── The report ───────────────────────────────────────────────────────────────

/// Python's truth value of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `a or b` as Python reads it.
fn or<'a>(a: &'a Value, b: &'a Value) -> &'a Value {
    if truthy(a) {
        a
    } else {
        b
    }
}

/// Python's `str()` of a JSON value, for the keys the report looks up.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// One value of the report, on one line (the reference's `_cell`): a
/// backslash is written `\\`, a `|` `\|`; a line feed, carriage return or
/// tab `\n`, `\r`, `\t`; any other control character (U+0000 to U+001F,
/// U+007F to U+009F) and the line and paragraph separators `\uXXXX`. A value
/// is written as itself when it is a string, in decimal when it is an
/// integer, `true` or `false`, empty when absent, and as canonical JSON
/// otherwise. A number with an integral value is written as an integer even
/// when it was read as a float (`1.0` is `1`; below 2^53 in magnitude).
pub fn report_cell(value: &Value) -> String {
    let text = match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
        // A number with an integral value is written as an integer even when
        // it was read as a float (`1.0` is `1`): JSON does not tell the two
        // apart in every language.
        Value::Number(n)
            if n.as_f64()
                .is_some_and(|f| f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0) =>
        {
            format!("{}", n.as_f64().unwrap_or_default() as i64)
        }
        other => pack_json(other),
    };
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        match ch {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if code < 0x20
                || (0x7F..=0x9F).contains(&code)
                || code == 0x2028
                || code == 0x2029 =>
            {
                out.push_str(&format!("\\u{code:04X}"));
            }
            _ => out.push(ch),
        }
    }
    out
}

/// One section of the report: its title, its headers and its rows.
type Section<'a> = (&'a str, &'a [&'a str], &'a [Vec<Value>]);

fn table(headers: &[&str], rows: &[Vec<Value>]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["None.".into(), String::new()];
    }
    let mut out = vec![
        format!("| {} |", headers.join(" | ")),
        format!("|{}|", vec!["---"; headers.len()].join("|")),
    ];
    for row in rows {
        let cells: Vec<String> = row.iter().map(report_cell).collect();
        out.push(format!("| {} |", cells.join(" | ")));
    }
    out.push(String::new());
    out
}

/// What [`render_report`] reads of a manifest (the reference's
/// `report_header`).
pub fn report_header(manifest: &Value) -> Value {
    let at = |key: &str| time_of(manifest, key).map(iso);
    json!({
        "pack_id": manifest["pack_id"],
        "sovereign_id": manifest["sovereign_id"],
        "from_sequence": manifest["from_sequence"],
        "through_sequence": manifest["through_sequence"],
        "start_anchor_sequence": manifest.get("start_anchor_sequence").cloned().unwrap_or(Value::Null),
        "end_anchor_sequence": manifest["end_anchor_sequence"],
        "created_at": at("created_at"),
        "requested_by": manifest.get("requested_by").cloned().unwrap_or(Value::Null),
        "period_from": at("period_from"),
        "period_until": at("period_until"),
    })
}

/// `report.md` (the reference's `render_report`, byte for byte): what a
/// reader of the pack sees first, from the manifest's header
/// ([`report_header`]), the entries, `checks.json` and the states and
/// notices of `states.json`.
pub fn render_report(
    header: &Value,
    entries: &[Value],
    checks: &Value,
    states: &Value,
    notices: &Value,
) -> String {
    let get = |key: &str| header.get(key).unwrap_or(&Value::Null);
    let cell = |key: &str| report_cell(get(key));
    let mut judgements: HashMap<(String, String), &Value> = HashMap::new();
    for e in entries {
        if field(&e["entry"], "entry_kind") == Some("judgement") {
            let p = &e["payload"];
            judgements.insert((py_str(&p["subject_kind"]), py_str(&p["subject_id"])), p);
        }
    }
    let mut lines: Vec<String> = vec![
        format!("# Audit pack {}", cell("pack_id")),
        String::new(),
        format!("- Sovereign: {}", cell("sovereign_id")),
        format!(
            "- Range: store entries {} to {}, ending at anchor {}{}",
            cell("from_sequence"),
            cell("through_sequence"),
            cell("end_anchor_sequence"),
            if truthy(get("start_anchor_sequence")) {
                format!(", starting after anchor {}", cell("start_anchor_sequence"))
            } else {
                String::new()
            }
        ),
        format!(
            "- Created: {}{}",
            cell("created_at"),
            if truthy(get("requested_by")) {
                format!(" for {}", cell("requested_by"))
            } else {
                String::new()
            }
        ),
    ];
    if truthy(get("period_from")) || truthy(get("period_until")) {
        lines.push(format!(
            "- Asked for: {} to {}",
            report_cell(or(get("period_from"), &json!("the start"))),
            report_cell(or(get("period_until"), &json!("the last anchor")))
        ));
    }
    lines.extend([
        String::new(),
        "Verify it with `genesis-mesh audit verify <dir> --anchor <root public key> --known-anchors <anchors>`, \
         from the root key and the anchors you hold. The remediation states and notices below are the \
         Network Authority's operational records at pack time (states.json), not signed records."
            .to_owned(),
        String::new(),
        "## Checks".to_owned(),
        String::new(),
        format!(
            "Verified by the Network Authority when it wrote the pack, against its own anchors: **{}**.",
            if truthy(&checks["verified"]) { "yes" } else { "no" }
        ),
        String::new(),
    ]);
    let failures: Vec<Vec<Value>> = checks["failures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f.is_object())
        .map(|f| {
            ["reason", "file", "store_sequence", "detail"]
                .iter()
                .map(|k| f.get(*k).cloned().unwrap_or(Value::Null))
                .collect()
        })
        .collect();
    lines.extend(table(&["Reason", "File", "Entry", "Detail"], &failures));
    lines.extend(["## Totals".to_owned(), String::new()]);
    let counts: Vec<Vec<Value>> = or(&checks["counts"], &json!({}))
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, v)| truthy(v))
        .map(|(k, v)| vec![json!(k), v.clone()])
        .collect();
    lines.extend(table(&["Records", "Count"], &counts));

    let state_of = |subject: &Value| -> Value {
        match states.get(py_str(subject)) {
            Some(Value::Object(value)) => value.get("state").cloned().unwrap_or(Value::Null),
            _ => Value::Null,
        }
    };
    let (mut changes, mut denials, mut remediations, mut reviews) =
        (vec![], vec![], vec![], vec![]);
    let (mut break_glass, mut quarantined, mut others) = (vec![], vec![], vec![]);
    // v1.6.0: grants and their revocations.
    let (mut grants, mut grant_revocations) = (vec![], vec![]);
    let null = Value::Null;
    for e in entries {
        let p = &e["payload"];
        let kind = field(&e["entry"], "entry_kind").unwrap_or_default();
        let seq = json!(seq_of(e));
        let at = |key: &str| p.get(key).cloned().unwrap_or(Value::Null);
        match kind {
            "execution" => {
                let state = state_of(&at("decision_id"));
                changes.push(vec![
                    seq,
                    json!(kind),
                    at("resource_id"),
                    at("resource_action"),
                    at("executed_at"),
                    json!("prior_decision"),
                    or(&state, &json!("recorded")).clone(),
                    at("executor_sovereign_id"),
                ]);
            }
            // v1.6.0: a change made under a grant, governed by it.
            "grant_execution" => changes.push(vec![
                seq,
                json!(kind),
                at("resource_id"),
                at("resource_action"),
                at("executed_at"),
                json!("grant"),
                json!("recorded"),
                at("executor_sovereign_id"),
            ]),
            "grant" => grants.push(vec![
                seq,
                at("grant_id"),
                at("bearer_sovereign_id"),
                at("capabilities"),
                at("valid_from"),
                at("valid_until"),
                at("max_uses"),
            ]),
            "grant_revocation" => {
                grant_revocations.push(vec![seq, at("grant_id"), at("reason"), at("revoked_at")])
            }
            "observation" | "break_glass" => {
                let record_id = py_str(or(&at("observation_id"), &at("break_glass_id")));
                let judgement = judgements.get(&(kind.to_owned(), record_id)).copied();
                let mut state = judgement.map_or(Value::Null, |j| state_of(&j["judgement_id"]));
                if state.is_null() {
                    state = json!(match judgement {
                        None => "observed",
                        // v1.6.0: or matched to a grant use.
                        Some(j)
                            if (j["governed_by"] == "prior_decision"
                                || j["governed_by"] == "grant")
                                && j["verdict"] != "deny" =>
                            "matched",
                        Some(j) => match py_str(&j["verdict"]).as_str() {
                            "allow" => "judged_allowed",
                            "deny" => "judged_denied",
                            _ => "indeterminate",
                        },
                    });
                }
                changes.push(vec![
                    seq.clone(),
                    json!(kind),
                    at("resource_id"),
                    or(&at("action"), &at("resource_action")).clone(),
                    or(
                        or(&at("changed_at"), &at("changed_not_after")),
                        &at("executed_at"),
                    )
                    .clone(),
                    judgement.map_or(Value::Null, |j| {
                        j.get("governed_by").cloned().unwrap_or(Value::Null)
                    }),
                    state,
                    at("actor"),
                ]);
                if kind == "break_glass" {
                    break_glass.push(vec![
                        seq,
                        at("resource_id"),
                        at("capability"),
                        at("executed_at"),
                        at("evaluation_failure"),
                        at("justification"),
                    ]);
                }
            }
            "decision" => {
                let decision = or(&p["decision"], &null);
                if decision.get("authorized") == Some(&Value::Bool(false)) {
                    denials.push(vec![
                        seq,
                        json!("decision"),
                        decision.get("decision_id").cloned().unwrap_or(Value::Null),
                        decision
                            .get("denial_reason")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ]);
                }
            }
            "judgement" if p["verdict"] == "deny" || p["verdict"] == "indeterminate" => {
                let reason = py_str(or(&at("reason"), &json!("")));
                denials.push(vec![
                    seq,
                    json!("judgement"),
                    at("judgement_id"),
                    json!(format!("{}: {reason}", py_str(&p["verdict"]))),
                ]);
            }
            "remediation" => remediations.push(vec![
                seq,
                at("subject_kind"),
                at("subject_id"),
                at("outcome"),
                at("steps"),
                at("remediated_at"),
                at("executor_sovereign_id"),
            ]),
            "review" => reviews.push(vec![
                seq,
                at("subject_id"),
                at("verdict"),
                at("requested_by"),
                at("requester_holder"),
                at("decided_by"),
                at("decider_holder"),
                at("decided_at"),
            ]),
            "quarantine" => quarantined.push(vec![
                seq,
                at("record_kind"),
                at("resource_id"),
                at("rejection_code"),
                at("quarantined_at"),
            ]),
            "key_succession" | "archive" => others.push(vec![
                seq,
                json!(kind),
                or(&at("succession_id"), &at("archive_id")).clone(),
                or(&at("effective_at"), &at("archived_at")).clone(),
            ]),
            _ => {}
        }
    }
    let notice_rows: Vec<Vec<Value>> = notices
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, v)| v.is_object())
        .map(|(k, v)| {
            vec![
                json!(k),
                v.get("notified_at").cloned().unwrap_or(Value::Null),
                v.get("notified_by").cloned().unwrap_or(Value::Null),
            ]
        })
        .collect();
    let mut sections: Vec<Section<'_>> = vec![
        (
            "Changes",
            &[
                "Entry",
                "Kind",
                "Resource",
                "Action",
                "Changed at",
                "Governed by",
                "State",
                "Actor",
            ],
            &changes,
        ),
        ("Denials", &["Entry", "Record", "ID", "Reason"], &denials),
        (
            "Remediations",
            &[
                "Entry",
                "Subject kind",
                "Subject",
                "Outcome",
                "Steps",
                "At",
                "Executor",
            ],
            &remediations,
        ),
        (
            "Reviews and deciders",
            &[
                "Entry",
                "Subject",
                "Verdict",
                "Requested by",
                "Requester holder",
                "Decided by",
                "Decider holder",
                "Decided at",
            ],
            &reviews,
        ),
        ("Notices", &["Subject", "Notified at", "By"], &notice_rows),
        (
            "Break-glass uses",
            &[
                "Entry",
                "Resource",
                "Capability",
                "Executed at",
                "Failure",
                "Justification",
            ],
            &break_glass,
        ),
        (
            "Quarantined records",
            &["Entry", "Record kind", "Resource", "Rejection", "At"],
            &quarantined,
        ),
        (
            "Key successions and archives",
            &["Entry", "Kind", "ID", "At"],
            &others,
        ),
    ];
    // v1.6.0: grants and their revocations, only in a pack that holds them
    // (a pack without them renders as in 1.5).
    if !grants.is_empty() {
        sections.push((
            "Grants",
            &[
                "Entry",
                "Grant",
                "Bearer",
                "Capabilities",
                "Valid from",
                "Valid until",
                "Budget",
            ],
            &grants,
        ));
    }
    if !grant_revocations.is_empty() {
        sections.push((
            "Grant revocations",
            &["Entry", "Grant", "Reason", "Revoked at"],
            &grant_revocations,
        ));
    }
    for (title, headers, rows) in sections {
        lines.extend([format!("## {title}"), String::new()]);
        lines.extend(table(headers, rows));
    }
    let mut text = lines.join("\n").trim_end_matches('\n').to_owned();
    text.push('\n');
    text
}

/// The report a verification renders from what it verified (`audit verify
/// --report`): its own verdict, failures and counts, the pack's verified
/// entries and its states and notices.
pub fn render_own_report(
    files: &BTreeMap<String, Vec<u8>>,
    result: &PackVerification,
) -> Result<String, String> {
    let manifest = read_json(files.get(MANIFEST_FILE).ok_or("manifest.json is missing")?)?;
    let entries = read_events(files.get(ENTRIES_FILE).ok_or("entries.jsonl is missing")?)?;
    let states = match files.get(STATES_FILE) {
        Some(data) => read_json(data)?,
        None => json!({}),
    };
    let checks = json!({
        "verified": result.verified,
        "failures": result.failures,
        "counts": result.counts,
    });
    let or_empty = |v: &Value| if truthy(v) { v.clone() } else { json!({}) };
    let text = render_report(
        &report_header(&manifest),
        &entries,
        &checks,
        &or_empty(&states["states"]),
        &or_empty(&states["notices"]),
    );
    Ok(text.replace(
        "Verified by the Network Authority when it wrote the pack, against its own anchors",
        "Verified by this verifier, from the root key and the anchors it holds",
    ))
}

// ── The completeness check ───────────────────────────────────────────────────

/// One change from a log outside Genesis Mesh (a cloud audit log, a
/// ticketing export).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// Its position in the file, from 1.
    pub index: usize,
    /// The resource changed.
    pub resource_id: String,
    /// What was done to it.
    pub action: String,
    /// When (microseconds since the epoch, UTC).
    pub changed_at: i64,
    /// The log it comes from (with `source_event_id`).
    pub source: Option<String>,
    /// Its id in that log.
    pub source_event_id: Option<String>,
    /// Who made it, as the log names them.
    pub actor: Option<String>,
}

impl Change {
    /// The reference's `Change.to_dict()`.
    pub fn to_json(&self) -> Value {
        json!({
            "index": self.index,
            "source": self.source,
            "source_event_id": self.source_event_id,
            "resource_id": self.resource_id,
            "action": self.action,
            "changed_at": iso(self.changed_at),
            "actor": self.actor,
        })
    }
}

/// The columns of a changes file.
pub const CHANGE_COLUMNS: [&str; 6] = [
    "source",
    "source_event_id",
    "resource_id",
    "action",
    "changed_at",
    "actor",
];

/// An RFC 3339 `date-time` (`T` and `Z` in either case, an offset required,
/// up to nine fraction digits, cut to microseconds), in microseconds since
/// the epoch, UTC; `None` for anything else: a date without a time, a space
/// for `T`, a missing offset, a leap second or an out-of-range field (the
/// reference's `parse_rfc3339`).
pub fn parse_rfc3339(value: &str) -> Option<i64> {
    let b = value.as_bytes();
    let digits = |from: usize, len: usize| -> Option<u32> {
        let part = b.get(from..from + len)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| std::str::from_utf8(part).ok()?.parse().ok())?
    };
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || !matches!(b.get(10), Some(b'T' | b't'))
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let mut at = 19;
    let mut micro = 0u32;
    if b.get(at) == Some(&b'.') {
        let count = b[at + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if !(1..=9).contains(&count) {
            return None;
        }
        let fraction = std::str::from_utf8(&b[at + 1..at + 1 + count]).ok()?;
        let six: String = fraction
            .chars()
            .chain(std::iter::repeat('0'))
            .take(6)
            .collect();
        micro = six.parse().ok()?;
        at += 1 + count;
    }
    let offset_minutes: i64 = match &b[at..] {
        b"Z" | b"z" => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (h, m) = (digits(at + 1, 2)?, digits(at + 4, 2)?);
            if h > 23 || m > 59 {
                return None;
            }
            let minutes = i64::from(h) * 60 + i64::from(m);
            if *sign == b'+' {
                minutes
            } else {
                -minutes
            }
        }
        _ => return None,
    };
    let date = chrono::NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?;
    if year == 0 {
        return None;
    }
    let time = chrono::NaiveTime::from_hms_micro_opt(hour, minute, second, micro)?;
    if second > 59 {
        return None;
    }
    let local = date.and_time(time).and_utc().timestamp_micros();
    Some(local - offset_minutes * 60_000_000)
}

/// RFC 4180 rows: commas, quoted fields with doubled quotes, CRLF or LF.
fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                cell.push('"');
            }
            (true, '"') => quoted = false,
            (true, c) => cell.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut cell)),
            (false, '\r') if chars.peek() == Some(&'\n') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|r| !(r.len() == 1 && r[0].is_empty()));
    rows
}

/// Changes from CSV (a header row naming [`CHANGE_COLUMNS`]) or JSON (a
/// list, or `{"changes": [...]}`), as the reference reads them:
/// `resource_id`, `action` and `changed_at` (RFC 3339 with an offset) are
/// required; `source` and `source_event_id` go together. In JSON a field is
/// a string or null (`true` or `7` is refused); an empty string is absent.
/// The error names the first bad row.
pub fn parse_changes(text: &str, csv: bool) -> std::result::Result<Vec<Change>, String> {
    let rows: Vec<Map<String, Value>> = if csv {
        let mut rows = csv_rows(text).into_iter();
        let header = rows.next().unwrap_or_default();
        rows.map(|row| {
            header
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    (
                        name.clone(),
                        row.get(i).map_or(Value::Null, |v| Value::String(v.clone())),
                    )
                })
                .collect()
        })
        .collect()
    } else {
        let data = parse_strict_json(text.trim_matches(JSON_SPACE)).map_err(|e| e.to_string())?;
        let listed = match &data {
            Value::Object(map) => map.get("changes").cloned().unwrap_or(Value::Null),
            other => other.clone(),
        };
        let Value::Array(items) = listed else {
            return Err("a JSON changes file is a list of changes or {\"changes\": [...]}".into());
        };
        items
            .into_iter()
            .enumerate()
            .map(|(i, item)| match item {
                Value::Object(map) => Ok(map),
                _ => Err(format!("change {} is not an object", i + 1)),
            })
            .collect::<std::result::Result<_, _>>()?
    };
    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let n = i + 1;
        let value = |name: &str| -> std::result::Result<Option<String>, String> {
            match row.get(name) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.trim().to_owned()).filter(|s| !s.is_empty())),
                Some(_) => Err(format!("change {n}: {name} must be a string")),
            }
        };
        let (Some(resource), Some(action), Some(changed)) = (
            value("resource_id")?,
            value("action")?,
            value("changed_at")?,
        ) else {
            return Err(format!(
                "change {n}: resource_id, action and changed_at are required"
            ));
        };
        let Some(at) = parse_rfc3339(&changed) else {
            return Err(format!(
                "change {n}: changed_at is not an RFC 3339 time with an offset (Z for UTC)"
            ));
        };
        let (source, event_id) = (value("source")?, value("source_event_id")?);
        if source.is_none() != event_id.is_none() {
            return Err(format!(
                "change {n}: source and source_event_id go together"
            ));
        }
        out.push(Change {
            index: n,
            resource_id: resource,
            action,
            changed_at: at,
            source,
            source_event_id: event_id,
            actor: value("actor")?,
        });
    }
    Ok(out)
}

/// A change as the pack records it: an observation, a break-glass record,
/// execution evidence or (1.6.0) a grant use.
#[derive(Debug, Clone)]
struct Recorded {
    kind: &'static str,
    record_id: String,
    store_sequence: i64,
    resource_id: String,
    action: String,
    earliest: i64,
    latest: i64,
    source: Option<String>,
    source_event_id: Option<String>,
    group: String,
}

impl Recorded {
    fn distance(&self, at: i64) -> i64 {
        if self.earliest <= at && at <= self.latest {
            0
        } else {
            (at - self.earliest).abs().min((at - self.latest).abs())
        }
    }
}

fn records(entries: &[Value], cited: &[Value]) -> Vec<Recorded> {
    let mut matched: HashMap<String, String> = HashMap::new();
    for event in cited.iter().chain(entries.iter()) {
        let p = &event["payload"];
        if field(&event["entry"], "entry_kind") == Some("judgement") {
            if let Some(evidence) = field(p, "matched_evidence_id").filter(|e| !e.is_empty()) {
                matched.insert(py_str(&p["subject_id"]), evidence.to_owned());
            }
        }
    }
    let mut out = Vec::new();
    for event in entries {
        let p = &event["payload"];
        let seq = seq_of(event);
        let text = |key: &str| field(p, key).map(str::to_owned);
        let when = |key: &str| field(p, key).and_then(|s| micros(s).ok());
        let record = match field(&event["entry"], "entry_kind") {
            Some("observation") => (|| {
                let start = when("changed_at").or_else(|| when("changed_not_before"))?;
                let stop = when("changed_at").or_else(|| when("changed_not_after"))?;
                Some(Recorded {
                    kind: "observation",
                    record_id: text("observation_id")?,
                    store_sequence: seq,
                    resource_id: text("resource_id")?,
                    action: text("action")?,
                    earliest: start,
                    latest: stop,
                    source: text("source"),
                    source_event_id: text("source_event_id"),
                    group: String::new(),
                })
            })(),
            // v1.6.0: a grant use is a change made under a grant.
            Some(kind @ ("break_glass" | "execution" | "grant_execution")) => (|| {
                if kind != "break_glass" && field(p, "resource_id").is_none_or(str::is_empty) {
                    return None;
                }
                let at = when("executed_at")?;
                let (kind, id) = match kind {
                    "execution" => ("execution", "evidence_id"),
                    "grant_execution" => ("grant_execution", "use_id"),
                    _ => ("break_glass", "break_glass_id"),
                };
                Some(Recorded {
                    kind,
                    record_id: text(id)?,
                    store_sequence: seq,
                    resource_id: text("resource_id")?,
                    action: text("resource_action")?,
                    earliest: at,
                    latest: at,
                    source: None,
                    source_event_id: None,
                    group: String::new(),
                })
            })(),
            _ => None,
        };
        out.extend(record);
    }
    // A governed change seen by an observer is one change: the observation
    // and what it matched.
    for record in &mut out {
        record.group = matched
            .get(&record.record_id)
            .cloned()
            .unwrap_or_else(|| record.record_id.clone());
    }
    out
}

/// The changes and recorded changes of one (resource, action).
type Bucket<'a, 'b> = (Vec<&'a Change>, Vec<&'b Group<'b>>);

/// One recorded change: the records of one group, matched by its
/// representative (its execution evidence or break-glass record when it
/// holds one, else its observation; the earliest in the store on a tie).
struct Group<'a> {
    group: String,
    members: Vec<&'a Recorded>,
}

impl Group<'_> {
    fn representative(&self) -> &Recorded {
        self.members
            .iter()
            .min_by_key(|r| (r.kind == "observation", r.store_sequence))
            .copied()
            .expect("a group holds a record")
    }
}

/// The matching of one (resource, action): the most pairs, then the least
/// total distance (the reference's `_match_bucket`). Changes in time order
/// (then by index) are matched to groups in time order (their
/// representative's earliest time, then store position) without crossing,
/// by dynamic programming; at each step the choices are, in this order,
/// pairing (when within the tolerance), leaving the change unmatched,
/// leaving the group unmatched, and the first best one is taken.
fn match_bucket<'a, 'b>(
    changes: &[&'a Change],
    groups: &[&'b Group<'b>],
    tolerance: i64,
) -> Vec<(&'a Change, &'b Group<'b>)> {
    let mut cs = changes.to_vec();
    cs.sort_by_key(|c| (c.changed_at, c.index));
    let mut gs = groups.to_vec();
    gs.sort_by_key(|g| {
        (
            g.representative().earliest,
            g.representative().store_sequence,
        )
    });
    let (n, m) = (cs.len(), gs.len());
    let mut best = vec![vec![(0i64, 0i64); m + 1]; n + 1];
    let mut choice = vec![vec![0u8; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            let mut options: Vec<((i64, i64), u8)> = Vec::with_capacity(3);
            let distance = gs[j].representative().distance(cs[i].changed_at);
            if distance <= tolerance {
                let (pairs, cost) = best[i + 1][j + 1];
                options.push(((pairs + 1, cost - distance), 0));
            }
            options.push((best[i + 1][j], 1));
            options.push((best[i][j + 1], 2));
            let top = options.iter().map(|o| o.0).max().unwrap_or_default();
            let (value, taken) = options
                .into_iter()
                .find(|o| o.0 == top)
                .unwrap_or(((0, 0), 1));
            best[i][j] = value;
            choice[i][j] = taken;
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        match choice[i][j] {
            0 => {
                out.push((cs[i], gs[j]));
                i += 1;
                j += 1;
            }
            1 => i += 1,
            _ => j += 1,
        }
    }
    out
}

/// Match changes from an outside log against a pack's records (the
/// reference's `check_completeness`):
///
/// 1. changes repeating a (source, source event id) pair already seen are set
///    aside (`duplicate_changes`);
/// 2. a change with a source and source event id matches the record that
///    names that very event when it agrees on resource and action;
/// 3. the rest are matched per (resource, action) by the best overall
///    pairing: an observation and the execution evidence it was matched to
///    are one change.
///
/// An unmatched change dated inside the period (microseconds, the tolerance
/// either side) is in `unmatched_changes`, one outside it in
/// `outside_period`; records no change matched are in `unmatched_records`.
pub fn check_completeness(
    changes: &[Change],
    entries: &[Value],
    cited: &[Value],
    period: (i64, i64),
    tolerance_seconds: i64,
) -> Value {
    let tolerance = tolerance_seconds * 1_000_000;
    let records = records(entries, cited);
    let mut groups: Vec<Group<'_>> = Vec::new();
    for record in &records {
        match groups.iter_mut().find(|g| g.group == record.group) {
            Some(group) => group.members.push(record),
            None => groups.push(Group {
                group: record.group.clone(),
                members: vec![record],
            }),
        }
    }
    let mut used: HashSet<String> = HashSet::new();
    let mut pairs: Vec<(usize, Value)> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let (mut duplicates, mut unique) = (Vec::new(), Vec::new());
    for change in changes {
        if let (Some(source), Some(event)) = (&change.source, &change.source_event_id) {
            if !seen.insert((source.clone(), event.clone())) {
                duplicates.push(change);
                continue;
            }
        }
        unique.push(change);
    }
    let mut by_event: HashMap<(String, String), &Recorded> = HashMap::new();
    for r in &records {
        if let (Some(source), Some(event)) = (&r.source, &r.source_event_id) {
            by_event.entry((source.clone(), event.clone())).or_insert(r);
        }
    }
    let pair = |change: &Change, r: &Recorded, how: &str| {
        (
            change.index,
            json!({"change": change.index, "kind": r.kind, "record_id": r.record_id,
                   "store_sequence": r.store_sequence, "matched_by": how}),
        )
    };
    let mut left: Vec<&Change> = Vec::new();
    for change in unique {
        let named = match (&change.source, &change.source_event_id) {
            (Some(source), Some(event)) => by_event.get(&(source.clone(), event.clone())).copied(),
            _ => None,
        };
        match named {
            Some(r)
                if !used.contains(&r.group)
                    && r.resource_id == change.resource_id
                    && r.action == change.action =>
            {
                used.insert(r.group.clone());
                pairs.push(pair(change, r, "source_event_id"));
            }
            _ => left.push(change),
        }
    }
    let mut buckets: BTreeMap<(String, String), Bucket<'_, '_>> = BTreeMap::new();
    for change in &left {
        buckets
            .entry((change.resource_id.clone(), change.action.clone()))
            .or_default()
            .0
            .push(change);
    }
    for group in groups.iter().filter(|g| !used.contains(&g.group)) {
        let rep = group.representative();
        if let Some(bucket) = buckets.get_mut(&(rep.resource_id.clone(), rep.action.clone())) {
            bucket.1.push(group);
        }
    }
    let mut matched_changes: HashSet<usize> = HashSet::new();
    for (bucket_changes, bucket_groups) in buckets.values() {
        for (change, group) in match_bucket(bucket_changes, bucket_groups, tolerance) {
            used.insert(group.group.clone());
            matched_changes.insert(change.index);
            pairs.push(pair(change, group.representative(), "resource_action_time"));
        }
    }
    let unmatched: Vec<&Change> = left
        .into_iter()
        .filter(|c| !matched_changes.contains(&c.index))
        .collect();
    let (start, end) = period;
    let (mut inside, mut outside): (Vec<&Change>, Vec<&Change>) = unmatched
        .into_iter()
        .partition(|c| start - tolerance <= c.changed_at && c.changed_at <= end + tolerance);
    inside.sort_by_key(|c| c.index);
    outside.sort_by_key(|c| c.index);
    let mut unmatched_records: Vec<&Recorded> = groups
        .iter()
        .filter(|g| !used.contains(&g.group))
        .map(Group::representative)
        .collect();
    unmatched_records.sort_by_key(|r| r.store_sequence);
    pairs.sort_by_key(|(index, _)| *index);
    json!({
        "changes": changes.len(),
        "tolerance_seconds": tolerance_seconds,
        "period": {"from": iso(start), "to": iso(end)},
        "pairs": pairs.into_iter().map(|(_, p)| p).collect::<Vec<_>>(),
        "unmatched_changes": inside.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
        "outside_period": outside.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
        "duplicate_changes": duplicates.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
        "unmatched_records": unmatched_records.iter().map(|r| json!({
            "kind": r.kind, "record_id": r.record_id, "store_sequence": r.store_sequence,
            "resource_id": r.resource_id, "action": r.action,
        })).collect::<Vec<_>>(),
        "complete": inside.is_empty(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{load_signing_key, public_key_from_seed, sign_canonical};

    fn seed(byte: u8) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    /// The registry suite's agreement, signed by `signers` (seeds).
    fn agreement(signers: &[u8]) -> Value {
        let suite: Value =
            serde_json::from_str(include_str!("../tests/fixtures/field_registry.json")).unwrap();
        let mut record = suite["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "agreementrecord-clean")
            .unwrap()["record"]
            .clone();
        let body = received_canonical("AgreementRecord", &record).unwrap();
        record["signatures"] = Value::Array(
            signers
                .iter()
                .map(|s| sign_canonical(&body, "k", &load_signing_key(&seed(*s)).unwrap()))
                .collect(),
        );
        record
    }

    fn grant_on(agreement: &Value) -> Value {
        let body = received_canonical("AgreementRecord", agreement).unwrap();
        json!({
            "basis_digest": sha256_hex(body.as_bytes()),
            "requester_sovereign_id": agreement["responder_sovereign_id"],
            "provider_sovereign_id": agreement["offerer_sovereign_id"],
        })
    }

    #[test]
    fn a_grant_on_an_agreement_rests_on_one_both_parties_signed_with_keys_the_pack_vouches_for() {
        // The NA is the offerer's sovereign (`sovereign-a`); the responder's
        // keys come from its treaty.
        let na = NaKeys::Any(vec![public_key_from_seed(&seed(1)).unwrap()]);
        let treaties: HashMap<String, Vec<String>> = [(
            "sovereign-b".to_owned(),
            vec![public_key_from_seed(&seed(2)).unwrap()],
        )]
        .into();
        let signed = agreement(&[1, 2]);
        let grant = grant_on(&signed);
        let problem = |record: Option<&Value>, grant: &Value| {
            agreement_problem(grant, record, "sovereign-a", &na, &treaties)
        };
        assert_eq!(problem(Some(&signed), &grant), None);
        assert_eq!(problem(None, &grant), Some("cited_agreement_missing"));
        // Another agreement than the grant's digest names, or other parties.
        let mut other = grant.clone();
        other["basis_digest"] = json!("0".repeat(64));
        assert_eq!(
            problem(Some(&signed), &other),
            Some("cited_agreement_mismatch")
        );
        let mut parties = grant.clone();
        parties["requester_sovereign_id"] = json!("sovereign-x");
        assert_eq!(
            problem(Some(&signed), &parties),
            Some("cited_agreement_mismatch")
        );
        // The NA is the responder's sovereign, and another key signed for it.
        let na_b = NaKeys::Any(vec![public_key_from_seed(&seed(2)).unwrap()]);
        let treaty_a: HashMap<String, Vec<String>> = [(
            "sovereign-a".to_owned(),
            vec![public_key_from_seed(&seed(1)).unwrap()],
        )]
        .into();
        let as_responder = |record: &Value| {
            agreement_problem(
                &grant_on(record),
                Some(record),
                "sovereign-b",
                &na_b,
                &treaty_a,
            )
        };
        assert_eq!(as_responder(&signed), None);
        assert_eq!(
            as_responder(&agreement(&[1, 3])),
            Some("agreement_invalid_signature")
        );
        // An offerer no treaty vouches for.
        assert_eq!(
            as_responder(&agreement(&[4, 2])),
            Some("agreement_invalid_signature")
        );
        // An agreement the NA offered and accepted itself, signed by the NA
        // alone: it holds while the pack carries the responder's treaty, and
        // not without it.
        let own = agreement(&[1]);
        assert_eq!(problem(Some(&own), &grant_on(&own)), None);
        let no_treaty = HashMap::new();
        assert_eq!(
            agreement_problem(&grant_on(&own), Some(&own), "sovereign-a", &na, &no_treaty),
            Some("agreement_invalid_signature")
        );
    }
}
