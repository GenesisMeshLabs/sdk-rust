//! Audit packs (1.5.0): offline verification and the completeness check, a
//! direct port of the Python reference's `audit verify`
//! (`workflows/audit_pack.py`), with its reason codes. The normative page is
//! the core's `docs/reference/audit-pack-format.md`.
//!
//! A pack (format `gm.audit.pack`, version 1) holds one range of the
//! evidence store between two anchors, everything its records cite, the NA's
//! key history and a manifest the NA signs. [`verify_audit_pack`] checks it
//! from material the verifier holds itself, the root public key and its
//! copies of the anchors, in this order:
//!
//! 1. the manifest (`manifest_*`); a pack whose manifest fails is not checked
//!    further;
//! 2. the key history from the root key down (`genesis_*`, the succession
//!    reasons, `key_history_invalid`); a history that fails stops it;
//! 3. the anchors (the anchor reasons, `pack_end_anchor_mismatch`,
//!    `pack_end_anchor_not_held`, `pack_start_not_tied`,
//!    `pack_start_anchor_not_held`, and the range against the held anchors);
//! 4. the entries (`entries_invalid`, `pack_range_mismatch`,
//!    `cited_out_of_range`, then every export reason with the cited records
//!    as predecessors, `cited_record_missing` among them);
//! 5. what the records rest on outside the store (`cited_trust_invalid`, the
//!    `*_invalid_signature` reasons, `cited_policy_*`, `cited_attestation_*`);
//! 6. with a changes file, the completeness check (`change_unmatched`).
//!
//! No network and no private key: every key comes from the caller.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    auth::{canonical_json, verify_canonical},
    canonical::{
        attestation_canonical, entry_digest, micros, out_of_band_canonical, parse_timestamp,
        policy_canonical, policy_digest, policy_set_digest, python_timestamp, received_canonical,
    },
    key_history::{verify_key_history, NaKeyHistory, NaKeys},
    strict::unknown_fields,
    strict_json::parse_strict_json,
    verify::{
        check_anchors, check_events_against_anchors, parse_export_lines, reads_as, signed_by,
        verify_boundary_decision, verify_evidence_events, verify_store_anchors, AnchorCoverage,
        EvidenceVerification, VerifyDecisionOptions, VerifyEvidenceOptions,
    },
};

/// The pack format and version this module reads.
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
/// The attestations the records name.
pub const ATTESTATIONS_FILE: &str = "trust/attestations.jsonl";
/// The treaties for those attestations' issuers.
pub const TREATIES_FILE: &str = "trust/treaties.jsonl";
/// The revocation feeds of those issuers.
pub const FEEDS_FILE: &str = "trust/feeds.jsonl";

/// Every file of a pack but the manifest (format version 1).
pub const PACK_FILES: [&str; 12] = [
    ANCHORS_FILE,
    CHECKS_FILE,
    CITED_FILE,
    ENTRIES_FILE,
    EXECUTOR_KEYS_FILE,
    GENESIS_FILE,
    KEY_HISTORY_FILE,
    POLICIES_FILE,
    REPORT_FILE,
    ATTESTATIONS_FILE,
    FEEDS_FILE,
    TREATIES_FILE,
];

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
        let set: std::collections::BTreeSet<&str> =
            self.failures.iter().map(|f| f.reason.as_str()).collect();
        set.into_iter().map(str::to_owned).collect()
    }

    /// The reference's JSON form (`audit verify --format json`, without
    /// `report_differences`).
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
    /// registry records (as `GET /admin/evidence/executor-keys` lists them).
    pub executor_keys: Vec<Value>,
    /// Changes from a log outside Genesis Mesh, for the completeness check.
    pub changes: Option<Vec<Change>>,
    /// How far apart a change and its record may be, in seconds.
    pub tolerance_seconds: i64,
    /// False verifies the files before a manifest exists (the NA writing
    /// `checks.json`).
    pub check_manifest: bool,
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

/// A pack JSON file's bytes: canonical JSON (keys sorted, no whitespace,
/// characters outside ASCII written as themselves) and an LF.
pub fn pack_json_bytes(value: &Value) -> Vec<u8> {
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

/// A time as Python's `datetime.isoformat()` writes a UTC one.
fn isoformat(at: i64) -> String {
    chrono::DateTime::from_timestamp_micros(at)
        .map(python_timestamp)
        .map(|s| match s.strip_suffix('Z') {
            Some(rest) => format!("{rest}+00:00"),
            None => s,
        })
        .unwrap_or_default()
}

fn time_of(value: &Value, key: &str) -> Option<i64> {
    micros(field(value, key)?).ok()
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
/// defaults filled), absent optional fields left out, `created_at` as
/// Pydantic writes it.
fn manifest_bytes(m: &Value) -> Option<Vec<u8>> {
    let mut wire = m.as_object()?.clone();
    wire.retain(|_, v| !v.is_null());
    for key in ["format", "format_version", "pack_id"] {
        if !wire.contains_key(key) {
            return None;
        }
    }
    let created = parse_timestamp(field(m, "created_at")?).ok()?;
    wire.insert(
        "created_at".into(),
        Value::String(python_timestamp(created)),
    );
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

/// `None` when the signature verifies with the NA key valid at `at`, else
/// the reason (`na_key_not_valid_at_time` for another key of the history).
fn signed_at(
    verifies: &dyn Fn(&[String]) -> bool,
    keys: &NaKeys,
    at: Option<i64>,
) -> Option<&'static str> {
    let at = at?;
    if verifies(&keys.at(Some(at))) {
        return None;
    }
    Some(if verifies(&keys.not_at(at)) {
        "na_key_not_valid_at_time"
    } else {
        "invalid_signature"
    })
}

/// Executor and observer keys from the registry records the NA signed (by
/// the key valid at the entry's time), in store order.
fn registry_keys(events: &[&Value], keys: &NaKeys) -> Vec<Value> {
    let mut sorted: Vec<&&Value> = events.iter().collect();
    sorted.sort_by_key(|e| seq_of(e));
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    for event in sorted {
        let record = &event["payload"];
        if field(&event["entry"], "entry_kind") != Some("registry")
            || !reads_as("RegistryRecord", record)
        {
            continue;
        }
        let verifies =
            |k: &[String]| signed_by(out_of_band_canonical(record), record.get("signature"), k);
        let at = time_of(&event["entry"], "recorded_at");
        if record["signature"].is_null() || signed_at(&verifies, keys, at).is_some() {
            continue;
        }
        let named = |key: &str| field(record, key).filter(|v| !v.is_empty());
        if let (Some("executor_key_registered"), Some(key_id), Some(public_key), Some(sovereign)) = (
            field(record, "event"),
            named("key_id"),
            named("public_key"),
            named("executor_sovereign_id"),
        ) {
            out.insert(
                key_id.to_owned(),
                json!({
                    "key_id": key_id,
                    "public_key": public_key,
                    "executor_sovereign_id": sovereign,
                    "role": field(record, "key_role").unwrap_or("executor"),
                    "resource_prefix": record.get("resource_prefix").cloned().unwrap_or(Value::Null),
                }),
            );
        }
    }
    out.into_values().collect()
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
        let verifies = |k: &[String]| signed_by(out_of_band_canonical(m), m.get("signature"), k);
        let refusal = if m["signature"].is_null() {
            Some("invalid_signature")
        } else {
            signed_at(&verifies, &keys, time_of(m, "created_at"))
        };
        if let Some(reason) = refusal {
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
    let recorded = |e: &Value| {
        time_of(&e["entry"], "recorded_at")
            .map(isoformat)
            .unwrap_or_default()
    };
    result.range = json!({
        "from_sequence": first,
        "through_sequence": last,
        "entries": entries.len(),
        "first_recorded_at": recorded(first_event),
        "last_recorded_at": recorded(last_event),
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
    let by_sequence: HashMap<i64, &Value> = pack_anchors
        .iter()
        .map(|a| (a["anchor_sequence"].as_i64().unwrap_or_default(), a))
        .collect();
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
    let start_anchor = manifest
        .as_ref()
        .and_then(|m| anchor_at(m, "start_anchor_sequence"));
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
            let held_by: HashMap<i64, &Value> = held
                .iter()
                .map(|a| (a["anchor_sequence"].as_i64().unwrap_or_default(), a))
                .collect();
            for anchor in &pack_anchors {
                let n = anchor["anchor_sequence"].as_i64().unwrap_or_default();
                if held_by.get(&n).is_some_and(|mine| anchor_wire(mine) != anchor_wire(anchor)) {
                    let detail = format!("anchor {n} differs from the one held");
                    result.fail(Some(ANCHORS_FILE), anchor["store_sequence"].as_i64(), "anchor_mismatch", &detail);
                }
            }
            let number = |a: &Value| a["anchor_sequence"].as_i64().unwrap_or_default();
            if let Some(end) = end.filter(|end| !held_by.contains_key(&number(end))) {
                let detail = format!("anchor {} is not among the anchors held", number(end));
                result.fail(Some(ANCHORS_FILE), Some(last), "pack_end_anchor_not_held", &detail);
            }
            if let Some(start) = start_anchor.filter(|start| {
                !held_by.contains_key(&number(start)) && start_checkpoint.is_none() && first != 1
            }) {
                let detail = format!("anchor {} is not among the anchors held", number(start));
                result.fail(Some(ANCHORS_FILE), Some(first), "pack_start_anchor_not_held", &detail);
            }
            let inside: Vec<Value> = held
                .iter()
                .filter(|a| a["store_sequence"].as_i64().is_some_and(|s| s <= last))
                .cloned()
                .collect();
            let mut tied_result = EvidenceVerification::empty();
            let coverage = check_events_against_anchors(&entries, &inside, &mut tied_result, false, true);
            for f in tied_result.failures {
                result.fail(Some(ENTRIES_FILE), f.store_sequence, &f.reason, &f.detail);
            }
            result.anchors = Some(coverage);
        }
    }

    // 4. Executor keys: from registry records the NA signed, then keys
    // supplied out of band.
    let all: Vec<&Value> = cited.iter().chain(entries.iter()).collect();
    let mut executor_keys = registry_keys(&all, &keys);
    let supplied: HashSet<&str> = options
        .executor_keys
        .iter()
        .filter_map(|k| field(k, "key_id"))
        .collect();
    executor_keys.retain(|k| !field(k, "key_id").is_some_and(|id| supplied.contains(id)));
    executor_keys.extend(options.executor_keys.iter().cloned());
    let verification = verify_evidence_events(
        &entries,
        &VerifyEvidenceOptions {
            checkpoint: start_checkpoint,
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

    // 6. Completeness.
    if let Some(changes) = &options.changes {
        let start = time_of(&first_event["entry"], "recorded_at").unwrap_or_default();
        let stop = end
            .and_then(|end| time_of(end, "anchored_at"))
            .or_else(|| time_of(&last_event["entry"], "recorded_at"))
            .unwrap_or_default();
        let report = check_completeness(
            changes,
            &entries,
            &cited,
            (start, stop),
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
        ))
    })();
    let (policies, attestations, treaties, feeds) = match read_all {
        Ok(all) => all,
        Err(e) => {
            let detail: String = e.chars().take(200).collect();
            result.fail(Some(POLICIES_FILE), None, "cited_trust_invalid", &detail);
            return;
        }
    };
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
            .all(|i| i["signatures"].is_array() || i.get("signatures").is_none())
    };
    if !shaped(&policies, &["policy_id"], "issued_at")
        || !policies.iter().all(|p| p["version"].is_i64())
        || !shaped(
            &attestations,
            &["attestation_id", "issuer_sovereign_id"],
            "issued_at",
        )
        || !lists(&attestations)
        || !shaped(
            &treaties,
            &["treaty_id", "subject_sovereign_id"],
            "issued_at",
        )
        || !lists(&treaties)
        || !shaped(&feeds, &["feed_id", "issuer_sovereign_id"], "issued_at")
        || !lists(&feeds)
    {
        result.fail(
            Some(POLICIES_FILE),
            None,
            "cited_trust_invalid",
            "a record is not of its model",
        );
        return;
    }
    let any_signature =
        |canonical: Result<String, crate::GenesisMeshError>, item: &Value, k: &[String]| {
            let Ok(body) = canonical else { return false };
            item["signatures"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| field(s, "sig"))
                .any(|sig| verify_canonical(&body, sig, k))
        };

    let mut by_version: HashMap<(String, i64), &Value> = HashMap::new();
    for policy in &policies {
        let verifies =
            |k: &[String]| signed_by(policy_canonical(policy), policy.get("signature"), k);
        let refusal = if policy["signature"].is_null() {
            Some("invalid_signature")
        } else {
            signed_at(&verifies, keys, time_of(policy, "issued_at"))
        };
        let id = field(policy, "policy_id").unwrap_or_default();
        let version = policy["version"].as_i64().unwrap_or_default();
        if let Some(reason) = refusal {
            let reason = if reason == "invalid_signature" {
                "policy_invalid_signature"
            } else {
                reason
            };
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
    let mut issuer_keys: HashMap<String, Vec<String>> = HashMap::new();
    for treaty in &treaties {
        let body = |t: &Value| {
            let mut fields = t.as_object().cloned().unwrap_or_default();
            fields.remove("signatures");
            canonical_json(&Value::Object(fields))
        };
        let verifies = |k: &[String]| any_signature(body(treaty), treaty, k);
        if let Some(reason) = signed_at(&verifies, keys, time_of(treaty, "issued_at")) {
            let reason = if reason == "invalid_signature" {
                "treaty_invalid_signature"
            } else {
                reason
            };
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
        let verifies =
            |k: &[String]| any_signature(attestation_canonical(attestation), attestation, k);
        let refusal = if issuer == own {
            signed_at(&verifies, keys, time_of(attestation, "issued_at"))
        } else {
            let k = issuer_keys.get(issuer).cloned().unwrap_or_default();
            (!verifies(&k)).then_some("invalid_signature")
        };
        let id = field(attestation, "attestation_id").unwrap_or_default();
        if let Some(reason) = refusal {
            let reason = if reason == "invalid_signature" {
                "attestation_invalid_signature"
            } else {
                reason
            };
            result.fail(Some(ATTESTATIONS_FILE), None, reason, id);
        }
        by_attestation.insert(id, attestation);
    }
    for feed in &feeds {
        let k = issuer_keys
            .get(field(feed, "issuer_sovereign_id").unwrap_or_default())
            .cloned()
            .unwrap_or_default();
        if !any_signature(
            received_canonical("SovereignRevocationFeed", feed),
            feed,
            &k,
        ) {
            result.fail(
                Some(FEEDS_FILE),
                None,
                "feed_invalid_signature",
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
    let reasons: std::collections::BTreeSet<String> = claimed["failures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f.is_object())
        .map(|f| match &f["reason"] {
            Value::String(s) => s.clone(),
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

/// Where a verification differs from what `report.md` says the NA found:
/// its verdict, the reasons in its checks table and its totals. The fields
/// start with `report.md`.
pub fn differences_from_report(
    result: &PackVerification,
    files: &BTreeMap<String, Vec<u8>>,
) -> Vec<Value> {
    let Some(report) = files
        .get(REPORT_FILE)
        .and_then(|data| std::str::from_utf8(data).ok())
    else {
        return vec![json!({"field": REPORT_FILE, "pack": null, "verifier": "unreadable"})];
    };
    let lines: Vec<&str> = report.lines().collect();
    // The table that follows a heading or line, up to the next blank line.
    let table = |from: usize| -> Vec<Vec<String>> {
        lines
            .iter()
            .skip(from)
            .skip_while(|l| !l.starts_with('|'))
            .take_while(|l| l.starts_with('|'))
            .skip(2)
            .map(|row| {
                row.trim_matches('|')
                    .split(" | ")
                    .map(|cell| cell.trim().to_owned())
                    .collect()
            })
            .collect()
    };
    let mut out = Vec::new();
    let verdict = lines
        .iter()
        .position(|l| l.starts_with("Verified by the Network Authority"));
    let said = verdict.map(|i| lines[i].contains("**yes**"));
    if said != Some(result.verified) {
        out.push(json!({"field": "report.md verified", "pack": said, "verifier": result.verified}));
    }
    if let Some(i) = verdict {
        let none = lines.get(i + 2).is_some_and(|l| l.starts_with("None."));
        let reasons: std::collections::BTreeSet<String> = if none {
            Default::default()
        } else {
            table(i + 1)
                .into_iter()
                .filter_map(|row| row.first().cloned())
                .collect()
        };
        let reasons: Vec<String> = reasons.into_iter().collect();
        if reasons != result.reasons() {
            out.push(json!({"field": "report.md failures", "pack": reasons, "verifier": result.reasons()}));
        }
    }
    if let Some(i) = lines.iter().position(|l| *l == "## Totals") {
        let none = lines.get(i + 2).is_some_and(|l| l.starts_with("None."));
        let said: BTreeMap<String, u64> = if none {
            BTreeMap::new()
        } else {
            table(i)
                .into_iter()
                .filter_map(|row| Some((row.first()?.clone(), row.get(1)?.parse().ok()?)))
                .collect()
        };
        for (name, value) in result.counts.iter().filter(|(_, v)| **v > 0) {
            let pack = said.get(name).copied().unwrap_or(0);
            if pack != *value {
                out.push(json!({"field": format!("report.md counts.{name}"), "pack": pack, "verifier": value}));
            }
        }
    }
    out
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
            "changed_at": isoformat(self.changed_at),
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
/// `resource_id`, `action` and `changed_at` (ISO 8601 with an offset) are
/// required; `source` and `source_event_id` go together. The error names the
/// first bad row.
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
        let value = |name: &str| match row.get(name) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) => Some(s.trim().to_owned()),
            Some(other) => Some(other.to_string().trim().to_owned()),
        };
        let (Some(resource), Some(action), Some(changed)) =
            (value("resource_id"), value("action"), value("changed_at"))
        else {
            return Err(format!(
                "change {n}: resource_id, action and changed_at are required"
            ));
        };
        if resource.is_empty() || action.is_empty() || changed.is_empty() {
            return Err(format!(
                "change {n}: resource_id, action and changed_at are required"
            ));
        }
        let at = chrono::DateTime::parse_from_rfc3339(&changed)
            .or_else(|_| chrono::DateTime::parse_from_str(&changed, "%Y-%m-%dT%H:%M:%S%.f%:z"))
            .map_err(|_| {
                if parse_timestamp(&changed).is_ok() {
                    format!("change {n}: changed_at needs an offset (Z for UTC)")
                } else {
                    format!("change {n}: changed_at is not an ISO 8601 time")
                }
            })?;
        let (source, event_id) = (value("source"), value("source_event_id"));
        if source.is_none() != event_id.is_none() {
            return Err(format!(
                "change {n}: source and source_event_id go together"
            ));
        }
        out.push(Change {
            index: n,
            resource_id: resource,
            action,
            changed_at: at.timestamp_micros(),
            source,
            source_event_id: event_id,
            actor: value("actor"),
        });
    }
    Ok(out)
}

/// A change as the pack records it: an observation, a break-glass record or
/// execution evidence.
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
                let subject = match &p["subject_id"] {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                matched.insert(subject, evidence.to_owned());
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
            Some(kind @ ("break_glass" | "execution")) => (|| {
                if kind == "execution" && field(p, "resource_id").is_none_or(str::is_empty) {
                    return None;
                }
                let at = when("executed_at")?;
                let id = if kind == "execution" {
                    "evidence_id"
                } else {
                    "break_glass_id"
                };
                Some(Recorded {
                    kind: if kind == "execution" {
                        "execution"
                    } else {
                        "break_glass"
                    },
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

/// Match changes from an outside log against a pack's records (the
/// reference's `check_completeness`): first by source and source event id
/// (an observation of that very event), then by resource, action and time
/// within the tolerance (the closest record, the earliest on a tie; each
/// record matched once; an observation and the execution evidence it was
/// matched to are one change). An unmatched change dated inside the period
/// (microseconds, widened by the tolerance) is in `unmatched_changes`, one
/// outside it in `outside_period`; records no change matched are in
/// `unmatched_records`.
pub fn check_completeness(
    changes: &[Change],
    entries: &[Value],
    cited: &[Value],
    period: (i64, i64),
    tolerance_seconds: i64,
) -> Value {
    let tolerance = tolerance_seconds * 1_000_000;
    let records = records(entries, cited);
    let mut used: HashSet<String> = HashSet::new();
    let mut pairs: Vec<(usize, Value)> = Vec::new();
    let mut left: Vec<&Change> = Vec::new();
    let mut by_event: HashMap<(String, String), &Recorded> = HashMap::new();
    for r in &records {
        if let (Some(source), Some(event)) = (&r.source, &r.source_event_id) {
            by_event.insert((source.clone(), event.clone()), r);
        }
    }
    let pair = |change: &Change, r: &Recorded, how: &str| {
        (
            change.index,
            json!({"change": change.index, "kind": r.kind, "record_id": r.record_id,
                   "store_sequence": r.store_sequence, "matched_by": how}),
        )
    };
    for change in changes {
        let found = change.source.as_ref().and_then(|source| {
            by_event
                .get(&(
                    source.clone(),
                    change.source_event_id.clone().unwrap_or_default(),
                ))
                .copied()
        });
        match found {
            Some(r) if !used.contains(&r.group) => {
                used.insert(r.group.clone());
                pairs.push(pair(change, r, "source_event_id"));
            }
            _ => left.push(change),
        }
    }
    let mut unmatched: Vec<&Change> = Vec::new();
    for change in left {
        let best = records
            .iter()
            .filter(|r| {
                !used.contains(&r.group)
                    && r.resource_id == change.resource_id
                    && r.action == change.action
                    && r.distance(change.changed_at) <= tolerance
            })
            .min_by_key(|r| (r.distance(change.changed_at), r.store_sequence));
        match best {
            Some(r) => {
                used.insert(r.group.clone());
                pairs.push(pair(change, r, "resource_action_time"));
            }
            None => unmatched.push(change),
        }
    }
    let (start, end) = period;
    let (inside, outside): (Vec<&Change>, Vec<&Change>) = unmatched
        .into_iter()
        .partition(|c| start - tolerance <= c.changed_at && c.changed_at <= end + tolerance);
    let mut last_of_group: BTreeMap<String, &Recorded> = BTreeMap::new();
    for r in records.iter().filter(|r| !used.contains(&r.group)) {
        last_of_group.insert(r.group.clone(), r);
    }
    let mut unmatched_records: Vec<&Recorded> = last_of_group.into_values().collect();
    unmatched_records.sort_by_key(|r| r.store_sequence);
    pairs.sort_by_key(|(index, _)| *index);
    json!({
        "changes": changes.len(),
        "tolerance_seconds": tolerance_seconds,
        "period": {"from": isoformat(start), "to": isoformat(end)},
        "pairs": pairs.into_iter().map(|(_, p)| p).collect::<Vec<_>>(),
        "unmatched_changes": inside.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
        "outside_period": outside.iter().map(|c| c.to_json()).collect::<Vec<_>>(),
        "unmatched_records": unmatched_records.iter().map(|r| json!({
            "kind": r.kind, "record_id": r.record_id, "store_sequence": r.store_sequence,
            "resource_id": r.resource_id, "action": r.action,
        })).collect::<Vec<_>>(),
        "complete": inside.is_empty(),
    })
}
