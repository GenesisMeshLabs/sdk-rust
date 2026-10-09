//! The evidence outbox storage (v1.2.0): `FileOutbox` and `MemoryOutbox`,
//! error classification and backoff.

use std::{fs, path::PathBuf, time::Duration};

use genesis_mesh_sdk::{
    classify_submission_error, json, retry_delay, EvidenceOutbox, FileOutbox, GenesisMeshError,
    MemoryOutbox, OutboxEntry, OutboxState,
};

fn entry(id: &str) -> OutboxEntry {
    OutboxEntry::new(json!({"evidence_id": id, "outcome": "success"}))
}

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("gm-outbox-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn outbox(&self) -> PathBuf {
        self.0.join("outbox")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ids(outbox: &dyn EvidenceOutbox) -> Vec<String> {
    outbox.list().unwrap().into_iter().map(|e| e.id).collect()
}

fn exercise(outbox: &dyn EvidenceOutbox) {
    for id in ["b", "a", "c"] {
        outbox.add(&entry(id)).unwrap();
    }
    assert_eq!(
        outbox.add(&entry("a")).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    let mut a = entry("a");
    a.attempts = 2;
    a.state = OutboxState::DeadLetter;
    outbox.update(&a).unwrap();
    outbox.remove("b").unwrap();
    outbox.remove("missing").unwrap();
    outbox.update(&entry("missing")).unwrap();
    let listed = outbox.list().unwrap();
    assert_eq!(ids(outbox), ["a", "c"]);
    assert_eq!(
        (listed[0].attempts, listed[0].state),
        (2, OutboxState::DeadLetter)
    );
}

#[test]
fn memory_outbox_keeps_order_and_updates_by_id() {
    exercise(&MemoryOutbox::default());
}

#[test]
fn file_outbox_keeps_order_and_updates_by_id() {
    let dir = TempDir::new();
    exercise(&FileOutbox::new(dir.outbox()));
}

#[test]
fn file_outbox_keeps_entries_across_instances_and_order_after_removal() {
    let dir = TempDir::new();
    FileOutbox::new(dir.outbox()).add(&entry("a")).unwrap();
    FileOutbox::new(dir.outbox()).add(&entry("b")).unwrap();
    let outbox = FileOutbox::new(dir.outbox());
    assert_eq!(ids(&outbox), ["a", "b"]);
    outbox.remove("a").unwrap();
    outbox.add(&entry("a")).unwrap();
    assert_eq!(ids(&outbox), ["b", "a"]);
}

#[test]
fn file_outbox_names_files_by_sequence_and_hashes_unusual_ids() {
    let dir = TempDir::new();
    let outbox = FileOutbox::new(dir.outbox());
    outbox.add(&entry("3f2a-uuid")).unwrap();
    outbox.add(&entry("../escape")).unwrap();
    let mut files: Vec<String> = fs::read_dir(dir.outbox())
        .unwrap()
        .map(|f| f.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(files[0], "000000000001-3f2a-uuid.json");
    assert!(files[1].starts_with("000000000002-") && files[1].len() == 13 + 64 + 5);
    assert_eq!(ids(&outbox), ["3f2a-uuid", "../escape"]);
    outbox.remove("../escape").unwrap();
    assert_eq!(fs::read_dir(dir.outbox()).unwrap().count(), 1);
}

#[test]
fn file_outbox_writes_the_shared_format_and_ignores_temporary_files() {
    let dir = TempDir::new();
    let outbox = FileOutbox::new(dir.outbox());
    outbox.add(&entry("a")).unwrap();
    fs::write(dir.outbox().join(".000000000002-b.json.tmp"), "partial").unwrap();
    let body: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(dir.outbox().join("000000000001-a.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(body["format"], "gm.evidence.outbox.v1");
    assert_eq!(body["entry"]["state"], "pending");
    assert_eq!(body["entry"]["next_attempt_at"], serde_json::Value::Null);
    assert_eq!(ids(&outbox), ["a"]);
}

#[test]
fn file_outbox_reads_entries_the_typescript_sdk_writes() {
    let dir = TempDir::new();
    fs::create_dir_all(dir.outbox()).unwrap();
    // As `FileOutbox` in genesis-mesh-sdk (TypeScript) writes it.
    let written = json!({"format": "gm.evidence.outbox.v1", "entry": {
        "id": "e-1", "evidence": {"evidence_id": "e-1"}, "state": "dead_letter", "attempts": 3,
        "queued_at": "2026-10-09T12:00:00.000Z", "next_attempt_at": null,
        "last_error": {"status": 409, "code": "evidence_conflict", "message": "taken"},
    }});
    fs::write(
        dir.outbox().join("000000000001-e-1.json"),
        serde_json::to_string_pretty(&written).unwrap(),
    )
    .unwrap();
    let listed = FileOutbox::new(dir.outbox()).list().unwrap();
    assert_eq!(listed[0].state, OutboxState::DeadLetter);
    assert_eq!(listed[0].last_error.as_ref().unwrap().status, 409);
    assert_eq!(serde_json::to_value(&listed[0]).unwrap(), written["entry"]);
}

#[test]
fn file_outbox_fails_loudly_on_an_unreadable_entry() {
    let dir = TempDir::new();
    let outbox = FileOutbox::new(dir.outbox());
    outbox.add(&entry("a")).unwrap();
    fs::write(dir.outbox().join("000000000002-b.json"), "{not json").unwrap();
    let err = outbox.list().unwrap_err().to_string();
    assert!(err.contains("000000000002-b.json"), "{err}");
    fs::write(
        dir.outbox().join("000000000002-b.json"),
        r#"{"format":"other"}"#,
    )
    .unwrap();
    assert!(outbox
        .list()
        .unwrap_err()
        .to_string()
        .contains("gm.evidence.outbox.v1"));
}

#[cfg(unix)]
#[test]
fn file_outbox_keeps_the_directory_and_entries_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    FileOutbox::new(dir.outbox()).add(&entry("a")).unwrap();
    let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir.outbox()), 0o700);
    assert_eq!(mode(dir.outbox().join("000000000001-a.json")), 0o600);
}

fn http(status: u16, code: &str) -> GenesisMeshError {
    GenesisMeshError::Http {
        status,
        message: "m".into(),
        code: code.into(),
    }
}

#[test]
fn classifies_transient_and_refused_submissions() {
    let transient = [
        http(503, "service_unavailable"),
        http(502, "bad_gateway"),
        http(409, "retention_in_progress"),
        GenesisMeshError::RateLimit {
            message: "m".into(),
            code: "rate_limit_exceeded".into(),
        },
        GenesisMeshError::Configuration("x".into()),
    ];
    for err in &transient {
        assert!(classify_submission_error(err).1, "{err}");
    }
    let refused = [
        http(409, "evidence_conflict"),
        GenesisMeshError::Validation {
            message: "m".into(),
            code: "evidence_malformed".into(),
        },
        GenesisMeshError::NotFound {
            message: "m".into(),
            code: "evidence_store_disabled".into(),
        },
        GenesisMeshError::SecretMaterial("field".into()),
    ];
    for err in &refused {
        assert!(!classify_submission_error(err).1, "{err}");
    }
    let (failure, _) = classify_submission_error(&http(409, "evidence_conflict"));
    assert_eq!(
        (failure.status, failure.code.as_str()),
        (409, "evidence_conflict")
    );
}

#[test]
fn backs_off_from_five_seconds_to_fifteen_minutes() {
    let delays: Vec<Duration> = [1, 2, 3, 8, 9, 50].into_iter().map(retry_delay).collect();
    let secs: Vec<u64> = delays.iter().map(Duration::as_secs).collect();
    assert_eq!(secs, [5, 10, 20, 640, 900, 900]);
}
