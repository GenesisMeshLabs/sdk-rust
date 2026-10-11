//! The record outbox (v1.3.0): `FileRecordOutbox`, `enqueue_record`,
//! `flush_records`, and `governed_action_with_break_glass`, against a
//! scripted local server.

use std::{collections::HashMap, fs, io, path::PathBuf, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use genesis_mesh_sdk::{
    canonical_digest, governed_action_with_break_glass, json, public_key_from_seed,
    verify::verify_out_of_band_record, ActionError, ActionReport, BreakGlassOptions,
    BreakGlassResult, ClientOptions, EvaluationFailure, EvidenceOutbox, ExecutionRecorder,
    FileOutbox, FileRecordOutbox, FlushOptions, GenesisMeshClient, GenesisMeshError,
    GovernedActionOutcome, GovernedActionParams, GovernedVerification, MemoryOutbox,
    MemoryRecordOutbox, ObservationInput, ObservationRecorder, OutboxEntry, OutboxFuture,
    OutboxState, RecordExecution, RecordKind, RecordOutbox, RecordOutboxEntry, Value,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

#[derive(Debug)]
struct Request {
    method: String,
    target: String,
    body: Value,
}

/// Serve one scripted response per connection, in order.
async fn scripted(responses: Vec<(u16, String)>) -> (String, JoinHandle<Vec<Request>>) {
    let delayed = responses
        .into_iter()
        .map(|(status, reply)| (status, reply, Duration::ZERO))
        .collect();
    serve(delayed).await
}

/// Serve one scripted response per connection, in order, each after its delay.
async fn serve(responses: Vec<(u16, String, Duration)>) -> (String, JoinHandle<Vec<Request>>) {
    let raw = responses
        .into_iter()
        .map(|(status, reply, delay)| {
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            (response, delay)
        })
        .collect();
    serve_raw(raw).await
}

/// Serve one raw HTTP response per connection, in order, each after its delay.
async fn serve_raw(responses: Vec<(String, Duration)>) -> (String, JoinHandle<Vec<Request>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut seen = Vec::new();
        for (response, delay) in responses {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("client made fewer requests than scripted")
                .unwrap();
            let mut bytes = Vec::new();
            let (head, offset) = loop {
                let mut chunk = [0; 8192];
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                    break (String::from_utf8(bytes[..end].to_vec()).unwrap(), end + 4);
                }
            };
            let mut lines = head.lines();
            let mut first = lines.next().unwrap().split(' ');
            let (method, target) = (
                first.next().unwrap().to_owned(),
                first.next().unwrap().to_owned(),
            );
            let headers: HashMap<_, _> = lines
                .map(|l| {
                    let (n, v) = l.split_once(':').unwrap();
                    (n.to_ascii_lowercase(), v.trim().to_owned())
                })
                .collect();
            let length = headers
                .get("content-length")
                .map_or(0, |s| s.parse().unwrap());
            while bytes.len() < offset + length {
                let mut chunk = [0; 8192];
                let count = stream.read(&mut chunk).await.unwrap();
                bytes.extend_from_slice(&chunk[..count]);
            }
            let body = if length == 0 {
                Value::Null
            } else {
                serde_json::from_slice(&bytes[offset..offset + length]).unwrap()
            };
            tokio::time::sleep(delay).await;
            stream.write_all(response.as_bytes()).await.unwrap();
            seen.push(Request {
                method,
                target,
                body,
            });
        }
        seen
    });
    (url, task)
}

/// A server that accepts connections and never answers.
async fn silent() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    (url, task)
}

fn ok(body: Value) -> (u16, String) {
    (200, body.to_string())
}

fn refusal(status: u16, code: &str) -> (u16, String) {
    (
        status,
        json!({"error": {"code": code, "message": "refused"}}).to_string(),
    )
}

fn unavailable() -> (u16, String) {
    refusal(503, "service_unavailable")
}

fn recorded() -> (u16, String) {
    ok(json!({"status": "recorded", "entry": {}, "entry_digest": "d", "payload": {}}))
}

fn options(url: &str) -> ClientOptions {
    ClientOptions::new(url)
        .with_signing_key(STANDARD.encode([7; 32]))
        .with_key_id("test-key")
        .with_audience("TEST")
}

fn client_with(url: &str, outbox: Arc<dyn RecordOutbox>) -> GenesisMeshClient {
    GenesisMeshClient::new(options(url).with_record_outbox(outbox)).unwrap()
}

fn client(url: &str) -> GenesisMeshClient {
    client_with(url, Arc::new(MemoryRecordOutbox::default()))
}

fn observer() -> ObservationRecorder {
    ObservationRecorder::new("cloud-observer", "observer-1", &STANDARD.encode([11; 32])).unwrap()
}

fn observe(n: u32) -> Value {
    observer()
        .record(ObservationInput {
            resource_id: format!("kv:prod/s{n}"),
            action: "rotate".into(),
            capability: "secret.rotate".into(),
            changed_at: Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
            source: "cloud-activity-log".into(),
            source_event_id: format!("event-{n}"),
            ..ObservationInput::default()
        })
        .unwrap()
}

async fn states(outbox: &dyn RecordOutbox) -> Vec<OutboxState> {
    outbox
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.state)
        .collect()
}

fn code(entry: &RecordOutboxEntry) -> &str {
    entry.last_error.as_ref().map_or("", |e| e.code.as_str())
}

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("gm-records-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn records(&self) -> PathBuf {
        self.0.join("records")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ── Storage ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn file_record_outbox_keeps_records_in_their_own_format_in_order() {
    let dir = TempDir::new();
    let first = RecordOutboxEntry::new(observe(1));
    let second = RecordOutboxEntry::new(observe(2));
    FileRecordOutbox::new(dir.records())
        .add(&first)
        .await
        .unwrap();
    FileRecordOutbox::new(dir.records())
        .add(&second)
        .await
        .unwrap();
    let listed = FileRecordOutbox::new(dir.records()).list().await.unwrap();
    assert_eq!(listed, [first.clone(), second]);
    assert_eq!(listed[0].kind, RecordKind::Observation);

    let mut files: Vec<_> = fs::read_dir(dir.records())
        .unwrap()
        .map(|f| f.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(files[0], format!("000000000001-{}.json", first.id));
    let written: Value =
        serde_json::from_str(&fs::read_to_string(dir.records().join(&files[0])).unwrap()).unwrap();
    assert_eq!(written["format"], "gm.evidence.record-outbox.v1");
    let keys: Vec<&str> = written["entry"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = [
        "id",
        "kind",
        "record",
        "state",
        "attempts",
        "queued_at",
        "next_attempt_at",
        "last_error",
    ];
    expected.sort();
    assert_eq!(keys, expected);
    assert_eq!(written["entry"]["kind"], "observation");
    assert_eq!(written["entry"]["state"], "pending");
}

#[tokio::test]
async fn file_record_outbox_reads_entries_the_typescript_sdk_writes() {
    let dir = TempDir::new();
    fs::create_dir_all(dir.records()).unwrap();
    let file = json!({"format": "gm.evidence.record-outbox.v1", "entry": {
        "id": "b-1", "kind": "break_glass", "record": {"break_glass_id": "b-1"}, "state": "dead_letter",
        "attempts": 2, "queued_at": "2026-10-09T00:00:00.000Z", "next_attempt_at": null,
        "last_error": {"status": 409, "code": "break_glass_conflict", "message": "conflict"},
    }});
    fs::write(
        dir.records().join("000000000001-b-1.json"),
        serde_json::to_string_pretty(&file).unwrap(),
    )
    .unwrap();
    let listed = FileRecordOutbox::new(dir.records()).list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].kind, listed[0].state),
        (RecordKind::BreakGlass, OutboxState::DeadLetter)
    );
    assert_eq!(code(&listed[0]), "break_glass_conflict");
}

#[tokio::test]
async fn file_record_outbox_refuses_a_directory_of_execution_records() {
    let dir = TempDir::new();
    FileOutbox::new(dir.records())
        .add(&OutboxEntry::new(json!({"evidence_id": "e"})))
        .await
        .unwrap();
    let err = FileRecordOutbox::new(dir.records())
        .list()
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("gm.evidence.record-outbox.v1"));
    // And the other way round.
    let other = TempDir::new();
    FileRecordOutbox::new(other.records())
        .add(&RecordOutboxEntry::new(observe(1)))
        .await
        .unwrap();
    let err = FileOutbox::new(other.records()).list().await.unwrap_err();
    assert!(err.to_string().contains("gm.evidence.outbox.v1"));
}

#[tokio::test]
async fn a_record_outbox_leaves_the_temporary_files_of_an_execution_outbox() {
    let source = TempDir::new();
    FileOutbox::new(source.records())
        .add(&OutboxEntry::new(json!({"evidence_id": "e"})))
        .await
        .unwrap();
    let name = fs::read_dir(source.records())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    // What a crash in `FileOutbox::add` leaves: a complete temporary file
    // and no entry file.
    let dir = TempDir::new();
    fs::create_dir_all(dir.records()).unwrap();
    let temporary = dir.records().join(format!(".{name}.abcd.tmp"));
    fs::copy(source.records().join(&name), &temporary).unwrap();
    let err = FileRecordOutbox::new(dir.records())
        .list()
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    // 1.3.1: left for the outbox it belongs to, which recovers the record.
    assert!(temporary.exists());
    assert_eq!(
        FileOutbox::new(dir.records()).list().await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn memory_record_outbox_refuses_an_id_twice() {
    let outbox = MemoryRecordOutbox::default();
    let entry = RecordOutboxEntry::new(observe(1));
    outbox.add(&entry).await.unwrap();
    assert_eq!(
        outbox.add(&entry).await.unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    outbox.remove(&entry.id).await.unwrap();
    assert!(outbox.list().await.unwrap().is_empty());
}

// ── enqueue_record and flush_records ─────────────────────────────────────────

#[tokio::test]
async fn enqueue_record_needs_a_record_outbox() {
    let c = GenesisMeshClient::new(options("http://127.0.0.1:9")).unwrap();
    let err = c
        .evidence_store
        .enqueue_record(observe(1))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "record_outbox_required");
    let err = c
        .evidence_store
        .flush_records(FlushOptions::default())
        .await
        .unwrap_err();
    assert_eq!(err.code(), "record_outbox_required");
}

#[tokio::test]
async fn an_admitted_record_is_removed_and_a_transient_failure_stays_pending() {
    let (url, task) = scripted(vec![recorded(), unavailable()]).await;
    let c = client(&url);
    let first = observe(1);
    let delivery = c
        .evidence_store
        .enqueue_record(first.clone())
        .await
        .unwrap();
    assert_eq!(delivery.submission.unwrap()["status"], "recorded");
    let delivery = c.evidence_store.enqueue_record(observe(2)).await.unwrap();
    let queued = delivery.queued.unwrap();
    assert_eq!((queued.state, queued.attempts), (OutboxState::Pending, 1));
    assert_eq!(queued.last_error.as_ref().unwrap().status, 503);
    assert!(queued.next_attempt_at.is_some());
    let outbox = c.evidence_store.record_outbox().unwrap();
    assert_eq!(outbox.list().await.unwrap().len(), 1);
    let r = task.await.unwrap();
    assert_eq!(
        (r[0].method.as_str(), r[0].target.as_str()),
        ("POST", "/evidence/observations")
    );
    assert_eq!(r[0].body, json!({"observation": first}));
}

#[tokio::test]
async fn only_refusals_no_retry_can_overcome_dead_letter_a_record() {
    for (status, refused, dead) in [
        (422, "observation_invalid_signature", true),
        (422, "observation_out_of_scope", true),
        (422, "observation_key_retired", true),
        (409, "observation_conflict", true),
        (400, "invalid_observation", true),
        (422, "observation_unknown_key", false),
        (404, "out_of_band_disabled", false),
        (429, "rate_limited", false),
        // A permanent code from a server error is not a refusal of the record.
        (500, "observation_malformed", false),
    ] {
        let (url, _task) = scripted(vec![refusal(status, refused)]).await;
        let c = client(&url);
        let queued = c
            .evidence_store
            .enqueue_record(observe(1))
            .await
            .unwrap()
            .queued
            .unwrap();
        let expected = if dead {
            OutboxState::DeadLetter
        } else {
            OutboxState::Pending
        };
        assert_eq!(queued.state, expected, "{refused}");
        assert_eq!(code(&queued), refused);
    }
}

#[tokio::test]
async fn enqueue_record_refuses_a_different_record_under_a_queued_id() {
    let (url, _task) = scripted(vec![unavailable(), unavailable()]).await;
    let c = client(&url);
    let record = observe(1);
    c.evidence_store
        .enqueue_record(record.clone())
        .await
        .unwrap();
    // The same record again is submitted again.
    let again = c
        .evidence_store
        .enqueue_record(record.clone())
        .await
        .unwrap();
    assert_eq!(again.queued.unwrap().attempts, 2);
    let mut changed = record;
    changed["action"] = json!("delete");
    let err = c.evidence_store.enqueue_record(changed).await.unwrap_err();
    assert!(err.to_string().contains("a different record"), "{err}");
    let err = c
        .evidence_store
        .enqueue_record(json!({"resource_id": "kv:v/s"}))
        .await
        .unwrap_err();
    assert!(matches!(err, GenesisMeshError::Configuration(_)));
}

#[tokio::test]
async fn flush_records_batches_observations_and_settles_each_result() {
    let (url, task) = scripted(vec![
        unavailable(),
        unavailable(),
        unavailable(),
        unavailable(),
        ok(json!({"results": [
            {"index": 0, "status": "recorded"},
            {"index": 1, "status": "refused", "error": {"code": "observation_out_of_scope", "message": "out of scope"}},
            {"index": 2, "status": "quarantined"},
            {"index": 3, "status": "refused", "error": {"code": "observation_conflict", "message": "conflict"}},
            {"index": 4, "status": "duplicate"},
        ]})),
    ])
    .await;
    let c = client(&url);
    let mut records = Vec::new();
    for n in 0..4 {
        let record = observe(n);
        c.evidence_store
            .enqueue_record(record.clone())
            .await
            .unwrap();
        records.push(record);
    }
    let report = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 2);
    assert_eq!(report.quarantined.len(), 1);
    assert_eq!(report.quarantined[0].record, records[2]);
    let refused: Vec<(&str, u16)> = report
        .dead_lettered
        .iter()
        .map(|e| (code(e), e.last_error.as_ref().unwrap().status))
        .collect();
    assert_eq!(
        refused,
        [
            ("observation_out_of_scope", 422),
            ("observation_conflict", 409)
        ]
    );
    let outbox = c.evidence_store.record_outbox().unwrap();
    assert_eq!(
        states(outbox.as_ref()).await,
        [OutboxState::DeadLetter, OutboxState::DeadLetter]
    );
    let r = task.await.unwrap();
    assert_eq!(r.len(), 5);
    assert_eq!(r[4].target, "/evidence/observations/batch");
    assert_eq!(r[4].body, json!({ "observations": records }));
}

#[tokio::test]
async fn a_flush_stops_at_a_transient_failure_and_skips_records_in_backoff() {
    let (url, task) = scripted(vec![unavailable(), unavailable()]).await;
    let c = client(&url);
    c.evidence_store.enqueue_record(observe(1)).await.unwrap();
    let skipped = c
        .evidence_store
        .flush_records(FlushOptions::default())
        .await
        .unwrap();
    assert_eq!(skipped.pending.len(), 1);
    let failed = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(failed.pending.len(), 1);
    assert_eq!(failed.pending[0].attempts, 2);
    assert_eq!(task.await.unwrap().len(), 2);
}

fn batch_recorded(count: u64) -> (u16, String) {
    let results: Vec<Value> = (0..count)
        .map(|index| json!({"index": index, "status": "recorded"}))
        .collect();
    ok(json!({ "results": results }))
}

#[tokio::test]
async fn a_batch_refused_as_a_whole_is_split_until_the_record_is_found() {
    // The NA's strict reader refuses a request with one record it cannot
    // read (`invalid_json`), whatever else it holds (1.3.1).
    let unreadable = || refusal(400, "invalid_json");
    let (url, task) = scripted(vec![
        unavailable(),
        unavailable(),
        unavailable(),
        unavailable(),
        unreadable(),      // 1, 2, 3, 4
        batch_recorded(2), // 1, 2
        unreadable(),      // 3, 4
        unreadable(),      // 3
        unreadable(),      // 3 alone, on its own route
        batch_recorded(1), // 4
    ])
    .await;
    let c = client(&url);
    for n in 1..=4 {
        c.evidence_store.enqueue_record(observe(n)).await.unwrap();
    }
    let report = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 3);
    // Final (1.3.1): sending the same record again cannot change the answer.
    assert_eq!(report.dead_lettered.len(), 1);
    assert_eq!(code(&report.dead_lettered[0]), "invalid_json");
    assert_eq!(report.dead_lettered[0].record["resource_id"], "kv:prod/s3");
    let r = task.await.unwrap();
    let sent: Vec<(&str, usize)> = r[4..]
        .iter()
        .map(|q| {
            let count = q.body["observations"].as_array().map_or(1, Vec::len);
            (q.target.as_str(), count)
        })
        .collect();
    assert_eq!(
        sent,
        [
            ("/evidence/observations/batch", 4),
            ("/evidence/observations/batch", 2),
            ("/evidence/observations/batch", 2),
            ("/evidence/observations/batch", 1),
            ("/evidence/observations", 1),
            ("/evidence/observations/batch", 1),
        ]
    );
}

/// A raw `429` asking the client to wait `seconds`.
fn throttled(seconds: u64) -> (String, Duration) {
    let body =
        json!({"error": {"code": "rate_limit_exceeded", "message": "slow down"}}).to_string();
    (
        format!(
            "HTTP/1.1 429 Test\r\nRetry-After: {seconds}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        Duration::ZERO,
    )
}

fn raw((status, reply): (u16, String)) -> (String, Duration) {
    (
        format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        ),
        Duration::ZERO,
    )
}

fn waits_at_least(entry: &RecordOutboxEntry, seconds: i64) -> bool {
    let at: chrono::DateTime<chrono::Utc> =
        entry.next_attempt_at.as_deref().unwrap().parse().unwrap();
    at - chrono::Utc::now() > chrono::Duration::seconds(seconds)
}

#[tokio::test]
async fn a_throttled_batch_halves_the_batches_after_it_and_waits_as_asked() {
    let (url, task) = serve_raw(vec![
        raw(unavailable()),
        raw(unavailable()),
        raw(unavailable()),
        raw(unavailable()),
        throttled(120),
        raw(batch_recorded(2)),
        raw(batch_recorded(2)),
    ])
    .await;
    let c = client(&url);
    for n in 1..=4 {
        c.evidence_store.enqueue_record(observe(n)).await.unwrap();
    }
    let throttled = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    // Every record waits as long as the NA asked, past its own backoff (1.3.1).
    assert_eq!(throttled.pending.len(), 4);
    assert!(throttled.pending.iter().all(|e| waits_at_least(e, 100)));
    assert!(throttled
        .pending
        .iter()
        .all(|e| e.last_error.as_ref().unwrap().status == 429));
    let skipped = c
        .evidence_store
        .flush_records(FlushOptions::default())
        .await
        .unwrap();
    assert_eq!(skipped.pending.len(), 4);
    // Batches of half the size from then on, so a limit below 100 a minute drains.
    let report = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 4);
    let r = task.await.unwrap();
    let counts: Vec<usize> = r[4..]
        .iter()
        .map(|q| q.body["observations"].as_array().unwrap().len())
        .collect();
    assert_eq!(counts, [4, 2, 2]);
}

#[tokio::test]
async fn an_execution_record_waits_as_long_as_the_na_asks() {
    let (url, _task) = serve_raw(vec![throttled(300), throttled(7200)]).await;
    let outbox = Arc::new(MemoryOutbox::default());
    let c = GenesisMeshClient::new(options(&url).with_outbox(outbox.clone())).unwrap();
    let v = vectors();
    let decision = signed_evaluation(&v, true, "ctx-w")["decision"].clone();
    let record = recorder()
        .record(RecordExecution {
            decision,
            executed_capability: "sp-secret.rotate".into(),
            ..RecordExecution::default()
        })
        .unwrap();
    let entry = c
        .evidence_store
        .enqueue(record)
        .await
        .unwrap()
        .queued
        .unwrap();
    let wait = |entry: &OutboxEntry| {
        let at: chrono::DateTime<chrono::Utc> =
            entry.next_attempt_at.as_deref().unwrap().parse().unwrap();
        at - chrono::Utc::now()
    };
    assert!(wait(&entry) > chrono::Duration::seconds(290), "{entry:?}");
    // At most 15 minutes, whatever the answer asks.
    let report = c
        .evidence_store
        .flush_pending(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    let again = wait(&report.pending[0]);
    assert!(again > chrono::Duration::minutes(14) && again <= chrono::Duration::minutes(15));
}

#[tokio::test]
async fn break_glass_records_are_flushed_first_one_at_a_time() {
    let (url, task) = scripted(vec![
        unavailable(),
        unavailable(),
        recorded(),
        ok(json!({"results": [{"index": 0, "status": "recorded"}]})),
    ])
    .await;
    let c = client(&url);
    let record = recorder()
        .sign_break_glass(genesis_mesh_sdk::BreakGlassInput::new(
            "kv:v/s",
            "rotate",
            "sp-secret.rotate",
            "incident 42",
            json!({}),
            EvaluationFailure::Timeout,
        ))
        .unwrap();
    c.evidence_store.enqueue_record(observe(1)).await.unwrap();
    c.evidence_store
        .enqueue_record(record.clone())
        .await
        .unwrap();
    let report = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 2);
    // 1.3.1: break-glass records first, though added later.
    let r = task.await.unwrap();
    assert_eq!(r[2].target, "/evidence/break-glass");
    assert_eq!(r[2].body, json!({ "record": record }));
    assert_eq!(r[3].target, "/evidence/observations/batch");
}

#[tokio::test]
async fn no_record_is_due_while_the_na_asks_to_wait() {
    let (url, task) = serve_raw(vec![
        throttled(120),
        raw(recorded()),
        raw(batch_recorded(1)),
    ])
    .await;
    let c = client(&url);
    let record = recorder()
        .sign_break_glass(genesis_mesh_sdk::BreakGlassInput::new(
            "kv:v/s",
            "rotate",
            "sp-secret.rotate",
            "incident 42",
            json!({}),
            EvaluationFailure::Timeout,
        ))
        .unwrap();
    c.evidence_store.enqueue_record(record).await.unwrap();
    // A record that never failed: due, but for the NA's request to wait.
    let outbox = c.evidence_store.record_outbox().unwrap();
    outbox
        .add(&RecordOutboxEntry::new(observe(2)))
        .await
        .unwrap();
    let waiting = c
        .evidence_store
        .flush_records(FlushOptions::default())
        .await
        .unwrap();
    assert_eq!(waiting.pending.len(), 2);
    assert!(waiting.admitted.is_empty());
    let report = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 2);
    assert_eq!(task.await.unwrap().len(), 3);
}

// ── governed_action_with_break_glass ─────────────────────────────────────────

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/python-vectors.json")).unwrap()
}

fn recorder() -> ExecutionRecorder {
    ExecutionRecorder::new(
        "secrets-controller",
        "ctrl-rust",
        &STANDARD.encode([5_u8; 32]),
    )
    .unwrap()
}

fn na_key() -> String {
    STANDARD.encode(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes())
}

/// A fresh decision over the vector's shape, signed by the test NA key.
fn signed_evaluation(v: &Value, allowed: bool, context_id: &str) -> Value {
    let na = SigningKey::from_bytes(&[3; 32]);
    let source = if allowed { &v["allowed"] } else { &v["denied"] };
    let mut decision = source["decision"].clone();
    let now = chrono::Utc::now();
    decision["context_id"] = json!(context_id);
    decision["decision_made_at"] = json!(genesis_mesh_sdk::canonical::python_timestamp(now));
    decision["decision_valid_until"] = json!(genesis_mesh_sdk::canonical::python_timestamp(
        now + chrono::Duration::minutes(5)
    ));
    let canonical = genesis_mesh_sdk::canonical::decision_canonical(&decision).unwrap();
    decision["signature"] = genesis_mesh_sdk::sign_canonical(&canonical, "na", &na);
    json!({"decision": decision, "justification_proof": source["justification_proof"]})
}

fn params(v: &Value, context_id: &str) -> GovernedActionParams {
    GovernedActionParams {
        evaluate: json!({
            "attestation_id": v["attestation"]["attestation_id"],
            "requested_capability": "sp-secret.rotate",
            "context": {"context_id": context_id, "request_parameters": {"app_id": "billing"},
                        "attributes": {"owner": "team-a"}},
        }),
        resource_id: Some("kv:v/s".into()),
        resource_action: Some("rotate".into()),
        prior_resource: Some(None),
        verify: GovernedVerification {
            operator_public_keys: vec![na_key()],
            expected_policies: vec![v["policy"].clone()],
            expected_attestation: Some(v["attestation"].clone()),
            ..GovernedVerification::default()
        },
    }
}

fn justification() -> BreakGlassOptions {
    BreakGlassOptions::new("incident 42: rotate the leaked key now")
}

type Report = std::result::Result<ActionReport<String>, ActionError>;

/// Run with break-glass; the action reports `report` and counts its calls.
async fn run(
    boundary: &GenesisMeshClient,
    store: &GenesisMeshClient,
    params: GovernedActionParams,
    options: BreakGlassOptions,
    report: Report,
) -> (
    genesis_mesh_sdk::Result<GovernedActionOutcome<String>>,
    Vec<Option<Value>>,
) {
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&calls);
    let outcome = governed_action_with_break_glass(
        &boundary.boundary,
        &store.evidence_store,
        &recorder(),
        params,
        options,
        move |decision| {
            seen.lock().unwrap().push(decision);
            async move { report }
        },
    )
    .await;
    let calls = calls.lock().unwrap().clone();
    (outcome, calls)
}

fn rotated() -> Report {
    Ok(ActionReport {
        value: Some("done".into()),
        execution_parameters: Some(json!({"version_id": "v9"})),
        ..ActionReport::default()
    })
}

fn broke(outcome: GovernedActionOutcome<String>) -> BreakGlassResult<String> {
    match outcome {
        GovernedActionOutcome::BrokeGlass(result) => result,
        GovernedActionOutcome::Evaluated(result) => panic!("evaluated: {result:?}"),
    }
}

#[tokio::test]
async fn a_transient_evaluation_failure_runs_the_action_and_records_it() {
    let v = vectors();
    let executor_key = public_key_from_seed(&STANDARD.encode([5_u8; 32])).unwrap();
    for (failure, response) in [
        (EvaluationFailure::ServerError, unavailable()),
        (EvaluationFailure::ServerError, refusal(502, "bad_gateway")),
        (EvaluationFailure::RateLimited, refusal(429, "rate_limited")),
    ] {
        let (url, task) = scripted(vec![response, recorded()]).await;
        let c = client(&url);
        let (outcome, calls) = run(&c, &c, params(&v, "ctx-b1"), justification(), rotated()).await;
        let result = broke(outcome.unwrap());
        assert_eq!(calls, [None]);
        assert_eq!(result.failure, failure);
        assert_eq!(result.value.as_deref(), Some("done"));
        assert_eq!(result.submission.unwrap()["status"], "recorded");
        assert!(result.queued.is_none() && result.dropped.is_empty());
        let record = &result.record;
        assert_eq!(record["executor_sovereign_id"], "secrets-controller");
        assert_eq!(record["resource_id"], "kv:v/s");
        assert_eq!(record["resource_action"], "rotate");
        assert_eq!(record["capability"], "sp-secret.rotate");
        assert_eq!(record["attestation_id"], v["attestation"]["attestation_id"]);
        assert_eq!(record["request_parameters"], json!({"app_id": "billing"}));
        assert_eq!(record["attributes"], json!({"owner": "team-a"}));
        assert_eq!(record["evaluation_failure"], failure.as_str());
        assert_eq!(record["execution_parameters"], json!({"version_id": "v9"}));
        assert_eq!(record["outcome"], "success");
        assert_eq!(
            record["justification"],
            "incident 42: rotate the leaked key now"
        );
        assert!(verify_out_of_band_record(
            record,
            std::slice::from_ref(&executor_key)
        ));
        let r = task.await.unwrap();
        assert_eq!(r[0].target, "/admin/boundary/evaluate");
        // The record names the request that failed by its digest.
        assert_eq!(
            record["evaluation_request_digest"],
            canonical_digest(&r[0].body).unwrap()
        );
        assert_eq!(r[1].target, "/evidence/break-glass");
        assert_eq!(&r[1].body["record"], record);
    }
}

#[tokio::test]
async fn an_unreachable_or_silent_na_breaks_the_glass() {
    let v = vectors();
    let (silent_url, silent_task) = silent().await;
    let timing_out =
        GenesisMeshClient::new(options(&silent_url).with_timeout(Duration::from_millis(300)))
            .unwrap();
    // Nothing listens on the discard port.
    let unreachable = GenesisMeshClient::new(options("http://127.0.0.1:9")).unwrap();
    for (boundary, failure) in [
        (&unreachable, EvaluationFailure::NetworkError),
        (&timing_out, EvaluationFailure::Timeout),
    ] {
        let (url, _task) = scripted(vec![recorded()]).await;
        let store = client(&url);
        let (outcome, calls) = run(
            boundary,
            &store,
            params(&v, "ctx-b2"),
            justification(),
            rotated(),
        )
        .await;
        let result = broke(outcome.unwrap());
        assert_eq!((result.failure, calls.len()), (failure, 1));
        assert!(matches!(
            result.evaluation_error,
            GenesisMeshError::Network(_)
        ));
        assert_eq!(result.record["evaluation_failure"], failure.as_str());
    }
    silent_task.abort();
}

#[tokio::test]
async fn a_deny_an_unverified_decision_or_a_refused_request_never_breaks_the_glass() {
    let v = vectors();
    let mut forged = signed_evaluation(&v, true, "ctx-b3");
    forged["decision"]["authorized"] = json!(true);
    forged["decision"]["signature"]["sig"] = json!(STANDARD.encode([0; 64]));
    let (url, _task) = scripted(vec![
        ok(signed_evaluation(&v, false, "ctx-b3")),
        ok(forged),
        refusal(400, "invalid_request"),
        refusal(404, "not_found"),
    ])
    .await;
    let c = client(&url);
    let (outcome, calls) = run(&c, &c, params(&v, "ctx-b3"), justification(), rotated()).await;
    match outcome.unwrap() {
        GovernedActionOutcome::Evaluated(result) => assert!(!result.authorized),
        GovernedActionOutcome::BrokeGlass(_) => panic!("broke the glass on a DENY"),
    }
    assert!(calls.is_empty());
    for code in ["invalid_signature", "invalid_request", "not_found"] {
        let (outcome, calls) = run(&c, &c, params(&v, "ctx-b3"), justification(), rotated()).await;
        assert_eq!(outcome.unwrap_err().code(), code);
        assert!(calls.is_empty());
    }
    let outbox = c.evidence_store.record_outbox().unwrap();
    assert!(outbox.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn break_glass_checks_what_it_needs_before_anything_runs() {
    let v = vectors();
    // Every check fails before the (unreachable) NA would be asked.
    let without = GenesisMeshClient::new(options("http://127.0.0.1:9")).unwrap();
    let c = client("http://127.0.0.1:9");
    let mut no_resource = params(&v, "ctx-b4");
    no_resource.resource_id = None;
    no_resource.resource_action = None;
    let mut secret_context = params(&v, "ctx-b4");
    secret_context.evaluate["context"]["attributes"]["api_key"] = json!("x");
    // An agreement-based evaluation cannot be judged after the fact.
    let mut agreement = params(&v, "ctx-b4");
    agreement.evaluate["attestation_id"] = Value::Null;
    agreement.evaluate["agreement"] = json!({"agreement_id": "a"});
    let changed = |key: &str, value: Value| {
        let mut p = params(&v, "ctx-b4");
        p.evaluate[key] = value;
        p
    };
    let mut not_an_object = params(&v, "ctx-b4");
    not_an_object.evaluate["context"]["request_parameters"] = json!("billing");
    // Room is kept for the action's report within the metadata limit.
    let mut no_room = params(&v, "ctx-b4");
    no_room.evaluate["context"]["attributes"]["note"] = json!("a short note, ".repeat(1100));
    // Measured as the NA measures it (1.3.1): text outside ASCII escaped, 5142
    // bytes as UTF-8 but 15188 as the NA counts the record.
    let mut no_room_escaped = params(&v, "ctx-b4");
    no_room_escaped.evaluate["context"]["attributes"]["note"] = json!("é".repeat(2500));
    // Nested deeper than every reader takes (1.3.1).
    let mut too_deep = params(&v, "ctx-b4");
    too_deep.evaluate["context"]["attributes"]["deep"] =
        (1..61).fold(json!({}), |inner, _| json!({ "a": inner }));
    let mut unknown_action = params(&v, "ctx-b4");
    unknown_action.resource_action = Some("rotated".into());
    let cases = [
        (
            &c,
            no_room_escaped,
            justification(),
            "break_glass_malformed",
        ),
        (&c, too_deep, justification(), "invalid_json"),
        (&c, unknown_action, justification(), "configuration"),
        (
            &c,
            changed("attestation_id", json!("a".repeat(129))),
            justification(),
            "break_glass_malformed",
        ),
        (&c, agreement, justification(), "break_glass_malformed"),
        (
            &c,
            changed("attestation_id", json!("")),
            justification(),
            "break_glass_malformed",
        ),
        (
            &c,
            changed("requested_capability", json!("")),
            justification(),
            "break_glass_malformed",
        ),
        (&c, not_an_object, justification(), "break_glass_malformed"),
        (&c, no_room, justification(), "break_glass_malformed"),
        (
            &without,
            params(&v, "ctx-b4"),
            justification(),
            "record_outbox_required",
        ),
        (
            &c,
            params(&v, "ctx-b4"),
            BreakGlassOptions::new(""),
            "break_glass_malformed",
        ),
        (
            &c,
            params(&v, "ctx-b4"),
            BreakGlassOptions::new("x".repeat(1025)),
            "break_glass_malformed",
        ),
        (
            &c,
            params(&v, "ctx-b4"),
            BreakGlassOptions::new("token -----BEGIN PRIVATE KEY-----"),
            "break_glass_secret_material",
        ),
        (
            &c,
            secret_context,
            justification(),
            "break_glass_secret_material",
        ),
        (&c, no_resource, justification(), "configuration"),
    ];
    for (client, params, options, code) in cases {
        let (outcome, calls) = run(client, client, params, options, rotated()).await;
        assert_eq!(outcome.unwrap_err().code(), code);
        assert!(calls.is_empty());
    }
}

#[tokio::test]
async fn a_failed_action_under_break_glass_records_its_failure() {
    let v = vectors();
    let (url, task) = scripted(vec![unavailable(), recorded()]).await;
    let c = client(&url);
    let (outcome, calls) = run(
        &c,
        &c,
        params(&v, "ctx-b5"),
        justification(),
        Err("cloud refused: secret=hunter2".into()),
    )
    .await;
    assert_eq!(calls.len(), 1);
    let err = outcome.unwrap_err();
    let GenesisMeshError::ActionFailed {
        source,
        evidence,
        queued_record,
        ..
    } = err
    else {
        panic!("unexpected error {err}");
    };
    assert!(source.to_string().contains("cloud refused"));
    assert!(queued_record.is_none());
    let record = evidence.unwrap();
    assert_eq!(record["outcome"], "failure");
    assert_eq!(record["outcome_detail"], "action failed");
    let r = task.await.unwrap();
    assert_eq!(&r[1].body["record"], record.as_ref());
}

/// A record outbox that lists and cannot add.
#[derive(Debug, Default)]
struct FullOutbox(MemoryRecordOutbox);

impl RecordOutbox for FullOutbox {
    fn add<'a>(&'a self, _: &'a RecordOutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async { Err(io::Error::other("disk full")) })
    }
    fn update<'a>(&'a self, entry: &'a RecordOutboxEntry) -> OutboxFuture<'a, ()> {
        self.0.update(entry)
    }
    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        self.0.remove(id)
    }
    fn list(&self) -> OutboxFuture<'_, Vec<RecordOutboxEntry>> {
        self.0.list()
    }
}

#[tokio::test]
async fn a_break_glass_record_that_cannot_be_kept_is_an_error_that_carries_the_value() {
    let v = vectors();
    let (url, _task) = scripted(vec![unavailable(), unavailable()]).await;
    let c = client_with(&url, Arc::new(FullOutbox::default()));
    let (outcome, _) = run(
        &c,
        &c,
        params(&v, "ctx-b6"),
        justification(),
        Err("cloud refused".into()),
    )
    .await;
    let err = outcome.unwrap_err();
    assert!(
        matches!(err, GenesisMeshError::ActionUnrecorded { .. }),
        "{err}"
    );
    let (outcome, _) = run(&c, &c, params(&v, "ctx-b6"), justification(), rotated()).await;
    let mut err = outcome.unwrap_err();
    assert_eq!(err.code(), "governed_action_evidence_unkept");
    assert_eq!(err.take_action_value::<String>().as_deref(), Some("done"));
}

#[tokio::test]
async fn a_break_glass_record_waits_while_the_na_is_down_without_refused_metadata() {
    let v = vectors();
    let (url, _task) = scripted(vec![unavailable(), unavailable()]).await;
    let c = client(&url);
    let report = Ok(ActionReport {
        value: Some("done".into()),
        execution_parameters: Some(json!({"version_id": "v9", "client_secret": "x"})),
        ..ActionReport::default()
    });
    let (outcome, _) = run(&c, &c, params(&v, "ctx-b7"), justification(), report).await;
    let result = broke(outcome.unwrap());
    let queued = result.queued.unwrap();
    assert_eq!(
        (queued.state, queued.kind),
        (OutboxState::Pending, RecordKind::BreakGlass)
    );
    assert_eq!(queued.record, result.record);
    assert_eq!(result.dropped, ["client_secret"]);
    assert_eq!(
        result.record["execution_parameters"],
        json!({"version_id": "v9"})
    );
    assert_eq!(
        result.record["outcome_detail"],
        "[secret guard dropped: client_secret]"
    );
    let executor_key = public_key_from_seed(&STANDARD.encode([5_u8; 32])).unwrap();
    assert!(verify_out_of_band_record(&result.record, &[executor_key]));
}

#[tokio::test]
async fn a_report_that_leaves_no_room_with_the_justification_is_left_out() {
    let v = vectors();
    let (url, task) = scripted(vec![unavailable(), recorded()]).await;
    let c = client(&url);
    let mut p = params(&v, "ctx-b10");
    p.evaluate["context"]["request_parameters"] = json!({"blob": "a b".repeat(4300)});
    let report = Ok(ActionReport {
        value: Some("done".into()),
        execution_parameters: Some(json!({"versions": "v ".repeat(1300)})),
        ..ActionReport::default()
    });
    // The NA counts the justification with the report (1.3.1): 16652 bytes.
    let (outcome, _) = run(&c, &c, p, BreakGlassOptions::new("x ".repeat(512)), report).await;
    let result = broke(outcome.unwrap());
    assert_eq!(result.value.as_deref(), Some("done"));
    assert_eq!(result.dropped, ["versions"]);
    assert_eq!(result.record["execution_parameters"], json!({}));
    assert_eq!(
        result.record["outcome_detail"],
        "[secret guard dropped the report]"
    );
    let executor_key = public_key_from_seed(&STANDARD.encode([5_u8; 32])).unwrap();
    assert!(verify_out_of_band_record(&result.record, &[executor_key]));
    assert_eq!(task.await.unwrap()[1].body["record"], result.record);
}

#[tokio::test]
async fn governed_action_never_breaks_the_glass() {
    let v = vectors();
    let (url, _task) = scripted(vec![unavailable()]).await;
    let c = client(&url);
    let err = genesis_mesh_sdk::governed_action(
        &c.boundary,
        &c.evidence_store,
        &recorder(),
        params(&v, "ctx-b8"),
        |_| async { panic!("the action must not run") as Report },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, GenesisMeshError::Http { status: 503, .. }),
        "{err}"
    );
}

#[test]
fn record_refusals_are_classified_by_their_own_list() {
    use genesis_mesh_sdk::{
        classify_record_submission_error, classify_submission_error, RECORD_PERMANENT_REFUSALS,
    };
    let validation = |code: &str| GenesisMeshError::Validation {
        message: "refused".into(),
        code: code.into(),
    };
    let out_of_scope = validation("observation_out_of_scope");
    let (failure, transient) = classify_record_submission_error(&out_of_scope);
    assert!(!transient);
    assert_eq!(
        (failure.status, failure.code.as_str()),
        (422, "observation_out_of_scope")
    );
    // Not a refusal of an execution record.
    assert!(classify_submission_error(&out_of_scope).1);
    assert!(classify_record_submission_error(&validation("evidence_conflict")).1);
    for code in ["observation_unknown_key", "break_glass_unknown_key"] {
        assert!(
            classify_record_submission_error(&validation(code)).1,
            "{code}"
        );
    }
    assert!(!classify_record_submission_error(&validation("break_glass_key_retired")).1);
    assert_eq!(RECORD_PERMANENT_REFUSALS.len(), 15);
    // 1.3.1: the NA's strict reader refusing the request is final for both
    // kinds of record; a response this crate could not read is not the NA's
    // refusal, and is retried.
    let unreadable_request = GenesisMeshError::BadRequest {
        message: "request body is not accepted JSON".into(),
        code: "invalid_json".into(),
    };
    assert!(!classify_record_submission_error(&unreadable_request).1);
    assert!(!classify_submission_error(&unreadable_request).1);
    let unreadable_response = GenesisMeshError::StrictJson {
        reason: "invalid_json".into(),
        detail: "text that is not UTF-8".into(),
    };
    assert!(classify_record_submission_error(&unreadable_response).1);
    assert!(classify_submission_error(&unreadable_response).1);
}

#[test]
fn evaluation_failures_are_the_transient_ones() {
    use genesis_mesh_sdk::evaluation_failure;
    let http = |status| GenesisMeshError::Http {
        status,
        message: String::new(),
        code: String::new(),
    };
    assert_eq!(
        evaluation_failure(&http(503)),
        Some(EvaluationFailure::ServerError)
    );
    assert_eq!(evaluation_failure(&http(409)), None);
    assert_eq!(evaluation_failure(&http(302)), None);
    assert_eq!(
        evaluation_failure(&GenesisMeshError::RateLimit {
            message: String::new(),
            code: String::new()
        }),
        Some(EvaluationFailure::RateLimited)
    );
    assert_eq!(
        evaluation_failure(&GenesisMeshError::DecisionVerification(
            "invalid_signature".into()
        )),
        None
    );
    assert_eq!(
        evaluation_failure(&GenesisMeshError::Configuration(String::new())),
        None
    );
    // Refusals that look transient but are not (v1.3.0).
    assert_eq!(
        evaluation_failure(&GenesisMeshError::RateLimit {
            message: String::new(),
            code: "admin_auth_throttled".into()
        }),
        None
    );
    assert_eq!(
        evaluation_failure(&GenesisMeshError::Http {
            status: 503,
            message: String::new(),
            code: "evidence_store_unavailable".into()
        }),
        None
    );
}

#[tokio::test]
async fn a_throttled_or_unstored_evaluation_never_breaks_the_glass() {
    let v = vectors();
    for (status, code) in [
        (429, "admin_auth_throttled"),
        (503, "evidence_store_unavailable"),
    ] {
        let (url, _task) = scripted(vec![refusal(status, code)]).await;
        let c = client(&url);
        let (outcome, calls) = run(&c, &c, params(&v, "ctx-b9"), justification(), rotated()).await;
        assert_eq!(outcome.unwrap_err().code(), code);
        assert!(calls.is_empty());
        let outbox = c.evidence_store.record_outbox().unwrap();
        assert!(outbox.list().await.unwrap().is_empty());
    }
}

// ── Outbox changes and flushes that overlap (v1.3.0) ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_is_never_undone_by_an_update_in_flight() {
    let dir = TempDir::new();
    let records = Arc::new(FileRecordOutbox::new(dir.0.join("records")));
    let executions = Arc::new(FileOutbox::new(dir.0.join("executions")));
    let mut tasks = Vec::new();
    for n in 0..20 {
        let record = RecordOutboxEntry::new(observe(n));
        records.add(&record).await.unwrap();
        let mut updated = record.clone();
        updated.attempts = 1;
        let (a, b) = (Arc::clone(&records), Arc::clone(&records));
        tasks.push(tokio::spawn(async move { a.update(&updated).await }));
        tasks.push(tokio::spawn(async move { b.remove(&record.id).await }));

        let evidence = OutboxEntry::new(json!({"evidence_id": format!("e-{n}")}));
        executions.add(&evidence).await.unwrap();
        let mut updated = evidence.clone();
        updated.attempts = 1;
        let (a, b) = (Arc::clone(&executions), Arc::clone(&executions));
        tasks.push(tokio::spawn(async move { a.update(&updated).await }));
        tasks.push(tokio::spawn(async move { b.remove(&evidence.id).await }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    for directory in ["records", "executions"] {
        assert_eq!(fs::read_dir(dir.0.join(directory)).unwrap().count(), 0);
    }
    assert!(FileRecordOutbox::new(dir.0.join("records"))
        .list()
        .await
        .unwrap()
        .is_empty());
    assert!(FileOutbox::new(dir.0.join("executions"))
        .list()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn an_add_takes_the_next_sequence_without_reusing_a_removed_one() {
    let dir = TempDir::new();
    let outbox = FileRecordOutbox::new(dir.records());
    let entries: Vec<RecordOutboxEntry> =
        (0..3).map(|n| RecordOutboxEntry::new(observe(n))).collect();
    for entry in &entries {
        outbox.add(entry).await.unwrap();
    }
    outbox.remove(&entries[2].id).await.unwrap();
    let fourth = RecordOutboxEntry::new(observe(3));
    outbox.add(&fourth).await.unwrap();
    assert!(dir
        .records()
        .join(format!("000000000004-{}.json", fourth.id))
        .exists());
    // A new instance continues after the highest sequence on disk.
    let fifth = RecordOutboxEntry::new(observe(4));
    FileRecordOutbox::new(dir.records())
        .add(&fifth)
        .await
        .unwrap();
    assert!(dir
        .records()
        .join(format!("000000000005-{}.json", fifth.id))
        .exists());
    let ids: Vec<String> = FileRecordOutbox::new(dir.records())
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.id)
        .collect();
    let expected = [&entries[0], &entries[1], &fourth, &fifth].map(|e| e.id.clone());
    assert_eq!(ids, expected);
}

fn slow_recorded() -> (u16, String, Duration) {
    let (status, reply) = recorded();
    (status, reply, Duration::from_millis(400))
}

#[tokio::test]
async fn a_flush_leaves_an_execution_record_enqueue_is_submitting_to_it() {
    let v = vectors();
    let (url, task) = serve(vec![slow_recorded()]).await;
    let c = GenesisMeshClient::new(options(&url).with_outbox(Arc::new(MemoryOutbox::default())))
        .unwrap();
    let evidence = recorder()
        .record(RecordExecution {
            decision: v["allowed"]["decision"].clone(),
            executed_capability: "sp-secret.rotate".into(),
            ..RecordExecution::default()
        })
        .unwrap();
    let store = &c.evidence_store;
    let (delivery, report) = tokio::join!(store.enqueue(evidence.clone()), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        store
            .flush_pending(FlushOptions {
                ignore_backoff: true,
            })
            .await
    });
    assert_eq!(delivery.unwrap().submission.unwrap()["status"], "recorded");
    let report = report.unwrap();
    assert!(report.admitted.is_empty() && report.dead_lettered.is_empty());
    assert_eq!(report.pending.len(), 1);
    assert_eq!(report.pending[0].evidence, evidence);
    // The flush did not submit it: no attempt, no error.
    assert_eq!(report.pending[0].attempts, 0);
    assert!(report.pending[0].last_error.is_none());
    assert!(store.outbox().unwrap().list().await.unwrap().is_empty());
    assert_eq!(task.await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_flush_leaves_a_record_enqueue_record_is_submitting_to_it() {
    let (url, task) = serve(vec![slow_recorded()]).await;
    let c = client(&url);
    let record = observe(1);
    let store = &c.evidence_store;
    let (delivery, report) = tokio::join!(store.enqueue_record(record.clone()), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        store
            .flush_records(FlushOptions {
                ignore_backoff: true,
            })
            .await
    });
    assert_eq!(delivery.unwrap().submission.unwrap()["status"], "recorded");
    let report = report.unwrap();
    assert!(report.admitted.is_empty() && report.dead_lettered.is_empty());
    assert_eq!(report.pending.len(), 1);
    assert_eq!(report.pending[0].record, record);
    // The flush did not submit it: no attempt, no error.
    assert_eq!(report.pending[0].attempts, 0);
    assert!(report.pending[0].last_error.is_none());
    let outbox = store.record_outbox().unwrap();
    assert!(outbox.list().await.unwrap().is_empty());
    assert_eq!(task.await.unwrap().len(), 1);
}

// ── Second review round (v1.3.0) ─────────────────────────────────────────────

/// A response whose body ends before its announced length.
fn truncated() -> (String, Duration) {
    (
        "HTTP/1.1 200 Test\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"decision\":"
            .into(),
        Duration::ZERO,
    )
}

#[tokio::test]
async fn an_answer_whose_body_cannot_be_read_never_breaks_the_glass() {
    let v = vectors();
    let (url, _task) = serve_raw(vec![truncated(), truncated()]).await;
    let c = client(&url);
    let (outcome, calls) = run(&c, &c, params(&v, "ctx-r1"), justification(), rotated()).await;
    let err = outcome.unwrap_err();
    assert!(
        matches!(
            err,
            GenesisMeshError::ResponseBodyUnreadable { status: 200, .. }
        ),
        "{err}"
    );
    assert_eq!(err.code(), "response_body_unreadable");
    assert!(genesis_mesh_sdk::evaluation_failure(&err).is_none());
    assert!(calls.is_empty());
    let outbox = c.evidence_store.record_outbox().unwrap();
    assert!(outbox.list().await.unwrap().is_empty());
    // An unread answer to a submission is retried: the NA admits a record once.
    let delivery = c.evidence_store.enqueue_record(observe(1)).await.unwrap();
    let queued = delivery.queued.unwrap();
    assert_eq!(queued.state, OutboxState::Pending);
    assert_eq!(code(&queued), "response_body_unreadable");
}

#[tokio::test]
async fn an_outcome_detail_is_cut_to_what_the_na_admits() {
    let v = vectors();
    let (url, _task) = scripted(vec![unavailable(), recorded()]).await;
    let c = client(&url);
    let report = Ok(ActionReport {
        outcome_detail: Some("one more detail, ".repeat(90)),
        ..ActionReport::default()
    });
    let (outcome, _) = run(&c, &c, params(&v, "ctx-r2"), justification(), report).await;
    let result = broke(outcome.unwrap());
    let detail = result.record["outcome_detail"].as_str().unwrap();
    assert_eq!(detail.chars().count(), 1024);
    assert!(detail.ends_with('\u{2026}'));
}

#[tokio::test]
async fn a_record_is_always_kept_once_the_action_ran() {
    let v = vectors();
    let (url, _task) = scripted(vec![unavailable(), unavailable()]).await;
    let c = client(&url);
    let mut p = params(&v, "ctx-r3");
    p.evaluate["context"]["attributes"]["note"] = json!("a short note, ".repeat(650));
    let report: serde_json::Map<String, Value> = (0..300)
        .map(|i| (format!("k{i}"), json!(format!("item {i} of the report"))))
        .collect();
    let report = Ok(ActionReport {
        value: Some("done".into()),
        execution_parameters: Some(Value::Object(report)),
        outcome_detail: Some("a long detail, ".repeat(100)),
        ..ActionReport::default()
    });
    let (outcome, _) = run(&c, &c, p, justification(), report).await;
    let result = broke(outcome.unwrap());
    assert_eq!(result.value.as_deref(), Some("done"));
    assert_eq!(result.queued.unwrap().state, OutboxState::Pending);
    assert_eq!(result.record["execution_parameters"], json!({}));
    assert_eq!(
        result.record["outcome_detail"],
        "[secret guard dropped the report]"
    );
    assert_eq!(result.dropped.len(), 301);
    assert!(result.dropped.iter().any(|d| d == "outcome_detail"));
    let executor_key = public_key_from_seed(&STANDARD.encode([5_u8; 32])).unwrap();
    assert!(verify_out_of_band_record(&result.record, &[executor_key]));
}

#[tokio::test]
async fn a_batch_too_large_for_the_na_is_sent_one_observation_at_a_time() {
    let (url, task) = scripted(vec![
        unavailable(),
        refusal(413, "request_entity_too_large"),
        recorded(),
    ])
    .await;
    let c = client(&url);
    c.evidence_store.enqueue_record(observe(1)).await.unwrap();
    let report = c
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 1);
    let targets: Vec<String> = task.await.unwrap().into_iter().map(|r| r.target).collect();
    assert_eq!(
        targets,
        [
            "/evidence/observations",
            "/evidence/observations/batch",
            "/evidence/observations"
        ]
    );
}

#[tokio::test]
async fn outboxes_read_the_compact_canonical_files_the_typescript_sdk_writes() {
    let dir = TempDir::new();
    // Signed over an integral float, as this crate and Python write it.
    let record = observer()
        .record(ObservationInput {
            resource_id: "kv:prod/f".into(),
            action: "rotate".into(),
            capability: "secret.rotate".into(),
            changed_at: Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
            source: "log".into(),
            source_event_id: "f-1".into(),
            metadata: Some(json!({"ratio": 1.0})),
            ..ObservationInput::default()
        })
        .unwrap();
    let canonical = genesis_mesh_sdk::canonical::out_of_band_canonical(&record).unwrap();
    assert!(canonical.contains(r#""ratio":1.0"#), "{canonical}");
    let entry = RecordOutboxEntry::new(record.clone());
    let compact = |entry: Value, format: &str| {
        format!(
            "{{\"entry\":{},\"format\":\"{format}\"}}\n",
            genesis_mesh_sdk::canonical_json(&entry).unwrap()
        )
    };
    fs::create_dir_all(dir.records()).unwrap();
    let file = dir
        .records()
        .join(format!("000000000001-{}.json", entry.id));
    let text = compact(
        serde_json::to_value(&entry).unwrap(),
        "gm.evidence.record-outbox.v1",
    );
    assert!(text.contains(r#""ratio":1.0"#) && text.lines().count() == 1);
    fs::write(&file, text).unwrap();
    let key = [public_key_from_seed(&STANDARD.encode([11; 32])).unwrap()];
    let outbox = FileRecordOutbox::new(dir.records());
    let listed = outbox.list().await.unwrap();
    assert_eq!(listed[0].record, record);
    assert!(verify_out_of_band_record(&listed[0].record, &key));
    // Written back by this crate, the record keeps the form it was signed over.
    let mut updated = listed[0].clone();
    updated.attempts = 1;
    outbox.update(&updated).await.unwrap();
    assert!(fs::read_to_string(&file)
        .unwrap()
        .contains(r#""ratio": 1.0"#));
    let reread = FileRecordOutbox::new(dir.records()).list().await.unwrap();
    assert_eq!(reread[0].attempts, 1);
    assert!(verify_out_of_band_record(&reread[0].record, &key));

    // The execution outbox reads the same layout.
    let executions = dir.0.join("executions");
    fs::create_dir_all(&executions).unwrap();
    let evidence =
        OutboxEntry::new(json!({"evidence_id": "e-1", "execution_parameters": {"ratio": 1.0}}));
    fs::write(
        executions.join("000000000001-e-1.json"),
        compact(
            serde_json::to_value(&evidence).unwrap(),
            "gm.evidence.outbox.v1",
        ),
    )
    .unwrap();
    let listed = FileOutbox::new(&executions).list().await.unwrap();
    assert_eq!(listed, [evidence]);
    let canonical = genesis_mesh_sdk::canonical_json(&listed[0].evidence).unwrap();
    assert!(canonical.contains(r#""ratio":1.0"#), "{canonical}");
}
