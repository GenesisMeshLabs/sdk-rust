//! Remediation, reviews and urgent changes (1.4.0) against a scripted local
//! server: the client calls, remediation records in the record outbox,
//! `rotate_forward_then_disable`, and the SDK's side of the urgent-change
//! scenarios (an emergency capability under an ordinary DENY, break-glass
//! naming it when the NA is down or answers `503` or `429`).

use std::{collections::HashMap, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, SigningKey};
use genesis_mesh_sdk::{
    admin_signing_payload, governed_action, governed_action_with_break_glass, json,
    rotate_forward_then_disable, ActionError, ActionReport, AdminRequest, BreakGlassOptions,
    ClientOptions, EvaluationFailure, ExecutionRecorder, FlushOptions, GenesisMeshClient,
    GenesisMeshError, GovernedActionOutcome, GovernedActionParams, GovernedVerification,
    MemoryRecordOutbox, OutboxState, RecordKind, RecordOutbox, RemediationInput, RemediationQuery,
    RemediationSteps, RemediationSubject, ReviewDecision, RotateForwardParams, RotatedVersion,
    Value,
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
    headers: HashMap<String, String>,
    body: Value,
}

impl Request {
    fn route(&self) -> &str {
        self.target.split('?').next().unwrap()
    }
}

/// Serve one scripted response per connection, in order.
async fn scripted(responses: Vec<(u16, String)>) -> (String, JoinHandle<Vec<Request>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut seen = Vec::new();
        for (status, reply) in responses {
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
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            seen.push(Request {
                method,
                target,
                headers,
                body,
            });
        }
        seen
    });
    (url, task)
}

fn options(url: &str) -> ClientOptions {
    ClientOptions::new(url)
        .with_signing_key(STANDARD.encode([7; 32]))
        .with_key_id("test-key")
        .with_audience("TEST")
}

fn client(url: &str) -> GenesisMeshClient {
    GenesisMeshClient::new(options(url)).unwrap()
}

fn with_records(url: &str) -> (GenesisMeshClient, Arc<MemoryRecordOutbox>) {
    let records = Arc::new(MemoryRecordOutbox::default());
    let outbox: Arc<dyn RecordOutbox> = records.clone();
    let client = GenesisMeshClient::new(options(url).with_record_outbox(outbox)).unwrap();
    (client, records)
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

/// The request is signed by the test operator key over what was sent.
fn assert_admin(request: &Request) {
    assert_eq!(request.headers["x-admin-key-id"], "test-key");
    let sent = reqwest::Url::parse(&format!("http://na{}", request.target)).unwrap();
    let path = percent_encoding::percent_decode_str(sent.path())
        .decode_utf8()
        .unwrap()
        .into_owned();
    let query: Vec<(String, String)> = sent.query_pairs().into_owned().collect();
    let body = if request.body.is_null() {
        json!({})
    } else {
        request.body.clone()
    };
    let payload = admin_signing_payload(
        &AdminRequest {
            method: &request.method,
            path: &path,
            query: &query,
            audience: "TEST",
            body: &body,
        },
        "test-key",
        &request.headers["x-admin-timestamp"],
        &request.headers["x-admin-nonce"],
    )
    .unwrap();
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&request.headers["x-admin-signature"])
            .unwrap(),
    )
    .unwrap();
    SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .verify_strict(payload.as_bytes(), &signature)
        .unwrap();
}

fn at(value: &str) -> DateTime<Utc> {
    value.parse().unwrap()
}

// ── Client calls ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn review_and_due_queue_routes_are_signed_and_encoded_once() {
    let (url, task) = scripted(vec![
        ok(json!({"state": "remediation_due", "count": 0, "remediations": [], "next_after": null})),
        ok(json!({"subject_id": "j/1", "state": "remediation_due", "reviews": [], "records": []})),
        ok(json!({"subject_id": "j/1", "notified_at": "2026-11-02T10:00:00.000000+00:00"})),
        ok(json!({"subject_id": "j/1"})),
        (
            201,
            json!({"review_id": "r-1", "state": "review_pending"}).to_string(),
        ),
        ok(json!({"review_id": "r-1", "opened_for": "requested"})),
        ok(json!({"review": {"payload": {}}, "state": "review_denied"})),
        ok(json!({"review": {"payload": {}}, "state": "upheld"})),
        ok(json!({"review": {"payload": {}}, "state": "waived"})),
    ])
    .await;
    let store = client(&url).evidence_store;
    store
        .remediations(&RemediationQuery {
            state: Some("remediation_due".into()),
            limit: Some(50),
            after: Some("2026-11-02T10:00:00.000000Z|j-0".into()),
        })
        .await
        .unwrap();
    store.remediation("j/1").await.unwrap();
    store.mark_notified("j/1", Some("email")).await.unwrap();
    store.mark_notified("j/1", None).await.unwrap();
    let opened = store
        .request_review("judgement", "j/1", "Planned with the vendor")
        .await
        .unwrap();
    assert_eq!(opened["review_id"], "r-1");
    store.review("r-1").await.unwrap();
    for decision in [
        ReviewDecision::Deny {
            note: Some("Not in the ticket".into()),
        },
        ReviewDecision::Uphold { note: None },
        ReviewDecision::WaiveUntil {
            until: at("2026-11-09T09:00:00Z"),
            note: None,
        },
    ] {
        store.decide_review("r-1", &decision).await.unwrap();
    }
    let r = task.await.unwrap();
    for request in &r {
        assert_admin(request);
    }
    assert_eq!(r[0].route(), "/admin/evidence/remediations");
    assert_eq!(
        r[0].target,
        "/admin/evidence/remediations?state=remediation_due&limit=50&after=2026-11-02T10%3A00%3A00.000000Z%7Cj-0"
    );
    assert_eq!(r[1].target, "/admin/evidence/remediations/j%2F1");
    assert_eq!(r[2].route(), "/admin/evidence/remediations/j%2F1/notified");
    assert_eq!(r[2].body, json!({"channel": "email"}));
    assert_eq!(r[3].body, json!({}));
    assert_eq!(
        (r[4].method.as_str(), r[4].route()),
        ("POST", "/admin/evidence/reviews")
    );
    assert_eq!(
        r[4].body,
        json!({"subject_kind": "judgement", "subject_id": "j/1",
               "justification": "Planned with the vendor"})
    );
    assert_eq!(
        (r[5].method.as_str(), r[5].route()),
        ("GET", "/admin/evidence/reviews/r%2D1")
    );
    // Identifiers are percent-encoded once; the signature covers the decoded
    // path, which the NA embeds in the review.
    assert_eq!(r[6].route(), "/admin/evidence/reviews/r%2D1/decide");
    assert_eq!(
        r[6].body,
        json!({"verdict": "deny", "note": "Not in the ticket"})
    );
    assert_eq!(r[7].body, json!({"verdict": "uphold"}));
    assert_eq!(
        r[8].body,
        json!({"verdict": "waive_until", "waive_until": "2026-11-09T09:00:00Z"})
    );
}

#[tokio::test]
async fn the_due_queue_is_read_page_by_page() {
    let page = |subjects: &[&str], next: Option<&str>| {
        ok(json!({
            "state": "overdue", "count": subjects.len(),
            "remediations": subjects.iter().map(|s| json!({"subject_id": s})).collect::<Vec<_>>(),
            "next_after": next,
        }))
    };
    let (url, task) = scripted(vec![
        page(&["a", "b"], Some("2026-11-02T10:00:00.000000Z|b")),
        page(&["c"], None),
        page(&["a"], Some("same")),
        page(&["a"], Some("same")),
    ])
    .await;
    let store = client(&url).evidence_store;
    let all = store.remediations_all(Some("overdue"), 2).await.unwrap();
    let subjects: Vec<&str> = all
        .iter()
        .map(|s| s["subject_id"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, ["a", "b", "c"]);
    let stuck = store.remediations_all(None, 2).await.unwrap_err();
    assert!(stuck.to_string().contains("did not advance"), "{stuck}");
    for size in [0, 501] {
        assert_eq!(
            store.remediations_all(None, size).await.unwrap_err().code(),
            "configuration"
        );
    }
    let r = task.await.unwrap();
    assert_eq!(
        r[0].target,
        "/admin/evidence/remediations?state=overdue&limit=2"
    );
    assert!(r[1]
        .target
        .ends_with("&after=2026-11-02T10%3A00%3A00.000000Z%7Cb"));
    assert_eq!(r[2].target, "/admin/evidence/remediations?limit=2");
}

// ── Remediation records ──────────────────────────────────────────────────────

fn executor() -> ExecutionRecorder {
    ExecutionRecorder::new(
        "secrets-controller",
        "ctrl-rust",
        &STANDARD.encode([5_u8; 32]),
    )
    .unwrap()
}

fn subject(resource: &str) -> RemediationSubject {
    RemediationSubject {
        subject_kind: "judgement".into(),
        subject_id: "judgement-1".into(),
        change_kind: "observation".into(),
        change_id: "observation-1".into(),
        resource_id: resource.into(),
    }
}

fn alerted() -> Value {
    executor()
        .sign_remediation(RemediationInput::new(
            subject("kv:vault/api-key"),
            RemediationSteps::Alerted,
        ))
        .unwrap()
}

#[tokio::test]
async fn a_remediation_record_is_submitted_by_its_signature_alone() {
    let (url, task) = scripted(vec![(
        201,
        json!({"status": "recorded", "remediation": {"state": "remediated"}}).to_string(),
    )])
    .await;
    let record = alerted();
    let answer = client(&url)
        .evidence_store
        .submit_remediation(record.clone())
        .await
        .unwrap();
    assert_eq!(answer["remediation"]["state"], "remediated");
    let r = task.await.unwrap();
    assert_eq!(r[0].route(), "/evidence/remediations");
    assert_eq!(r[0].body, json!({ "record": record }));
    assert!(!r[0].headers.keys().any(|k| k.starts_with("x-admin-")));
}

#[tokio::test]
async fn the_record_outbox_retries_what_may_be_admitted_later_and_keeps_the_rest() {
    let (url, task) = scripted(vec![
        refusal(422, "remediation_rotation_missing"),
        refusal(422, "remediation_steps_mismatch"),
        refusal(409, "remediation_already_recorded"),
        refusal(422, "remediation_subject_not_found"),
        refusal(422, "remediation_unknown_key"),
    ])
    .await;
    let (c, records) = with_records(&url);
    let mut outcomes = Vec::new();
    for _ in 0..5 {
        let delivery = c.evidence_store.enqueue_record(alerted()).await.unwrap();
        let queued = delivery.queued.unwrap();
        assert_eq!(queued.kind, RecordKind::Remediation);
        outcomes.push((
            queued.last_error.unwrap().code,
            queued.state == OutboxState::Pending,
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("remediation_rotation_missing".to_owned(), true),
            ("remediation_steps_mismatch".to_owned(), false),
            ("remediation_already_recorded".to_owned(), false),
            ("remediation_subject_not_found".to_owned(), true),
            ("remediation_unknown_key".to_owned(), true),
        ]
    );
    let kept = records.list().await.unwrap();
    assert_eq!(kept.len(), 5);
    assert_eq!(
        serde_json::to_value(&kept[0]).unwrap()["kind"],
        "remediation"
    );
    let r = task.await.unwrap();
    assert!(r.iter().all(|q| q.route() == "/evidence/remediations"));
}

#[tokio::test]
async fn a_flush_submits_remediations_after_break_glass_records_and_observations() {
    use genesis_mesh_sdk::{BreakGlassInput, ObservationInput, ObservationRecorder};
    let remediation = alerted();
    let break_glass = executor()
        .sign_break_glass(BreakGlassInput::new(
            "kv:vault/api-key",
            "rotate",
            "secret.rotate",
            "incident 42",
            json!({"requested_capability": "secret.rotate"}),
            EvaluationFailure::NetworkError,
        ))
        .unwrap();
    let observation = ObservationRecorder::new("observer", "observer-1", &STANDARD.encode([9; 32]))
        .unwrap()
        .record(ObservationInput {
            resource_id: "kv:vault/api-key".into(),
            action: "rotate".into(),
            capability: "secret.rotate".into(),
            changed_at: Some(at("2026-11-02T10:00:00Z")),
            source: "cloud-activity-log".into(),
            source_event_id: "event-1".into(),
            ..ObservationInput::default()
        })
        .unwrap();
    let records = Arc::new(MemoryRecordOutbox::default());
    for record in [&remediation, &observation, &break_glass] {
        records
            .add(&genesis_mesh_sdk::RecordOutboxEntry::new(record.clone()))
            .await
            .unwrap();
    }
    let (url, task) = scripted(vec![
        ok(json!({"status": "recorded"})),
        ok(json!({"results": [{"index": 0, "status": "recorded"}]})),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let outbox: Arc<dyn RecordOutbox> = records.clone();
    let c = GenesisMeshClient::new(options(&url).with_record_outbox(outbox)).unwrap();
    let report = c
        .evidence_store
        .flush_records(FlushOptions::default())
        .await
        .unwrap();
    assert_eq!(report.admitted.len(), 3);
    assert!(records.list().await.unwrap().is_empty());
    let routes: Vec<String> = task
        .await
        .unwrap()
        .iter()
        .map(|r| r.route().to_owned())
        .collect();
    assert_eq!(
        routes,
        [
            "/evidence/break-glass",
            "/evidence/observations/batch",
            "/evidence/remediations"
        ]
    );
}

// ── rotate_forward_then_disable ──────────────────────────────────────────────

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/python-vectors.json")).unwrap()
}

/// A decision of the vectors' shape signed now by a test NA key.
fn signed_evaluation(v: &Value, allowed: bool, context_id: &str) -> Value {
    let na = SigningKey::from_bytes(&[3; 32]);
    let source = if allowed { &v["allowed"] } else { &v["denied"] };
    let mut decision = source["decision"].clone();
    let now = Utc::now();
    decision["context_id"] = json!(context_id);
    decision["decision_made_at"] = json!(genesis_mesh_sdk::canonical::python_timestamp(now));
    decision["decision_valid_until"] = json!(genesis_mesh_sdk::canonical::python_timestamp(
        now + chrono::Duration::minutes(5)
    ));
    let canonical = genesis_mesh_sdk::canonical::decision_canonical(&decision).unwrap();
    decision["signature"] = genesis_mesh_sdk::sign_canonical(&canonical, "na", &na);
    json!({"decision": decision, "justification_proof": source["justification_proof"]})
}

fn na_key() -> String {
    STANDARD.encode(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes())
}

fn governed(
    v: &Value,
    context_id: &str,
    capability: &str,
    parameters: Value,
) -> GovernedActionParams {
    GovernedActionParams {
        evaluate: json!({
            "attestation_id": v["attestation"]["attestation_id"],
            "requested_capability": capability,
            "context": {"context_id": context_id, "request_parameters": parameters},
        }),
        resource_id: Some(v["resource_id"].as_str().unwrap().to_owned()),
        resource_action: None,
        prior_resource: Some(None),
        verify: GovernedVerification {
            operator_public_keys: vec![na_key()],
            expected_policies: vec![v["policy"].clone()],
            expected_attestation: Some(v["attestation"].clone()),
            ..GovernedVerification::default()
        },
    }
}

fn forward(v: &Value, context_id: &str) -> RotateForwardParams {
    RotateForwardParams {
        governed: governed(
            v,
            context_id,
            "sp-secret.rotate",
            json!({"app_id": "billing"}),
        ),
        subject: subject(v["resource_id"].as_str().unwrap()),
        disabled_version_id: "v8".into(),
        detail: Some("ticket 7".into()),
    }
}

async fn rotated(
    version: &'static str,
) -> std::result::Result<RotatedVersion<&'static str>, ActionError> {
    Ok(RotatedVersion {
        value: Some("current"),
        ..RotatedVersion::new(version)
    })
}

#[tokio::test]
async fn a_forward_rotation_then_a_disable_is_recorded_as_two_linked_records() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-1")),
        ok(json!({"status": "recorded"})),
        (
            201,
            json!({"status": "recorded", "remediation": {"state": "remediated"}}).to_string(),
        ),
    ])
    .await;
    let (c, records) = with_records(&url);
    let disabled = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = disabled.clone();
    let result = rotate_forward_then_disable(
        &c.boundary,
        &c.evidence_store,
        &executor(),
        forward(&v, "ctx-1"),
        |decision| {
            assert_eq!(decision["authorized"], true);
            rotated("v9")
        },
        |version| async move {
            seen.lock().unwrap().push(version);
            Ok::<_, ActionError>(())
        },
    )
    .await
    .unwrap();
    assert_eq!(*disabled.lock().unwrap(), ["v8"]);
    assert_eq!(result.rotation.value, Some("current"));
    let evidence = result.rotation.evidence.unwrap();
    assert_eq!(evidence["resource_action"], "rotate");
    assert_eq!(
        evidence["execution_parameters"],
        json!({"version_id": "v9"})
    );
    let record = result.record.unwrap();
    assert_eq!(record["rotation_evidence_id"], evidence["evidence_id"]);
    assert_eq!(
        (&record["version_id"], &record["disabled_version_id"]),
        (&json!("v9"), &json!("v8"))
    );
    assert_eq!(record["steps"], "rotate_forward_then_disable");
    assert_eq!(record["detail"], "ticket 7");
    assert_eq!(result.submission.unwrap()["status"], "recorded");
    assert!(result.queued.is_none());
    assert!(records.list().await.unwrap().is_empty());
    let r = task.await.unwrap();
    assert_eq!(r[1].route(), "/evidence/execution");
    assert_eq!(r[2].route(), "/evidence/remediations");
    assert_eq!(r[2].body["record"], record);
}

#[tokio::test]
async fn a_denied_rotation_disables_nothing() {
    let v = vectors();
    let (url, task) = scripted(vec![ok(signed_evaluation(&v, false, "ctx-2"))]).await;
    let (c, _) = with_records(&url);
    let result: genesis_mesh_sdk::RotateForwardResult<()> = rotate_forward_then_disable(
        &c.boundary,
        &c.evidence_store,
        &executor(),
        forward(&v, "ctx-2"),
        |_| async { panic!("the rotation ran under a DENY") },
        |_: String| async { panic!("disabled under a DENY") },
    )
    .await
    .unwrap();
    assert!(!result.rotation.authorized);
    assert!(result.record.is_none() && result.rotation.evidence.is_none());
    assert_eq!(task.await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_failed_disable_leaves_the_rotation_recorded_and_the_remediation_incomplete() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-3")),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let (c, records) = with_records(&url);
    let err = rotate_forward_then_disable(
        &c.boundary,
        &c.evidence_store,
        &executor(),
        forward(&v, "ctx-3"),
        |_| rotated("v9"),
        |_| async { Err::<(), ActionError>("the vault refused".into()) },
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "remediation_incomplete");
    let GenesisMeshError::RemediationIncomplete {
        rotation, record, ..
    } = err
    else {
        panic!("not incomplete");
    };
    assert_eq!(rotation["execution_parameters"]["version_id"], "v9");
    assert!(record.is_none());
    assert!(records.list().await.unwrap().is_empty());
    assert_eq!(task.await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_rotation_that_cannot_be_remediated_is_refused_before_it_runs() {
    let v = vectors();
    // Nothing listens: every refusal comes before the NA is asked.
    let (c, _) = with_records("http://127.0.0.1:9");
    let run = |params: RotateForwardParams, client: GenesisMeshClient| async move {
        rotate_forward_then_disable(
            &client.boundary,
            &client.evidence_store,
            &executor(),
            params,
            |_| async { panic!("ran") },
            |_: String| async { panic!("disabled") },
        )
        .await
        .map(|_: genesis_mesh_sdk::RotateForwardResult<()>| ())
        .unwrap_err()
        .code()
        .to_owned()
    };
    assert_eq!(
        run(forward(&v, "c"), client("http://127.0.0.1:9")).await,
        "record_outbox_required"
    );
    let other_resource = RotateForwardParams {
        subject: subject("kv:vault/other"),
        ..forward(&v, "c")
    };
    assert_eq!(run(other_resource, c.clone()).await, "configuration");
    let mut deleted = forward(&v, "c");
    deleted.governed.resource_action = Some("delete".into());
    assert_eq!(run(deleted, c.clone()).await, "configuration");
    let secret = RotateForwardParams {
        disabled_version_id: "-----BEGIN PRIVATE KEY-----".into(),
        ..forward(&v, "c")
    };
    assert_eq!(run(secret, c.clone()).await, "remediation_secret_material");
    let long = RotateForwardParams {
        disabled_version_id: format!("version {}", "x".repeat(248)),
        ..forward(&v, "c")
    };
    // A 256-character version is one the NA takes: the NA is asked.
    assert_eq!(run(long, c).await, "network");
}

// ── Urgent changes (SDK side) ────────────────────────────────────────────────

const EMERGENCY: &str = "sp-secret.rotate.emergency";

fn emergency(v: &Value, context_id: &str) -> GovernedActionParams {
    let mut params = governed(
        v,
        context_id,
        EMERGENCY,
        json!({"app_id": "billing", "justification": "key leaked in a public repository"}),
    );
    params.resource_action = Some("rotate".into());
    params
}

/// The NA is up and denies the ordinary capability: the controller asks for
/// the emergency capability with its justification, the NA decides it under
/// the emergency policy, and the change runs and is recorded under it.
#[tokio::test]
async fn an_urgent_change_under_an_ordinary_deny_runs_under_the_emergency_capability() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, false, "ordinary")),
        ok(signed_evaluation(&v, true, "urgent")),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = client(&url);
    let mut ordinary = emergency(&v, "ordinary");
    ordinary.evaluate["requested_capability"] = json!("sp-secret.rotate");
    let denied = governed_action(
        &c.boundary,
        &c.evidence_store,
        &executor(),
        ordinary,
        |_| async { panic!("ran under a DENY") },
    )
    .await
    .map(|r: genesis_mesh_sdk::GovernedActionResult<()>| r.authorized)
    .unwrap();
    assert!(!denied);
    let urgent = governed_action(
        &c.boundary,
        &c.evidence_store,
        &executor(),
        emergency(&v, "urgent"),
        |_| async {
            Ok::<_, ActionError>(ActionReport {
                value: Some("rotated"),
                execution_parameters: Some(json!({"version_id": "v9"})),
                ..ActionReport::default()
            })
        },
    )
    .await
    .unwrap();
    assert!(urgent.authorized);
    let evidence = urgent.evidence.unwrap();
    assert_eq!(evidence["executed_capability"], EMERGENCY);
    let r = task.await.unwrap();
    assert_eq!(r[1].body["requested_capability"], EMERGENCY);
    assert_eq!(
        r[1].body["context"]["request_parameters"]["justification"],
        "key leaked in a public repository"
    );
    assert_eq!(r[2].body["evidence"], evidence);
}

async fn break_glass_naming_the_emergency_capability(
    boundary: &GenesisMeshClient,
    store: &GenesisMeshClient,
    v: &Value,
) -> genesis_mesh_sdk::BreakGlassResult<&'static str> {
    let outcome = governed_action_with_break_glass(
        &boundary.boundary,
        &store.evidence_store,
        &executor(),
        emergency(v, "urgent"),
        BreakGlassOptions::new("key leaked in a public repository; NA unavailable"),
        |decision| async move {
            assert!(decision.is_none());
            Ok::<_, ActionError>(ActionReport {
                value: Some("rotated"),
                execution_parameters: Some(json!({"version_id": "v9"})),
                ..ActionReport::default()
            })
        },
    )
    .await
    .unwrap();
    let GovernedActionOutcome::BrokeGlass(result) = outcome else {
        panic!("the glass was not broken");
    };
    // Judged under the emergency policy when it arrives: it names the
    // emergency capability and carries the justification parameter.
    assert_eq!(result.record["capability"], EMERGENCY);
    assert_eq!(
        result.record["request_parameters"]["justification"],
        "key leaked in a public repository"
    );
    assert_eq!(result.value, Some("rotated"));
    result
}

/// The NA cannot be reached: the change runs under break-glass naming the
/// emergency capability, kept in the record outbox until the NA is back.
#[tokio::test]
async fn an_urgent_change_with_the_na_down_breaks_the_glass_naming_the_emergency_capability() {
    let v = vectors();
    let down = client("http://127.0.0.1:9");
    let (stores, records) = with_records("http://127.0.0.1:9");
    let result = break_glass_naming_the_emergency_capability(&down, &stores, &v).await;
    assert_eq!(result.failure, EvaluationFailure::NetworkError);
    assert_eq!(result.queued.unwrap().state, OutboxState::Pending);
    assert_eq!(records.list().await.unwrap().len(), 1);
}

/// The NA answers `503` or `429`: the same, and the record is admitted (and
/// judged) once it answers again.
#[tokio::test]
async fn an_urgent_change_with_the_na_answering_503_or_429_breaks_the_glass() {
    let v = vectors();
    for (status, code, failure) in [
        (503, "service_unavailable", EvaluationFailure::ServerError),
        (429, "rate_limited", EvaluationFailure::RateLimited),
    ] {
        let (url, task) = scripted(vec![
            refusal(status, code),
            (
                201,
                json!({"status": "recorded", "judgement": {"payload": {"verdict": "allow"}}})
                    .to_string(),
            ),
        ])
        .await;
        let (c, _) = with_records(&url);
        let result = break_glass_naming_the_emergency_capability(&c, &c, &v).await;
        assert_eq!(result.failure, failure);
        assert_eq!(
            result.submission.unwrap()["judgement"]["payload"]["verdict"],
            "allow"
        );
        let r = task.await.unwrap();
        assert_eq!(r[1].route(), "/evidence/break-glass");
        assert_eq!(r[1].body["record"]["capability"], EMERGENCY);
    }
}
