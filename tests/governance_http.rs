//! HTTP contract tests for the policy, evidence-store and health clients and
//! for `governed_action`, against a scripted local server.

use std::{collections::HashMap, io, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, SigningKey};
use genesis_mesh_sdk::{
    admin_signing_payload, canonical::execution_digest, governed_action, json, ActionError,
    ActionReport, AdminRequest, ClientOptions, EvidenceOutbox, ExecutionRecorder, FlushOptions,
    GenesisMeshClient, GenesisMeshError, GovernedActionParams, GovernedActionResult,
    GovernedVerification, MemoryOutbox, OutboxEntry, OutboxFuture, OutboxState, PriorResource,
    RecordExecution, ResourceHead, Value, PREDECESSOR_DEAD_LETTERED,
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
    fn query(&self) -> HashMap<String, String> {
        self.target
            .split_once('?')
            .map(|(_, q)| {
                q.split('&')
                    .filter_map(|p| p.split_once('='))
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect()
            })
            .unwrap_or_default()
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
        // Admin signatures name the NA's sovereign ID; the mock NA is "TEST".
        .with_audience("TEST")
}

fn client(url: &str) -> GenesisMeshClient {
    GenesisMeshClient::new(options(url)).unwrap()
}

fn client_with(url: &str, outbox: Arc<dyn EvidenceOutbox>) -> GenesisMeshClient {
    GenesisMeshClient::new(options(url).with_outbox(outbox)).unwrap()
}

fn with_outbox(url: &str) -> GenesisMeshClient {
    client_with(url, Arc::new(MemoryOutbox::default()))
}

fn assert_admin(request: &Request, signed_body: &Value) {
    assert_eq!(request.headers["x-admin-key-id"], "test-key");
    // Signature version 2: method, decoded path, query and audience are signed.
    let sent = reqwest::Url::parse(&format!("http://na{}", request.target)).unwrap();
    let path = percent_encoding::percent_decode_str(sent.path())
        .decode_utf8()
        .unwrap()
        .into_owned();
    let query: Vec<(String, String)> = sent.query_pairs().into_owned().collect();
    let payload = admin_signing_payload(
        &AdminRequest {
            method: &request.method,
            path: &path,
            query: &query,
            audience: "TEST",
            body: signed_body,
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

fn assert_public(request: &Request) {
    assert!(!request.headers.keys().any(|k| k.starts_with("x-admin-")));
}

fn ok(body: Value) -> (u16, String) {
    (200, body.to_string())
}

fn not_found(code: &str) -> (u16, String) {
    (
        404,
        json!({"error": {"code": code, "message": "not found"}}).to_string(),
    )
}

#[tokio::test]
async fn policy_lifecycle_routes() {
    let (url, task) = scripted(vec![
        ok(json!({"valid": true})),
        ok(json!({"policy_id": "p/1"})),
        ok(json!({"policies": [{"policy_id": "p"}]})),
        ok(json!({"active": []})),
        ok(json!({"versions": []})),
        ok(json!({"active": true})),
        ok(json!({"active": false})),
        ok(json!({"valid": true})),
    ])
    .await;
    let c = client(&url);
    let intent = json!({"policy_id": "p/1"});
    c.policy.validate(intent.clone()).await.unwrap();
    c.policy.publish(intent.clone()).await.unwrap();
    assert_eq!(
        c.policy.list().await.unwrap(),
        vec![json!({"policy_id": "p"})]
    );
    c.policy.active().await.unwrap();
    c.policy.history("p/1").await.unwrap();
    c.policy.activate("p/1", 2).await.unwrap();
    c.policy.deactivate("p/1", 2).await.unwrap();
    c.policy.verify(json!({"policy": {}})).await.unwrap();
    let r = task.await.unwrap();
    let expected = [
        ("POST", "/admin/boundary-policies/validate"),
        ("POST", "/admin/boundary-policies"),
        ("GET", "/admin/boundary-policies"),
        ("GET", "/admin/boundary-policies/active"),
        ("GET", "/admin/boundary-policies/p%2F1/history"),
        ("POST", "/admin/boundary-policies/p%2F1/activate"),
        ("POST", "/admin/boundary-policies/p%2F1/deactivate"),
        ("POST", "/boundary-policies/verify"),
    ];
    for (request, (method, route)) in r.iter().zip(expected) {
        assert_eq!((request.method.as_str(), request.route()), (method, route));
    }
    assert_admin(&r[0], &intent);
    assert_admin(&r[2], &json!({}));
    assert_admin(&r[5], &json!({"version": 2}));
    assert_eq!(r[5].body, json!({"version": 2}));
    assert_public(&r[7]);
}

#[tokio::test]
async fn evidence_store_routes_encode_identifiers_once() {
    let (url, task) = scripted(vec![
        ok(json!({"mode": "on"})),
        ok(json!({"verified": true})),
        ok(json!({"entries": []})),
        ok(json!({"entries": []})),
        ok(json!({"executor_keys": [{"key_id": "k"}]})),
        ok(json!({"key_id": "k"})),
        ok(json!({"retired": true})),
        ok(json!({"removed_count": 0})),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = client(&url);
    c.evidence_store.status().await.unwrap();
    c.evidence_store.verify().await.unwrap();
    c.evidence_store
        .resource_history("kv:pilot vault/secret")
        .await
        .unwrap();
    c.evidence_store.vendor_history("vendor/zoë").await.unwrap();
    assert_eq!(
        c.evidence_store.list_executor_keys().await.unwrap().len(),
        1
    );
    c.evidence_store
        .register_executor_key(
            json!({"key_id": "k", "public_key": "x", "executor_sovereign_id": "c"}),
        )
        .await
        .unwrap();
    c.evidence_store.retire_executor_key("k").await.unwrap();
    c.evidence_store.apply_retention(90).await.unwrap();
    let evidence =
        json!({"execution_parameters": {"secret_version": "v1"}, "outcome_detail": null});
    c.evidence_store.submit(evidence.clone()).await.unwrap();
    let r = task.await.unwrap();
    let routes: Vec<&str> = r.iter().map(Request::route).collect();
    assert_eq!(
        routes,
        [
            "/admin/evidence/status",
            "/admin/evidence/verify",
            "/admin/evidence/resources/kv%3Apilot%20vault/secret",
            "/admin/evidence/vendors/vendor%2Fzo%C3%AB",
            "/admin/evidence/executor-keys",
            "/admin/evidence/executor-keys",
            "/admin/evidence/executor-keys/k/retire",
            "/admin/evidence/retention/apply",
            "/evidence/execution",
        ]
    );
    for request in &r[..4] {
        assert_eq!(request.method, "GET");
        assert_admin(request, &json!({}));
    }
    assert_eq!(r[7].body, json!({"older_than_days": 90}));
    assert_public(&r[8]);
    assert_eq!(r[8].body, json!({"evidence": evidence}));
}

#[tokio::test]
async fn refuses_dot_segments_and_secret_material_before_sending() {
    let c = client("http://127.0.0.1:9");
    for id in ["..", ".", "", "kv:v/../admin", "kv:v//s"] {
        let err = c.evidence_store.resource_head(id).await.unwrap_err();
        assert!(matches!(err, GenesisMeshError::Configuration(_)), "{id}");
    }
    let err = c
        .evidence_store
        .submit(json!({"execution_parameters": {"token": "x"}}))
        .await
        .unwrap_err();
    assert!(matches!(err, GenesisMeshError::SecretMaterial(_)));
    let err = c
        .boundary
        .evaluate(json!({"requested_capability": "c", "attestation_id": "a", "agreement": {}}))
        .await
        .unwrap_err();
    assert!(matches!(err, GenesisMeshError::Configuration(_)));
}

#[tokio::test]
async fn search_all_follows_cursors_and_rejects_a_stuck_cursor() {
    let (url, task) = scripted(vec![
        ok(json!({"entries": [{"n": 1}], "next_after_sequence": 5})),
        ok(json!({"entries": [{"n": 2}], "next_after_sequence": null})),
        ok(json!({"entries": [], "next_after_sequence": 0})),
    ])
    .await;
    let c = client(&url);
    let entries = c
        .evidence_store
        .search_all(json!({"entry_kind": "execution", "vendor_id": "v 1"}))
        .await
        .unwrap();
    assert_eq!(entries, vec![json!({"n": 1}), json!({"n": 2})]);
    let stuck = c.evidence_store.search_all(json!({})).await.unwrap_err();
    assert!(matches!(stuck, GenesisMeshError::Verification(_)));
    let r = task.await.unwrap();
    assert_eq!(r[0].query()["after_sequence"], "0");
    assert_eq!(r[0].query()["vendor_id"], "v+1");
    assert_eq!(r[1].query()["after_sequence"], "5");
    assert_eq!(r[1].query()["entry_kind"], "execution");
}

#[tokio::test]
async fn export_pages_ndjson_and_validates_page_size() {
    let v: Value = serde_json::from_str(include_str!("fixtures/python-vectors.json")).unwrap();
    let lines: Vec<&str> = v["export"].as_str().unwrap().lines().collect();
    let (url, task) = scripted(vec![
        (200, lines[..5].join("\n")),
        (200, lines[5..].join("\n") + "\n"),
    ])
    .await;
    let c = client(&url);
    assert_eq!(c.evidence_store.export_all(0, 5).await.unwrap().len(), 8);
    let r = task.await.unwrap();
    assert_eq!(r[0].query()["since_sequence"], "0");
    assert_eq!(r[1].query()["since_sequence"], "5");
    assert_eq!(r[1].query()["limit"], "5");
    for bad in [0, 1001] {
        assert!(c.evidence_store.export_all(0, bad).await.is_err());
    }
}

#[tokio::test]
async fn resource_head_uses_its_route_and_returns_none_for_an_unknown_resource() {
    let (url, task) = scripted(vec![
        ok(json!({"resource_id": "kv:v/s", "resource_sequence": 4, "record_digest": "d"})),
        not_found("resource_not_found"),
    ])
    .await;
    let c = client(&url);
    let head = c.evidence_store.resource_head("kv:v/s").await.unwrap();
    assert_eq!(
        head,
        Some(ResourceHead {
            resource_sequence: 4,
            record_digest: "d".into()
        })
    );
    assert_eq!(
        c.evidence_store.resource_head("kv:v/s").await.unwrap(),
        None
    );
    let r = task.await.unwrap();
    assert_eq!(r[0].route(), "/admin/evidence/resource-heads/kv%3Av/s");
    assert_admin(&r[0], &json!({}));
}

fn history_with(v: &Value, verified: bool, truncated: bool) -> (u16, String) {
    let events: Vec<Value> = v["export"]
        .as_str()
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    ok(json!({"entries": events, "verification": {"verified": verified}, "truncated": truncated}))
}

#[tokio::test]
async fn older_na_falls_back_to_history_and_refuses_unverified_or_truncated_history() {
    let v: Value = serde_json::from_str(include_str!("fixtures/python-vectors.json")).unwrap();
    let resource = v["resource_id"].as_str().unwrap();
    let (url, task) = scripted(vec![
        not_found("not_found"),
        history_with(&v, true, false),
        not_found("not_found"),
        history_with(&v, true, true),
        not_found("not_found"),
        history_with(&v, false, false),
        not_found("not_found"),
        not_found("resource_not_found"),
        ok(json!({"entries": [{"payload": v["checkpoint"]}], "next_after_sequence": null})),
    ])
    .await;
    let c = client(&url);
    let head = c
        .evidence_store
        .resource_head(resource)
        .await
        .unwrap()
        .unwrap();
    let digests = v["execution_digests"].as_array().unwrap();
    assert_eq!(
        head.record_digest,
        digests.last().unwrap().as_str().unwrap()
    );
    for _ in 0..2 {
        let err = c.evidence_store.resource_head(resource).await.unwrap_err();
        assert!(matches!(err, GenesisMeshError::Verification(_)), "{err}");
    }
    let from_checkpoint = c.evidence_store.resource_head(resource).await.unwrap();
    let expected = v["checkpoint"]["resource_heads"].get(resource).cloned();
    assert_eq!(
        from_checkpoint.map(|h| serde_json::to_value(h).unwrap()),
        expected
    );
    task.await.unwrap();
}

#[tokio::test]
async fn readiness_reports_not_ready_without_an_error() {
    let (url, task) = scripted(vec![
        ok(json!({"status": "ready", "database": {"backend": "sqlite"}})),
        (
            503,
            json!({"error": {"code": "service_not_ready", "message": "x", "details": {"checks": {"database": false}}}})
                .to_string(),
        ),
        ok(json!({"status": "ok"})),
    ])
    .await;
    let c = client(&url);
    let ready = c.health.readiness().await.unwrap();
    assert_eq!(
        (ready["ready"].clone(), ready["database"]["backend"].clone()),
        (json!(true), json!("sqlite"))
    );
    let not_ready = c.health.readiness().await.unwrap();
    assert_eq!(not_ready["ready"], false);
    assert_eq!(not_ready["status"], "not_ready");
    assert_eq!(not_ready["checks"]["database"], false);
    c.health.liveness().await.unwrap();
    let r = task.await.unwrap();
    assert_eq!(r[2].route(), "/healthz");
    assert_public(&r[0]);
}

// ── governed_action ──────────────────────────────────────────────────────────

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

/// The vectors' decisions expire within minutes of generation, so the
/// governed-action tests sign fresh decisions with a test NA key over the
/// vector's shape.
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

fn na_key() -> String {
    STANDARD.encode(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes())
}

fn params(v: &Value, context_id: &str) -> GovernedActionParams {
    GovernedActionParams {
        evaluate: json!({
            "attestation_id": v["attestation"]["attestation_id"],
            "requested_capability": "sp-secret.rotate",
            "context": {"context_id": context_id, "request_parameters": {"app_id": "billing"}},
        }),
        resource_id: Some(v["resource_id"].as_str().unwrap().to_owned()),
        resource_action: Some("rotate".into()),
        prior_resource: None,
        verify: GovernedVerification {
            operator_public_keys: vec![na_key()],
            expected_policies: vec![v["policy"].clone()],
            expected_attestation: Some(v["attestation"].clone()),
            ..GovernedVerification::default()
        },
    }
}

async fn rotate(
    report: std::result::Result<ActionReport<String>, ActionError>,
) -> std::result::Result<ActionReport<String>, ActionError> {
    report
}

#[tokio::test]
async fn governed_action_verifies_allow_reads_the_head_and_records_the_result() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-1")),
        ok(json!({"resource_id": v["resource_id"], "resource_sequence": 2, "record_digest": "head-digest"})),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = client(&url);
    let result = governed_action(
        &c.boundary,
        &c.evidence_store,
        &recorder(),
        params(&v, "ctx-1"),
        |decision| {
            assert_eq!(decision["authorized"], true);
            rotate(Ok(ActionReport {
                value: Some("rotated".into()),
                execution_parameters: Some(json!({"secret_version": "v3"})),
                ..ActionReport::default()
            }))
        },
    )
    .await
    .unwrap();
    assert!(result.authorized);
    assert_eq!(result.value.as_deref(), Some("rotated"));
    let evidence = result.evidence.unwrap();
    assert_eq!(evidence["resource_sequence"], 3);
    assert_eq!(evidence["prev_resource_digest"], "head-digest");
    assert_eq!(
        evidence["execution_parameters"],
        json!({"secret_version": "v3"})
    );
    assert_eq!(result.submission.unwrap()["status"], "recorded");
    assert!(result.queued.is_none());
    assert_eq!(result.summary.observed_failures.len(), 1);
    let r = task.await.unwrap();
    assert_eq!(r[0].route(), "/admin/boundary/evaluate");
    assert_eq!(r[0].body["context"]["context_id"], "ctx-1");
    assert_eq!(r[2].body["evidence"], evidence);
}

#[tokio::test]
async fn governed_action_returns_a_verified_deny_without_running_the_action() {
    let v = vectors();
    let (url, task) = scripted(vec![ok(signed_evaluation(&v, false, "ctx-2"))]).await;
    let c = client(&url);
    let result = governed_action(
        &c.boundary,
        &c.evidence_store,
        &recorder(),
        params(&v, "ctx-2"),
        |_| async {
            panic!("a denied action must not run");
            #[allow(unreachable_code)]
            Ok::<ActionReport<()>, ActionError>(ActionReport::default())
        },
    )
    .await
    .unwrap();
    assert!(!result.authorized);
    assert!(result.evidence.is_none());
    assert!(!result.summary.enforced_failures.is_empty());
    assert_eq!(task.await.unwrap().len(), 1);
}

type Tamper = Box<dyn Fn(&mut Value, &mut GovernedActionParams)>;

#[tokio::test]
async fn governed_action_blocks_unverifiable_allows() {
    let v = vectors();
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "invalid_signature",
            Box::new(|e, _| e["decision"]["agreement_id"] = json!("changed")),
        ),
        (
            "missing_signature",
            Box::new(|e, _| e["decision"]["signature"] = Value::Null),
        ),
        (
            "context_binding_mismatch",
            Box::new(|_, p| p.evaluate["context"]["context_id"] = json!("other")),
        ),
        (
            "policy_binding_mismatch",
            Box::new(|_, p| p.verify.expected_policies.clear()),
        ),
        (
            "attestation_expectation_required",
            Box::new(|_, p| p.verify.expected_attestation = None),
        ),
    ];
    for (reason, tamper) in cases {
        let mut evaluation = signed_evaluation(&v, true, "ctx-3");
        let mut p = params(&v, "ctx-3");
        tamper(&mut evaluation, &mut p);
        let (url, _task) = scripted(vec![ok(evaluation)]).await;
        let c = client(&url);
        let err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
            Ok::<ActionReport<()>, ActionError>(ActionReport::default())
        })
        .await
        .unwrap_err();
        assert_eq!(err.code(), reason, "{err}");
    }
    let mut p = params(&v, "x");
    p.verify.operator_public_keys.clear();
    let c = client("http://127.0.0.1:9");
    let err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Ok::<ActionReport<()>, ActionError>(ActionReport::default())
    })
    .await
    .unwrap_err();
    assert_eq!(err.code(), "verification_keys_required");
}

#[tokio::test]
async fn governed_action_records_a_failure_without_the_error_text() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-4")),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = client(&url);
    let mut p = params(&v, "ctx-4");
    p.prior_resource = Some(Some(PriorResource::Head(ResourceHead {
        resource_sequence: 7,
        record_digest: "explicit".into(),
    })));
    let err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Err::<ActionReport<()>, ActionError>("vault said: password=hunter2".into())
    })
    .await
    .unwrap_err();
    assert!(matches!(err, GenesisMeshError::ActionFailed { .. }));
    let r = task.await.unwrap();
    let evidence = &r[1].body["evidence"];
    assert_eq!(evidence["outcome"], "failure");
    assert_eq!(evidence["outcome_detail"], "action failed");
    assert_eq!(evidence["resource_sequence"], 8);
    assert!(!r[1].body.to_string().contains("hunter2"));
}

#[tokio::test]
async fn governed_action_reports_both_errors_when_failure_evidence_is_refused() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-5")),
        (
            422,
            json!({"error": {"code": "evidence_rejected", "message": "no"}}).to_string(),
        ),
    ])
    .await;
    let c = client(&url);
    let mut p = params(&v, "ctx-5");
    p.prior_resource = Some(None);
    let err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Err::<ActionReport<()>, ActionError>("boom".into())
    })
    .await
    .unwrap_err();
    match err {
        GenesisMeshError::ActionUnrecorded {
            source,
            evidence_error,
            evidence,
            ..
        } => {
            assert_eq!(source.to_string(), "boom");
            assert_eq!(evidence_error.code(), "evidence_rejected");
            assert_eq!(evidence.unwrap()["outcome"], "failure");
        }
        other => panic!("unexpected {other}"),
    }
    assert_eq!(task.await.unwrap().len(), 2);
}

#[tokio::test]
async fn without_an_outbox_a_failed_submission_is_an_error_and_secrets_are_refused_unsigned() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-n1")),
        unavailable(),
        ok(signed_evaluation(&v, true, "ctx-n2")),
    ])
    .await;
    let c = client(&url);
    let err = rotate_to(&c, &v, "ctx-n1", Some(None), "v1")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "service_unavailable");
    let mut p = params(&v, "ctx-n2");
    p.prior_resource = Some(None);
    let err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Ok::<_, ActionError>(ActionReport::<()> {
            execution_parameters: Some(json!({"client_secret": "s3cr3t"})),
            ..ActionReport::default()
        })
    })
    .await
    .unwrap_err();
    assert!(matches!(err, GenesisMeshError::SecretMaterial(_)), "{err}");
    assert_eq!(task.await.unwrap().len(), 3);
}

// ── the evidence outbox (1.2.0) ──────────────────────────────────────────────

fn unavailable() -> (u16, String) {
    (
        503,
        json!({"error": {"code": "service_unavailable", "message": "down"}}).to_string(),
    )
}

fn refusal(status: u16, code: &str) -> (u16, String) {
    (
        status,
        json!({"error": {"code": code, "message": "refused"}}).to_string(),
    )
}

async fn rotate_to(
    c: &GenesisMeshClient,
    v: &Value,
    context_id: &str,
    prior: Option<Option<PriorResource>>,
    version: &str,
) -> genesis_mesh_sdk::Result<GovernedActionResult<String>> {
    let mut p = params(v, context_id);
    p.prior_resource = prior;
    let version = version.to_owned();
    governed_action(
        &c.boundary,
        &c.evidence_store,
        &recorder(),
        p,
        |_| async move {
            Ok::<_, ActionError>(ActionReport {
                value: Some(format!("rotated to {version}")),
                execution_parameters: Some(json!({"secret_version": version})),
                ..ActionReport::default()
            })
        },
    )
    .await
}

/// An outbox whose every operation fails (or only `add`, when `adds_only`).
#[derive(Debug, Default)]
struct BrokenOutbox {
    adds_only: bool,
    inner: MemoryOutbox,
}

impl EvidenceOutbox for BrokenOutbox {
    fn add<'a>(&'a self, _: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        Box::pin(async { Err(io::Error::other("disk full")) })
    }
    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        self.inner.update(entry)
    }
    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        self.inner.remove(id)
    }
    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>> {
        if self.adds_only {
            return self.inner.list();
        }
        Box::pin(async { Err(io::Error::other("outbox file is unreadable")) })
    }
}

/// An outbox that cannot remove entries.
#[derive(Debug, Default)]
struct StickyOutbox(MemoryOutbox);

impl EvidenceOutbox for StickyOutbox {
    fn add<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        self.0.add(entry)
    }
    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        self.0.update(entry)
    }
    fn remove<'a>(&'a self, _: &'a str) -> OutboxFuture<'a, ()> {
        Box::pin(async { Err(io::Error::other("disk")) })
    }
    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>> {
        self.0.list()
    }
}

/// An outbox whose `list` takes a while, to overlap two flushes.
#[derive(Debug, Default)]
struct SlowOutbox(MemoryOutbox);

impl EvidenceOutbox for SlowOutbox {
    fn add<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        self.0.add(entry)
    }
    fn update<'a>(&'a self, entry: &'a OutboxEntry) -> OutboxFuture<'a, ()> {
        self.0.update(entry)
    }
    fn remove<'a>(&'a self, id: &'a str) -> OutboxFuture<'a, ()> {
        self.0.remove(id)
    }
    fn list(&self) -> OutboxFuture<'_, Vec<OutboxEntry>> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            self.0.list().await
        })
    }
}

fn state(entry: &Option<OutboxEntry>) -> Option<OutboxState> {
    entry.as_ref().map(|e| e.state)
}

fn code(entry: &Option<OutboxEntry>) -> &str {
    entry
        .as_ref()
        .and_then(|e| e.last_error.as_ref())
        .map_or("", |e| e.code.as_str())
}

#[tokio::test]
async fn an_unreadable_outbox_fails_before_evaluating() {
    let v = vectors();
    let c = client_with("http://127.0.0.1:9", Arc::new(BrokenOutbox::default()));
    let err = rotate_to(&c, &v, "ctx-o0", Some(None), "v1")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "outbox_error");
}

#[tokio::test]
async fn a_transient_error_keeps_the_record_pending_and_a_flush_admits_it() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-o1")),
        unavailable(),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = with_outbox(&url);
    let result = rotate_to(&c, &v, "ctx-o1", Some(None), "v1").await.unwrap();
    assert_eq!(result.value.as_deref(), Some("rotated to v1"));
    assert!(result.submission.is_none());
    let entry = result.queued.unwrap();
    assert_eq!((entry.state, entry.attempts), (OutboxState::Pending, 1));
    assert_eq!(entry.last_error.as_ref().unwrap().status, 503);
    assert!(entry.next_attempt_at.is_some());
    assert_eq!(&entry.evidence, result.evidence.as_ref().unwrap());

    let outbox = c.evidence_store.outbox().unwrap();
    let skipped = c
        .evidence_store
        .flush_pending(FlushOptions::default())
        .await
        .unwrap();
    assert_eq!(skipped.pending.len(), 1);
    let flushed = c
        .evidence_store
        .flush_pending(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(flushed.admitted.len(), 1);
    assert!(outbox.list().await.unwrap().is_empty());
    let r = task.await.unwrap();
    assert_eq!(&r[2].body["evidence"], result.evidence.as_ref().unwrap());
}

#[tokio::test]
async fn only_refusals_no_retry_can_overcome_dead_letter_a_record() {
    let v = vectors();
    for (status, refused, dead) in [
        (409, "evidence_conflict", true),
        (422, "evidence_outside_decision_window", true),
        (422, "evidence_executor_key_retired", true),
        (422, "evidence_out_of_scope", true),
        (409, "retention_in_progress", false),
        (404, "evidence_store_disabled", false),
        (422, "evidence_unknown_executor", false),
        (422, "resource_chain_gap", false),
        (403, "unknown", false),
    ] {
        let (url, _task) = scripted(vec![
            ok(signed_evaluation(&v, true, "ctx-o2")),
            refusal(status, refused),
        ])
        .await;
        let c = with_outbox(&url);
        let result = rotate_to(&c, &v, "ctx-o2", Some(None), "v1").await.unwrap();
        let expected = if dead {
            OutboxState::DeadLetter
        } else {
            OutboxState::Pending
        };
        assert_eq!(state(&result.queued), Some(expected), "{refused}");
        assert_eq!(code(&result.queued), refused);
    }
}

#[tokio::test]
async fn a_second_action_chains_from_the_pending_head_and_submits_it_first() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-o4")),
        ok(json!({"resource_id": v["resource_id"], "resource_sequence": 2, "record_digest": "head-digest"})),
        unavailable(),
        ok(signed_evaluation(&v, true, "ctx-o5")),
        ok(json!({"status": "recorded"})),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = with_outbox(&url);
    let first = rotate_to(&c, &v, "ctx-o4", None, "v1").await.unwrap();
    let second = rotate_to(&c, &v, "ctx-o5", None, "v2").await.unwrap();
    let first = first.evidence.unwrap();
    assert_eq!(first["resource_sequence"], 3);
    let second_evidence = second.evidence.unwrap();
    assert_eq!(second_evidence["resource_sequence"], 4);
    assert_eq!(
        second_evidence["prev_resource_digest"],
        execution_digest(&first).unwrap()
    );
    // The NA just answered the evaluation: the first record goes first.
    assert_eq!(second.submission.unwrap()["status"], "recorded");
    assert!(c
        .evidence_store
        .outbox()
        .unwrap()
        .list()
        .await
        .unwrap()
        .is_empty());
    let r = task.await.unwrap();
    assert_eq!(r.len(), 6);
    assert_eq!(r[3].route(), "/admin/boundary/evaluate");
    assert_eq!(r[4].body["evidence"], first);
    assert_eq!(r[5].body["evidence"], second_evidence);
}

#[tokio::test]
async fn a_record_behind_a_refused_one_is_dead_lettered_without_submission() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-o6")),
        unavailable(),
        ok(signed_evaluation(&v, true, "ctx-o7")),
        refusal(409, "evidence_conflict"),
        ok(signed_evaluation(&v, true, "ctx-o8")),
        ok(json!({"resource_id": v["resource_id"], "resource_sequence": 9, "record_digest": "na-head"})),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = with_outbox(&url);
    rotate_to(&c, &v, "ctx-o6", Some(None), "v1").await.unwrap();
    let second = rotate_to(&c, &v, "ctx-o7", None, "v2").await.unwrap();
    assert_eq!(state(&second.queued), Some(OutboxState::DeadLetter));
    assert_eq!(code(&second.queued), PREDECESSOR_DEAD_LETTERED);
    // A third action no longer chains from the dead records.
    let third = rotate_to(&c, &v, "ctx-o8", None, "v3").await.unwrap();
    assert_eq!(third.evidence.unwrap()["prev_resource_digest"], "na-head");
    assert_eq!(task.await.unwrap().len(), 7);
}

#[tokio::test]
async fn enqueue_dead_letters_at_once_behind_a_dead_letter_and_waits_on_the_decision_chain() {
    let v = vectors();
    let (url, task) = scripted(vec![
        refusal(409, "evidence_conflict"),
        unavailable(),
        unavailable(),
    ])
    .await;
    let c = with_outbox(&url);
    let decision = signed_evaluation(&v, true, "ctx-e")["decision"].clone();
    let sign = |prior: Option<Value>, resource: bool| {
        recorder()
            .record(RecordExecution {
                decision: decision.clone(),
                executed_capability: "sp-secret.rotate".into(),
                resource_id: resource.then(|| "kv:v/e".to_owned()),
                resource_action: resource.then(|| "rotate".to_owned()),
                prior_resource: if resource {
                    prior.clone().map(PriorResource::Record)
                } else {
                    None
                },
                prior_record: if resource { None } else { prior },
                ..RecordExecution::default()
            })
            .unwrap()
    };
    let a = sign(None, true);
    let refused = c.evidence_store.enqueue(a.clone()).await.unwrap();
    assert_eq!(state(&refused.queued), Some(OutboxState::DeadLetter));
    let b = sign(Some(a), true);
    let behind = c.evidence_store.enqueue(b).await.unwrap();
    assert_eq!(code(&behind.queued), PREDECESSOR_DEAD_LETTERED);
    // The decision chain: d waits behind c's failed retry.
    let first = sign(None, false);
    c.evidence_store.enqueue(first.clone()).await.unwrap();
    let next = c
        .evidence_store
        .enqueue(sign(Some(first), false))
        .await
        .unwrap();
    let waiting = next.queued.unwrap();
    assert_eq!((waiting.state, waiting.attempts), (OutboxState::Pending, 0));
    assert_eq!(task.await.unwrap().len(), 3);
}

#[tokio::test]
async fn enqueue_resubmits_a_kept_record_and_refuses_another_with_its_id() {
    let v = vectors();
    let (url, _task) = scripted(vec![unavailable(), ok(json!({"status": "recorded"}))]).await;
    let c = with_outbox(&url);
    let decision = signed_evaluation(&v, true, "ctx-r")["decision"].clone();
    let record = recorder()
        .record(RecordExecution {
            decision,
            executed_capability: "c".into(),
            ..RecordExecution::default()
        })
        .unwrap();
    c.evidence_store.enqueue(record.clone()).await.unwrap();
    let again = c.evidence_store.enqueue(record.clone()).await.unwrap();
    assert_eq!(again.submission.unwrap()["status"], "recorded");
    let mut imposter = record;
    imposter["outcome"] = json!("failure");
    c.evidence_store
        .outbox()
        .unwrap()
        .add(&OutboxEntry::new(imposter.clone()))
        .await
        .unwrap();
    let mut other = imposter.clone();
    other["outcome"] = json!("success");
    other["outcome_detail"] = json!("different");
    assert_eq!(
        c.evidence_store.enqueue(other).await.unwrap_err().code(),
        "outbox_error"
    );
}

#[tokio::test]
async fn an_admitted_record_stays_admitted_when_the_outbox_cannot_remove_it() {
    let v = vectors();
    let (url, _task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-s")),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = client_with(&url, Arc::new(StickyOutbox::default()));
    let result = rotate_to(&c, &v, "ctx-s", Some(None), "v1").await.unwrap();
    assert_eq!(result.submission.unwrap()["status"], "recorded");
}

#[tokio::test]
async fn a_flush_ends_at_the_first_transient_error() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-o8")),
        unavailable(),
        ok(signed_evaluation(&v, true, "ctx-o9")),
        unavailable(),
        unavailable(),
    ])
    .await;
    let c = with_outbox(&url);
    rotate_to(&c, &v, "ctx-o8", Some(None), "v1").await.unwrap();
    let mut p = params(&v, "ctx-o9");
    p.resource_id = Some("kv:v/other".into());
    p.prior_resource = Some(None);
    governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Ok::<_, ActionError>(ActionReport::<()>::default())
    })
    .await
    .unwrap();
    let flushed = c
        .evidence_store
        .flush_pending(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    let attempts: Vec<u32> = flushed.pending.iter().map(|e| e.attempts).collect();
    assert_eq!(attempts, [2, 1]);
    assert_eq!(task.await.unwrap().len(), 5);
}

#[tokio::test]
async fn one_flush_runs_at_a_time() {
    let c = client_with("http://127.0.0.1:9", Arc::new(SlowOutbox::default()));
    let options = FlushOptions::default();
    let (a, b) = tokio::join!(
        c.evidence_store.flush_pending(options),
        c.evidence_store.flush_pending(options)
    );
    let codes: Vec<&str> = [&a, &b]
        .iter()
        .map(|r| r.as_ref().map_or_else(|e| e.code(), |_| "ok"))
        .collect();
    assert!(
        codes.contains(&"ok") && codes.contains(&"outbox_flush_in_progress"),
        "{codes:?}"
    );
}

#[tokio::test]
async fn a_guard_refusal_after_the_action_records_the_outcome_and_returns_the_value() {
    let v = vectors();
    let (url, task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-o10")),
        ok(json!({"status": "recorded"})),
    ])
    .await;
    let c = with_outbox(&url);
    let mut p = params(&v, "ctx-o10");
    p.prior_resource = Some(None);
    let mut err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Ok::<_, ActionError>(ActionReport {
            value: Some(42_u32),
            execution_parameters: Some(json!({"client_secret": "s3cr3t", "secret_version": "v2"})),
            outcome_detail: Some("rotated".into()),
            ..ActionReport::default()
        })
    })
    .await
    .unwrap_err();
    assert_eq!(err.code(), "governed_action_metadata_refused");
    assert_eq!(err.take_action_value::<String>(), None);
    assert_eq!(err.take_action_value::<u32>(), Some(42));
    assert_eq!(err.take_action_value::<u32>(), None);
    let GenesisMeshError::MetadataRefused {
        dropped,
        evidence,
        submission,
        ..
    } = err
    else {
        panic!("unexpected error");
    };
    assert_eq!(dropped, ["client_secret"]);
    assert_eq!(
        evidence["execution_parameters"],
        json!({"secret_version": "v2"})
    );
    assert_eq!(
        evidence["outcome_detail"],
        "rotated [secret guard dropped: client_secret]"
    );
    assert_eq!(submission.unwrap()["status"], "recorded");
    let r = task.await.unwrap();
    assert_eq!(r[1].body["evidence"], *evidence);
    assert!(!r[1].body.to_string().contains("s3cr3t"));
}

#[tokio::test]
async fn an_outbox_failure_after_the_action_returns_the_value_and_the_record() {
    let v = vectors();
    let (url, task) = scripted(vec![ok(signed_evaluation(&v, true, "ctx-o11"))]).await;
    let c = client_with(
        &url,
        Arc::new(BrokenOutbox {
            adds_only: true,
            ..BrokenOutbox::default()
        }),
    );
    let mut err = rotate_to(&c, &v, "ctx-o11", Some(None), "v1")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "governed_action_evidence_unkept");
    assert_eq!(
        err.take_action_value::<String>().as_deref(),
        Some("rotated to v1")
    );
    assert!(matches!(
        err,
        GenesisMeshError::EvidenceNotKept {
            evidence: Some(_),
            ..
        }
    ));
    assert_eq!(task.await.unwrap().len(), 1);
}

#[tokio::test]
async fn with_an_outbox_a_failed_action_keeps_its_failure_record() {
    let v = vectors();
    let (url, _task) = scripted(vec![
        ok(signed_evaluation(&v, true, "ctx-o12")),
        unavailable(),
    ])
    .await;
    let c = with_outbox(&url);
    let mut p = params(&v, "ctx-o12");
    p.prior_resource = Some(None);
    let err = governed_action(&c.boundary, &c.evidence_store, &recorder(), p, |_| async {
        Err::<ActionReport<()>, ActionError>("boom".into())
    })
    .await
    .unwrap_err();
    let GenesisMeshError::ActionFailed {
        evidence, queued, ..
    } = err
    else {
        panic!("unexpected {err}");
    };
    assert_eq!(evidence.unwrap()["outcome"], "failure");
    assert_eq!(queued.unwrap().state, OutboxState::Pending);
}

#[test]
fn the_guard_fallback_drops_only_refused_fields_and_names_plain_ones() {
    use genesis_mesh_sdk::without_refused_metadata;
    let cleaned = without_refused_metadata(
        &json!({"password": "x", "version": "v1", "nested": {"token": "y"}}),
        Some("-----BEGIN KEY"),
    );
    assert_eq!(cleaned.execution_parameters, json!({"version": "v1"}));
    assert_eq!(
        cleaned.outcome_detail,
        "[secret guard dropped: nested, outcome_detail, password]"
    );
    let odd = without_refused_metadata(
        &json!({"a b": "x".repeat(130), "ok": 1, "y".repeat(70): "z".repeat(130)}),
        None,
    );
    assert_eq!(odd.execution_parameters, json!({"ok": 1}));
    assert_eq!(odd.outcome_detail, "[secret guard dropped: 2 other fields]");
    let big: serde_json::Map<String, Value> = (0..4)
        .map(|i| (format!("k{i}"), json!("x".repeat(5000))))
        .collect();
    let all = without_refused_metadata(&Value::Object(big), None);
    assert_eq!(all.execution_parameters, json!({}));
    assert_eq!(all.dropped, ["k0", "k1", "k2", "k3"]);
    assert_eq!(all.outcome_detail, "[secret guard dropped: k0, k1, k2, k3]");
}
