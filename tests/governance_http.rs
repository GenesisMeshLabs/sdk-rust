//! HTTP contract tests for the policy, evidence-store and health clients and
//! for `governed_action`, against a scripted local server.

use std::{collections::HashMap, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, SigningKey};
use genesis_mesh_sdk::{
    canonical_json, governed_action, json, ActionError, ActionReport, ClientOptions,
    ExecutionRecorder, GenesisMeshClient, GenesisMeshError, GovernedActionParams,
    GovernedVerification, PriorResource, ResourceHead, Value,
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

fn client(url: &str) -> GenesisMeshClient {
    GenesisMeshClient::new(
        ClientOptions::new(url)
            .with_signing_key(STANDARD.encode([7; 32]))
            .with_key_id("test-key"),
    )
    .unwrap()
}

fn assert_admin(request: &Request, signed_body: &Value) {
    assert_eq!(request.headers["x-admin-key-id"], "test-key");
    let payload = json!({"body": signed_body, "key_id": "test-key", "nonce": request.headers["x-admin-nonce"], "timestamp": request.headers["x-admin-timestamp"]});
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&request.headers["x-admin-signature"])
            .unwrap(),
    )
    .unwrap();
    SigningKey::from_bytes(&[7; 32])
        .verifying_key()
        .verify_strict(canonical_json(&payload).unwrap().as_bytes(), &signature)
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
        } => {
            assert_eq!(source.to_string(), "boom");
            assert_eq!(evidence_error.code(), "evidence_rejected");
        }
        other => panic!("unexpected {other}"),
    }
    assert_eq!(task.await.unwrap().len(), 2);
}
