//! The grant holder (1.6.0): acting within a pre-issued grant offline,
//! checking it, signing uses with the bearer key, keeping them in the record
//! outbox, uploading them, and falling back to break-glass; against an NA
//! that cannot be reached or a scripted local server.

use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use genesis_mesh_sdk::{
    canonical::{python_timestamp, received_canonical},
    grants::{use_digest, use_problem, UseContext},
    json, load_signing_key, public_key_from_seed, sign_canonical, ActionError, ActionReport,
    ClientOptions, EvaluationFailure, ExecutionRecorder, FlushOptions, GenesisMeshClient,
    GenesisMeshError, GovernedActionOutcome, GovernedVerification, GrantActionOutcome,
    GrantAuthority, GrantFallback, GrantHolder, GrantHolderState, GrantRequest, GrantUseInput,
    MemoryRecordOutbox, OutboxState, RecordKind, RecordOutbox, RecordOutboxEntry, Value,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const NA_SEED: [u8; 32] = [3; 32];
const BEARER_SEED: [u8; 32] = [5; 32];

fn seed(bytes: [u8; 32]) -> String {
    STANDARD.encode(bytes)
}

fn na_key() -> String {
    public_key_from_seed(&seed(NA_SEED)).unwrap()
}

fn recorder() -> ExecutionRecorder {
    ExecutionRecorder::new("device-b", "executor-b", &seed(BEARER_SEED)).unwrap()
}

/// A record signed by the NA over its signed form as received.
fn na_signed(model: &str, mut record: Value) -> Value {
    let canonical = received_canonical(model, &record).unwrap();
    let key = load_signing_key(&seed(NA_SEED)).unwrap();
    let field = if model == "SovereignRevocationFeed" {
        "signatures"
    } else {
        "signature"
    };
    let signature = sign_canonical(&canonical, "na-key", &key);
    record[field] = if field == "signatures" {
        json!([signature])
    } else {
        signature
    };
    record
}

fn at(offset_minutes: i64) -> String {
    python_timestamp(Utc::now() + chrono::Duration::minutes(offset_minutes))
}

/// A grant for `device-b`'s key: `secret.rotate`, 1 to 90 days, three uses,
/// two per time token, valid from `from` to `until` minutes from now.
fn grant(from: i64, until: i64) -> Value {
    na_signed(
        "CapabilityGrant",
        json!({
            "grant_id": "00000000-0000-4000-8000-000000000010",
            "bearer_key_id": "executor-b",
            "bearer_public_key": recorder().public_key(),
            "bearer_sovereign_id": "device-b",
            "capabilities": ["secret.rotate"],
            "basis_kind": "attestation",
            "basis_id": "00000000-0000-4000-8000-000000000001",
            "basis_digest": "e".repeat(64),
            "requester_sovereign_id": "vendor-acme",
            "provider_sovereign_id": "sovereign-c",
            "valid_from": at(from),
            "valid_until": at(until),
            "max_uses": 3,
            "max_uses_per_time_token": 2,
            "parameter_envelope": {"lifetime_days": {
                "required": true, "one_of": null, "subset_of": null,
                "number_range": {"number_type": "integer", "minimum": 1, "maximum": 90,
                                 "exclusive_minimum": false, "exclusive_maximum": false},
            }},
            "basis_checks": [],
            "policy_binding": {"policies": [], "policy_set_digest": "p", "gate_outcomes": [],
                               "registry_gate_types": []},
            // Issued before its first time token (a token is never older).
            "issued_at": at(from.min(-1) - 1),
            "issuer_sovereign_id": "sovereign-c",
            "issued_by": "na-key",
        }),
    )
}

fn token(sequence: u64, head: Option<&str>, issued: i64) -> Value {
    let mut token = json!({
        "time_token_id": format!("00000000-0000-4000-8000-0000000000{:02}", 30 + sequence),
        "grant_id": "00000000-0000-4000-8000-000000000010",
        "use_sequence": sequence,
        "issued_at": at(issued),
        "issuer_sovereign_id": "sovereign-c",
        "issued_by": "na-key",
    });
    if let Some(head) = head {
        token["use_head_digest"] = json!(head);
    }
    na_signed("TimeToken", token)
}

fn holder(from: i64, until: i64) -> GrantHolder {
    GrantHolder::new(
        grant(from, until),
        token(0, None, from),
        recorder(),
        vec![na_key()],
    )
    .unwrap()
}

/// A client whose NA cannot be reached (nothing listens on the port).
fn offline() -> (GenesisMeshClient, Arc<MemoryRecordOutbox>) {
    client("http://127.0.0.1:9")
}

fn client(url: &str) -> (GenesisMeshClient, Arc<MemoryRecordOutbox>) {
    let outbox = Arc::new(MemoryRecordOutbox::default());
    let options = ClientOptions::new(url)
        .with_signing_key(STANDARD.encode([7; 32]))
        .with_audience("TEST")
        .with_timeout(Duration::from_secs(2))
        .with_record_outbox(outbox.clone());
    (GenesisMeshClient::new(options).unwrap(), outbox)
}

fn rotate(lifetime: i64) -> GrantRequest {
    GrantRequest::new("secret.rotate", json!({"lifetime_days": lifetime}))
        .on("kv:vault/api-key", "rotate")
}

fn fallback() -> GrantFallback {
    GrantFallback::new(
        "the device must rotate its credential now",
        GovernedVerification {
            operator_public_keys: vec![na_key()],
            ..GovernedVerification::default()
        },
    )
}

async fn report(version: &str) -> Result<ActionReport<String>, ActionError> {
    Ok(ActionReport {
        value: Some(version.to_owned()),
        execution_parameters: Some(json!({"version_id": version})),
        ..ActionReport::default()
    })
}

fn used<T: std::fmt::Debug>(outcome: GrantActionOutcome<T>) -> genesis_mesh_sdk::GrantUseResult<T> {
    match outcome {
        GrantActionOutcome::Used(result) => result,
        other => panic!("not used under the grant: {other:?}"),
    }
}

#[tokio::test]
async fn acts_offline_within_the_grant_and_chains_its_uses() {
    let (client, outbox) = offline();
    let mut holder = holder(-1, 60);
    let first = used(
        holder
            .act(&client, rotate(30), |authority| async move {
                assert!(matches!(
                    authority,
                    GrantAuthority::Grant {
                        use_sequence: 1,
                        ..
                    }
                ));
                report("v1").await
            })
            .await
            .unwrap(),
    );
    assert_eq!(first.value.as_deref(), Some("v1"));
    assert!(first.submission.is_none());
    assert_eq!(first.queued.as_ref().unwrap().state, OutboxState::Pending);
    let second = used(
        holder
            .act(&client, rotate(45), |_| report("v2"))
            .await
            .unwrap(),
    );
    // Signed by the bearer key, chained, citing the token, inside the grant.
    let first_digest = use_digest(&first.record).unwrap();
    assert_eq!(second.record["use_sequence"], 2);
    assert_eq!(second.record["prev_use_digest"], first_digest.as_str());
    assert_eq!(second.record["signature"]["key_id"], "executor-b");
    assert!(first.record.get("prev_use_digest").is_none());
    let keys = [na_key()];
    for record in [&first.record, &second.record] {
        let context = UseContext {
            grant: Some(holder.grant()),
            token_keys: &keys,
            recorded_at: Some(Utc::now()),
            ..UseContext::default()
        };
        assert_eq!(use_problem(record, &context), None);
    }
    // Both are kept for the upload, in their chain's order.
    let kept = outbox.list().await.unwrap();
    assert_eq!(kept.len(), 2);
    assert!(kept.iter().all(|e| e.kind == RecordKind::GrantExecution));
    assert_eq!(kept[0].id, first.record["use_id"].as_str().unwrap());
    assert_eq!(holder.uses(), 2);
    assert_eq!(holder.remaining_uses(), 1);
}

#[tokio::test]
async fn refuses_a_request_the_grant_does_not_cover_without_running_it() {
    let (client, _) = offline();
    let mut holder = holder(-1, 60);
    for (request, code) in [
        (rotate(400), "grant_envelope_mismatch"),
        (rotate(0), "grant_envelope_mismatch"),
        (
            GrantRequest::new("secret.delete", json!({"lifetime_days": 1})),
            "grant_capability_mismatch",
        ),
    ] {
        let request = request.with_fallback(fallback());
        let err = holder
            .act(&client, request, |_| async {
                panic!("the action must not run");
                #[allow(unreachable_code)]
                report("x").await
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), code);
    }
    // Secret material is refused before anything is signed or run.
    let secret = GrantRequest::new(
        "secret.rotate",
        json!({"lifetime_days": 1, "password": "x"}),
    );
    let err = holder
        .act(&client, secret, |_| report("x"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "grant_use_secret_material");
    assert_eq!(holder.uses(), 0);
}

#[tokio::test]
async fn falls_back_to_break_glass_once_the_time_token_is_spent_and_the_na_is_unreachable() {
    let (client, outbox) = offline();
    let mut holder = holder(-1, 60);
    for version in ["v1", "v2"] {
        used(
            holder
                .act(&client, rotate(30), |_| report(version))
                .await
                .unwrap(),
        );
    }
    // Two uses per token: the third needs a new one, which the NA cannot give.
    let err = holder
        .act(&client, rotate(30), |_| report("v3"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "grant_time_token_exhausted");
    let outcome = holder
        .act(
            &client,
            rotate(30).with_fallback(fallback()),
            |authority| async move {
                assert_eq!(authority, GrantAuthority::BreakGlass);
                report("v3").await
            },
        )
        .await
        .unwrap();
    let GrantActionOutcome::FellBack { unusable, outcome } = outcome else {
        panic!("did not fall back");
    };
    assert_eq!(unusable.code, "grant_time_token_exhausted");
    let GovernedActionOutcome::BrokeGlass(glass) = *outcome else {
        panic!("did not break the glass");
    };
    // Nothing listens on the port: Linux refuses at once (network_error), Windows retries the
    // connection until the client's timeout. Either is an outage that breaks the glass.
    assert!(
        matches!(
            glass.failure,
            EvaluationFailure::NetworkError | EvaluationFailure::Timeout
        ),
        "{:?}",
        glass.failure
    );
    assert_eq!(glass.record["capability"], "secret.rotate");
    assert_eq!(
        glass.record["request_parameters"],
        json!({"lifetime_days": 30})
    );
    assert_eq!(glass.record["attestation_id"], holder.grant()["basis_id"]);
    let kinds: Vec<RecordKind> = outbox
        .list()
        .await
        .unwrap()
        .iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            RecordKind::GrantExecution,
            RecordKind::GrantExecution,
            RecordKind::BreakGlass
        ]
    );
    assert_eq!(holder.uses(), 2);
}

#[tokio::test]
async fn falls_back_past_the_grants_end_and_when_the_feed_revokes_it() {
    let (client, _) = offline();
    // Ended a minute ago.
    let mut ended = holder(-120, -1);
    let outcome = ended
        .act(&client, rotate(30).with_fallback(fallback()), |_| {
            report("v1")
        })
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        GrantActionOutcome::FellBack { ref unusable, .. } if unusable.code == "grant_expired"
    ));
    // Revoked: the feed the NA signed lists it.
    let mut revoked = holder(-1, 60);
    let feed = na_signed(
        "SovereignRevocationFeed",
        json!({
            "feed_id": "feed-1", "issuer_sovereign_id": "sovereign-c", "sequence": 1,
            "issued_at": at(0), "revoked_attestation_ids": [], "revocation_reasons": {},
            "revoked_grant_ids": [revoked.grant_id()], "issued_by": "na-key",
        }),
    );
    assert!(revoked.set_feed(feed.clone()).unwrap());
    let err = revoked
        .act(&client, rotate(30), |_| report("v1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, GenesisMeshError::GrantRefused { ref code, .. } if code == "grant_revoked")
    );
    // A feed someone else signed, or another sovereign's, is not kept.
    let mut forged = feed.clone();
    forged["sequence"] = json!(2);
    assert!(revoked.set_feed(forged).is_err());
    // Not valid yet: refused, never a fallback.
    let mut early = GrantHolder::new(
        grant(30, 60),
        token(0, None, -1),
        recorder(),
        vec![na_key()],
    )
    .unwrap();
    let err = early
        .act(&client, rotate(30).with_fallback(fallback()), |_| {
            report("v1")
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), "grant_use_outside_validity");
}

#[tokio::test]
async fn a_failed_action_is_a_use_with_outcome_failure() {
    let (client, _) = offline();
    let mut holder = holder(-1, 60);
    let err = holder
        .act(&client, rotate(30), |_| async {
            Err::<ActionReport<String>, ActionError>("vault unavailable".into())
        })
        .await
        .unwrap_err();
    let GenesisMeshError::ActionFailed {
        evidence,
        queued_record,
        ..
    } = err
    else {
        panic!("not ActionFailed");
    };
    assert_eq!(evidence.unwrap()["outcome"], "failure");
    assert!(queued_record.is_some());
    assert_eq!(holder.uses(), 1);
}

#[tokio::test]
async fn a_holder_keeps_its_chain_across_a_restart() {
    let (client, _) = offline();
    let mut holder = holder(-1, 60);
    let first = used(
        holder
            .act(&client, rotate(30), |_| report("v1"))
            .await
            .unwrap(),
    );
    let saved = serde_json::to_string(holder.state()).unwrap();
    let state: GrantHolderState = serde_json::from_str(&saved).unwrap();
    let mut again = GrantHolder::restore(state, recorder(), vec![na_key()]).unwrap();
    let second = used(
        again
            .act(&client, rotate(30), |_| report("v2"))
            .await
            .unwrap(),
    );
    assert_eq!(second.record["use_sequence"], 2);
    assert_eq!(
        second.record["prev_use_digest"],
        use_digest(&first.record).unwrap().as_str()
    );
    // Another key than the grant's bearer cannot hold it.
    let other = ExecutionRecorder::new("device-b", "executor-b", &seed([9; 32])).unwrap();
    let state: GrantHolderState = serde_json::from_str(&saved).unwrap();
    assert!(GrantHolder::restore(state, other, vec![na_key()]).is_err());
    // Nor does a grant signed by another key than the NA's verify.
    assert!(GrantHolder::new(
        grant(-1, 60),
        token(0, None, -1),
        recorder(),
        vec![recorder().public_key()]
    )
    .is_err());
}

#[derive(Debug)]
struct Request {
    target: String,
    body: Value,
}

/// Serve one scripted response per connection, in order.
async fn scripted(responses: Vec<(u16, Value)>) -> (String, JoinHandle<Vec<Request>>) {
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
            let target = head.split(' ').nth(1).unwrap().to_owned();
            let length = head
                .lines()
                .find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
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
            let reply = reply.to_string();
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            seen.push(Request { target, body });
        }
        seen
    });
    (url, task)
}

fn error(code: &str) -> Value {
    json!({"error": {"code": code, "message": code}})
}

#[tokio::test]
async fn asks_for_a_new_time_token_naming_its_head_and_uses_it() {
    // Two uses offline, then a third once the NA answers again.
    let (offline_client, _) = offline();
    let mut holder = holder(-1, 60);
    for version in ["v1", "v2"] {
        used(
            holder
                .act(&offline_client, rotate(30), |_| report(version))
                .await
                .unwrap(),
        );
    }
    let head = holder.state().head_digest.clone().unwrap();
    let fresh = token(2, Some(&head), 0);
    let (url, server) = scripted(vec![
        (201, json!({"time_token": fresh})),
        (201, json!({"status": "recorded", "resource_sequence": 3})),
    ])
    .await;
    let (client, _) = client(&url);
    let third = used(
        holder
            .act(&client, rotate(30), |_| report("v3"))
            .await
            .unwrap(),
    );
    assert_eq!(third.record["time_token"], fresh);
    assert_eq!(third.submission.unwrap()["status"], "recorded");
    let seen = server.await.unwrap();
    assert_eq!(seen[0].target, "/grants/time-tokens");
    let request = &seen[0].body["request"];
    assert_eq!(request["use_sequence"], 2);
    assert_eq!(request["use_head_digest"], head.as_str());
    assert_eq!(request["signature"]["key_id"], "executor-b");
    assert!(genesis_mesh_sdk::grants::signed_as_received(
        "TimeTokenRequest",
        request,
        &[recorder().public_key()]
    ));
    assert_eq!(seen[1].target, "/evidence/grant-executions");
    assert_eq!(seen[1].body["evidence"], third.record);
    // The budget is spent.
    let err = holder
        .act(&client, rotate(30), |_| report("v4"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "grant_budget_exhausted");
}

#[tokio::test]
async fn an_na_that_says_the_grant_ended_sends_the_holder_to_its_fallback() {
    let (offline_client, _) = offline();
    let mut holder = holder(-1, 60);
    for version in ["v1", "v2"] {
        used(
            holder
                .act(&offline_client, rotate(30), |_| report(version))
                .await
                .unwrap(),
        );
    }
    // The token route says the grant ended; the evaluation then fails (the
    // NA is overloaded): break-glass.
    let (url, _server) = scripted(vec![
        (409, error("grant_expired")),
        (503, error("server_error")),
        (503, error("server_error")),
    ])
    .await;
    let (client, _) = client(&url);
    let outcome = holder
        .act(&client, rotate(30).with_fallback(fallback()), |_| {
            report("v3")
        })
        .await
        .unwrap();
    let GrantActionOutcome::FellBack { unusable, outcome } = outcome else {
        panic!("did not fall back");
    };
    assert_eq!(unusable.code, "grant_expired");
    assert!(matches!(*outcome, GovernedActionOutcome::BrokeGlass(_)));
    assert_eq!(holder.state().ended.as_deref(), Some("grant_expired"));
}

#[tokio::test]
async fn uploads_in_chain_order_past_a_quarantined_use_and_retries_one_in_the_future() {
    let (offline_client, outbox) = offline();
    let mut holder = holder(-1, 60);
    let mut uses = Vec::new();
    for version in ["v1", "v2"] {
        uses.push(
            used(
                holder
                    .act(&offline_client, rotate(30), |_| report(version))
                    .await
                    .unwrap(),
            )
            .record,
        );
    }
    // The first is quarantined, and still takes its place in the chain: the
    // second is submitted and judged on its own. The NA dates it ahead of its
    // clock: it is retried, and admitted on the next flush.
    let (url, server) = scripted(vec![
        (422, error("grant_envelope_mismatch")),
        (422, error("grant_use_in_future")),
        (201, json!({"status": "recorded", "resource_sequence": 1})),
    ])
    .await;
    let (client, _) = client(&url);
    for entry in outbox.list().await.unwrap() {
        client
            .evidence_store
            .record_outbox()
            .unwrap()
            .add(&entry)
            .await
            .unwrap();
    }
    let report = client
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(report.dead_lettered.len(), 1);
    assert_eq!(
        report.dead_lettered[0].last_error.as_ref().unwrap().code,
        "grant_envelope_mismatch"
    );
    assert_eq!(report.pending.len(), 1);
    assert_eq!(
        report.pending[0].last_error.as_ref().unwrap().code,
        "grant_use_in_future"
    );
    let again = client
        .evidence_store
        .flush_records(FlushOptions {
            ignore_backoff: true,
        })
        .await
        .unwrap();
    assert_eq!(again.admitted.len(), 1);
    let seen = server.await.unwrap();
    assert_eq!(seen[0].body["evidence"], uses[0]);
    assert_eq!(seen[1].body["evidence"], uses[1]);
    assert_eq!(seen[2].body["evidence"], uses[1]);
    // A use alone is a grant use entry of the record outbox.
    assert_eq!(
        RecordOutboxEntry::new(uses[0].clone()).kind,
        RecordKind::GrantExecution
    );
}

#[test]
fn signs_a_use_and_a_time_token_request_as_the_na_reads_them() {
    let recorder = recorder();
    let grant = grant(-1, 60);
    let use_record = recorder
        .sign_grant_use(GrantUseInput {
            request_parameters: Some(json!({"lifetime_days": 30})),
            ..GrantUseInput::new(grant.clone(), token(0, None, -1), 1, None, "secret.rotate")
        })
        .unwrap();
    assert!(genesis_mesh_sdk::verify::valid_grant_record(
        "GrantExecutionEvidence",
        &use_record
    ));
    assert!(genesis_mesh_sdk::grants::signed_as_received(
        "GrantExecutionEvidence",
        &use_record,
        &[recorder.public_key()]
    ));
    // Refused before signing, with the NA's codes.
    let bad = recorder
        .sign_grant_use(GrantUseInput {
            resource_id: Some("kv:vault/x".into()),
            ..GrantUseInput::new(grant.clone(), token(0, None, -1), 1, None, "secret.rotate")
        })
        .unwrap_err();
    assert_eq!(bad.code(), "grant_use_malformed");
    let secret = recorder
        .sign_grant_use(GrantUseInput {
            execution_parameters: Some(json!({"api_key": "x"})),
            ..GrantUseInput::new(grant, token(0, None, -1), 1, None, "secret.rotate")
        })
        .unwrap_err();
    assert_eq!(secret.code(), "grant_use_secret_material");
    let request = recorder
        .sign_time_token_request("g", 0, None, None)
        .unwrap();
    assert!(request.get("use_head_digest").is_none());
    assert!(genesis_mesh_sdk::verify::valid_grant_record(
        "TimeTokenRequest",
        &{
            let mut r = request.clone();
            r["grant_id"] = json!("g");
            r
        }
    ));
    assert_eq!(
        recorder
            .sign_time_token_request("g", 1, None, None)
            .unwrap_err()
            .code(),
        "time_token_request_malformed"
    );
}

#[tokio::test]
async fn the_grant_routes_are_the_nas() {
    let (url, server) = scripted(vec![
        (201, json!({"grant": {}, "time_token": {}})),
        (200, json!({"grants": [], "next_before": null})),
        (200, json!({"grant_id": "g/1"})),
        (200, json!({"status": "revoked"})),
        (201, json!({"time_token": {}})),
        (200, json!({"status": "duplicate"})),
        (200, json!({"sequence": 0})),
        (404, error("grants_disabled")),
    ])
    .await;
    let (client, _) = client(&url);
    let grants = &client.grants;
    grants
        .issue(json!({"bearer_key_id": "executor-b"}))
        .await
        .unwrap();
    let query = genesis_mesh_sdk::GrantQuery {
        status: Some("active".into()),
        bearer_key_id: Some("executor-b".into()),
        limit: Some(10),
        before: None,
    };
    grants.list(&query).await.unwrap();
    grants.get("g/1").await.unwrap();
    grants
        .revoke("g/1", Some("the device was lost"))
        .await
        .unwrap();
    grants
        .request_time_token(json!({"grant_id": "g"}))
        .await
        .unwrap();
    grants.submit_use(json!({"use_id": "u"})).await.unwrap();
    grants.revocation_feed().await.unwrap();
    let off = grants.get("g").await.unwrap_err();
    assert_eq!(off.code(), "grants_disabled");
    let seen = server.await.unwrap();
    let targets: Vec<&str> = seen.iter().map(|r| r.target.as_str()).collect();
    assert_eq!(
        targets,
        [
            "/admin/grants",
            "/admin/grants?status=active&bearer_key_id=executor-b&limit=10",
            "/admin/grants/g%2F1",
            "/admin/grants/g%2F1/revoke",
            "/grants/time-tokens",
            "/evidence/grant-executions",
            "/sovereign-revocation-feed",
            "/admin/grants/g",
        ]
    );
    assert_eq!(seen[3].body, json!({"reason": "the device was lost"}));
    assert_eq!(seen[4].body, json!({"request": {"grant_id": "g"}}));
    assert_eq!(seen[5].body, json!({"evidence": {"use_id": "u"}}));
}

#[tokio::test]
async fn applies_the_bearer_keys_resource_prefix_offline() {
    let (client, _) = offline();
    let mut holder = holder(-1, 60);
    holder.set_resource_prefix(Some("kv:other/".into()));
    let err = holder
        .act(&client, rotate(30), |_| report("v1"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "grant_use_out_of_scope");
    holder.set_resource_prefix(Some("kv:vault/".into()));
    used(
        holder
            .act(&client, rotate(30), |_| report("v1"))
            .await
            .unwrap(),
    );
    // Without a resource, a scoped key signs nothing.
    let bare = GrantRequest::new("secret.rotate", json!({"lifetime_days": 1}));
    let err = holder
        .act(&client, bare, |_| report("v2"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "grant_use_out_of_scope");
    // The prefix is kept with the holder's state.
    let state: GrantHolderState =
        serde_json::from_value(serde_json::to_value(holder.state()).unwrap()).unwrap();
    assert_eq!(state.resource_prefix.as_deref(), Some("kv:vault/"));
}

#[test]
fn a_use_id_is_a_lowercase_uuid() {
    let recorder = recorder();
    let input = |id: &str| GrantUseInput {
        use_id: Some(id.to_owned()),
        ..GrantUseInput::new(grant(-1, 60), token(0, None, -1), 1, None, "secret.rotate")
    };
    assert!(recorder
        .sign_grant_use(input("00000000-0000-4000-8000-000000000101"))
        .is_ok());
    for bad in ["use-1", "00000000-0000-4000-8000-00000000010A", ""] {
        assert_eq!(
            recorder.sign_grant_use(input(bad)).unwrap_err().code(),
            "grant_use_malformed",
            "{bad}"
        );
    }
    assert!(genesis_mesh_sdk::grants::valid_use_id(
        "c287470c-692b-442b-a950-62740b3ea6e0"
    ));
}
