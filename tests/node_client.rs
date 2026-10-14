//! The node client (1.7.0): requests signed by the node key, and a client
//! acting as an edge node, which evaluates and reads resource heads on the
//! node-scoped routes without an operator key; against a scripted local
//! server.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use genesis_mesh_sdk::{
    json,
    node_auth::{executor_key_id, executor_proof_payload, node_signing_payload},
    public_key_from_seed, verify_canonical, ClientOptions, GenesisMeshClient, NodeIdentity,
    NodeJoin, Value,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const NODE_SEED: [u8; 32] = [11; 32];
const EXECUTOR_SEED: [u8; 32] = [12; 32];

#[derive(Debug)]
struct Request {
    target: String,
    head: String,
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
            seen.push(Request {
                target: head.split(' ').nth(1).unwrap().to_owned(),
                head,
                body,
            });
        }
        seen
    });
    (url, task)
}

fn node_public_key() -> String {
    public_key_from_seed(&STANDARD.encode(NODE_SEED)).unwrap()
}

fn identity() -> NodeIdentity {
    NodeIdentity::new("cert-1", &STANDARD.encode(NODE_SEED), "NA-KEY").unwrap()
}

fn client(url: &str) -> GenesisMeshClient {
    GenesisMeshClient::new(ClientOptions::new(url).with_timeout(Duration::from_secs(2)))
        .unwrap()
        .with_node_identity(identity())
}

fn signed_by_node(body: &Value) -> bool {
    verify_canonical(
        &node_signing_payload(body).unwrap(),
        body["signature"].as_str().unwrap(),
        &[node_public_key()],
    )
}

#[tokio::test]
async fn an_edge_node_evaluates_and_reads_heads_on_the_node_routes_without_an_operator_key() {
    let (url, server) = scripted(vec![
        (
            201,
            json!({"decision": {"authorized": false}, "justification_proof": {}}),
        ),
        (200, json!({"resource_sequence": 4, "record_digest": "d"})),
        (
            404,
            json!({"error": {"code": "resource_not_found", "message": "none"}}),
        ),
    ])
    .await;
    let client = client(&url);
    let evaluation = client
        .boundary
        .evaluate(json!({
            "attestation_id": "att-1",
            "requested_capability": "secret.rotate",
            "context": {"context_id": "ctx", "request_parameters": {"ratio": 0.1}},
        }))
        .await
        .unwrap();
    assert_eq!(evaluation["decision"]["authorized"], false);
    let head = client
        .evidence_store
        .resource_head("edge:site7/kv/db")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.resource_sequence, 4);
    assert!(client
        .evidence_store
        .resource_head_entry("edge:site7/kv/none")
        .await
        .unwrap()
        .is_none());

    let seen = server.await.unwrap();
    assert_eq!(seen[0].target, "/node/boundary/evaluate");
    assert_eq!(seen[1].target, "/node/evidence/resource-head");
    assert_eq!(seen[2].target, "/node/evidence/resource-head");
    for (request, purpose) in seen.iter().zip([
        "node_boundary_evaluate",
        "node_resource_head",
        "node_resource_head",
    ]) {
        assert!(!request.head.to_ascii_lowercase().contains("x-admin-"));
        let body = &request.body;
        assert_eq!(body["purpose"], purpose);
        assert_eq!(body["audience"], "NA-KEY");
        assert_eq!(body["cert_id"], "cert-1");
        assert_eq!(body["node_public_key"], node_public_key().as_str());
        assert!(signed_by_node(body), "{purpose} is not signed by the node");
    }
    assert_eq!(seen[0].body["attestation_id"], "att-1");
    assert_eq!(seen[1].body["resource_id"], "edge:site7/kv/db");
    // A nonce is never reused.
    assert_ne!(seen[1].body["nonce"], seen[2].body["nonce"]);
}

#[tokio::test]
async fn joins_with_an_executor_key_that_co_signs_and_heartbeats_with_an_agent_block() {
    let (url, server) = scripted(vec![
        (201, json!({"cert_id": "cert-1"})),
        (200, json!({"ack": true})),
        (201, json!({"cert_id": "cert-2"})),
        (200, json!({"grants": []})),
    ])
    .await;
    let client = client(&url);
    let join = NodeJoin::new(&STANDARD.encode(NODE_SEED), "invite")
        .unwrap()
        .with_executor_key(&STANDARD.encode(EXECUTOR_SEED))
        .unwrap()
        .with_validity_hours(24)
        .with_agent_version("1.7.0");
    assert!(!format!("{join:?}").contains("invite\""));
    client.node.join(&join).await.unwrap();
    client
        .node
        .heartbeat(&identity(), "healthy", Some(json!({"pending_uploads": 0})))
        .await
        .unwrap();
    client.node.renew(&identity(), 24).await.unwrap();
    client.node.state(&identity()).await.unwrap();

    let seen = server.await.unwrap();
    let joined = &seen[0].body;
    assert_eq!(seen[0].target, "/join");
    assert_eq!(joined["invite_token"], "invite");
    assert_eq!(joined["validity_hours"], 24);
    assert_eq!(joined["agent_version"], "1.7.0");
    let executor = public_key_from_seed(&STANDARD.encode(EXECUTOR_SEED)).unwrap();
    assert_eq!(joined["executor_public_key"], executor.as_str());
    assert!(verify_canonical(
        &executor_proof_payload(joined).unwrap(),
        joined["executor_signature"].as_str().unwrap(),
        std::slice::from_ref(&executor)
    ));
    assert!(signed_by_node(joined));
    assert!(executor_key_id(&executor).unwrap().starts_with("edge-"));

    let beat = &seen[1].body;
    assert_eq!(seen[1].target, "/heartbeat");
    assert_eq!(beat["status"], "healthy");
    assert_eq!(beat["agent"]["pending_uploads"], 0);
    // /heartbeat and /renew keep their scheme: no purpose, no audience.
    assert!(beat.get("purpose").is_none() && beat.get("audience").is_none());
    assert!(signed_by_node(beat));
    assert_eq!(seen[2].target, "/renew");
    assert_eq!(seen[2].body["validity_hours"], 24);
    assert!(signed_by_node(&seen[2].body));
    assert_eq!(seen[3].target, "/node/state");
    assert_eq!(seen[3].body["purpose"], "node_state");
}

#[test]
fn a_node_identity_never_shows_its_key() {
    let shown = format!("{:?}", identity());
    assert!(shown.contains("[REDACTED]"));
    assert!(!shown.contains(&STANDARD.encode(NODE_SEED)));
    assert!(NodeIdentity::new("", &STANDARD.encode(NODE_SEED), "NA").is_err());
}
