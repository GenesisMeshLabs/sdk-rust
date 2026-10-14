//! The edge agent against a live NA (1.7.0, docs/edge.md): enrolment,
//! renewal and revocation (C1), no operator key on the device (C2), hours
//! with the NA stopped (C3), a stale snapshot, and local client
//! authentication (C4). Skipped unless `GM_E2E_PYTHON` names a Python with a
//! core that has the edge routes (`scripts/e2e_na.py`).
//!
//! `GM_EDGE_OFFLINE_SECONDS` sets how long the NA stays stopped in
//! `offline` (120 on pull requests, 7200 in the soak); `GM_EDGE_BINARY` runs
//! another build of the agent (the static release build) and
//! `GM_EDGE_WRAP` runs it under a wrapper (`/usr/bin/time -v`).

mod support;

use std::time::Duration;

use genesis_mesh_sdk::{json, Value};
use support::{assert_only_agent_files, offline_seconds, start_na, Agent, Proxy};

fn request(capability: &str, prefix: &str, lifetime: u64, justification: Option<&str>) -> Value {
    let mut request = json!({
        "capability": capability,
        "request_parameters": {"lifetime_days": lifetime},
        "resource_id": format!("{prefix}kv/{capability}"),
        "resource_action": "rotate",
    });
    if let Some(justification) = justification {
        request["justification"] = json!(justification);
    }
    request
}

fn sovereign() -> String {
    format!("site-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

#[tokio::test]
async fn lifecycle() {
    let Some(na) = start_na() else { return };
    let proxy = Proxy::start(&na.base_url).await;
    let site = sovereign();
    // A certificate valid for one hour, renewed once less than 3595 s of it
    // are left: within seconds of enrolment.
    let token = na.edge_invite(&site, 1).await;
    let mut agent = Agent::new(
        &proxy.url,
        &na.na_public_key,
        &[
            ("GM_EDGE_RENEW_BEFORE_SECONDS", "3595"),
            ("GM_EDGE_VALIDITY_HOURS", "1"),
        ],
    );
    // Enrolment needs the token; a wrong one is refused for good (exit 4).
    assert_eq!(
        agent
            .once(&["enroll"], &[("GM_EDGE_INVITE_TOKEN", "not-a-token")])
            .await,
        4,
        "{}",
        agent.log()
    );
    assert_eq!(agent.once(&["run"], &[]).await, 3, "not enrolled, no token");
    assert_eq!(
        agent
            .once(&["enroll"], &[("GM_EDGE_INVITE_TOKEN", &token)])
            .await,
        0,
        "{}",
        agent.log()
    );
    let enrollment: Value = serde_json::from_str(
        &std::fs::read_to_string(agent.state_dir.join("enrollment.json")).unwrap(),
    )
    .unwrap();
    let executor_key_id = enrollment["executor_key"]["key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let prefix = enrollment["executor_key"]["resource_prefix"]
        .as_str()
        .unwrap()
        .to_owned();
    let first_cert = enrollment["cert"]["cert_id"].as_str().unwrap().to_owned();
    assert!(executor_key_id.starts_with("edge-"));
    // The NA registered the executor key at join.
    let keys = na.admin.evidence_store.list_executor_keys().await.unwrap();
    let key = keys
        .iter()
        .find(|k| k["key_id"] == executor_key_id.as_str())
        .expect("registered");
    assert!(key["retired_at"].is_null());

    let attestation = na.attest(&site, &["secret.rotate"]).await;
    let grant = na
        .grant(&executor_key_id, &attestation, "secret.rotate", 5, 5, 60)
        .await;

    agent.start();
    // Renewed, and the grant held.
    let status = agent
        .wait_for(Duration::from_secs(60), |s| {
            s["cert_id"].as_str().is_some_and(|c| c != first_cert)
                && s["grants"].as_array().is_some_and(|g| !g.is_empty())
                && s["connected"] == true
        })
        .await;
    assert_eq!(status["state"], "active");
    assert_eq!(status["executor_key_id"], executor_key_id.as_str());
    assert_eq!(status["grants"][0]["grant_id"], grant.as_str());
    // Connected: the NA decides.
    let (code, allowed) = agent.act(request("secret.rotate", &prefix, 30, None)).await;
    assert_eq!(code, 200, "{allowed}");
    assert_eq!(
        allowed["authority"],
        "decision",
        "{allowed}\n{}",
        agent.log()
    );
    assert_eq!(allowed["outcome"]["record_kind"], "execution");
    // Outside the node's prefix: refused before anything else.
    let mut outside = request("secret.rotate", &prefix, 30, None);
    outside["resource_id"] = json!("kv:elsewhere/db");
    let (code, refused) = agent.call("POST", "/v1/authorize", Some(&outside)).await;
    assert_eq!(
        (code, refused["error"]["code"].as_str()),
        (400, Some("resource_out_of_scope"))
    );

    // The operator revokes the node once: every certificate, the key, its grants.
    let cert_id = agent.status().await["cert_id"].as_str().unwrap().to_owned();
    let revoked: Value = na
        .transport
        .admin_post(
            "/admin/revoke",
            json!({"cert_id": cert_id, "reason": "cessation_of_operation"}),
        )
        .await
        .unwrap();
    assert_eq!(
        revoked["edge_node"]["executor_key_retired"], true,
        "{revoked}"
    );
    let keys = na.admin.evidence_store.list_executor_keys().await.unwrap();
    let key = keys
        .iter()
        .find(|k| k["key_id"] == executor_key_id.as_str())
        .unwrap();
    assert!(!key["retired_at"].is_null());
    let held = na.admin.grants.get(&grant).await.unwrap();
    assert_eq!(held["revocation"]["reason"], "bearer_key_retired", "{held}");
    agent
        .wait_for(Duration::from_secs(30), |s| s["state"] == "revoked")
        .await;
    let (code, refused) = agent
        .call(
            "POST",
            "/v1/authorize",
            Some(&request("secret.rotate", &prefix, 30, None)),
        )
        .await;
    assert_eq!(
        (code, refused["error"]["code"].as_str()),
        (403, Some("node_revoked"))
    );

    // C2: no operator key ever crossed to the NA; the state is the agent's own.
    assert!(!proxy.admin_headers_seen());
    assert_eq!(agent.stop().await, Some(0), "{}", agent.log());
    assert_only_agent_files(&agent.state_dir);
}

#[tokio::test]
async fn offline() {
    let Some(na) = start_na() else { return };
    let proxy = Proxy::start(&na.base_url).await;
    let site = sovereign();
    let token = na.edge_invite(&site, 168).await;
    let mut agent = Agent::new(
        &proxy.url,
        &na.na_public_key,
        &[("GM_EDGE_INVITE_TOKEN", &token)],
    );
    agent.start();
    let status = agent
        .wait_for(Duration::from_secs(30), |s| s["state"] == "active")
        .await;
    let executor_key_id = status["executor_key_id"].as_str().unwrap().to_owned();
    let prefix = status["resource_prefix"].as_str().unwrap().to_owned();
    let offline = offline_seconds();
    let attestation = na.attest(&site, &["cap.a", "cap.b", "cap.c"]).await;
    // Grant A: 20 uses, 10 per time token, valid for twice the outage and
    // half an hour (34 min on pull requests, 4.5 h in the soak).
    let minutes = (offline / 60) as i64 * 2 + 30;
    let grant_a = na
        .grant(&executor_key_id, &attestation, "cap.a", 20, 10, minutes)
        .await;
    let grant_b = na
        .grant(&executor_key_id, &attestation, "cap.b", 5, 5, minutes)
        .await;
    agent
        .wait_for(Duration::from_secs(30), |s| {
            s["grants"].as_array().is_some_and(|g| g.len() == 2) && s["connected"] == true
        })
        .await;
    // Online first: one decision.
    let (_, decided) = agent.act(request("cap.c", &prefix, 30, None)).await;
    assert_eq!(
        decided["authority"],
        "decision",
        "{decided}\n{}",
        agent.log()
    );

    proxy.cut();
    let started = tokio::time::Instant::now();
    let at = |fraction: f64| started + Duration::from_secs_f64(offline as f64 * fraction);
    let grant_uses = 8;
    let mut outcomes = Vec::new();
    for n in 0..grant_uses {
        tokio::time::sleep_until(at(n as f64 / grant_uses as f64)).await;
        let (_, used) = agent.act(request("cap.a", &prefix, 10 + n, None)).await;
        assert_eq!(used["authority"], "grant", "{used}\n{}", agent.log());
        outcomes.push(used);
        match n {
            1 => {
                // Out of the envelope: refused, even with a justification.
                let (_, outside) = agent
                    .act(request("cap.a", &prefix, 400, Some("urgent")))
                    .await;
                assert_eq!(outside["allowed"], false);
                assert_eq!(outside["code"], "outside_grant", "{outside}");
                // No grant names cap.c: break-glass with a justification, refused without.
                let (_, glass) = agent
                    .act(request(
                        "cap.c",
                        &prefix,
                        30,
                        Some("the line is down; rotate now"),
                    ))
                    .await;
                assert_eq!(glass["authority"], "break_glass", "{glass}");
                assert_eq!(glass["code"], "no_grant");
                let (_, refused) = agent.act(request("cap.c", &prefix, 30, None)).await;
                assert_eq!(refused["code"], "justification_required");
                assert_eq!(refused["grant_code"], "no_grant");
                // One use of B before the operator revokes it.
                let (_, b) = agent.act(request("cap.b", &prefix, 30, None)).await;
                assert_eq!(b["authority"], "grant", "{b}");
            }
            4 => {
                // Half way: the operator revokes B at the NA; the agent cannot know.
                na.admin
                    .grants
                    .revoke(&grant_b, Some("scenario"))
                    .await
                    .unwrap();
                for _ in 0..2 {
                    let (_, b) = agent.act(request("cap.b", &prefix, 30, None)).await;
                    assert_eq!(b["authority"], "grant", "{b}");
                }
            }
            _ => {}
        }
    }
    tokio::time::sleep_until(at(1.0)).await;
    let during = agent.status().await;
    assert_eq!(during["connected"], false);
    assert!(
        during["pending_uploads"].as_u64().unwrap() >= 12,
        "{during}"
    );

    // Restored: everything uploads within T = 120 s.
    proxy.restore().await;
    let t0 = tokio::time::Instant::now();
    agent
        .wait_for(Duration::from_secs(180), |s| {
            s["pending_uploads"] == 0 && s["connected"] == true
        })
        .await;
    let uploaded = t0.elapsed();
    assert!(
        uploaded <= Duration::from_secs(120),
        "uploads took {uploaded:?}"
    );
    eprintln!("offline {offline} s: uploaded in {uploaded:?}");

    // At the NA: A's chain holds the 8 uses in order.
    let chain = |page: &Value| -> Vec<(u64, String, Value)> {
        let mut uses: Vec<(u64, String, Value)> = page["uses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| {
                (
                    u["use_sequence"].as_u64().unwrap(),
                    u["state"].as_str().unwrap().to_owned(),
                    u["rejection_code"].clone(),
                )
            })
            .collect();
        uses.sort_by_key(|u| u.0);
        uses
    };
    let a = chain(
        &na.admin
            .grants
            .uses(&grant_a, None, Some(100))
            .await
            .unwrap(),
    );
    assert_eq!(a.len(), grant_uses as usize, "{a:?}");
    assert!(
        a.iter()
            .enumerate()
            .all(|(i, u)| u.0 == i as u64 + 1 && u.1 == "admitted"),
        "{a:?}"
    );
    // B: one admitted, then two quarantined as revoked, in chain order.
    let b = chain(
        &na.admin
            .grants
            .uses(&grant_b, None, Some(100))
            .await
            .unwrap(),
    );
    assert_eq!(b.len(), 3, "{b:?}");
    assert_eq!(b[0].1, "admitted");
    assert!(
        b[1..]
            .iter()
            .all(|u| u.1 == "quarantined" && u.2 == "grant_revoked"),
        "{b:?}"
    );
    // The break-glass record is admitted and judged.
    let glass = na
        .admin
        .evidence_store
        .search_all(json!({"entry_kind": "break_glass"}))
        .await
        .unwrap();
    let ours: Vec<&Value> = glass
        .iter()
        .filter(|e| e["payload"]["executor_sovereign_id"] == site.as_str())
        .collect();
    assert_eq!(ours.len(), 1, "{glass:?}");
    let judged = na
        .admin
        .evidence_store
        .judge_break_glass(ours[0]["payload"]["break_glass_id"].as_str().unwrap())
        .await
        .unwrap();
    assert!(
        judged["status"] == "judged" || judged["status"] == "existing",
        "{judged}"
    );
    // The store verifies.
    let verified = na.admin.evidence_store.verify().await.unwrap();
    assert_eq!(verified["verified"], true, "{verified}");
    assert!(!proxy.admin_headers_seen());
    assert_eq!(agent.stop().await, Some(0), "{}", agent.log());
    assert_only_agent_files(&agent.state_dir);
}

#[tokio::test]
async fn stale() {
    let Some(na) = start_na() else { return };
    let proxy = Proxy::start(&na.base_url).await;
    let site = sovereign();
    let token = na.edge_invite(&site, 168).await;
    let mut agent = Agent::new(
        &proxy.url,
        &na.na_public_key,
        &[
            ("GM_EDGE_INVITE_TOKEN", &token),
            ("GM_EDGE_MAX_SNAPSHOT_AGE_SECONDS", "60"),
        ],
    );
    agent.start();
    let status = agent
        .wait_for(Duration::from_secs(30), |s| s["state"] == "active")
        .await;
    let executor_key_id = status["executor_key_id"].as_str().unwrap().to_owned();
    let prefix = status["resource_prefix"].as_str().unwrap().to_owned();
    let attestation = na.attest(&site, &["cap.a"]).await;
    na.grant(&executor_key_id, &attestation, "cap.a", 20, 10, 60)
        .await;
    agent
        .wait_for(Duration::from_secs(30), |s| {
            s["grants"].as_array().is_some_and(|g| g.len() == 1) && s["snapshot_fresh"] == true
        })
        .await;
    proxy.cut();
    tokio::time::sleep(Duration::from_secs(70)).await;
    let status = agent.status().await;
    assert_eq!(status["snapshot_fresh"], false, "{status}");
    let (_, refused) = agent.act(request("cap.a", &prefix, 30, None)).await;
    assert_eq!(refused["code"], "justification_required", "{refused}");
    assert_eq!(refused["grant_code"], "snapshot_stale");
    let (_, glass) = agent
        .act(request("cap.a", &prefix, 30, Some("stale, but urgent")))
        .await;
    assert_eq!(
        glass["authority"],
        "break_glass",
        "{glass}\n{}",
        agent.log()
    );
    assert_eq!(glass["code"], "snapshot_stale");
    proxy.restore().await;
    agent
        .wait_for(Duration::from_secs(60), |s| {
            s["pending_uploads"] == 0 && s["snapshot_fresh"] == true
        })
        .await;
    assert_eq!(agent.stop().await, Some(0), "{}", agent.log());
}

#[tokio::test]
async fn local_auth() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(na) = start_na() else { return };
    let site = sovereign();
    let token = na.edge_invite(&site, 168).await;

    // (b) Loopback: no token or a wrong one is 401, the right one 200.
    let mut agent = Agent::new(
        &na.base_url,
        &na.na_public_key,
        &[("GM_EDGE_INVITE_TOKEN", &token)],
    );
    agent.start();
    agent.status().await;
    let (address, right) = agent.api.clone().unwrap();
    for token in [None, Some("wrong")] {
        let (code, body) = support::call_tcp(&address, "GET", "/v1/status", None, token).await;
        assert_eq!(
            (code, body["error"]["code"].as_str()),
            (401, Some("local_auth_required"))
        );
    }
    assert_eq!(
        support::call_tcp(&address, "GET", "/v1/status", None, Some(&right))
            .await
            .0,
        200
    );
    assert_eq!(agent.stop().await, Some(0), "{}", agent.log());

    // (a) and (c): a Unix socket, 0660, open to this uid only.
    let uid = std::fs::metadata("/proc/self")
        .map(|m| {
            use std::os::unix::fs::MetadataExt as _;
            m.uid()
        })
        .unwrap();
    let socket_dir = support::temporary("gm-edge-socket");
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let socket = socket_dir.join("agent.sock");
    let uid_text = uid.to_string();
    let listen = format!("unix:{}", socket.display());
    let mut unix = Agent::new(&na.base_url, &na.na_public_key, &[]);
    unix.state_dir = agent.state_dir.clone();
    unix.env = agent.env.clone();
    unix.env.retain(|(k, _)| {
        k != "GM_EDGE_LISTEN" && k != "GM_EDGE_TOKENS" && k != "GM_EDGE_INVITE_TOKEN"
    });
    unix.env.push(("GM_EDGE_LISTEN".into(), listen));
    unix.env.push(("GM_EDGE_ALLOWED_UIDS".into(), uid_text));
    unix.start();
    let mut answered = None;
    for _ in 0..100 {
        answered = support::call_unix(&socket, "GET", "/v1/status").await;
        if answered.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (code, status) = answered.expect("the socket answers");
    assert_eq!(code, 200, "{status}");
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    // Another uid, with the socket opened to it at the file level: the agent
    // refuses it by its credentials.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    let refused = std::process::Command::new("sudo")
        .args([
            "-n",
            "setpriv",
            "--reuid=65534",
            "--regid=65534",
            "--clear-groups",
            "--",
        ])
        .arg("curl")
        .args(["-s", "--unix-socket"])
        .arg(&socket)
        .arg("http://agent/v1/status")
        .output();
    match refused {
        Ok(output) if output.status.success() => {
            let body: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
            assert_eq!(body["error"]["code"], "local_peer_refused", "{body}");
        }
        Ok(output) => eprintln!(
            "skipped (a), another uid: sudo -n setpriv is not permitted here ({})",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(err) => eprintln!("skipped (a), another uid: no sudo ({err})"),
    }
    assert_eq!(unix.stop().await, Some(0), "{}", unix.log());
}
