use std::{collections::HashMap, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, SigningKey};
use genesis_mesh_sdk::{
    admin_signing_payload, json, AdminRequest, ClientOptions, GenesisMeshClient, GenesisMeshError,
    HttpTransport, Value,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

struct Request {
    line: String,
    headers: HashMap<String, String>,
    body: Value,
}

async fn server(
    status: u16,
    body: &str,
    headers: &str,
    delay: Duration,
) -> (String, JoinHandle<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    );
    let task = tokio::spawn(async move {
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        let (head, offset) = loop {
            let mut chunk = [0; 4096];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break (String::from_utf8(bytes[..end].to_vec()).unwrap(), end + 4);
            }
        };
        let mut lines = head.lines();
        let line = lines.next().unwrap().to_owned();
        let headers: HashMap<_, _> = lines
            .map(|line| {
                let (name, value) = line.split_once(':').unwrap();
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let length = headers
            .get("content-length")
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(0);
        while bytes.len() < offset + length {
            let mut chunk = [0; 4096];
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        let body = if length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&bytes[offset..offset + length]).unwrap()
        };
        tokio::time::sleep(delay).await;
        let _ = stream.write_all(response.as_bytes()).await;
        Request {
            line,
            headers,
            body,
        }
    });
    (url, task)
}

fn signed_options(url: &str) -> ClientOptions {
    ClientOptions::new(url)
        .with_signing_key(STANDARD.encode([7; 32]))
        .with_key_id("test-key")
        // Admin signatures name the NA's sovereign ID; the mock NA is "TEST".
        .with_audience("TEST")
}

fn verify_request(request: &Request, method: &str, route: &str, body: Value, admin: bool) {
    assert_eq!(request.line, format!("{method} {route} HTTP/1.1"));
    assert_eq!(request.body, body);
    assert_eq!(
        request.headers["user-agent"],
        concat!("genesis-mesh-sdk/", env!("CARGO_PKG_VERSION"))
    );
    if admin {
        assert_eq!(request.headers["x-admin-key-id"], "test-key");
        // Signature version 2: method, decoded path, query and audience are signed.
        let target = request.line.split(' ').nth(1).unwrap();
        let sent = reqwest::Url::parse(&format!("http://na{target}")).unwrap();
        let path = percent_encoding::percent_decode_str(sent.path())
            .decode_utf8()
            .unwrap()
            .into_owned();
        let query: Vec<(String, String)> = sent.query_pairs().into_owned().collect();
        let signed_body = if request.body.is_null() {
            json!({})
        } else {
            request.body.clone()
        };
        let payload = admin_signing_payload(
            &AdminRequest {
                method,
                path: &path,
                query: &query,
                audience: "TEST",
                body: &signed_body,
            },
            &request.headers["x-admin-key-id"],
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
    } else {
        assert!(!request
            .headers
            .keys()
            .any(|key| key.starts_with("x-admin-")));
    }
}

macro_rules! route_test {
    ($name:ident, $domain:ident, $method:ident, $route:literal, $admin:literal) => {
        #[tokio::test]
        async fn $name() {
            let (url, request) = server(200, r#"{"ok":true}"#, "", Duration::ZERO).await;
            let client = GenesisMeshClient::new(signed_options(&url)).unwrap();
            let body = json!({"message": "مرحبا 😀", "score": 1e-7});
            assert_eq!(client.$domain.$method(body.clone()).await.unwrap(), json!({"ok":true}));
            verify_request(&request.await.unwrap(), "POST", $route, body, $admin);
        }
    };
}

route_test!(
    agreement_offer,
    agreement,
    offer,
    "/admin/agreements/offer",
    true
);
route_test!(
    agreement_counter,
    agreement,
    counter,
    "/admin/agreements/counter",
    true
);
route_test!(
    agreement_accept,
    agreement,
    accept,
    "/admin/agreements/accept",
    true
);
route_test!(
    agreement_verify,
    agreement,
    verify,
    "/agreements/verify",
    false
);
route_test!(
    attestation_issue,
    attestation,
    issue,
    "/admin/attestations",
    true
);
route_test!(
    attestation_policy,
    attestation,
    save_policy,
    "/admin/recognition-policy",
    true
);
route_test!(
    boundary_decide,
    boundary,
    decide,
    "/admin/boundary/decide",
    true
);
route_test!(boundary_verify, boundary, verify, "/boundary/verify", false);
route_test!(
    consensus_vote,
    consensus,
    vote,
    "/admin/consensus/vote",
    true
);
route_test!(
    consensus_proof,
    consensus,
    proof,
    "/admin/consensus/proof",
    true
);
route_test!(
    consensus_verify,
    consensus,
    verify,
    "/consensus/verify",
    false
);
route_test!(
    data_policy,
    data_usage,
    create_policy,
    "/admin/data-usage/policy",
    true
);
route_test!(
    data_intent,
    data_usage,
    create_intent,
    "/admin/data-usage/intent",
    true
);
route_test!(data_verify, data_usage, verify, "/data-usage/verify", false);
route_test!(
    disclosure_commit,
    disclosure,
    commit,
    "/admin/disclosure/commit",
    true
);
route_test!(
    disclosure_nullifier,
    disclosure,
    nullifier,
    "/admin/disclosure/nullifier",
    true
);
route_test!(
    disclosure_prove,
    disclosure,
    prove,
    "/disclosure/prove",
    false
);
route_test!(
    disclosure_verify,
    disclosure,
    verify,
    "/disclosure/verify",
    false
);
route_test!(
    evidence_verify,
    evidence,
    verify,
    "/trust-evidence/verify",
    false
);

#[tokio::test]
async fn evidence_build_wraps_decision() {
    let (url, request) = server(201, "{}", "", Duration::ZERO).await;
    let client = GenesisMeshClient::new(signed_options(&url)).unwrap();
    let decision = json!({"verdict":"allow"});
    client.evidence.build(decision.clone()).await.unwrap();
    verify_request(
        &request.await.unwrap(),
        "POST",
        "/admin/trust-evidence",
        json!({"decision":decision}),
        true,
    );
}

#[tokio::test]
async fn policy_get_supports_base_path_and_public_only_client() {
    let (url, request) = server(200, "{}", "", Duration::ZERO).await;
    let client = GenesisMeshClient::new(ClientOptions::new(format!("{url}/prefix/"))).unwrap();
    client.data_usage.get_policy().await.unwrap();
    verify_request(
        &request.await.unwrap(),
        "GET",
        "/prefix/data-usage/policy",
        Value::Null,
        false,
    );
}

#[tokio::test]
async fn revoke_encodes_path_and_handles_optional_body() {
    for body in [None, Some(json!({"reason":"compromised"}))] {
        let (url, request) = server(200, "{}", "", Duration::ZERO).await;
        let client = GenesisMeshClient::new(signed_options(&url)).unwrap();
        client
            .attestation
            .revoke("a/b?#%", body.clone())
            .await
            .unwrap();
        verify_request(
            &request.await.unwrap(),
            "POST",
            "/admin/attestations/a%2Fb%3F%23%25/revoke",
            body.unwrap_or(json!({})),
            true,
        );
    }
}

#[tokio::test]
async fn maps_http_errors_even_without_json() {
    for (status, body) in [
        (400, r#"{"error":"bad"}"#),
        (401, r#"{"error":{"message":"denied","code":"auth"}}"#),
        (404, "missing"),
        (422, r#"{"detail":"invalid"}"#),
        (429, "slow down"),
        (503, "<html>unavailable</html>"),
        (500, ""),
    ] {
        let (url, request) = server(status, body, "", Duration::ZERO).await;
        let transport = HttpTransport::new(ClientOptions::new(url)).unwrap();
        let error = transport.public_get::<Value>("/test").await.unwrap_err();
        assert!(match status {
            400 => matches!(error, GenesisMeshError::BadRequest { .. }),
            401 => matches!(error, GenesisMeshError::Unauthorized { .. }),
            404 =>
                matches!(error, GenesisMeshError::NotFound { ref message, .. } if message == "missing"),
            422 =>
                matches!(error, GenesisMeshError::Validation { ref message, .. } if message == "invalid"),
            429 => matches!(error, GenesisMeshError::RateLimit { .. }),
            _ => matches!(error, GenesisMeshError::Http { status: actual, .. } if actual == status),
        });
        request.await.unwrap();
    }
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let (url, request) = server(
        307,
        "",
        "Location: http://127.0.0.1:1/leak\r\n",
        Duration::ZERO,
    )
    .await;
    let transport = HttpTransport::new(signed_options(&url)).unwrap();
    assert!(matches!(
        transport
            .admin_post::<Value>("/admin/test", json!({}))
            .await,
        Err(GenesisMeshError::Http { status: 307, .. })
    ));
    request.await.unwrap();
}

#[tokio::test]
async fn timeout_is_enforced() {
    let (url, request) = server(200, "{}", "", Duration::from_millis(300)).await;
    let transport =
        HttpTransport::new(ClientOptions::new(url).with_timeout(Duration::from_millis(50)))
            .unwrap();
    assert!(
        matches!(transport.public_get::<Value>("/test").await, Err(GenesisMeshError::Network(error)) if error.is_timeout())
    );
    request.abort();
}

#[tokio::test]
async fn success_json_and_empty_body_contract() {
    for (status, body) in [(200, "invalid"), (204, "")] {
        let (url, request) = server(status, body, "", Duration::ZERO).await;
        let transport = HttpTransport::new(ClientOptions::new(url)).unwrap();
        let result = transport.public_get::<Value>("/test").await;
        if status == 204 {
            assert_eq!(result.unwrap(), json!({}));
        } else {
            // v1.2.0: a response is read strictly, so malformed JSON is named.
            assert!(
                matches!(result, Err(GenesisMeshError::StrictJson { ref reason, .. }) if reason == "invalid_json")
            );
        }
        request.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_invalid_configuration_before_network_access() {
    for url in [
        "",
        "localhost:9443",
        "ftp://example.com",
        "https://user:secret@example.com",
        "https://example.com?q=1",
        "https://example.com/#fragment",
    ] {
        assert!(matches!(
            HttpTransport::new(ClientOptions::new(url)),
            Err(GenesisMeshError::Configuration(_))
        ));
    }
    for key_id in ["", "  ", "bad\r\nheader", " key", "key ", "clé"] {
        assert!(
            HttpTransport::new(ClientOptions::new("http://localhost").with_key_id(key_id)).is_err()
        );
    }
    assert!(HttpTransport::new(
        ClientOptions::new("http://localhost").with_timeout(Duration::ZERO)
    )
    .is_err());
    let transport = HttpTransport::new(ClientOptions::new("http://127.0.0.1:1")).unwrap();
    assert!(matches!(
        transport.admin_post::<Value>("/test", json!({})).await,
        Err(GenesisMeshError::MissingSigningKey)
    ));
    for route in [
        "relative",
        "//example.com",
        "/test#fragment",
        "/test\\escape",
    ] {
        assert!(matches!(
            transport.public_get::<Value>(route).await,
            Err(GenesisMeshError::Configuration(_))
        ));
    }
    let client = GenesisMeshClient::new(signed_options("http://127.0.0.1:1")).unwrap();
    for id in ["", ".", ".."] {
        assert!(matches!(
            client.attestation.revoke(id, None).await,
            Err(GenesisMeshError::Configuration(_))
        ));
    }
}

#[test]
fn debug_does_not_expose_signing_seed() {
    let options = signed_options("http://localhost");
    let secret = options.signing_key_base64.clone().unwrap();
    let debug = format!("{options:?}");
    assert!(!debug.contains(&secret));
    assert!(debug.contains("[REDACTED]"));
}

#[tokio::test]
async fn transport_deserializes_typed_responses() {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Policy {
        enabled: bool,
    }
    let (url, request) = server(200, r#"{"enabled":true}"#, "", Duration::ZERO).await;
    let transport = HttpTransport::new(ClientOptions::new(url)).unwrap();
    assert_eq!(
        transport.public_get::<Policy>("/test").await.unwrap(),
        Policy { enabled: true }
    );
    request.await.unwrap();
}
