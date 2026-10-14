//! The local API (docs/edge.md, "Local API"): HTTP/1.1 JSON on a Unix
//! socket (authenticated by the peer's credentials) or a loopback port
//! (authenticated by a bearer token).

use std::{convert::Infallible, path::Path, sync::Arc, time::Duration};

use genesis_mesh_sdk::{json, parse_strict_json, Value};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
use tokio::{
    io::AsyncWriteExt as _,
    net::{TcpListener, UnixListener},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
};

use crate::{
    agent::{Agent, ApiError, AuthorizeRequest, Outcome},
    config::{Config, Listen, TokenEntry},
    log,
};

/// The largest request body.
pub const MAX_BODY: usize = 64 * 1024;

const ACTIONS: [&str; 5] = ["create", "rotate", "revoke", "update", "delete"];
const OUTCOMES: [&str; 3] = ["success", "failure", "partial"];

/// Authorizations per minute per local client: a client that asks too often
/// gets `429 local_rate_limited`, before the agent asks the NA anything.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>,
}

impl RateLimiter {
    /// Count one request of `client`; false when it is over `per_minute`.
    pub fn allow(&self, client: &str, per_minute: u32) -> bool {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = std::time::Instant::now();
        let minute = std::time::Duration::from_secs(60);
        windows.retain(|_, window| now.duration_since(window.0) < minute);
        let window = windows.entry(client.to_owned()).or_insert((now, 0));
        window.1 += 1;
        window.1 <= per_minute
    }
}

/// Whether a Unix socket peer may use the API: its uid or gid is allowed.
/// Root is not implied, and only the peer's primary gid is checked (the
/// kernel reports no supplementary groups).
pub fn peer_allowed(uid: u32, gid: u32, allowed_uids: &[u32], allowed_gids: &[u32]) -> bool {
    allowed_uids.contains(&uid) || allowed_gids.contains(&gid)
}

/// Whether an `Authorization` header carries one of the tokens, compared in
/// constant time by SHA-256. Returns the token's name.
pub fn token_name<'a>(header: Option<&str>, tokens: &'a [TokenEntry]) -> Option<&'a str> {
    let token = header?.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    let digest: String = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut found = None;
    for entry in tokens {
        if constant_time_eq(digest.as_bytes(), entry.sha256.as_bytes()) {
            found = Some(entry.name.as_str());
        }
    }
    found
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn respond(status: u16, body: &Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn error(err: &ApiError) -> Response<Full<Bytes>> {
    let mut response = respond(
        err.status,
        &json!({"error": {"code": err.code, "message": err.message}}),
    );
    if err.code == "agent_busy" {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(400, "invalid_request", message)
}

async fn body_of(request: Request<Incoming>) -> Result<Value, ApiError> {
    let bytes = Limited::new(request.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|_| ApiError::new(413, "request_too_large", "the body is larger than 64 KiB"))?
        .to_bytes();
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("the body is not UTF-8"))?;
    let value = parse_strict_json(text)
        .map_err(|e| invalid(format!("the body is not strict JSON: {e}")))?;
    if !value.is_object() {
        return Err(invalid("the body must be a JSON object"));
    }
    Ok(value)
}

fn text_field(body: &Value, key: &str, required: bool) -> Result<Option<String>, ApiError> {
    match &body[key] {
        Value::Null if !required => Ok(None),
        Value::String(s) if !s.is_empty() && s.chars().count() <= 1024 => Ok(Some(s.clone())),
        _ if required => Err(invalid(format!(
            "{key} is required: a string of 1 to 1024 characters"
        ))),
        _ => Err(invalid(format!(
            "{key} must be a string of 1 to 1024 characters"
        ))),
    }
}

fn object_field(body: &Value, key: &str) -> Result<Value, ApiError> {
    match &body[key] {
        Value::Null => Ok(json!({})),
        Value::Object(_) => Ok(body[key].clone()),
        _ => Err(invalid(format!("{key} must be a JSON object"))),
    }
}

const AUTHORIZE_FIELDS: [&str; 7] = [
    "capability",
    "request_parameters",
    "resource_id",
    "resource_action",
    "attributes",
    "attestation_id",
    "justification",
];

/// Read a `/v1/authorize` body.
pub fn authorize_request(body: &Value) -> Result<AuthorizeRequest, ApiError> {
    if let Some(unknown) = body
        .as_object()
        .and_then(|m| m.keys().find(|k| !AUTHORIZE_FIELDS.contains(&k.as_str())))
    {
        return Err(invalid(format!("unknown field {unknown}")));
    }
    let resource_action = text_field(body, "resource_action", true)?.unwrap_or_default();
    if !ACTIONS.contains(&resource_action.as_str()) {
        return Err(invalid(
            "resource_action is create, rotate, revoke, update or delete",
        ));
    }
    Ok(AuthorizeRequest {
        capability: text_field(body, "capability", true)?.unwrap_or_default(),
        request_parameters: object_field(body, "request_parameters")?,
        resource_id: text_field(body, "resource_id", true)?.unwrap_or_default(),
        resource_action,
        attributes: object_field(body, "attributes")?,
        attestation_id: text_field(body, "attestation_id", false)?,
        justification: text_field(body, "justification", false)?,
    })
}

/// Read an outcome body.
pub fn outcome_of(body: &Value) -> Result<Outcome, ApiError> {
    let outcome = text_field(body, "outcome", true)?.unwrap_or_default();
    if !OUTCOMES.contains(&outcome.as_str()) {
        return Err(invalid("outcome is success, failure or partial"));
    }
    Ok(Outcome {
        outcome,
        execution_parameters: match &body["execution_parameters"] {
            Value::Null => None,
            Value::Object(_) => Some(body["execution_parameters"].clone()),
            _ => return Err(invalid("execution_parameters must be a JSON object")),
        },
        outcome_detail: text_field(body, "outcome_detail", false)?,
    })
}

async fn route(
    agent: Arc<Agent>,
    request: Request<Incoming>,
    client: &str,
    limiter: &RateLimiter,
) -> Result<Value, ApiError> {
    let path = request.uri().path().to_owned();
    match (request.method().clone(), path.as_str()) {
        (Method::GET, "/v1/status") => Ok(agent.status().await),
        (Method::POST, "/v1/authorize") => {
            if !limiter.allow(client, agent.config.rate_limit_per_minute) {
                log::warn("local_rate_limited", json!({"client": client}));
                return Err(ApiError::new(
                    429,
                    "local_rate_limited",
                    "too many authorizations from this client; try again in a minute",
                ));
            }
            let body = body_of(request).await?;
            agent.authorize(authorize_request(&body)?, client).await
        }
        (Method::POST, _) if path.starts_with("/v1/authorizations/") => {
            let id = path
                .strip_prefix("/v1/authorizations/")
                .and_then(|rest| rest.strip_suffix("/outcome"))
                .filter(|id| !id.is_empty() && !id.contains('/'))
                .ok_or_else(|| {
                    ApiError::new(404, "authorization_not_found", "no such authorization")
                })?
                .to_owned();
            let body = body_of(request).await?;
            agent.report(&id, client, outcome_of(&body)?).await
        }
        _ => Err(ApiError::new(404, "not_found", "no such route")),
    }
}

async fn handle(
    agent: Arc<Agent>,
    request: Request<Incoming>,
    peer: Option<String>,
    limiter: Arc<RateLimiter>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // A socket peer is known by its uid; a loopback client by its token.
    let client = match peer {
        Some(peer) => peer,
        None => match token_name(
            request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok()),
            &agent.config.tokens,
        ) {
            Some(name) => format!("token:{name}"),
            None => {
                log::warn("local_client_refused", json!({"reason": "token"}));
                return Ok(error(&ApiError::new(
                    401,
                    "local_auth_required",
                    "a valid bearer token is required",
                )));
            }
        },
    };
    Ok(match route(agent, request, &client, &limiter).await {
        Ok(body) => respond(200, &body),
        Err(err) => error(&err),
    })
}

/// Set the socket's mode and group.
fn secure_socket(path: &Path, config: &Config) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(group) = &config.socket_group {
        let gid = group_id(group).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, format!("no group {group}"))
        })?;
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(config.socket_mode))
}

/// A group's ID: a number, or a name in /etc/group.
fn group_id(group: &str) -> Option<u32> {
    if let Ok(id) = group.parse() {
        return Some(id);
    }
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == group).then(|| fields.nth(1)?.parse().ok())?
        })
}

/// The most connections the local API holds at once: more are closed at
/// once, so idle clients cannot exhaust the agent's file descriptors.
pub const MAX_CONNECTIONS: usize = 64;

/// How long a client may take to send a request's headers.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve_connection<S>(
    agent: Arc<Agent>,
    stream: S,
    peer: Option<String>,
    limiter: Arc<RateLimiter>,
    _slot: OwnedSemaphorePermit,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        handle(
            Arc::clone(&agent),
            request,
            peer.clone(),
            Arc::clone(&limiter),
        )
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// An accept error is logged and the loop goes on; out of file descriptors,
/// it waits a moment first.
async fn accept_failed(err: &std::io::Error) {
    log::warn("accept_failed", json!({"error": err.to_string()}));
    // EMFILE, ENFILE: wait for connections to close.
    if matches!(err.raw_os_error(), Some(23 | 24)) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Serve the local API until `stop` fires. Errors only when it cannot
/// listen at all.
pub async fn serve(agent: Arc<Agent>, mut stop: watch::Receiver<bool>) -> std::io::Result<()> {
    let limiter = Arc::new(RateLimiter::default());
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    match agent.config.listen.clone() {
        Listen::Unix(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path)?;
            secure_socket(&path, &agent.config)?;
            log::info(
                "listening",
                json!({"listen": format!("unix:{}", path.display())}),
            );
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = stop.changed() => break,
                };
                let mut stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(err) => {
                        accept_failed(&err).await;
                        continue;
                    }
                };
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    log::warn("local_connections_full", json!({"max": MAX_CONNECTIONS}));
                    continue;
                };
                let credentials = stream.peer_cred();
                let allowed = credentials.as_ref().is_ok_and(|c| {
                    peer_allowed(
                        c.uid(),
                        c.gid(),
                        &agent.config.allowed_uids,
                        &agent.config.allowed_gids,
                    )
                });
                if !allowed {
                    let uid = credentials.as_ref().ok().map(|c| c.uid());
                    log::warn("local_peer_refused", json!({"uid": uid}));
                    let body = json!({"error": {"code": "local_peer_refused", "message": "this user may not use the agent"}}).to_string();
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    tokio::spawn(async move {
                        let _slot = slot;
                        let _ = tokio::time::timeout(
                            HEADER_TIMEOUT,
                            stream.write_all(response.as_bytes()),
                        )
                        .await;
                        let _ = stream.shutdown().await;
                    });
                    continue;
                }
                let peer = credentials.ok().map(|c| format!("uid:{}", c.uid()));
                tokio::spawn(serve_connection(
                    Arc::clone(&agent),
                    stream,
                    peer,
                    Arc::clone(&limiter),
                    slot,
                ));
            }
            let _ = std::fs::remove_file(&path);
        }
        Listen::Tcp(address) => {
            let listener = TcpListener::bind(address).await?;
            log::info(
                "listening",
                json!({"listen": format!("tcp://{}", listener.local_addr()?)}),
            );
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = stop.changed() => break,
                };
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(err) => {
                        accept_failed(&err).await;
                        continue;
                    }
                };
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    log::warn("local_connections_full", json!({"max": MAX_CONNECTIONS}));
                    continue;
                };
                tokio::spawn(serve_connection(
                    Arc::clone(&agent),
                    stream,
                    None,
                    Arc::clone(&limiter),
                    slot,
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_is_allowed_by_its_uid_or_gid_and_root_is_not_implied() {
        assert!(peer_allowed(1000, 1000, &[1000], &[]));
        assert!(peer_allowed(1001, 50, &[1000], &[50]));
        assert!(!peer_allowed(0, 0, &[1000], &[50]));
        assert!(!peer_allowed(65534, 65534, &[1000], &[]));
        assert!(!peer_allowed(1000, 1000, &[], &[]));
    }

    #[test]
    fn a_client_is_limited_per_minute() {
        let limiter = RateLimiter::default();
        assert!((0..3).all(|_| limiter.allow("uid:1000", 3)));
        assert!(!limiter.allow("uid:1000", 3));
        assert!(limiter.allow("token:ops", 3));
    }

    #[test]
    fn a_token_matches_by_its_sha256_only() {
        let token = "s3cret-token";
        let digest: String = Sha256::digest(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let tokens = [TokenEntry {
            name: "ops".into(),
            sha256: digest,
        }];
        assert_eq!(
            token_name(Some("Bearer s3cret-token"), &tokens),
            Some("ops")
        );
        assert_eq!(token_name(Some("Bearer wrong"), &tokens), None);
        assert_eq!(token_name(Some("Basic s3cret-token"), &tokens), None);
        assert_eq!(token_name(Some("Bearer "), &tokens), None);
        assert_eq!(token_name(None, &tokens), None);
    }

    #[test]
    fn reads_an_authorize_body_strictly() {
        let body = json!({
            "capability": "secret.rotate", "resource_id": "edge:a/kv", "resource_action": "rotate",
            "request_parameters": {"lifetime_days": 30},
        });
        let request = authorize_request(&body).unwrap();
        assert_eq!(request.attributes, json!({}));
        assert!(request.justification.is_none());
        for broken in [
            json!({"capability": "c", "resource_id": "r", "resource_action": "fly"}),
            json!({"capability": "c", "resource_id": "r"}),
            json!({"capability": "c", "resource_id": "r", "resource_action": "rotate", "extra": 1}),
            json!({"capability": "c", "resource_id": "r", "resource_action": "rotate", "justification": ""}),
            json!({"capability": "c", "resource_id": "r", "resource_action": "rotate", "request_parameters": []}),
        ] {
            assert_eq!(
                authorize_request(&broken).unwrap_err().code,
                "invalid_request"
            );
        }
        assert!(outcome_of(&json!({"outcome": "done"})).is_err());
        assert_eq!(
            outcome_of(&json!({"outcome": "partial"})).unwrap().outcome,
            "partial"
        );
    }
}
