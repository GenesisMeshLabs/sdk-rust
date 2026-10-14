//! The scenario harness: a loopback NA from `scripts/e2e_na.py`, a proxy
//! between the agent and the NA ("the NA is stopped" means the proxy refuses
//! connections; it also records any request carrying an `X-Admin-` header),
//! the agent binary and a minimal client of its local API.
//!
//! The test is the operator: it signs admin requests with the NA's test
//! operator key. The agent never does (edge/clippy.toml); the proxy checks
//! that no admin header crosses it.
#![allow(dead_code, clippy::disallowed_methods)]

use std::{
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use genesis_mesh_sdk::{json, ClientOptions, GenesisMeshClient, HttpTransport, Value};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UnixStream},
    task::JoinHandle,
};

/// A loopback NA.
pub struct Na {
    /// Its base URL.
    pub base_url: String,
    /// The operator's client.
    pub admin: GenesisMeshClient,
    /// The operator's transport, for routes the SDK does not wrap.
    pub transport: HttpTransport,
    /// The NA's (and the genesis root's) public key.
    pub na_public_key: String,
    child: Child,
}

impl Drop for Na {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a loopback NA with `GM_E2E_PYTHON`, or `None` (the test is skipped)
/// when it is not set or the core has no edge routes.
pub fn start_na() -> Option<Na> {
    let Ok(python) = std::env::var("GM_E2E_PYTHON") else {
        eprintln!("skipped: set GM_E2E_PYTHON to a Python with the core installed");
        return None;
    };
    let mut child = Command::new(python)
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/e2e_na.py"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the loopback NA");
    let stdout = child.stdout.take().unwrap();
    let line = BufReader::new(stdout)
        .lines()
        .map(Result::unwrap)
        .find(|line| line.starts_with('{'))
        .expect("the NA printed its configuration");
    let config: Value = serde_json::from_str(&line).unwrap();
    if !config["edge"].as_bool().unwrap_or(false) || !config["grants"].as_bool().unwrap_or(false) {
        eprintln!("skipped 1.7.0: the core has no edge routes (/node/state) or no grants");
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let base_url = config["baseUrl"].as_str().unwrap().to_owned();
    let options = ClientOptions::new(&base_url)
        .with_signing_key(config["signingKeyBase64"].as_str().unwrap())
        .with_key_id(config["keyId"].as_str().unwrap())
        .with_timeout(Duration::from_secs(30));
    Some(Na {
        admin: GenesisMeshClient::new(options.clone()).unwrap(),
        transport: HttpTransport::new(options).unwrap(),
        na_public_key: config["naPublicKey"].as_str().unwrap().to_owned(),
        base_url,
        child,
    })
}

impl Na {
    /// An edge invite for `sovereign`: its token.
    pub async fn edge_invite(&self, sovereign: &str, max_validity_hours: u32) -> String {
        let invite: Value = self
            .transport
            .admin_post(
                "/admin/invite",
                json!({
                    "roles": ["role:client"],
                    "max_validity_hours": max_validity_hours,
                    "node_sovereign_id": sovereign,
                    "executor_resource_prefix": format!("edge:{sovereign}/"),
                }),
            )
            .await
            .expect("an edge invite");
        invite["token_id"].as_str().unwrap().to_owned()
    }

    /// An attestation issued to `sovereign` for `capabilities`, and an
    /// active policy over them (decisions need one).
    pub async fn attest(&self, sovereign: &str, capabilities: &[&str]) -> Value {
        let attestation = self
            .admin
            .attestation
            .issue(json!({"subject_id": sovereign, "roles": ["role:client"],
                          "claims": {"capabilities": capabilities}}))
            .await
            .expect("an attestation");
        let now = chrono::Utc::now();
        let policy = self
            .admin
            .policy
            .publish(json!({
                "policy_id": format!("edge-{sovereign}"),
                "valid_from": (now - chrono::Duration::minutes(1)).to_rfc3339(),
                "valid_until": (now + chrono::Duration::days(2)).to_rfc3339(),
                "selector": {"capabilities": capabilities},
                "gates": [{"gate_id": "lifetime", "gate_type": "max_value.v1", "order": 0,
                           "config": {"path": "request_parameters.lifetime_days", "max": 90}}],
            }))
            .await
            .expect("a policy");
        self.admin
            .policy
            .activate(
                policy["policy_id"].as_str().unwrap(),
                policy["version"].as_u64().unwrap(),
            )
            .await
            .expect("the policy is active");
        attestation
    }

    /// A grant to the edge node's executor key.
    pub async fn grant(
        &self,
        executor_key_id: &str,
        attestation: &Value,
        capability: &str,
        max_uses: u64,
        per_token: u64,
        minutes: i64,
    ) -> String {
        let issued = self
            .admin
            .grants
            .issue(json!({
                "bearer_key_id": executor_key_id, "capabilities": [capability],
                "attestation_id": attestation["attestation_id"],
                "valid_until": genesis_mesh_sdk::canonical::python_timestamp(
                    chrono::Utc::now() + chrono::Duration::minutes(minutes)),
                "max_uses": max_uses, "max_uses_per_time_token": per_token,
                "parameter_envelope": {"lifetime_days": {"number_range": {
                    "number_type": "integer", "minimum": 1, "maximum": 60}}},
            }))
            .await
            .expect("a grant");
        issued["grant"]["grant_id"].as_str().unwrap().to_owned()
    }
}

/// How the proxy treats a connection.
const FORWARD: u8 = 0;
const THROTTLE: u8 = 1;
const BLACKHOLE: u8 = 2;
const GATEWAY: u8 = 3;

/// A TCP proxy between the agent and the NA: it forwards, refuses
/// connections (the NA is stopped), answers every request `429` (the NA
/// throttles the device), or accepts connections and never answers (a
/// blackholed network).
pub struct Proxy {
    mode: Arc<std::sync::atomic::AtomicU8>,
    /// The URL the agent is given.
    pub url: String,
    address: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    serving: Mutex<Option<JoinHandle<()>>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    admin_seen: Arc<AtomicBool>,
}

impl Proxy {
    /// A proxy to `upstream` (`http://127.0.0.1:port`).
    pub async fn start(upstream: &str) -> Arc<Self> {
        let upstream: std::net::SocketAddr = upstream
            .trim_start_matches("http://")
            .parse()
            .expect("a loopback NA");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = Arc::new(Self {
            url: format!("http://{address}"),
            address,
            upstream,
            serving: Mutex::new(None),
            mode: Arc::default(),
            connections: Arc::default(),
            admin_seen: Arc::default(),
        });
        proxy.serve(listener);
        proxy
    }

    fn serve(&self, listener: TcpListener) {
        let upstream = self.upstream;
        let connections = Arc::clone(&self.connections);
        let admin_seen = Arc::clone(&self.admin_seen);
        let mode = Arc::clone(&self.mode);
        let task = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let admin_seen = Arc::clone(&admin_seen);
                let mode = mode.load(Ordering::SeqCst);
                let connection = tokio::spawn(async move {
                    if mode == THROTTLE {
                        return refuse(client, THROTTLED).await;
                    }
                    if mode == GATEWAY {
                        return refuse(client, BAD_GATEWAY).await;
                    }
                    if mode == BLACKHOLE {
                        let mut client = client;
                        let mut sink = vec![0_u8; 4096];
                        while matches!(client.read(&mut sink).await, Ok(n) if n > 0) {}
                        // Never answered; held until the proxy cuts it.
                        return std::future::pending::<()>().await;
                    }
                    let Ok(server) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let up = async {
                        let mut buffer = vec![0_u8; 16384];
                        let mut tail = Vec::new();
                        loop {
                            let count = match client_read.read(&mut buffer).await {
                                Ok(0) | Err(_) => break,
                                Ok(count) => count,
                            };
                            tail.extend_from_slice(&buffer[..count]);
                            if tail
                                .to_ascii_lowercase()
                                .windows(10)
                                .any(|w| w == b"\nx-admin-")
                            {
                                admin_seen.store(true, Ordering::SeqCst);
                            }
                            let keep = tail.len().saturating_sub(16);
                            tail.drain(..keep);
                            if server_write.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                        let _ = server_write.shutdown().await;
                    };
                    let down = async {
                        let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
                        let _ = client_write.shutdown().await;
                    };
                    tokio::join!(up, down);
                });
                connections.lock().unwrap().push(connection);
            }
        });
        *self.serving.lock().unwrap() = Some(task);
    }

    /// The NA is stopped: connections are refused, open ones are cut.
    pub fn cut(&self) {
        if let Some(task) = self.serving.lock().unwrap().take() {
            task.abort();
        }
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    /// The NA answers every request `429 rate_limit_exceeded`.
    pub fn throttle(&self) {
        self.cut_connections();
        self.mode.store(THROTTLE, Ordering::SeqCst);
    }

    /// A reverse proxy whose upstream is stopped: every request gets its own
    /// `502` page (HTML, not the NA's JSON).
    pub fn bad_gateway(&self) {
        self.cut_connections();
        self.mode.store(GATEWAY, Ordering::SeqCst);
    }

    /// The network swallows every request: connections open, nothing answers.
    pub fn blackhole(&self) {
        self.cut_connections();
        self.mode.store(BLACKHOLE, Ordering::SeqCst);
    }

    /// Forward again (after `throttle` or `blackhole`).
    pub fn forward(&self) {
        self.cut_connections();
        self.mode.store(FORWARD, Ordering::SeqCst);
    }

    fn cut_connections(&self) {
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    /// The NA is back.
    pub async fn restore(&self) {
        let mut tries = 0;
        let listener = loop {
            match TcpListener::bind(self.address).await {
                Ok(listener) => break listener,
                Err(err) if tries < 50 => {
                    tries += 1;
                    let _ = err;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => panic!("cannot listen again on {}: {err}", self.address),
            }
        };
        self.serve(listener);
    }

    /// Whether any request carried an `X-Admin-` header.
    pub fn admin_headers_seen(&self) -> bool {
        self.admin_seen.load(Ordering::SeqCst)
    }
}

/// A throttling NA's answer, with its JSON error body.
const THROTTLED: (&str, &str) = (
    "429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 60",
    r#"{"error":{"code":"rate_limit_exceeded","message":"Rate limit exceeded"}}"#,
);

/// nginx's answer when its upstream is down: its own HTML page.
const BAD_GATEWAY: (&str, &str) = (
    "502 Bad Gateway\r\nServer: nginx\r\nContent-Type: text/html",
    "<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>",
);

/// Answer each request on a connection with `response`.
async fn refuse(mut client: TcpStream, (head, body): (&str, &str)) {
    let mut buffer = Vec::new();
    let mut chunk = vec![0_u8; 8192];
    loop {
        let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            continue;
        };
        let request = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
        let length: usize = request
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        while buffer.len() < end + 4 + length {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
        }
        buffer.drain(..end + 4 + length);
        let response = format!(
            "HTTP/1.1 {head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = client.write_all(response.as_bytes()).await;
        let _ = client.shutdown().await;
        return;
    }
}

fn support_token() -> (String, String) {
    token()
}

/// A loopback token and its digest.
pub fn token() -> (String, String) {
    let token = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
    let digest = Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    (token, digest)
}

/// A new directory under the system's temporary directory.
pub fn temporary(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The agent binary: `GM_EDGE_BINARY` (the static build) or this build's.
pub fn binary() -> String {
    std::env::var("GM_EDGE_BINARY")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_genesis-mesh-edge").to_owned())
}

/// The agent's command, under `GM_EDGE_WRAP` when set (e.g. `/usr/bin/time -v -o out`).
pub fn command(env: &[(String, String)], args: &[&str]) -> Command {
    let wrap: Vec<String> = std::env::var("GM_EDGE_WRAP")
        .map(|w| w.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let mut command = match wrap.split_first() {
        Some((program, rest)) => {
            let mut command = Command::new(program);
            command.args(rest).arg(binary());
            command
        }
        None => Command::new(binary()),
    };
    command.args(args).env_clear();
    command.env("PATH", std::env::var("PATH").unwrap_or_default());
    for (key, value) in env {
        command.env(key, value);
    }
    command
}

/// A running agent.
pub struct Agent {
    /// Its state directory.
    pub state_dir: PathBuf,
    /// Its environment.
    pub env: Vec<(String, String)>,
    /// Its loopback API and token, when it listens on TCP.
    pub api: Option<(String, String)>,
    /// Its socket, when it listens on one.
    pub socket: Option<PathBuf>,
    /// A second loopback token, of another client.
    pub other_token: String,
    child: Option<Child>,
    /// Started without the `GM_EDGE_WRAP` wrapper.
    direct: bool,
    log: PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A free loopback port.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Agent {
    /// The configuration for an agent talking to `na_url`, listening on a
    /// loopback port with a token, plus `extra` settings.
    pub fn new(na_url: &str, root_public_key: &str, extra: &[(&str, &str)]) -> Self {
        let state_dir = temporary("gm-edge-scenario");
        let (token, digest) = token();
        let (other_token, other_digest) = support_token();
        let listen = format!("127.0.0.1:{}", free_port());
        let mut env: Vec<(String, String)> = [
            ("GM_EDGE_NA_URL", na_url.to_owned()),
            ("GM_EDGE_ROOT_PUBLIC_KEY", root_public_key.to_owned()),
            (
                "GM_EDGE_STATE_DIR",
                state_dir.join("state").display().to_string(),
            ),
            ("GM_EDGE_LISTEN", format!("tcp://{listen}")),
            (
                "GM_EDGE_TOKENS",
                format!("scenario:{digest},other:{other_digest}"),
            ),
            ("GM_EDGE_HEARTBEAT_INTERVAL_SECONDS", "2".to_owned()),
            ("GM_EDGE_SYNC_INTERVAL_SECONDS", "5".to_owned()),
            ("GM_EDGE_RETRY_INTERVAL_SECONDS", "1".to_owned()),
            ("GM_EDGE_NA_TIMEOUT_SECONDS", "3".to_owned()),
            ("GM_EDGE_LOG_LEVEL", "debug".to_owned()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        for (key, value) in extra {
            env.retain(|(k, _)| k != key);
            env.push(((*key).to_owned(), (*value).to_owned()));
        }
        Self {
            log: state_dir.join("agent.log"),
            state_dir: state_dir.join("state"),
            env,
            api: Some((listen, token)),
            socket: None,
            other_token,
            child: None,
            direct: false,
        }
    }

    /// Run a one-shot command (`enroll`, `status`, ...): its exit code. It
    /// runs off the test's runtime, which serves the proxy meanwhile.
    pub async fn once(&self, args: &[&str], extra: &[(&str, &str)]) -> i32 {
        let mut env = self.env.clone();
        env.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            command(&env, &args)
                .stdout(Stdio::null())
                .stderr(log)
                .status()
                .expect("run the agent")
                .code()
                .unwrap_or(-1)
        })
        .await
        .unwrap()
    }

    /// Start `run`.
    pub fn start(&mut self) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let child = command(&self.env, &["run"])
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start the agent");
        self.child = Some(child);
    }

    /// Start `run` with at most `files` open file descriptors (`ulimit -n`).
    pub fn start_limited(&mut self, files: u32) {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                &format!("ulimit -n {files} && exec \"$0\" run"),
                &binary(),
            ])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default());
        for (key, value) in &self.env {
            command.env(key, value);
        }
        let child = command
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start the agent");
        self.child = Some(child);
        self.direct = true;
    }

    /// Whether the agent is still running.
    pub fn alive(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| child.try_wait().ok().flatten().is_none())
    }

    /// Stop it with SIGTERM and wait; its exit code. Under a wrapper the
    /// agent (the wrapper's child) gets the signal, and the wrapper exits
    /// with the agent's code.
    pub async fn stop(&mut self) -> Option<i32> {
        let mut child = self.child.take()?;
        let pid = child.id().to_string();
        if !self.direct && std::env::var("GM_EDGE_WRAP").is_ok_and(|w| !w.trim().is_empty()) {
            let _ = Command::new("pkill").args(["-TERM", "-P", &pid]).status();
        } else {
            let _ = Command::new("kill").args(["-TERM", &pid]).status();
        }
        tokio::task::spawn_blocking(move || child.wait().ok()?.code())
            .await
            .ok()?
    }

    /// The agent's log so far (for failures).
    pub fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Call the local API with the agent's token (or `token`).
    pub async fn call(&self, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
        let (address, token) = self.api.clone().expect("a loopback API");
        match try_tcp(&address, method, path, body, Some(&token)).await {
            Some(answer) => answer,
            None => panic!(
                "the agent did not answer {method} {path}:
{}",
                self.log()
            ),
        }
    }

    /// Call the local API with another client's token.
    pub async fn call_as_other(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> (u16, Value) {
        let (address, _) = self.api.clone().expect("a loopback API");
        match try_tcp(&address, method, path, body, Some(&self.other_token)).await {
            Some(answer) => answer,
            None => panic!("the agent did not answer {method} {path}:\n{}", self.log()),
        }
    }

    /// The loopback API's address.
    pub fn address(&self) -> String {
        self.api.clone().expect("a loopback API").0
    }

    /// `GET /v1/status`, waiting for the agent to listen.
    pub async fn status(&self) -> Value {
        for _ in 0..100 {
            let (address, token) = self.api.clone().expect("a loopback API");
            if let Some((200, body)) =
                try_tcp(&address, "GET", "/v1/status", None, Some(&token)).await
            {
                return body;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("the agent never answered /v1/status:\n{}", self.log());
    }

    /// Poll `/v1/status` until `done` holds, at most `limit`.
    pub async fn wait_for(&self, limit: Duration, done: impl Fn(&Value) -> bool) -> Value {
        let start = tokio::time::Instant::now();
        loop {
            let status = self.status().await;
            if done(&status) {
                return status;
            }
            if start.elapsed() > limit {
                panic!("timed out; last status {status}\n{}", self.log());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// `POST /v1/authorize`, and when allowed report `success`.
    pub async fn act(&self, request: Value) -> (u16, Value) {
        let (status, answer) = self.call("POST", "/v1/authorize", Some(&request)).await;
        if status == 200 && answer["allowed"] == true {
            let id = answer["authorization_id"].as_str().unwrap().to_owned();
            let (reported, outcome) = self
                .call(
                    "POST",
                    &format!("/v1/authorizations/{id}/outcome"),
                    Some(
                        &json!({"outcome": "success", "execution_parameters": {"version_id": id}}),
                    ),
                )
                .await;
            assert_eq!(reported, 200, "outcome refused: {outcome}\n{}", self.log());
            let mut answer = answer;
            answer["outcome"] = outcome;
            return (status, answer);
        }
        (status, answer)
    }
}

async fn exchange<S>(
    mut stream: S,
    method: &str,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Option<(u16, Value)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: agent\r\nConnection: close\r\n");
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok()?;
    let text = String::from_utf8_lossy(&response);
    let (head, rest) = text.split_once("\r\n\r\n")?;
    let status = head.split(' ').nth(1)?.parse().ok()?;
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let payload = if chunked {
        dechunk(rest)
    } else {
        rest.to_owned()
    };
    Some((
        status,
        serde_json::from_str(&payload).unwrap_or(Value::Null),
    ))
}

fn dechunk(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some((size, after)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if size == 0 || after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].trim_start_matches("\r\n");
    }
    out
}

async fn try_tcp(
    address: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Option<(u16, Value)> {
    let stream = TcpStream::connect(address).await.ok()?;
    exchange(stream, method, path, body, token).await
}

/// One request to a loopback API.
pub async fn call_tcp(
    address: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> (u16, Value) {
    try_tcp(address, method, path, body, token)
        .await
        .expect("the agent answered")
}

/// One request to a Unix socket API.
pub async fn call_unix(socket: &Path, method: &str, path: &str) -> Option<(u16, Value)> {
    let stream = UnixStream::connect(socket).await.ok()?;
    exchange(stream, method, path, None, None).await
}

/// Seconds the NA stays stopped: `GM_EDGE_OFFLINE_SECONDS`, 120 by default.
pub fn offline_seconds() -> u64 {
    std::env::var("GM_EDGE_OFFLINE_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120)
}

/// The state directory's files: only the agent's own (C2).
pub fn assert_only_agent_files(state_dir: &Path) {
    let mut names: Vec<String> = std::fs::read_dir(state_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let allowed = [
        "agent.lock",
        "agent.db",
        "agent.db-shm",
        "agent.db-wal",
        "enrollment.json",
        "executor.key",
        "node.key",
        "snapshot.json",
    ];
    for name in &names {
        assert!(
            allowed.contains(&name.as_str()),
            "unexpected file {name} in the state directory"
        );
    }
    for name in [
        "node.key",
        "executor.key",
        "enrollment.json",
        "snapshot.json",
        "agent.db",
    ] {
        assert!(
            names.iter().any(|n| n == name),
            "{name} missing from the state directory"
        );
    }
}
