//! Configuration (docs/edge.md, "Configuration"): a TOML file, then the
//! environment over it, then the defaults. Validation failures exit 2.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;

/// The default configuration file.
pub const DEFAULT_CONFIG: &str = "/etc/genesis-mesh-edge/edge.toml";

/// A configuration problem: the agent exits 2.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn bad(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    authority: FileAuthority,
    #[serde(default)]
    node: FileNode,
    #[serde(default)]
    snapshot: FileSnapshot,
    #[serde(default)]
    decisions: FileDecisions,
    #[serde(default)]
    local_api: FileLocalApi,
    #[serde(default)]
    log: FileLog,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAuthority {
    url: Option<String>,
    root_public_key: Option<String>,
    timeout_seconds: Option<u64>,
    allow_insecure_http: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileNode {
    state_dir: Option<PathBuf>,
    validity_hours: Option<u32>,
    heartbeat_interval_seconds: Option<u64>,
    renew_before_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSnapshot {
    sync_interval_seconds: Option<u64>,
    retry_interval_seconds: Option<u64>,
    max_snapshot_age_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDecisions {
    attestation_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLocalApi {
    listen: Option<String>,
    allowed_uids: Option<Vec<u32>>,
    allowed_gids: Option<Vec<u32>>,
    socket_mode: Option<SocketMode>,
    socket_group: Option<String>,
    tokens: Option<Vec<TokenEntry>>,
    report_timeout_seconds: Option<u64>,
    queue_timeout_seconds: Option<u64>,
    rate_limit_per_minute: Option<u32>,
}

/// `socket_mode` as an octal string (`"0660"`) or a number.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SocketMode {
    Text(String),
    Number(u32),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLog {
    level: Option<String>,
}

/// A loopback client token: its name and the SHA-256 of the token (hex).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEntry {
    /// Who holds it (logged).
    pub name: String,
    /// `sha256(token)`, lowercase hex.
    pub sha256: String,
}

/// Where the local API listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listen {
    /// A Unix socket, authenticated by the peer's credentials.
    Unix(PathBuf),
    /// A loopback TCP port, authenticated by a bearer token.
    Tcp(SocketAddr),
}

/// Log levels, least verbose last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Everything.
    Debug,
    /// What the agent did.
    Info,
    /// What went wrong but was handled.
    Warn,
    /// Failures.
    Error,
}

impl Level {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    /// Its name in a log line.
    pub fn name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// The agent's configuration, validated.
#[derive(Debug, Clone)]
pub struct Config {
    /// The NA's base URL.
    pub na_url: String,
    /// The root public key the NA's key history is verified from.
    pub root_public_key: String,
    /// Request timeout towards the NA.
    pub na_timeout: Duration,
    /// Plain HTTP to a host that is not loopback was allowed.
    pub allow_insecure_http: bool,
    /// The state directory.
    pub state_dir: PathBuf,
    /// The certificate validity asked for at join and renewal.
    pub validity_hours: u32,
    /// Between heartbeats.
    pub heartbeat_interval: Duration,
    /// Renew when the certificate expires sooner than this.
    pub renew_before: Duration,
    /// Between syncs while connected.
    pub sync_interval: Duration,
    /// The first retry while offline (doubling, at most 60 s).
    pub retry_interval: Duration,
    /// The oldest snapshot grants may be used under.
    pub max_snapshot_age: Duration,
    /// The attestation decisions are asked under, when pinned.
    pub attestation_id: Option<String>,
    /// Where the local API listens.
    pub listen: Listen,
    /// Unix socket peers allowed by uid.
    pub allowed_uids: Vec<u32>,
    /// Unix socket peers allowed by gid.
    pub allowed_gids: Vec<u32>,
    /// The socket's mode.
    pub socket_mode: u32,
    /// The socket's group, when set.
    pub socket_group: Option<String>,
    /// Loopback tokens.
    pub tokens: Vec<TokenEntry>,
    /// How long an allowed action may take to report its outcome.
    pub report_timeout: Duration,
    /// How long a request waits for the open authorization to finish.
    pub queue_timeout: Duration,
    /// Authorizations per minute per local client (uid or token name).
    pub rate_limit_per_minute: u32,
    /// The least severe level logged.
    pub log_level: Level,
}

/// Where a value came from, for `check-config`.
type Env = BTreeMap<String, String>;

fn env_of(env: &Env, key: &str) -> Option<String> {
    env.get(key).filter(|v| !v.is_empty()).cloned()
}

fn number<T: std::str::FromStr>(env: &Env, key: &str) -> Result<Option<T>, ConfigError> {
    env_of(env, key)
        .map(|v| {
            v.trim()
                .parse::<T>()
                .map_err(|_| bad(format!("{key} must be a number")))
        })
        .transpose()
}

fn flag(env: &Env, key: &str) -> Result<Option<bool>, ConfigError> {
    env_of(env, key)
        .map(|v| match v.trim() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(bad(format!("{key} must be true or false"))),
        })
        .transpose()
}

fn ids(env: &Env, key: &str) -> Result<Option<Vec<u32>>, ConfigError> {
    env_of(env, key)
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<u32>()
                        .map_err(|_| bad(format!("{key} must be a comma list of numbers")))
                })
                .collect()
        })
        .transpose()
}

fn mode(text: &str) -> Result<u32, ConfigError> {
    u32::from_str_radix(text.trim().trim_start_matches("0o"), 8)
        .ok()
        .filter(|m| *m <= 0o777)
        .ok_or_else(|| bad("socket_mode must be an octal mode such as 0660"))
}

/// The tokens of `GM_EDGE_TOKENS`: `name:hex,...`.
fn tokens_of(text: &str) -> Result<Vec<TokenEntry>, ConfigError> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|item| {
            let (name, sha256) = item
                .split_once(':')
                .ok_or_else(|| bad("GM_EDGE_TOKENS is a comma list of name:sha256"))?;
            Ok(TokenEntry {
                name: name.trim().to_owned(),
                sha256: sha256.trim().to_owned(),
            })
        })
        .collect()
}

fn loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Whether a URL is plain `http://` to a host that is not loopback.
pub fn insecure_remote(url: &str) -> bool {
    matches!(url_host(url), Some(("http", host)) if !loopback_host(host))
}

/// The host of an `http://` or `https://` URL, or `None`.
fn url_host(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        &authority[..end + 2]
    } else {
        authority.split(':').next()?
    };
    Some((scheme, host))
}

fn listen_of(text: &str) -> Result<Listen, ConfigError> {
    if let Some(path) = text.strip_prefix("unix:") {
        if !path.starts_with('/') {
            return Err(bad("local_api.listen unix: needs an absolute path"));
        }
        return Ok(Listen::Unix(PathBuf::from(path)));
    }
    if let Some(address) = text.strip_prefix("tcp://") {
        let address: SocketAddr = address
            .parse()
            .map_err(|_| bad("local_api.listen tcp:// needs an address and a port"))?;
        return Ok(Listen::Tcp(address));
    }
    Err(bad(
        "local_api.listen is unix:/path or tcp://127.0.0.1:port",
    ))
}

impl Config {
    /// Read the configuration: `path` (or `GM_EDGE_CONFIG`, or the default
    /// when it exists), then the environment, then the defaults.
    pub fn load(path: Option<&Path>, env: &Env) -> Result<Self, ConfigError> {
        let explicit = path
            .map(Path::to_path_buf)
            .or_else(|| env_of(env, "GM_EDGE_CONFIG").map(PathBuf::from));
        let file = match &explicit {
            Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
                bad(format!(
                    "cannot read the configuration {}: {e}",
                    path.display()
                ))
            })?),
            None => std::fs::read_to_string(DEFAULT_CONFIG).ok(),
        };
        let parsed: FileConfig = match file {
            Some(text) => toml::from_str(&text)
                .map_err(|e| bad(format!("the configuration file does not parse: {e}")))?,
            None => FileConfig::default(),
        };
        Self::build(parsed, env)
    }

    /// From TOML text and an environment (tests).
    #[cfg(test)]
    pub fn from_parts(toml_text: &str, env: &Env) -> Result<Self, ConfigError> {
        let parsed: FileConfig = toml::from_str(toml_text)
            .map_err(|e| bad(format!("the configuration file does not parse: {e}")))?;
        Self::build(parsed, env)
    }

    fn build(file: FileConfig, env: &Env) -> Result<Self, ConfigError> {
        let na_url = env_of(env, "GM_EDGE_NA_URL")
            .or(file.authority.url)
            .ok_or_else(|| bad("authority.url (GM_EDGE_NA_URL) is required"))?;
        let na_url = na_url.trim_end_matches('/').to_owned();
        let root_public_key = env_of(env, "GM_EDGE_ROOT_PUBLIC_KEY")
            .or(file.authority.root_public_key)
            .ok_or_else(|| {
                bad("authority.root_public_key (GM_EDGE_ROOT_PUBLIC_KEY) is required")
            })?;
        let allow_insecure_http = flag(env, "GM_EDGE_ALLOW_INSECURE_HTTP")?
            .or(file.authority.allow_insecure_http)
            .unwrap_or(false);
        match url_host(&na_url) {
            Some(("https", _)) => {}
            Some(("http", host)) if loopback_host(host) || allow_insecure_http => {}
            Some(("http", _)) => {
                return Err(bad(
                    "authority.url is plain http to a host that is not loopback: use https, or set authority.allow_insecure_http",
                ))
            }
            _ => return Err(bad("authority.url must be an http(s) URL")),
        }
        let seconds =
            |value: Option<u64>, default: u64| Duration::from_secs(value.unwrap_or(default));
        let na_timeout = seconds(
            number(env, "GM_EDGE_NA_TIMEOUT_SECONDS")?.or(file.authority.timeout_seconds),
            5,
        );
        let validity_hours = number(env, "GM_EDGE_VALIDITY_HOURS")?
            .or(file.node.validity_hours)
            .unwrap_or(168);
        let heartbeat_interval = seconds(
            number(env, "GM_EDGE_HEARTBEAT_INTERVAL_SECONDS")?
                .or(file.node.heartbeat_interval_seconds),
            30,
        );
        let renew_before = seconds(
            number(env, "GM_EDGE_RENEW_BEFORE_SECONDS")?.or(file.node.renew_before_seconds),
            86400,
        );
        let sync_interval = seconds(
            number(env, "GM_EDGE_SYNC_INTERVAL_SECONDS")?.or(file.snapshot.sync_interval_seconds),
            60,
        );
        let retry_interval = seconds(
            number(env, "GM_EDGE_RETRY_INTERVAL_SECONDS")?.or(file.snapshot.retry_interval_seconds),
            15,
        );
        let max_snapshot_age = seconds(
            number(env, "GM_EDGE_MAX_SNAPSHOT_AGE_SECONDS")?
                .or(file.snapshot.max_snapshot_age_seconds),
            86400,
        );
        if !(60..=604_800).contains(&max_snapshot_age.as_secs()) {
            return Err(bad(
                "snapshot.max_snapshot_age_seconds must be 60 to 604800",
            ));
        }
        // Upper bounds keep every time computed from these within range.
        for (name, value, most) in [
            ("authority.timeout_seconds", na_timeout, 300),
            ("node.heartbeat_interval_seconds", heartbeat_interval, 3600),
            ("node.renew_before_seconds", renew_before, 30 * 86400),
            ("snapshot.sync_interval_seconds", sync_interval, 86400),
            ("snapshot.retry_interval_seconds", retry_interval, 3600),
        ] {
            if value.is_zero() && name != "node.renew_before_seconds" {
                return Err(bad(format!("{name} must be greater than zero")));
            }
            if value.as_secs() > most {
                return Err(bad(format!("{name} must be at most {most}")));
            }
        }
        if !(1..=8760).contains(&validity_hours) {
            return Err(bad("node.validity_hours must be 1 to 8760"));
        }
        let state_dir = env_of(env, "GM_EDGE_STATE_DIR")
            .map(PathBuf::from)
            .or(file.node.state_dir)
            .unwrap_or_else(|| PathBuf::from("/var/lib/genesis-mesh-edge"));
        let attestation_id =
            env_of(env, "GM_EDGE_ATTESTATION_ID").or(file.decisions.attestation_id);
        let listen = listen_of(
            &env_of(env, "GM_EDGE_LISTEN")
                .or(file.local_api.listen)
                .unwrap_or_else(|| "unix:/run/genesis-mesh-edge/agent.sock".into()),
        )?;
        let allowed_uids = ids(env, "GM_EDGE_ALLOWED_UIDS")?
            .or(file.local_api.allowed_uids)
            .unwrap_or_default();
        let allowed_gids = ids(env, "GM_EDGE_ALLOWED_GIDS")?
            .or(file.local_api.allowed_gids)
            .unwrap_or_default();
        let socket_mode = match env_of(env, "GM_EDGE_SOCKET_MODE") {
            Some(text) => mode(&text)?,
            None => match file.local_api.socket_mode {
                Some(SocketMode::Text(text)) => mode(&text)?,
                Some(SocketMode::Number(number)) => mode(&number.to_string())?,
                None => 0o660,
            },
        };
        let socket_group = env_of(env, "GM_EDGE_SOCKET_GROUP").or(file.local_api.socket_group);
        let tokens = match env_of(env, "GM_EDGE_TOKENS") {
            Some(text) => tokens_of(&text)?,
            None => file.local_api.tokens.unwrap_or_default(),
        };
        for token in &tokens {
            let hex = token.sha256.len() == 64
                && token
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if token.name.is_empty() || !hex {
                return Err(bad(
                    "each local_api token needs a name and the lowercase hex SHA-256 of the token",
                ));
            }
        }
        match &listen {
            Listen::Unix(_) if allowed_uids.is_empty() && allowed_gids.is_empty() => {
                return Err(bad(
                    "local_api.allowed_uids and allowed_gids are both empty: no local client could use the socket",
                ))
            }
            Listen::Tcp(address) if !address.ip().is_loopback() => {
                return Err(bad("local_api.listen tcp:// must be a loopback address"))
            }
            Listen::Tcp(_) if tokens.is_empty() => {
                return Err(bad("local_api.listen tcp:// needs at least one token"))
            }
            _ => {}
        }
        let report_timeout = seconds(
            number(env, "GM_EDGE_REPORT_TIMEOUT_SECONDS")?
                .or(file.local_api.report_timeout_seconds),
            300,
        );
        let queue_timeout = seconds(
            number(env, "GM_EDGE_QUEUE_TIMEOUT_SECONDS")?.or(file.local_api.queue_timeout_seconds),
            30,
        );
        let rate_limit_per_minute = number(env, "GM_EDGE_RATE_LIMIT_PER_MINUTE")?
            .or(file.local_api.rate_limit_per_minute)
            .unwrap_or(30);
        if !(1..=100_000).contains(&rate_limit_per_minute) {
            return Err(bad("local_api.rate_limit_per_minute must be 1 to 100000"));
        }
        if report_timeout.is_zero() || report_timeout.as_secs() > 86400 {
            return Err(bad("local_api.report_timeout_seconds must be 1 to 86400"));
        }
        if queue_timeout.as_secs() > 3600 {
            return Err(bad("local_api.queue_timeout_seconds must be at most 3600"));
        }
        let level = env_of(env, "GM_EDGE_LOG_LEVEL")
            .or(file.log.level)
            .unwrap_or_else(|| "info".into());
        let log_level =
            Level::parse(&level).ok_or_else(|| bad("log.level is debug, info, warn or error"))?;
        Ok(Self {
            na_url,
            root_public_key,
            na_timeout,
            allow_insecure_http,
            state_dir,
            validity_hours,
            heartbeat_interval,
            renew_before,
            sync_interval,
            retry_interval,
            max_snapshot_age,
            attestation_id,
            listen,
            allowed_uids,
            allowed_gids,
            socket_mode,
            socket_group,
            tokens,
            report_timeout,
            queue_timeout,
            rate_limit_per_minute,
            log_level,
        })
    }

    /// The effective configuration, without secrets (`check-config`).
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "authority": {
                "url": self.na_url,
                "root_public_key": self.root_public_key,
                "timeout_seconds": self.na_timeout.as_secs(),
                "allow_insecure_http": self.allow_insecure_http,
            },
            "node": {
                "state_dir": self.state_dir.display().to_string(),
                "validity_hours": self.validity_hours,
                "heartbeat_interval_seconds": self.heartbeat_interval.as_secs(),
                "renew_before_seconds": self.renew_before.as_secs(),
            },
            "snapshot": {
                "sync_interval_seconds": self.sync_interval.as_secs(),
                "retry_interval_seconds": self.retry_interval.as_secs(),
                "max_snapshot_age_seconds": self.max_snapshot_age.as_secs(),
            },
            "decisions": {"attestation_id": self.attestation_id},
            "local_api": {
                "listen": match &self.listen {
                    Listen::Unix(path) => format!("unix:{}", path.display()),
                    Listen::Tcp(address) => format!("tcp://{address}"),
                },
                "allowed_uids": self.allowed_uids,
                "allowed_gids": self.allowed_gids,
                "socket_mode": format!("{:04o}", self.socket_mode),
                "socket_group": self.socket_group,
                "tokens": self.tokens.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
                "report_timeout_seconds": self.report_timeout.as_secs(),
                "queue_timeout_seconds": self.queue_timeout.as_secs(),
                "rate_limit_per_minute": self.rate_limit_per_minute,
            },
            "log": {"level": self.log_level.name()},
        })
    }
}

/// The process environment.
pub fn process_env() -> Env {
    std::env::vars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    const BASE: &str = r#"
[authority]
url = "https://na.example"
root_public_key = "ROOT"
[local_api]
allowed_uids = [1000]
"#;

    #[test]
    fn reads_the_file_then_the_environment_then_the_defaults() {
        let config = Config::from_parts(BASE, &env(&[("GM_EDGE_VALIDITY_HOURS", "24")])).unwrap();
        assert_eq!(config.na_url, "https://na.example");
        assert_eq!(config.validity_hours, 24);
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.socket_mode, 0o660);
        assert_eq!(
            config.listen,
            Listen::Unix("/run/genesis-mesh-edge/agent.sock".into())
        );
        let config =
            Config::from_parts(BASE, &env(&[("GM_EDGE_NA_URL", "http://127.0.0.1:9443/")]))
                .unwrap();
        assert_eq!(config.na_url, "http://127.0.0.1:9443");
    }

    #[test]
    fn refuses_what_would_leave_the_agent_open_or_unreachable() {
        let refused =
            |text: &str, pairs: &[(&str, &str)]| Config::from_parts(text, &env(pairs)).is_err();
        // A socket no one may use.
        assert!(refused(
            "[authority]\nurl = \"https://na\"\nroot_public_key = \"R\"\n",
            &[]
        ));
        // TCP that is not loopback, or without a token.
        let hex = "a".repeat(64);
        let tokens = format!("ops:{hex}");
        assert!(refused(
            BASE,
            &[
                ("GM_EDGE_LISTEN", "tcp://0.0.0.0:7000"),
                ("GM_EDGE_TOKENS", &tokens)
            ]
        ));
        assert!(refused(BASE, &[("GM_EDGE_LISTEN", "tcp://127.0.0.1:7000")]));
        assert!(!refused(
            BASE,
            &[
                ("GM_EDGE_LISTEN", "tcp://127.0.0.1:7000"),
                ("GM_EDGE_TOKENS", &tokens)
            ]
        ));
        // Plain http to a remote host.
        assert!(refused(BASE, &[("GM_EDGE_NA_URL", "http://na.example")]));
        assert!(insecure_remote("http://na.example:9443"));
        assert!(!insecure_remote("http://127.0.0.1:9443"));
        assert!(!insecure_remote("http://[::1]:9443"));
        assert!(!insecure_remote("https://na.example"));
        assert!(!refused(
            BASE,
            &[
                ("GM_EDGE_NA_URL", "http://na.example"),
                ("GM_EDGE_ALLOW_INSECURE_HTTP", "true")
            ]
        ));
        // Out of range, unknown keys.
        assert!(refused(BASE, &[("GM_EDGE_MAX_SNAPSHOT_AGE_SECONDS", "59")]));
        assert!(refused(&format!("{BASE}\n[extra]\nx = 1\n"), &[]));
        assert!(refused(BASE, &[("GM_EDGE_SOCKET_MODE", "999")]));
        // Bounded durations: nothing computed from them can overflow.
        assert!(refused(
            BASE,
            &[("GM_EDGE_REPORT_TIMEOUT_SECONDS", "18446744073709551615")]
        ));
        assert!(refused(
            BASE,
            &[("GM_EDGE_REPORT_TIMEOUT_SECONDS", "86401")]
        ));
        assert!(refused(
            BASE,
            &[("GM_EDGE_HEARTBEAT_INTERVAL_SECONDS", "3601")]
        ));
        assert!(refused(BASE, &[("GM_EDGE_VALIDITY_HOURS", "0")]));
        assert!(refused(BASE, &[("GM_EDGE_RATE_LIMIT_PER_MINUTE", "0")]));
        assert!(refused(BASE, &[("GM_EDGE_TOKENS", "ops:short")]));
    }
}
