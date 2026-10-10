use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, RETRY_AFTER};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    agreement::AgreementClient,
    attestation::AttestationClient,
    auth::{build_admin_headers, load_signing_key, AdminRequest},
    boundary::BoundaryClient,
    consensus::ConsensusClient,
    data_usage::DataUsageClient,
    disclosure::DisclosureClient,
    errors::{from_http_error, GenesisMeshError, Result},
    evidence::EvidenceClient,
    evidence_store::EvidenceStoreClient,
    health::HealthClient,
    outbox::{EvidenceOutbox, RecordOutbox},
    policy::PolicyClient,
};

/// Options used to construct a Genesis Mesh HTTP client.
#[derive(Clone)]
pub struct ClientOptions {
    /// Base URL of the Network Authority, for example `http://127.0.0.1:9443`.
    pub base_url: String,
    /// Base64-encoded raw Ed25519 seed. Required for admin routes.
    pub signing_key_base64: Option<String>,
    /// Admin key id registered with the Network Authority.
    pub key_id: Option<String>,
    /// Request timeout. Defaults to 10 seconds.
    pub timeout: Option<Duration>,
    /// The NA's public key, which admin signatures name as their audience
    /// (signature version 2). When `None` it is read once from `/sovereign.json`
    /// (`network_authority.public_key`).
    pub audience: Option<String>,
    /// Durable storage for signed execution records not yet admitted
    /// (v1.2.0), e.g. a [`FileOutbox`](crate::FileOutbox). With one,
    /// [`governed_action`](crate::governed_action) keeps every record until
    /// the NA admits it; see [`EvidenceStoreClient::flush_pending`].
    pub outbox: Option<Arc<dyn EvidenceOutbox>>,
    /// Durable storage for signed observations and break-glass records not
    /// yet admitted (v1.3.0), e.g. a [`FileRecordOutbox`](crate::FileRecordOutbox)
    /// in a directory of its own.
    /// [`governed_action_with_break_glass`](crate::governed_action_with_break_glass)
    /// needs one; see [`EvidenceStoreClient::flush_records`].
    pub record_outbox: Option<Arc<dyn RecordOutbox>>,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("base_url", &self.base_url)
            .field(
                "signing_key_base64",
                &self.signing_key_base64.as_ref().map(|_| "[REDACTED]"),
            )
            .field("key_id", &self.key_id)
            .field("timeout", &self.timeout)
            .field("audience", &self.audience)
            .field("outbox", &self.outbox)
            .field("record_outbox", &self.record_outbox)
            .finish()
    }
}

impl ClientOptions {
    /// Create options for a public-only client.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            signing_key_base64: None,
            key_id: None,
            timeout: None,
            audience: None,
            outbox: None,
            record_outbox: None,
        }
    }

    /// Keep signed evidence in `outbox` until the NA admits it (v1.2.0).
    pub fn with_outbox(mut self, outbox: Arc<dyn EvidenceOutbox>) -> Self {
        self.outbox = Some(outbox);
        self
    }

    /// Keep signed observations and break-glass records in `record_outbox`
    /// until the NA admits them (v1.3.0).
    pub fn with_record_outbox(mut self, record_outbox: Arc<dyn RecordOutbox>) -> Self {
        self.record_outbox = Some(record_outbox);
        self
    }

    /// Name the NA's public key for admin signatures instead of reading it
    /// (`network_authority.public_key`) from `/sovereign.json`.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Attach a base64 Ed25519 seed for admin routes.
    pub fn with_signing_key(mut self, signing_key_base64: impl Into<String>) -> Self {
        self.signing_key_base64 = Some(signing_key_base64.into());
        self
    }

    /// Override the admin key id. Defaults to `operator-local`.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Override the request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Shared HTTP transport for Genesis Mesh sub-clients.
#[derive(Debug)]
pub struct HttpTransport {
    base_url: String,
    http: reqwest::Client,
    signing_key: Option<SigningKey>,
    key_id: String,
    audience: std::sync::Mutex<Option<String>>,
}

impl HttpTransport {
    /// Construct a transport from client options.
    pub fn new(options: ClientOptions) -> Result<Self> {
        let base_url = reqwest::Url::parse(&options.base_url).map_err(|_| {
            GenesisMeshError::Configuration("base URL must be an absolute HTTP(S) URL".into())
        })?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(GenesisMeshError::Configuration(
                "base URL must use HTTP(S) without credentials, query, or fragment".into(),
            ));
        }
        let key_id = options
            .key_id
            .unwrap_or_else(|| "operator-local".to_owned());
        if key_id.is_empty()
            || !key_id.is_ascii()
            || key_id.trim() != key_id
            || HeaderValue::from_str(&key_id).is_err()
        {
            return Err(GenesisMeshError::Configuration(
                "key id must be a nonempty ASCII HTTP header value without surrounding whitespace"
                    .into(),
            ));
        }
        let timeout = options.timeout.unwrap_or_else(|| Duration::from_secs(10));
        if timeout.is_zero() {
            return Err(GenesisMeshError::Configuration(
                "timeout must be greater than zero".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("genesis-mesh-sdk/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let signing_key = options
            .signing_key_base64
            .as_deref()
            .map(load_signing_key)
            .transpose()?;

        Ok(Self {
            base_url: base_url.as_str().trim_end_matches('/').to_owned(),
            http,
            signing_key,
            key_id,
            audience: std::sync::Mutex::new(options.audience),
        })
    }

    /// The NA's public key for admin signatures, read once from `/sovereign.json`.
    async fn admin_audience(&self) -> Result<String> {
        if let Some(audience) = self.audience.lock().expect("audience lock").clone() {
            return Ok(audience);
        }
        // Fetched directly (not through `get`, which signs admin requests).
        let response = self.http.get(self.url("/sovereign.json")?).send().await?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(|e| unreadable(status, e))?;
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let public_key = body
            .pointer("/network_authority/public_key")
            .and_then(Value::as_str)
            .filter(|key| status == 200 && !key.is_empty())
            .ok_or_else(|| GenesisMeshError::Http {
                status,
                message: "could not read the NA public key from /sovereign.json".into(),
                code: "na_public_key_unavailable".into(),
            })?
            .to_owned();
        *self.audience.lock().expect("audience lock") = Some(public_key.clone());
        Ok(public_key)
    }

    async fn admin_headers(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: &Value,
    ) -> Result<HeaderMap> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(GenesisMeshError::MissingSigningKey)?;
        let audience = self.admin_audience().await?;
        // Segments are percent-encoded on the wire; the NA verifies the decoded path.
        let decoded = percent_encoding::percent_decode_str(path)
            .decode_utf8()
            .map_err(|_| GenesisMeshError::Configuration("route is not UTF-8".into()))?;
        let request = AdminRequest {
            method,
            path: &decoded,
            query,
            audience: &audience,
            body,
        };
        let admin_headers = build_admin_headers(&request, &self.key_id, signing_key)?;
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("X-Admin-Key-Id", &admin_headers.key_id),
            ("X-Admin-Signature", &admin_headers.signature),
            ("X-Admin-Timestamp", &admin_headers.timestamp),
            ("X-Admin-Nonce", &admin_headers.nonce),
        ] {
            headers.insert(
                name,
                HeaderValue::from_str(value)
                    .map_err(|err| GenesisMeshError::SigningKey(err.to_string()))?,
            );
        }
        Ok(headers)
    }

    /// POST an admin route with X-Admin-* authentication.
    pub async fn admin_post<T>(&self, path: &str, body: impl Serialize) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let body = serde_json::to_value(body)?;
        let headers = self.admin_headers("POST", path, &[], &body).await?;
        self.post(path, body, headers).await
    }

    /// GET an admin route with X-Admin-* authentication (the signature
    /// covers an empty body `{}`) and optional query parameters.
    pub async fn admin_get<T>(&self, path: &str, query: &[(String, String)]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.get(path, query, true).await?;
        self.parse(response).await
    }

    /// GET an admin route that answers with text (e.g. JSON Lines export).
    pub async fn admin_get_text(&self, path: &str, query: &[(String, String)]) -> Result<String> {
        let response = self.get(path, query, true).await?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| unreadable(status.as_u16(), e))?;
        if !status.is_success() {
            return Err(error_from_body(status.as_u16(), &bytes));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| GenesisMeshError::Verification("response is not UTF-8 text".into()))
    }

    /// GET a public route and return the status with the JSON body, without
    /// mapping error statuses (e.g. a not-ready `/readyz`).
    pub async fn public_get_status(&self, path: &str) -> Result<(u16, Value)> {
        let response = self.get(path, &[], false).await?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(|e| unreadable(status, e))?;
        let body = if bytes.is_empty() {
            json!({})
        } else {
            crate::strict_json::parse_strict_json_bytes(&bytes)?
        };
        Ok((status, body))
    }

    async fn get(
        &self,
        path: &str,
        query: &[(String, String)],
        admin: bool,
    ) -> Result<reqwest::Response> {
        let mut url = reqwest::Url::parse(&self.url(path)?)
            .map_err(|_| GenesisMeshError::Configuration("invalid route".into()))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut request = self.http.get(url);
        if admin {
            request = request.headers(self.admin_headers("GET", path, query, &json!({})).await?);
        }
        Ok(request.send().await?)
    }

    /// POST a public route without admin authentication.
    pub async fn public_post<T>(&self, path: &str, body: impl Serialize) -> Result<T>
    where
        T: DeserializeOwned,
    {
        self.post(path, serde_json::to_value(body)?, HeaderMap::new())
            .await
    }

    /// GET a public route without admin authentication.
    pub async fn public_get<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.get(path, &[], false).await?;
        self.parse(response).await
    }

    /// [`public_post`](Self::public_post), with how long the NA asked the
    /// caller to wait (`Retry-After`) when it refused the request (1.3.1).
    pub(crate) async fn public_post_waiting<T>(
        &self,
        path: &str,
        body: impl Serialize,
    ) -> (Result<T>, Option<Duration>)
    where
        T: DeserializeOwned,
    {
        let sent = match serde_json::to_value(body) {
            Ok(body) => self.send_post(path, body, HeaderMap::new()).await,
            Err(err) => Err(err.into()),
        };
        let response = match sent {
            Ok(response) => response,
            Err(err) => return (Err(err), None),
        };
        let wait = retry_after(response.headers(), Utc::now());
        match self.parse(response).await {
            Ok(value) => (Ok(value), None),
            Err(err) => (Err(err), wait),
        }
    }

    async fn send_post(
        &self,
        path: &str,
        body: Value,
        extra_headers: HeaderMap,
    ) -> Result<reqwest::Response> {
        Ok(self
            .http
            .post(self.url(path)?)
            .header(CONTENT_TYPE, "application/json")
            .headers(extra_headers)
            .json(&body)
            .send()
            .await?)
    }

    async fn post<T>(&self, path: &str, body: Value, extra_headers: HeaderMap) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send_post(path, body, extra_headers).await?;
        self.parse(response).await
    }

    async fn parse<T>(&self, response: reqwest::Response) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| unreadable(status.as_u16(), e))?;
        if !status.is_success() {
            return Err(error_from_body(status.as_u16(), &bytes));
        }
        // Deserialize directly into the caller's type instead of building an
        // intermediate JSON tree for every successful response.
        if bytes.is_empty() {
            Ok(serde_json::from_slice(b"{}")?)
        } else {
            // v1.2.0: refuse JSON every implementation would not read alike.
            let text = std::str::from_utf8(&bytes).map_err(|_| GenesisMeshError::StrictJson {
                reason: "invalid_json".into(),
                detail: "text that is not UTF-8".into(),
            })?;
            crate::strict_json::check_strict_json(text)?;
            Ok(serde_json::from_slice(&bytes)?)
        }
    }

    fn url(&self, path: &str) -> Result<String> {
        if !path.starts_with('/') || path.starts_with("//") || path.contains(['#', '\\']) {
            return Err(GenesisMeshError::Configuration(
                "route must start with a single slash and contain no fragment or backslash".into(),
            ));
        }
        Ok(format!("{}{}", self.base_url, path))
    }
}

/// How long a response asks the caller to wait before trying again
/// (`Retry-After`, 1.3.1): delay seconds or an HTTP date; `None` when it says
/// nothing usable.
pub(crate) fn retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let at = DateTime::parse_from_rfc2822(value).ok()?;
    Some((at.with_timezone(&Utc) - now).to_std().unwrap_or_default())
}

/// A response whose body could not be read (v1.3.0): the NA answered, so this
/// is not a request that never arrived.
fn unreadable(status: u16, source: reqwest::Error) -> GenesisMeshError {
    GenesisMeshError::ResponseBodyUnreadable { status, source }
}

fn error_from_body(status: u16, bytes: &[u8]) -> GenesisMeshError {
    let body = serde_json::from_slice::<Value>(bytes)
        .unwrap_or_else(|_| json!({"message": String::from_utf8_lossy(bytes), "code": "unknown"}));
    from_http_error(status, &body)
}

/// One path segment for an identifier, percent-encoded once. Empty, `.`,
/// `..` and control characters are refused: URL parsers resolve dot
/// segments, which would send the request to another route.
pub(crate) fn segment(id: &str) -> Result<String> {
    if id.is_empty() || id == "." || id == ".." || id.chars().any(char::is_control) {
        return Err(GenesisMeshError::Configuration(
            "identifier must be a nonempty path segment without control characters".into(),
        ));
    }
    Ok(percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC).to_string())
}

/// A resource identifier such as `kv:vault/secret` as path segments, each
/// encoded once, for the NA's `<path:resource_id>` routes.
pub(crate) fn resource_path(resource_id: &str) -> Result<String> {
    let segments: Result<Vec<String>> = resource_id.split('/').map(segment).collect();
    Ok(segments?.join("/"))
}

/// Query pairs from a JSON object of parameters; nulls are omitted.
pub(crate) fn query_pairs(params: &Value) -> Result<Vec<(String, String)>> {
    let Some(map) = params.as_object() else {
        return Err(GenesisMeshError::Configuration(
            "query parameters must be a JSON object".into(),
        ));
    };
    let mut pairs = Vec::new();
    for (key, value) in map {
        let text = match value {
            Value::Null => continue,
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => {
                return Err(GenesisMeshError::Configuration(format!(
                    "query parameter {key} must be a string, number or boolean"
                )))
            }
        };
        pairs.push((key.clone(), text));
    }
    Ok(pairs)
}

/// Entry point for the Genesis Mesh Rust SDK.
#[derive(Debug, Clone)]
pub struct GenesisMeshClient {
    /// Agreement lifecycle: offer, counter, accept, verify.
    pub agreement: AgreementClient,
    /// Membership attestations: issue, revoke, recognition policy.
    pub attestation: AttestationClient,
    /// Capability boundary decisions: decide, evaluate, verify.
    pub boundary: BoundaryClient,
    /// Consensus voting and proofs: vote, proof, verify.
    pub consensus: ConsensusClient,
    /// Data usage licensing: policy, intent, verify.
    pub data_usage: DataUsageClient,
    /// Selective capability disclosure: commit, nullifier, prove, verify.
    pub disclosure: DisclosureClient,
    /// Trust evidence: build, verify.
    pub evidence: EvidenceClient,
    /// Execution evidence store: submission, search, history, export,
    /// executor keys, retention and resource heads; observations,
    /// break-glass records and their judgements (v1.3.0).
    pub evidence_store: EvidenceStoreClient,
    /// Liveness, readiness and health.
    pub health: HealthClient,
    /// Boundary policy lifecycle: validate, publish, activate, history, verify.
    pub policy: PolicyClient,
}

impl GenesisMeshClient {
    /// Construct a client from options.
    pub fn new(options: ClientOptions) -> Result<Self> {
        let outbox = options.outbox.clone();
        let record_outbox = options.record_outbox.clone();
        let transport = Arc::new(HttpTransport::new(options)?);

        Ok(Self {
            agreement: AgreementClient::new(Arc::clone(&transport)),
            attestation: AttestationClient::new(Arc::clone(&transport)),
            boundary: BoundaryClient::new(Arc::clone(&transport)),
            consensus: ConsensusClient::new(Arc::clone(&transport)),
            data_usage: DataUsageClient::new(Arc::clone(&transport)),
            disclosure: DisclosureClient::new(Arc::clone(&transport)),
            evidence: EvidenceClient::new(Arc::clone(&transport)),
            evidence_store: EvidenceStoreClient::new(Arc::clone(&transport), outbox, record_outbox),
            health: HealthClient::new(Arc::clone(&transport)),
            policy: PolicyClient::new(transport),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_retry_after_as_seconds_or_a_date() {
        let now = DateTime::parse_from_rfc3339("2026-10-10T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let wait = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            retry_after(&headers, now)
        };
        assert_eq!(wait("60"), Some(Duration::from_secs(60)));
        assert_eq!(wait(" 0 "), Some(Duration::ZERO));
        assert_eq!(
            wait("Sat, 10 Oct 2026 12:02:00 GMT"),
            Some(Duration::from_secs(120))
        );
        // A date already past asks for no wait.
        assert_eq!(wait("Sat, 10 Oct 2026 11:00:00 GMT"), Some(Duration::ZERO));
        assert_eq!(wait("soon"), None);
        assert_eq!(wait("-5"), None);
        assert_eq!(retry_after(&HeaderMap::new(), now), None);
    }
}
