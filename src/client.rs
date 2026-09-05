use std::{sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    agreement::AgreementClient,
    attestation::AttestationClient,
    auth::{build_admin_headers, load_signing_key},
    boundary::BoundaryClient,
    consensus::ConsensusClient,
    data_usage::DataUsageClient,
    disclosure::DisclosureClient,
    errors::{from_http_error, GenesisMeshError, Result},
    evidence::EvidenceClient,
};

/// Options used to construct a Genesis Mesh HTTP client.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Base URL of the Network Authority, for example `http://127.0.0.1:9443`.
    pub base_url: String,
    /// Base64-encoded raw Ed25519 seed. Required for admin routes.
    pub signing_key_base64: Option<String>,
    /// Admin key id registered with the Network Authority.
    pub key_id: Option<String>,
    /// Request timeout. Defaults to 10 seconds.
    pub timeout: Option<Duration>,
}

impl ClientOptions {
    /// Create options for a public-only client.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            signing_key_base64: None,
            key_id: None,
            timeout: None,
        }
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
}

impl HttpTransport {
    /// Construct a transport from client options.
    pub fn new(options: ClientOptions) -> Result<Self> {
        let timeout = options.timeout.unwrap_or_else(|| Duration::from_secs(10));
        let http = reqwest::Client::builder().timeout(timeout).build()?;
        let signing_key = options
            .signing_key_base64
            .as_deref()
            .map(load_signing_key)
            .transpose()?;

        Ok(Self {
            base_url: options.base_url.trim_end_matches('/').to_owned(),
            http,
            signing_key,
            key_id: options
                .key_id
                .unwrap_or_else(|| "operator-local".to_owned()),
        })
    }

    /// POST an admin route with X-Admin-* authentication.
    pub async fn admin_post<T>(&self, path: &str, body: impl Serialize) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let body = serde_json::to_value(body)?;
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(GenesisMeshError::MissingSigningKey)?;
        let admin_headers = build_admin_headers(&body, &self.key_id, signing_key)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Admin-Key-Id",
            HeaderValue::from_str(&admin_headers.key_id)
                .map_err(|err| GenesisMeshError::SigningKey(err.to_string()))?,
        );
        headers.insert(
            "X-Admin-Signature",
            HeaderValue::from_str(&admin_headers.signature)
                .map_err(|err| GenesisMeshError::SigningKey(err.to_string()))?,
        );
        headers.insert(
            "X-Admin-Timestamp",
            HeaderValue::from_str(&admin_headers.timestamp)
                .map_err(|err| GenesisMeshError::SigningKey(err.to_string()))?,
        );
        headers.insert(
            "X-Admin-Nonce",
            HeaderValue::from_str(&admin_headers.nonce)
                .map_err(|err| GenesisMeshError::SigningKey(err.to_string()))?,
        );

        self.post(path, body, headers).await
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
        let response = self.http.get(self.url(path)).send().await?;
        self.parse(response).await
    }

    async fn post<T>(&self, path: &str, body: Value, extra_headers: HeaderMap) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self
            .http
            .post(self.url(path))
            .header(CONTENT_TYPE, "application/json")
            .headers(extra_headers)
            .json(&body)
            .send()
            .await?;
        self.parse(response).await
    }

    async fn parse<T>(&self, response: reqwest::Response) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let status = response.status();
        let bytes = response.bytes().await?;
        let body = if bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice::<Value>(&bytes)?
        };

        if !status.is_success() {
            return Err(from_http_error(status.as_u16(), &body));
        }

        Ok(serde_json::from_value(body)?)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Entry point for the Genesis Mesh Rust SDK.
#[derive(Debug, Clone)]
pub struct GenesisMeshClient {
    /// Agreement lifecycle: offer, counter, accept, verify.
    pub agreement: AgreementClient,
    /// Membership attestations: issue, revoke, recognition policy.
    pub attestation: AttestationClient,
    /// Capability boundary decisions: decide, verify.
    pub boundary: BoundaryClient,
    /// Consensus voting and proofs: vote, proof, verify.
    pub consensus: ConsensusClient,
    /// Data usage licensing: policy, intent, verify.
    pub data_usage: DataUsageClient,
    /// Selective capability disclosure: commit, nullifier, prove, verify.
    pub disclosure: DisclosureClient,
    /// Trust evidence: build, verify.
    pub evidence: EvidenceClient,
}

impl GenesisMeshClient {
    /// Construct a client from options.
    pub fn new(options: ClientOptions) -> Result<Self> {
        let transport = Arc::new(HttpTransport::new(options)?);

        Ok(Self {
            agreement: AgreementClient::new(Arc::clone(&transport)),
            attestation: AttestationClient::new(Arc::clone(&transport)),
            boundary: BoundaryClient::new(Arc::clone(&transport)),
            consensus: ConsensusClient::new(Arc::clone(&transport)),
            data_usage: DataUsageClient::new(Arc::clone(&transport)),
            disclosure: DisclosureClient::new(Arc::clone(&transport)),
            evidence: EvidenceClient::new(transport),
        })
    }
}
