//! A node's own routes (1.7.0, beta): `/join`, `/heartbeat`, `/renew`, and
//! the node-scoped routes an edge node calls with its node key instead of an
//! operator key (`/node/state`, `/node/boundary/evaluate`,
//! `/node/evidence/resource-head`). Every request is signed by the node key
//! ([`node_auth`](crate::node_auth)).

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::load_signing_key,
    errors::{GenesisMeshError, Result},
    execution::{ensure_metadata_only, ResourceHead},
    node_auth::{
        node_timestamp, sign_executor_proof, sign_node_request, PURPOSE_BOUNDARY_EVALUATE,
        PURPOSE_RESOURCE_HEAD, PURPOSE_STATE,
    },
    transport::HttpTransport,
};

/// An enrolled node's identity (1.7.0, beta): its certificate, its node key
/// and the NA it talks to (`audience`, the NA's public key). Debug output
/// never shows the key.
#[derive(Clone)]
pub struct NodeIdentity {
    cert_id: String,
    key: SigningKey,
    node_public_key: String,
    audience: String,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("cert_id", &self.cert_id)
            .field("node_public_key", &self.node_public_key)
            .field("audience", &self.audience)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl NodeIdentity {
    /// The node holding certificate `cert_id`, with its node key (a base64
    /// Ed25519 seed), talking to the NA whose public key is `audience`.
    pub fn new(
        cert_id: impl Into<String>,
        node_seed_b64: &str,
        audience: impl Into<String>,
    ) -> Result<Self> {
        let key = load_signing_key(node_seed_b64)?;
        let cert_id = cert_id.into();
        let audience = audience.into();
        if cert_id.is_empty() || audience.is_empty() {
            return Err(GenesisMeshError::Configuration(
                "a node identity needs a certificate ID and the NA's public key".into(),
            ));
        }
        Ok(Self {
            cert_id,
            node_public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            key,
            audience,
        })
    }

    /// The same node with a renewed certificate.
    pub fn with_cert_id(&self, cert_id: impl Into<String>) -> Self {
        Self {
            cert_id: cert_id.into(),
            ..self.clone()
        }
    }

    /// The certificate it signs with.
    pub fn cert_id(&self) -> &str {
        &self.cert_id
    }

    /// The node's public key (base64).
    pub fn node_public_key(&self) -> &str {
        &self.node_public_key
    }

    /// The NA's public key its node-scoped requests name.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// `fields` as a signed request of this node: its certificate and key,
    /// and for a node-scoped route its `purpose` and `audience`.
    fn sign(&self, purpose: Option<&str>, fields: Value) -> Result<Value> {
        let mut body = match fields {
            Value::Object(map) => Value::Object(map),
            _ => {
                return Err(GenesisMeshError::Configuration(
                    "a node request body must be a JSON object".into(),
                ))
            }
        };
        body["cert_id"] = json!(self.cert_id);
        body["node_public_key"] = json!(self.node_public_key);
        if let Some(purpose) = purpose {
            body["purpose"] = json!(purpose);
            body["audience"] = json!(self.audience);
        }
        sign_node_request(
            body,
            &self.key,
            &node_timestamp(Utc::now()),
            &Uuid::new_v4().to_string(),
        )
    }
}

/// A `/join` request (1.7.0, beta): the node key, the invite token and, for
/// an edge invite, the executor key the NA registers at join. Debug output
/// never shows the keys or the token.
#[derive(Clone)]
pub struct NodeJoin {
    node_key: SigningKey,
    invite_token: String,
    validity_hours: Option<u32>,
    executor_key: Option<SigningKey>,
    agent_version: Option<String>,
}

impl std::fmt::Debug for NodeJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeJoin")
            .field("invite_token", &"[REDACTED]")
            .field("validity_hours", &self.validity_hours)
            .field(
                "executor_key",
                &self.executor_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("agent_version", &self.agent_version)
            .finish()
    }
}

impl NodeJoin {
    /// Join with this node key (a base64 Ed25519 seed) and invite token.
    pub fn new(node_seed_b64: &str, invite_token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            node_key: load_signing_key(node_seed_b64)?,
            invite_token: invite_token.into(),
            validity_hours: None,
            executor_key: None,
            agent_version: None,
        })
    }

    /// Ask for a certificate valid this long (the invite caps it).
    pub fn with_validity_hours(mut self, hours: u32) -> Self {
        self.validity_hours = Some(hours);
        self
    }

    /// Register this executor key (a base64 Ed25519 seed) at join, as an
    /// edge invite requires; it co-signs the request.
    pub fn with_executor_key(mut self, executor_seed_b64: &str) -> Result<Self> {
        self.executor_key = Some(load_signing_key(executor_seed_b64)?);
        Ok(self)
    }

    /// Name the agent's version.
    pub fn with_agent_version(mut self, version: impl Into<String>) -> Self {
        self.agent_version = Some(version.into());
        self
    }

    /// The signed request body.
    pub fn body(&self) -> Result<Value> {
        let mut body = json!({
            "node_public_key": STANDARD.encode(self.node_key.verifying_key().to_bytes()),
            "invite_token": self.invite_token,
            "validity_hours": self.validity_hours.unwrap_or(168),
        });
        let timestamp = node_timestamp(Utc::now());
        let nonce = Uuid::new_v4().to_string();
        if let Some(executor) = &self.executor_key {
            body["executor_public_key"] =
                json!(STANDARD.encode(executor.verifying_key().to_bytes()));
            if let Some(version) = &self.agent_version {
                body["agent_version"] = json!(version);
            }
            body["timestamp"] = json!(timestamp);
            body["nonce"] = json!(nonce);
            body = sign_executor_proof(body, executor)?;
        }
        sign_node_request(body, &self.node_key, &timestamp, &nonce)
    }
}

/// A node's routes (1.7.0, beta), signed by its node key.
#[derive(Debug, Clone)]
pub struct NodeClient {
    http: Arc<HttpTransport>,
}

impl NodeClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// `POST /join`: the signed `JoinCertificate`; with an executor key, an
    /// NA from 1.7.0 adds an `edge` block naming the registered executor key.
    pub async fn join(&self, join: &NodeJoin) -> Result<Value> {
        self.http.public_post("/join", join.body()?).await
    }

    /// `POST /heartbeat` with `status` (`healthy` or `degraded` for an edge
    /// agent) and, from an edge agent, its `agent` block:
    /// `{ack, server_time}`.
    pub async fn heartbeat(
        &self,
        identity: &NodeIdentity,
        status: &str,
        agent: Option<Value>,
    ) -> Result<Value> {
        let mut fields = json!({ "status": status });
        if let Some(agent) = agent {
            fields["agent"] = agent;
        }
        self.http
            .public_post("/heartbeat", identity.sign(None, fields)?)
            .await
    }

    /// `POST /renew`: the new signed `JoinCertificate` (with the `edge`
    /// block for an edge node). Persist it before using it.
    pub async fn renew(&self, identity: &NodeIdentity, validity_hours: u32) -> Result<Value> {
        self.http
            .public_post(
                "/renew",
                identity.sign(None, json!({ "validity_hours": validity_hours }))?,
            )
            .await
    }

    /// `POST /node/state`: what the NA issued to this edge node,
    /// `{server_time, node, executor_key, attestations, grants}`.
    pub async fn state(&self, identity: &NodeIdentity) -> Result<Value> {
        self.http
            .public_post(
                "/node/state",
                identity.sign(Some(PURPOSE_STATE), json!({}))?,
            )
            .await
    }

    /// `POST /node/evidence/resource-head`: the head of a resource within
    /// the node's resource prefix, as the NA answers it, or `None` for a
    /// resource with no history.
    pub async fn resource_head_entry(
        &self,
        identity: &NodeIdentity,
        resource_id: &str,
    ) -> Result<Option<Value>> {
        let body = identity.sign(
            Some(PURPOSE_RESOURCE_HEAD),
            json!({ "resource_id": resource_id }),
        )?;
        match self
            .http
            .public_post::<Value>("/node/evidence/resource-head", body)
            .await
        {
            Ok(head) => Ok(Some(head)),
            Err(GenesisMeshError::NotFound { code, .. }) if code == "resource_not_found" => {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// [`resource_head_entry`](Self::resource_head_entry) as a
    /// [`ResourceHead`].
    pub async fn resource_head(
        &self,
        identity: &NodeIdentity,
        resource_id: &str,
    ) -> Result<Option<ResourceHead>> {
        self.resource_head_entry(identity, resource_id)
            .await?
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// `POST /node/boundary/evaluate`: the NA's signed decision on a request
    /// under an attestation issued to this node (`attestation_id`,
    /// `requested_capability`, `context`), `{decision, justification_proof}`.
    /// A denial is a signed decision, not an error.
    pub async fn evaluate(&self, identity: &NodeIdentity, params: Value) -> Result<Value> {
        if params.get("agreement").is_some_and(|a| !a.is_null()) {
            return Err(GenesisMeshError::Configuration(
                "a node evaluates under an attestation, never an agreement".into(),
            ));
        }
        if let Some(context) = params.get("context").filter(|c| !c.is_null()) {
            ensure_metadata_only(context, None)?;
        }
        self.http
            .public_post(
                "/node/boundary/evaluate",
                identity.sign(Some(PURPOSE_BOUNDARY_EVALUATE), params)?,
            )
            .await
    }
}
