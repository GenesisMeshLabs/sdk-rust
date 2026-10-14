//! The agent: its enrolment, the trust snapshot, the schedule (heartbeat,
//! renewal, sync) and the decision order for one authorization
//! (docs/edge.md, "Decision order").

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use genesis_mesh_sdk::{
    canonical::{parse_timestamp, python_timestamp},
    check_metadata_only, evaluation_failure, governed_action,
    grants::use_digest,
    json,
    key_history::verify_key_history,
    node_auth::executor_key_id,
    verify::{verify_attestation_signature, verify_crl, verify_join_certificate},
    without_refused_metadata, ActionError, ActionReport, BreakGlassInput, ClientOptions,
    EvaluationFailure, ExecutionRecorder, FlushOptions, GenesisMeshClient, GenesisMeshError,
    GovernedActionOutcome, GovernedActionParams, GovernedVerification, GrantActionOutcome,
    GrantAuthority, GrantHolder, GrantHolderState, GrantRequest, HttpTransport, NodeIdentity,
    NodeJoin, Value,
};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

use crate::{
    config::Config,
    db::{Db, SqliteOutbox, SqliteRecordOutbox},
    log,
    state::{StateDir, StateError, DATABASE, ENROLLMENT, EXECUTOR_KEY, NODE_KEY, SNAPSHOT},
};

/// How far the device's clock may be behind the NA's signing time.
const CLOCK_SKEW_SECONDS: i64 = 300;

/// The agent's version (the SDK's).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Why the agent stops, as its exit code.
#[derive(Debug)]
pub enum Exit {
    /// 1: an internal error.
    Internal(String),
    /// 2: usage or configuration.
    Usage(String),
    /// 3: not enrolled and no invite token.
    NotEnrolled(String),
    /// 4: the NA refused the enrolment for good.
    Refused(String),
    /// 5: the NA could not be reached during enrolment.
    Unreachable(String),
    /// 6: insecure permissions in the state directory.
    Insecure(String),
}

impl Exit {
    /// The process exit code.
    pub fn code(&self) -> u8 {
        match self {
            Self::Internal(_) => 1,
            Self::Usage(_) => 2,
            Self::NotEnrolled(_) => 3,
            Self::Refused(_) => 4,
            Self::Unreachable(_) => 5,
            Self::Insecure(_) => 6,
        }
    }

    /// What went wrong.
    pub fn message(&self) -> &str {
        match self {
            Self::Internal(m)
            | Self::Usage(m)
            | Self::NotEnrolled(m)
            | Self::Refused(m)
            | Self::Unreachable(m)
            | Self::Insecure(m) => m,
        }
    }
}

impl From<StateError> for Exit {
    fn from(err: StateError) -> Self {
        match err {
            StateError::Insecure(m) => Self::Insecure(m),
            StateError::Io(m) => Self::Internal(m),
        }
    }
}

fn internal(err: impl std::fmt::Display) -> Exit {
    Exit::Internal(err.to_string())
}

/// Where the agent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// No enrolment.
    Unenrolled,
    /// Enrolled, with a certificate in force.
    Active,
    /// The certificate has expired: no decisions; grants, break-glass and
    /// uploads still work.
    CertificateExpired,
    /// The NA revoked the node.
    Revoked,
}

impl AgentState {
    /// Its name in `/v1/status`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unenrolled => "unenrolled",
            Self::Active => "active",
            Self::CertificateExpired => "certificate_expired",
            Self::Revoked => "revoked",
        }
    }
}

/// What the agent knows about its NA and itself, shared by the schedule and
/// the local API.
struct Shared {
    enrollment: Option<Value>,
    client: Option<GenesisMeshClient>,
    identity: Option<NodeIdentity>,
    recorder: Option<ExecutionRecorder>,
    snapshot: Value,
    na_keys: Vec<String>,
    revoked: bool,
    last_contact: Option<DateTime<Utc>>,
}

/// The grant holders, one per grant, and the one an authorization holds.
#[derive(Default)]
struct Holders {
    map: BTreeMap<String, GrantHolder>,
    out: Option<String>,
}

/// The agent.
pub struct Agent {
    /// The configuration.
    pub config: Config,
    dir: StateDir,
    db: Db,
    shared: Mutex<Shared>,
    holders: tokio::sync::Mutex<Holders>,
    /// One authorization at a time; others queue FIFO.
    slot: Arc<Semaphore>,
    open: Mutex<HashMap<String, Open>>,
    lost: AtomicU64,
}

/// An authorization handed to the caller, waiting for its outcome.
struct Open {
    outcome: Option<oneshot::Sender<Outcome>>,
    task: tokio::task::JoinHandle<Finished>,
    link: Arc<Link>,
}

/// The outcome the caller reports.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// `success`, `failure` or `partial`.
    pub outcome: String,
    /// Identifiers and versions only.
    pub execution_parameters: Option<Value>,
    /// A short detail.
    pub outcome_detail: Option<String>,
}

/// One `/v1/authorize` request, checked.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    /// The capability.
    pub capability: String,
    /// The request's parameters (an object).
    pub request_parameters: Value,
    /// The resource, within the node's prefix.
    pub resource_id: String,
    /// `create`, `rotate`, `revoke`, `update` or `delete`.
    pub resource_action: String,
    /// The request's attributes (an object).
    pub attributes: Value,
    /// The attestation to evaluate under, one of the node's.
    pub attestation_id: Option<String>,
    /// Why the change cannot wait, for break-glass.
    pub justification: Option<String>,
}

/// What the action was allowed under, as `/v1/authorize` answers it.
#[derive(Debug, Clone, Default)]
struct Granted {
    authority: &'static str,
    code: Option<String>,
    decision_id: Option<String>,
    grant_id: Option<String>,
    use_sequence: Option<u64>,
}

/// Between the SDK's action closure and the local API.
struct Link {
    granted: Mutex<Option<oneshot::Sender<Granted>>>,
    outcome: Mutex<Option<oneshot::Receiver<Outcome>>>,
    report_timeout: Duration,
    expired: std::sync::atomic::AtomicBool,
}

/// How an authorization ended.
#[derive(Debug)]
enum Finished {
    /// The action ran and its record was signed.
    Ran {
        record_kind: &'static str,
        record_id: Option<String>,
        queued: bool,
        dropped: Vec<String>,
    },
    /// Not allowed: the code and its details.
    Refused { code: String, details: Value },
    /// Something failed.
    Failed(String),
}

/// A local API error: status, code, message.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status.
    pub status: u16,
    /// The code.
    pub code: &'static str,
    /// The message.
    pub message: String,
}

impl ApiError {
    /// An error.
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn micros(value: &Value) -> Option<i64> {
    value
        .as_str()
        .and_then(|s| parse_timestamp(s).ok())
        .map(|t| t.timestamp_micros())
}

fn timestamp(at: DateTime<Utc>) -> String {
    python_timestamp(at)
}

/// A failed request to the NA that names a revoked node.
fn revoked_code(err: &GenesisMeshError) -> bool {
    matches!(err.code(), "certificate_revoked" | "edge_node_retired")
}

impl Agent {
    /// Open the state directory and what it holds.
    pub fn load(config: Config) -> Result<Arc<Self>, Exit> {
        let dir = StateDir::open(&config.state_dir)?;
        let db = Db::open(&dir.path(DATABASE)).map_err(internal)?;
        let lost = db.lose_open_authorizations().map_err(internal)?;
        let agent = Arc::new(Self {
            slot: Arc::new(Semaphore::new(1)),
            config,
            dir,
            db,
            shared: Mutex::new(Shared {
                enrollment: None,
                client: None,
                identity: None,
                recorder: None,
                snapshot: json!({}),
                na_keys: Vec::new(),
                revoked: false,
                last_contact: None,
            }),
            holders: tokio::sync::Mutex::new(Holders::default()),
            open: Mutex::new(HashMap::new()),
            lost: AtomicU64::new(lost),
        });
        if let Some(enrollment) = agent.dir.read_json(ENROLLMENT)? {
            agent.adopt(enrollment)?;
            agent.restore_holders()?;
        }
        Ok(agent)
    }

    /// Whether the agent holds an enrolment.
    pub fn enrolled(&self) -> bool {
        lock(&self.shared).enrollment.is_some()
    }

    fn client_options(&self) -> ClientOptions {
        ClientOptions::new(&self.config.na_url).with_timeout(self.config.na_timeout)
    }

    fn transport(&self) -> Result<HttpTransport, GenesisMeshError> {
        HttpTransport::new(self.client_options())
    }

    /// Use an enrolment: the node identity, the client acting as the node,
    /// the executor recorder, and the snapshot held.
    fn adopt(&self, enrollment: Value) -> Result<(), Exit> {
        let node_seed = self
            .dir
            .read_key(NODE_KEY)?
            .ok_or_else(|| Exit::Internal("enrolled, but node.key is missing".into()))?;
        let executor_seed = self
            .dir
            .read_key(EXECUTOR_KEY)?
            .ok_or_else(|| Exit::Internal("enrolled, but executor.key is missing".into()))?;
        let audience = enrollment["audience"].as_str().unwrap_or_default();
        let cert_id = enrollment["cert"]["cert_id"].as_str().unwrap_or_default();
        let identity = NodeIdentity::new(cert_id, &node_seed, audience).map_err(internal)?;
        let recorder = ExecutionRecorder::new(
            enrollment["node_sovereign_id"].as_str().unwrap_or_default(),
            enrollment["executor_key"]["key_id"]
                .as_str()
                .unwrap_or_default(),
            &executor_seed,
        )
        .map_err(internal)?;
        let client = GenesisMeshClient::new(
            self.client_options()
                .with_audience(audience)
                .with_outbox(Arc::new(SqliteOutbox(self.db.clone())))
                .with_record_outbox(Arc::new(SqliteRecordOutbox(self.db.clone()))),
        )
        .map_err(|e| Exit::Usage(e.to_string()))?
        .with_node_identity(identity.clone());
        let snapshot = self.dir.read_json(SNAPSHOT)?.unwrap_or_else(|| json!({}));
        let na_keys = self.keys_of(&snapshot["key_history"]).unwrap_or_default();
        let revoked = self.db.meta("revoked").map_err(internal)?.is_some()
            || crl_names(&snapshot["crl"], cert_id);
        let mut shared = lock(&self.shared);
        shared.enrollment = Some(enrollment);
        shared.client = Some(client);
        shared.identity = Some(identity);
        shared.recorder = Some(recorder);
        shared.na_keys = na_keys;
        shared.snapshot = snapshot;
        shared.revoked = revoked;
        Ok(())
    }

    /// The NA's keys from a key history, verified from the pinned root key.
    fn keys_of(&self, key_history: &Value) -> Option<Vec<String>> {
        let successions: Vec<Value> = key_history["successions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let verified = verify_key_history(
            &key_history["genesis"],
            &successions,
            Some(&self.config.root_public_key),
        );
        verified.history.map(|h| h.all_keys())
    }

    /// Restore the grant holders, each advanced to the newest use of its
    /// grant the agent made (in the record outbox, or admitted): a crash
    /// between keeping a use and saving the holder never forks the chain.
    fn restore_holders(&self) -> Result<(), Exit> {
        let (recorder, keys, prefix) = {
            let shared = lock(&self.shared);
            (
                shared.recorder.clone(),
                shared.na_keys.clone(),
                shared
                    .enrollment
                    .as_ref()
                    .and_then(|e| e["executor_key"]["resource_prefix"].as_str())
                    .map(str::to_owned),
            )
        };
        let Some(recorder) = recorder else {
            return Ok(());
        };
        let uses = self.db.grant_uses().map_err(internal)?;
        let mut holders = BTreeMap::new();
        for (grant_id, state) in self.db.holders().map_err(internal)? {
            let mut state: GrantHolderState = match serde_json::from_value(state) {
                Ok(state) => state,
                Err(err) => {
                    log::error(
                        "grant_holder_unreadable",
                        json!({"grant_id": grant_id, "error": err.to_string()}),
                    );
                    continue;
                }
            };
            let newest = uses
                .iter()
                .filter(|u| u["grant_id"].as_str() == Some(grant_id.as_str()))
                .max_by_key(|u| u["use_sequence"].as_u64().unwrap_or(0));
            if let Some(newest) = newest {
                let sequence = newest["use_sequence"].as_u64().unwrap_or(0);
                if sequence > state.uses {
                    state.uses = sequence;
                    state.head_digest = use_digest(newest).ok();
                    state.head_executed_at = newest["executed_at"]
                        .as_str()
                        .and_then(|s| parse_timestamp(s).ok())
                        .map(python_timestamp);
                    log::warn(
                        "grant_holder_advanced",
                        json!({"grant_id": grant_id, "uses": sequence}),
                    );
                }
            }
            match GrantHolder::restore(state, recorder.clone(), keys.clone()) {
                Ok(mut holder) => {
                    holder.set_resource_prefix(prefix.clone());
                    holders.insert(grant_id, holder);
                }
                Err(err) => log::error(
                    "grant_holder_unusable",
                    json!({"grant_id": grant_id, "code": err.code()}),
                ),
            }
        }
        // Not yet running: no one else holds the lock.
        if let Ok(mut held) = self.holders.try_lock() {
            held.map = holders;
        }
        Ok(())
    }

    fn save_holder(&self, holder: &GrantHolder) {
        match serde_json::to_value(holder.state()) {
            Ok(state) => {
                if let Err(err) = self.db.save_holder(holder.grant_id(), &state) {
                    log::error(
                        "grant_holder_not_saved",
                        json!({"grant_id": holder.grant_id(), "error": err.to_string()}),
                    );
                }
            }
            Err(err) => log::error("grant_holder_not_saved", json!({"error": err.to_string()})),
        }
    }

    // ── Enrolment ───────────────────────────────────────────────────────────

    /// Enrol with an invite token (docs/edge.md, "Enrolment").
    pub async fn enroll(&self, invite_token: &str) -> Result<(), Exit> {
        // The invite token is a bearer secret for a privileged act: never in
        // clear text over a network (allow_insecure_http covers `run` only).
        if crate::config::insecure_remote(&self.config.na_url) {
            return Err(Exit::Usage(
                "enrolment needs https (or a loopback NA): the invite token would cross the network in clear text"
                    .into(),
            ));
        }
        let transport = self.transport().map_err(|e| Exit::Usage(e.to_string()))?;
        let key_history: Value = transport
            .public_get("/na/key-history")
            .await
            .map_err(|e| unreachable_or_refused(&e, "reading the NA's key history"))?;
        let na_keys = self.keys_of(&key_history).ok_or_else(|| {
            Exit::Refused(
                "the NA's key history does not verify from the configured root public key".into(),
            )
        })?;
        let audience = key_history["genesis"]["network_authority"]["public_key"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let node_seed = self.dir.key(NODE_KEY)?;
        let executor_seed = self.dir.key(EXECUTOR_KEY)?;
        let node_public_key =
            genesis_mesh_sdk::public_key_from_seed(&node_seed).map_err(internal)?;
        let executor_public_key =
            genesis_mesh_sdk::public_key_from_seed(&executor_seed).map_err(internal)?;
        let join = NodeJoin::new(&node_seed, invite_token)
            .and_then(|j| j.with_executor_key(&executor_seed))
            .map_err(internal)?
            .with_validity_hours(self.config.validity_hours)
            .with_agent_version(VERSION);
        let client = GenesisMeshClient::new(self.client_options()).map_err(internal)?;
        let cert = client
            .node
            .join(&join)
            .await
            .map_err(|e| unreachable_or_refused(&e, "joining"))?;
        let edge = check_certificate(&cert, &na_keys, &node_public_key, &executor_public_key)?;
        let enrollment = json!({
            "na_url": self.config.na_url,
            "audience": audience,
            "cert": strip_edge(&cert),
            "node_sovereign_id": edge["node_sovereign_id"],
            "executor_key": edge["executor_key"],
            "enrolled_at": timestamp(Utc::now()),
        });
        self.dir.write_json(ENROLLMENT, &enrollment)?;
        self.dir.write_json(
            SNAPSHOT,
            &json!({"key_history": key_history, "synced_at": Value::Null}),
        )?;
        self.adopt(enrollment)?;
        log::info(
            "enrolled",
            json!({
                "node_sovereign_id": edge["node_sovereign_id"],
                "executor_key_id": edge["executor_key"]["key_id"],
                "cert_id": cert["cert_id"],
            }),
        );
        Ok(())
    }

    /// Pending uploads and dead letters.
    pub fn outbox_counts(&self) -> (u64, u64) {
        self.db.outbox_counts().unwrap_or((0, 0))
    }

    // ── State ───────────────────────────────────────────────────────────────

    /// Where the agent stands now.
    pub fn state(&self) -> AgentState {
        let shared = lock(&self.shared);
        let Some(enrollment) = &shared.enrollment else {
            return AgentState::Unenrolled;
        };
        if shared.revoked {
            return AgentState::Revoked;
        }
        match micros(&enrollment["cert"]["expires_at"]) {
            Some(expires) if expires > Utc::now().timestamp_micros() => AgentState::Active,
            _ => AgentState::CertificateExpired,
        }
    }

    fn connected(&self) -> bool {
        let last = lock(&self.shared).last_contact;
        let window = chrono::Duration::from_std(self.config.heartbeat_interval * 2)
            .unwrap_or(chrono::Duration::MAX);
        self.state() == AgentState::Active && last.is_some_and(|at| Utc::now() - at <= window)
    }

    fn contact(&self) {
        lock(&self.shared).last_contact = Some(Utc::now());
    }

    fn mark_revoked(&self, why: &str) {
        let mut shared = lock(&self.shared);
        if !shared.revoked {
            shared.revoked = true;
            let _ = self.db.set_meta("revoked", why);
            log::warn("node_revoked", json!({"reason": why}));
        }
    }

    /// The snapshot's age in seconds, from the time the NA signed what it
    /// holds: `now - min(synced_at, feed.issued_at)`. Negative when the
    /// device's clock is behind that time.
    fn snapshot_age(&self) -> Option<i64> {
        let shared = lock(&self.shared);
        let synced = micros(&shared.snapshot["synced_at"])?;
        let anchor = micros(&shared.snapshot["revocation_feed"]["issued_at"])
            .map_or(synced, |issued| issued.min(synced));
        Some((Utc::now().timestamp_micros() - anchor) / 1_000_000)
    }

    /// The device's clock is more than 300 s behind the time the NA signed
    /// the snapshot: the clock cannot be trusted to age it.
    fn clock_behind(&self) -> bool {
        self.snapshot_age()
            .is_some_and(|age| age < -CLOCK_SKEW_SECONDS)
    }

    fn snapshot_fresh(&self) -> bool {
        self.snapshot_age().is_some_and(|age| {
            (-CLOCK_SKEW_SECONDS..=self.config.max_snapshot_age.as_secs() as i64).contains(&age)
        })
    }

    // ── The schedule ────────────────────────────────────────────────────────

    /// The agent's block in a heartbeat.
    fn agent_block(&self) -> Value {
        let (pending, dead) = self.outbox_counts();
        json!({
            "version": VERSION,
            "snapshot_age_seconds": self.snapshot_age().map(|age| age.max(0)),
            "pending_uploads": pending,
            "dead_letters": dead,
        })
    }

    fn node(&self) -> Option<(GenesisMeshClient, NodeIdentity)> {
        let shared = lock(&self.shared);
        Some((shared.client.clone()?, shared.identity.clone()?))
    }

    /// Send a heartbeat; true when the NA answered it.
    pub async fn heartbeat(&self) -> bool {
        if self.state() != AgentState::Active {
            return false;
        }
        let Some((client, identity)) = self.node() else {
            return false;
        };
        let (_, dead) = self.outbox_counts();
        let status = if self.snapshot_fresh() && dead == 0 {
            "healthy"
        } else {
            "degraded"
        };
        match client
            .node
            .heartbeat(&identity, status, Some(self.agent_block()))
            .await
        {
            Ok(_) => {
                self.contact();
                true
            }
            Err(err) => {
                self.na_error("heartbeat_failed", &err);
                // A refusal (a 429 included) is an answer: the NA is there.
                answered(&err)
            }
        }
    }

    fn na_error(&self, event: &str, err: &GenesisMeshError) {
        if answered(err) {
            self.contact();
        }
        if revoked_code(err) {
            self.mark_revoked(err.code());
        } else if err.code() == "certificate_expired" {
            log::warn(event, json!({"code": err.code()}));
        } else {
            log::debug(event, json!({"code": err.code()}));
        }
    }

    /// Renew the certificate when it expires within `renew_before`. The new
    /// certificate is saved before it is used.
    pub async fn maybe_renew(&self) {
        if self.state() != AgentState::Active {
            return;
        }
        let (expires, node_public_key, executor_public_key, keys) = {
            let shared = lock(&self.shared);
            let Some(enrollment) = &shared.enrollment else {
                return;
            };
            (
                micros(&enrollment["cert"]["expires_at"]).unwrap_or(0),
                enrollment["cert"]["node_public_key"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                enrollment["executor_key"]["public_key"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                shared.na_keys.clone(),
            )
        };
        let left = expires - Utc::now().timestamp_micros();
        if left >= self.config.renew_before.as_micros() as i64 {
            return;
        }
        let Some((client, identity)) = self.node() else {
            return;
        };
        let cert = match client
            .node
            .renew(&identity, self.config.validity_hours)
            .await
        {
            Ok(cert) => cert,
            Err(err) => {
                self.na_error("renewal_failed", &err);
                return;
            }
        };
        self.contact();
        if let Err(err) = check_certificate(&cert, &keys, &node_public_key, &executor_public_key) {
            log::error("renewal_refused", json!({"reason": err.message()}));
            return;
        }
        let enrollment = {
            let shared = lock(&self.shared);
            let mut enrollment = shared.enrollment.clone().unwrap_or_default();
            enrollment["cert"] = strip_edge(&cert);
            enrollment
        };
        if let Err(err) = self.dir.write_json(ENROLLMENT, &enrollment) {
            log::error("renewal_not_saved", json!({"error": err.to_string()}));
            return;
        }
        if let Err(err) = self.adopt(enrollment) {
            log::error("renewal_not_used", json!({"error": err.message()}));
            return;
        }
        log::info(
            "renewed",
            json!({"cert_id": cert["cert_id"], "expires_at": cert["expires_at"]}),
        );
    }

    /// Sync with the NA: the key history, the CRL, the revocation feed and
    /// the node's state; new grants get a holder and a first time token;
    /// then the uploads (break-glass, grant uses in chain order, execution
    /// evidence) and a fresh time token for every usable holder.
    pub async fn sync(&self) -> Result<(), GenesisMeshError> {
        let state = self.state();
        if !matches!(state, AgentState::Active | AgentState::CertificateExpired) {
            return Ok(());
        }
        let Some((client, identity)) = self.node() else {
            return Ok(());
        };
        let transport = self.transport()?;
        let key_history: Value = transport.public_get("/na/key-history").await?;
        let Some(na_keys) = self.keys_of(&key_history) else {
            log::error("key_history_unverified", json!({}));
            return Err(GenesisMeshError::Verification(
                "the NA's key history does not verify".into(),
            ));
        };
        let crl: Value = transport.public_get("/crl").await?;
        let feed = client.grants.revocation_feed().await?;
        if !verify_crl(&crl, &na_keys) {
            log::error("crl_unverified", json!({}));
            return Err(GenesisMeshError::Verification(
                "the CRL does not verify".into(),
            ));
        }
        if crl_names(&crl, identity.cert_id()) {
            self.mark_revoked("certificate_in_crl");
        }
        let mut node_state = Value::Null;
        if state == AgentState::Active && self.state() == AgentState::Active {
            match client.node.state(&identity).await {
                Ok(answer) => {
                    self.contact();
                    // An executor key retired another way than by revoking
                    // the node: its records would be refused.
                    if !answer["executor_key"]["retired_at"].is_null() {
                        self.mark_revoked("executor_key_retired");
                        return Ok(());
                    }
                    node_state = answer;
                }
                Err(err) => {
                    self.na_error("node_state_failed", &err);
                    if revoked_code(&err) {
                        return Ok(());
                    }
                    return Err(err);
                }
            }
        }
        let attestations = verified_attestations(&node_state, &na_keys, &identity);
        if !node_state.is_null() {
            node_state["attestations"] = Value::Array(attestations);
        }
        {
            let mut shared = lock(&self.shared);
            shared.na_keys = na_keys.clone();
            if node_state.is_null() {
                node_state = shared.snapshot["node_state"].clone();
            }
            shared.snapshot = json!({
                "key_history": key_history,
                "crl": crl,
                "revocation_feed": feed,
                "node_state": node_state,
                "synced_at": timestamp(Utc::now()),
            });
            if let Err(err) = self.dir.write_json(SNAPSHOT, &shared.snapshot) {
                log::error("snapshot_not_saved", json!({"error": err.to_string()}));
            }
        }
        self.sync_grants(&client, &node_state, &feed, &na_keys)
            .await;
        let store = &client.evidence_store;
        let uploads = store
            .flush_records(FlushOptions {
                ignore_backoff: true,
            })
            .await;
        let pending = store
            .flush_pending(FlushOptions {
                ignore_backoff: true,
            })
            .await;
        match (&uploads, &pending) {
            (Ok(records), Ok(evidence)) => log::info(
                "uploaded",
                json!({
                    "records_admitted": records.admitted.len(),
                    "records_quarantined": records.quarantined.len(),
                    "records_dead_lettered": records.dead_lettered.len(),
                    "evidence_admitted": evidence.admitted.len(),
                    "evidence_dead_lettered": evidence.dead_lettered.len(),
                    "pending": records.pending.len() + evidence.pending.len(),
                }),
            ),
            _ => log::debug("upload_incomplete", json!({})),
        }
        let mut holders = self.holders.lock().await;
        let outbox = SqliteRecordOutbox(self.db.clone());
        for holder in holders.map.values_mut() {
            let _ = holder.count_quarantined(&outbox).await;
            if !holder.revoked() && holder.state().ended.is_none() && holder.remaining_uses() > 0 {
                if let Err(err) = holder.refresh_time_token(&client.grants).await {
                    log::debug(
                        "time_token_not_refreshed",
                        json!({"grant_id": holder.grant_id(), "code": err.code()}),
                    );
                }
            }
            self.save_holder(holder);
        }
        drop(holders);
        uploads?;
        pending?;
        Ok(())
    }

    /// Holders for new grants (with a first time token), the resource prefix
    /// and the revocation feed for every holder.
    async fn sync_grants(
        &self,
        client: &GenesisMeshClient,
        node_state: &Value,
        feed: &Value,
        na_keys: &[String],
    ) {
        let Some(recorder) = lock(&self.shared).recorder.clone() else {
            return;
        };
        let prefix = node_state["executor_key"]["resource_prefix"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                lock(&self.shared)
                    .enrollment
                    .as_ref()
                    .and_then(|e| e["executor_key"]["resource_prefix"].as_str())
                    .map(str::to_owned)
            });
        let mut holders = self.holders.lock().await;
        for grant in node_state["grants"].as_array().into_iter().flatten() {
            let Some(grant_id) = grant["grant_id"].as_str() else {
                continue;
            };
            if holders.map.contains_key(grant_id) || holders.out.as_deref() == Some(grant_id) {
                continue;
            }
            let request = match recorder.sign_time_token_request(grant_id, 0, None, None) {
                Ok(request) => request,
                Err(err) => {
                    log::error(
                        "grant_refused",
                        json!({"grant_id": grant_id, "code": err.code()}),
                    );
                    continue;
                }
            };
            let token = match client.grants.request_time_token(request).await {
                Ok(answer) => answer["time_token"].clone(),
                Err(err) => {
                    log::warn(
                        "grant_not_held",
                        json!({"grant_id": grant_id, "code": err.code()}),
                    );
                    continue;
                }
            };
            match GrantHolder::new(grant.clone(), token, recorder.clone(), na_keys.to_vec()) {
                Ok(holder) => {
                    log::info(
                        "grant_held",
                        json!({"grant_id": grant_id, "capabilities": grant["capabilities"]}),
                    );
                    holders.map.insert(grant_id.to_owned(), holder);
                }
                Err(err) => log::error(
                    "grant_unverified",
                    json!({"grant_id": grant_id, "code": err.code()}),
                ),
            }
        }
        for holder in holders.map.values_mut() {
            holder.set_resource_prefix(prefix.clone());
            if !feed.is_null() {
                if let Err(err) = holder.set_feed(feed.clone()) {
                    log::warn(
                        "feed_not_kept",
                        json!({"grant_id": holder.grant_id(), "code": err.code()}),
                    );
                }
            }
            self.save_holder(holder);
        }
    }

    /// The schedule: heartbeats, renewal and syncs, until `stop` fires.
    pub async fn run(self: &Arc<Self>, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut next_heartbeat = tokio::time::Instant::now();
        let mut next_sync = tokio::time::Instant::now();
        let mut retry = self.config.retry_interval;
        let mut was_connected = false;
        loop {
            let now = tokio::time::Instant::now();
            if now >= next_heartbeat {
                self.maybe_renew().await;
                let answered = self.heartbeat().await;
                next_heartbeat = now + self.config.heartbeat_interval;
                if answered && !was_connected {
                    // Reconnected: sync now.
                    next_sync = now;
                }
                was_connected = answered;
            }
            if tokio::time::Instant::now() >= next_sync && self.enrolled() {
                match self.sync().await {
                    Ok(()) => {
                        retry = self.config.retry_interval;
                        next_sync = tokio::time::Instant::now() + self.config.sync_interval;
                    }
                    Err(err) => {
                        log::debug("sync_failed", json!({"code": err.code()}));
                        next_sync = tokio::time::Instant::now() + retry;
                        retry = (retry * 2).min(Duration::from_secs(60)).max(retry);
                    }
                }
            }
            let wake = next_heartbeat.min(next_sync);
            tokio::select! {
                () = tokio::time::sleep_until(wake) => {}
                _ = stop.changed() => return,
            }
            if *stop.borrow() {
                return;
            }
        }
    }

    // ── The local API ───────────────────────────────────────────────────────

    /// `GET /v1/status`.
    pub async fn status(&self) -> Value {
        let state = self.state();
        let (pending, dead) = self.outbox_counts();
        let fresh = self.snapshot_fresh();
        let (enrollment, snapshot, last_contact) = {
            let shared = lock(&self.shared);
            (
                shared.enrollment.clone().unwrap_or(Value::Null),
                shared.snapshot.clone(),
                shared.last_contact,
            )
        };
        let holders = self.holders.lock().await;
        let grants: Vec<Value> = holders
            .map
            .values()
            .map(|holder| {
                let code = holder_code(holder, fresh);
                json!({
                    "grant_id": holder.grant_id(),
                    "capabilities": holder.grant()["capabilities"],
                    "valid_until": holder.grant()["valid_until"],
                    "uses": holder.uses(),
                    "max_uses": holder.grant()["max_uses"],
                    "usable": code.is_none(),
                    "code": code,
                })
            })
            .collect();
        json!({
            "agent_version": VERSION,
            "state": state.name(),
            "node_public_key": enrollment["cert"]["node_public_key"],
            "node_sovereign_id": enrollment["node_sovereign_id"],
            "executor_key_id": enrollment["executor_key"]["key_id"],
            "resource_prefix": enrollment["executor_key"]["resource_prefix"],
            "cert_id": enrollment["cert"]["cert_id"],
            "cert_expires_at": enrollment["cert"]["expires_at"],
            "connected": self.connected(),
            "last_na_contact_at": last_contact.map(timestamp),
            "snapshot_synced_at": snapshot["synced_at"],
            "snapshot_age_seconds": self.snapshot_age().map(|age| age.max(0)),
            "snapshot_fresh": fresh,
            "clock_behind": self.clock_behind(),
            "grants": grants,
            "pending_uploads": pending,
            "dead_letters": dead,
            "lost_authorizations": self.lost.load(Ordering::Relaxed),
        })
    }

    /// `POST /v1/authorize`: decide, and when allowed hand the authority to
    /// the caller and wait for its outcome.
    pub async fn authorize(self: &Arc<Self>, request: AuthorizeRequest) -> Result<Value, ApiError> {
        match self.state() {
            AgentState::Unenrolled => {
                return Err(ApiError::new(
                    503,
                    "not_enrolled",
                    "the agent is not enrolled",
                ))
            }
            AgentState::Revoked => {
                return Err(ApiError::new(
                    403,
                    "node_revoked",
                    "the NA revoked this node",
                ))
            }
            _ => {}
        }
        let prefix = lock(&self.shared)
            .enrollment
            .as_ref()
            .and_then(|e| e["executor_key"]["resource_prefix"].as_str())
            .unwrap_or_default()
            .to_owned();
        if prefix.is_empty() || !request.resource_id.starts_with(&prefix) {
            return Err(ApiError::new(
                400,
                "resource_out_of_scope",
                format!("the resource must start with the node's prefix {prefix:?}"),
            ));
        }
        for (name, value) in [
            ("request_parameters", &request.request_parameters),
            ("attributes", &request.attributes),
        ] {
            if let Some(reason) = check_metadata_only(value, None) {
                return Err(ApiError::new(
                    400,
                    "secret_material",
                    format!("{name} would carry secret material: {reason}"),
                ));
            }
        }
        let permit = tokio::time::timeout(
            self.config.queue_timeout,
            Arc::clone(&self.slot).acquire_owned(),
        )
        .await
        .map_err(|_| ApiError::new(503, "agent_busy", "another authorization is open"))?
        .map_err(|_| ApiError::new(503, "agent_busy", "the agent is stopping"))?;
        self.prune_open();
        let id = uuid::Uuid::new_v4().to_string();
        let (granted_tx, granted_rx) = oneshot::channel();
        let (outcome_tx, outcome_rx) = oneshot::channel();
        let link = Arc::new(Link {
            granted: Mutex::new(Some(granted_tx)),
            outcome: Mutex::new(Some(outcome_rx)),
            report_timeout: self.config.report_timeout,
            expired: std::sync::atomic::AtomicBool::new(false),
        });
        log::info(
            "authorization_requested",
            json!({
                "authorization_id": id,
                "capability": request.capability,
                "resource_id": request.resource_id,
                "resource_action": request.resource_action,
                "justification_length": request.justification.as_ref().map(|j| j.chars().count()),
            }),
        );
        let agent = Arc::clone(self);
        let task_link = Arc::clone(&link);
        let mut task = tokio::spawn(async move { agent.decide(request, task_link, permit).await });
        let mut granted_rx = granted_rx;
        let (answer, done) = tokio::select! {
            biased;
            granted = &mut granted_rx => match granted {
                Ok(granted) => (Some(granted), None),
                // The SDK dropped the action without calling it: the task ends.
                Err(_) => (None, Some((&mut task).await)),
            },
            done = &mut task => (None, Some(done)),
        };
        if let Some(granted) = answer {
            let report_by = Utc::now()
                + chrono::Duration::from_std(self.config.report_timeout)
                    .unwrap_or(chrono::Duration::MAX);
            let _ = self
                .db
                .set_authorization(&id, "open", Some(granted.authority), None);
            lock(&self.open).insert(
                id.clone(),
                Open {
                    outcome: Some(outcome_tx),
                    task,
                    link,
                },
            );
            log::info(
                "authorization_allowed",
                json!({"authorization_id": id, "authority": granted.authority, "code": granted.code}),
            );
            return Ok(json!({
                "authorization_id": id,
                "allowed": true,
                "authority": granted.authority,
                "code": granted.code,
                "detail": format!("allowed under {}", granted.authority.replace('_', "-")),
                "decision_id": granted.decision_id,
                "grant_id": granted.grant_id,
                "use_sequence": granted.use_sequence,
                "report_by": timestamp(report_by),
            }));
        }
        // The action was not called: the task tells why.
        let finished = match done {
            Some(Ok(finished)) => finished,
            Some(Err(err)) => Finished::Failed(err.to_string()),
            None => Finished::Failed("the authorization ended without an answer".into()),
        };
        match finished {
            Finished::Refused { code, details } => {
                log::info(
                    "authorization_refused",
                    json!({"authorization_id": id, "code": code, "details": details}),
                );
                let mut body = json!({
                    "authorization_id": id,
                    "allowed": false,
                    "authority": Value::Null,
                    "code": code,
                    "detail": refusal_detail(&code),
                    "decision_id": details.get("decision_id").cloned().unwrap_or(Value::Null),
                    "grant_id": Value::Null,
                    "use_sequence": Value::Null,
                    "report_by": Value::Null,
                });
                if let Some(map) = details.as_object() {
                    for (key, value) in map {
                        if key != "decision_id" {
                            body[key] = value.clone();
                        }
                    }
                }
                Ok(body)
            }
            Finished::Failed(message) => {
                log::error(
                    "authorization_failed",
                    json!({"authorization_id": id, "error": message}),
                );
                Err(ApiError::new(
                    500,
                    "internal_error",
                    "the authorization failed",
                ))
            }
            Finished::Ran { .. } => Err(ApiError::new(
                500,
                "internal_error",
                "the action ran without being handed to the caller",
            )),
        }
    }

    fn prune_open(&self) {
        lock(&self.open).retain(|_, open| !open.task.is_finished() || open.outcome.is_some());
    }

    /// `POST /v1/authorizations/{id}/outcome`.
    pub async fn report(&self, id: &str, outcome: Outcome) -> Result<Value, ApiError> {
        let open = lock(&self.open).remove(id);
        let Some(mut open) = open else {
            return Err(match self.authorization_state(id).as_deref() {
                Some("reported") => {
                    ApiError::new(409, "outcome_already_reported", "the outcome was reported")
                }
                Some("expired") | Some("lost") => ApiError::new(
                    410,
                    "authorization_expired",
                    "the outcome was not reported in time",
                ),
                _ => ApiError::new(404, "authorization_not_found", "no such authorization"),
            });
        };
        let sender = open.outcome.take();
        let sent = sender.is_some_and(|s| s.send(outcome).is_ok());
        let expired = !sent || open.link.expired.load(Ordering::Acquire);
        let finished = match open.task.await {
            Ok(finished) => finished,
            Err(err) => Finished::Failed(err.to_string()),
        };
        if expired {
            let _ = self.db.set_authorization(id, "expired", None, None);
            return Err(ApiError::new(
                410,
                "authorization_expired",
                "the outcome was not reported in time; it was recorded as a failure",
            ));
        }
        match finished {
            Finished::Ran {
                record_kind,
                record_id,
                queued,
                dropped,
            } => {
                let _ = self
                    .db
                    .set_authorization(id, "reported", None, record_id.as_deref());
                log::info(
                    "outcome_recorded",
                    json!({"authorization_id": id, "record_kind": record_kind, "record_id": record_id, "queued": queued}),
                );
                Ok(json!({
                    "authorization_id": id,
                    "record_kind": record_kind,
                    "record_id": record_id,
                    "queued": queued,
                    "dropped": dropped,
                }))
            }
            Finished::Refused { code, .. } | Finished::Failed(code) => {
                let _ = self.db.set_authorization(id, "reported", None, None);
                log::error(
                    "outcome_not_recorded",
                    json!({"authorization_id": id, "error": code}),
                );
                Err(ApiError::new(
                    500,
                    "internal_error",
                    "the outcome could not be recorded",
                ))
            }
        }
    }

    fn authorization_state(&self, id: &str) -> Option<String> {
        self.db.authorization_state(id).ok().flatten()
    }

    /// On SIGTERM: wait up to `wait` for the open authorization, then record
    /// it as not reported (a failure).
    pub async fn shut_down(&self, wait: Duration) {
        if tokio::time::timeout(wait, self.slot.acquire())
            .await
            .is_ok()
        {
            self.slot.close();
            return;
        }
        self.slot.close();
        let open: Vec<(String, Open)> = lock(&self.open).drain().collect();
        for (id, mut open) in open {
            if let Some(sender) = open.outcome.take() {
                let _ = sender.send(Outcome {
                    outcome: "failure".into(),
                    execution_parameters: None,
                    outcome_detail: Some(
                        "not reported: the agent stopped before the outcome was reported".into(),
                    ),
                });
            }
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut open.task).await;
            let _ = self.db.set_authorization(&id, "expired", None, None);
            log::warn(
                "authorization_not_reported",
                json!({"authorization_id": id}),
            );
        }
    }

    // ── The decision order ──────────────────────────────────────────────────

    async fn decide(
        self: Arc<Self>,
        request: AuthorizeRequest,
        link: Arc<Link>,
        _permit: OwnedSemaphorePermit,
    ) -> Finished {
        let state = self.state();
        let Some((client, _)) = self.node() else {
            return Finished::Failed("not enrolled".into());
        };
        let (recorder, na_keys, attestations) = {
            let shared = lock(&self.shared);
            (
                shared.recorder.clone(),
                shared.na_keys.clone(),
                shared.snapshot["node_state"]["attestations"].clone(),
            )
        };
        let Some(recorder) = recorder else {
            return Finished::Failed("not enrolled".into());
        };
        let attestation = match self.attestation(&request, &attestations) {
            Ok(attestation) => attestation,
            Err(refused) => return refused,
        };
        let evaluate = attestation.as_ref().map(|attestation| {
            json!({
                "attestation_id": attestation["attestation_id"],
                "requested_capability": request.capability,
                "context": {
                    "context_id": uuid::Uuid::new_v4().to_string(),
                    "request_parameters": request.request_parameters,
                    "attributes": request.attributes,
                },
            })
        });
        let verify = GovernedVerification {
            operator_public_keys: na_keys,
            expected_attestation: attestation.clone(),
            any_bound_policies: true,
            ..GovernedVerification::default()
        };
        let params = |evaluate: Value| GovernedActionParams {
            evaluate,
            resource_id: Some(request.resource_id.clone()),
            resource_action: Some(request.resource_action.clone()),
            prior_resource: None,
            verify: verify.clone(),
        };

        // 1. Connected: the NA decides. Only a request that got no answer
        // (no connection, a timeout) goes on; any answer of the NA, a 429 or
        // a 5xx included, is final.
        let mut unanswered = None;
        if state == AgentState::Active && self.connected() {
            if let Some(evaluate) = &evaluate {
                match self
                    .ask(&client, &recorder, params(evaluate.clone()), &link)
                    .await
                {
                    Asked::Done(finished) => return finished,
                    Asked::Unanswered(failure) => unanswered = Some(failure),
                }
            }
        }

        // 2. Grants. A request a held grant names but does not cover is
        // refused, fresh snapshot or not; a covered one is acted on only
        // while the snapshot is fresh.
        let fresh = self.snapshot_fresh();
        let grant_code = match self.choose_holder(&request, fresh).await {
            Choice::Use(holder) => match self.act(&client, holder, &request, &link).await {
                Ok(finished) => return finished,
                Err(code) => code,
            },
            Choice::Outside(code) => return refused("outside_grant", json!({"grant_code": code})),
            Choice::Covered | Choice::Ended(_) if !fresh => "snapshot_stale".to_owned(),
            Choice::Ended(code) => code,
            Choice::Covered | Choice::None => "no_grant".to_owned(),
        };

        // 3. Break-glass, with a justification, when the NA does not answer.
        let Some(justification) = request.justification.clone() else {
            return refused("justification_required", json!({"grant_code": grant_code}));
        };
        let Some(evaluate) = evaluate else {
            return refused("no_attestation", json!({"grant_code": grant_code}));
        };
        let failure = match (state, unanswered) {
            // The NA refuses a node whose certificate has expired: it is not asked.
            (AgentState::CertificateExpired, _) => EvaluationFailure::NetworkError,
            (_, Some(failure)) => failure,
            _ => match self
                .ask(&client, &recorder, params(evaluate.clone()), &link)
                .await
            {
                Asked::Done(finished) => return finished,
                Asked::Unanswered(failure) => failure,
            },
        };
        self.break_glass(
            &client,
            &recorder,
            &request,
            &evaluate,
            BreakGlass {
                justification,
                grant_code,
                failure,
            },
            &link,
        )
        .await
    }

    /// Ask the NA to decide (`governed_action` through the node route).
    async fn ask(
        &self,
        client: &GenesisMeshClient,
        recorder: &ExecutionRecorder,
        params: GovernedActionParams,
        link: &Arc<Link>,
    ) -> Asked {
        // Uses and break-glass records still pending go first, so a decision's
        // evidence follows them in the resource's chain.
        let _ = client
            .evidence_store
            .flush_records(FlushOptions {
                ignore_backoff: true,
            })
            .await;
        let decided = governed_action(
            &client.boundary,
            &client.evidence_store,
            recorder,
            params,
            |decision: Value| {
                action(
                    Arc::clone(link),
                    Granted {
                        authority: "decision",
                        decision_id: decision["decision_id"].as_str().map(str::to_owned),
                        ..Granted::default()
                    },
                )
            },
        )
        .await;
        match decided {
            Ok(result) => {
                self.contact();
                Asked::Done(evaluated(result))
            }
            Err(err) => match unanswered(&err) {
                Some(failure) => {
                    log::info("na_unreachable", json!({"failure": failure.as_str()}));
                    Asked::Unanswered(failure)
                }
                None => {
                    if answered(&err) {
                        self.contact();
                    }
                    Asked::Done(self.decision_error(err))
                }
            },
        }
    }

    /// The attestation to evaluate under: the request's (one of the node's),
    /// the pinned one, or the single active one naming the capability with
    /// the latest expiry.
    fn attestation(
        &self,
        request: &AuthorizeRequest,
        attestations: &Value,
    ) -> Result<Option<Value>, Finished> {
        let held: Vec<Value> = attestations
            .as_array()
            .into_iter()
            .flatten()
            .map(|a| a["attestation"].clone())
            .collect();
        let by_id = |id: &str| held.iter().find(|a| a["attestation_id"] == id).cloned();
        if let Some(id) = &request.attestation_id {
            return by_id(id).map(Some).ok_or_else(|| {
                refused(
                    "no_attestation",
                    json!({"detail": "the attestation is not one issued to this node"}),
                )
            });
        }
        if let Some(id) = &self.config.attestation_id {
            return Ok(by_id(id));
        }
        let now = Utc::now().timestamp_micros();
        Ok(held
            .iter()
            .filter(|a| {
                a["status"] == "active"
                    && micros(&a["expires_at"]).is_some_and(|e| e > now)
                    && a["claims"]["capabilities"]
                        .as_array()
                        .is_some_and(|c| c.iter().any(|c| c == request.capability.as_str()))
            })
            .max_by_key(|a| micros(&a["expires_at"]).unwrap_or(0))
            .cloned())
    }

    fn decision_error(&self, err: GenesisMeshError) -> Finished {
        if revoked_code(&err) {
            self.mark_revoked(err.code());
        }
        match &err {
            GenesisMeshError::DecisionVerification(reason) => refused(
                "decision_unverifiable",
                json!({"verification_reason": reason}),
            ),
            GenesisMeshError::MetadataRefused {
                evidence,
                queued,
                dropped,
                ..
            } => Finished::Ran {
                record_kind: if evidence.get("break_glass_id").is_some() {
                    "break_glass"
                } else {
                    "execution"
                },
                record_id: evidence["evidence_id"]
                    .as_str()
                    .or_else(|| evidence["break_glass_id"].as_str())
                    .map(str::to_owned),
                queued: queued.is_some(),
                dropped: dropped.clone(),
            },
            GenesisMeshError::EvidenceNotKept { .. }
            | GenesisMeshError::ActionFailed { .. }
            | GenesisMeshError::ActionUnrecorded { .. } => Finished::Failed(err.to_string()),
            _ => refused("na_refused", json!({"na_code": err.code()})),
        }
    }

    /// The holder to use for a request, soonest `valid_until` first.
    async fn choose_holder(&self, request: &AuthorizeRequest, take: bool) -> Choice {
        let mut holders = self.holders.lock().await;
        let now = Utc::now();
        let mut ordered: Vec<(&String, &GrantHolder)> = holders.map.iter().collect();
        ordered.sort_by_key(|(_, h)| micros(&h.grant()["valid_until"]).unwrap_or(i64::MAX));
        let mut ended: Option<String> = None;
        let mut outside: Option<String> = None;
        let mut usable: Option<String> = None;
        for (id, holder) in ordered {
            match holder.check(
                &request.capability,
                &request.request_parameters,
                Some(&request.resource_id),
                now,
            ) {
                None => {
                    usable = Some(id.clone());
                    break;
                }
                // Spent tokens: the holder asks for a fresh one when it can.
                Some(check) if check.code == "grant_time_token_exhausted" => {
                    if usable.is_none() && ended.is_none() {
                        usable = Some(id.clone());
                    }
                }
                Some(check) if check.code == "grant_capability_mismatch" => {}
                Some(check) if check.ends_use() => {
                    ended.get_or_insert(check.code);
                }
                Some(check) => {
                    outside.get_or_insert(check.code);
                }
            }
        }
        if let Some(id) = usable {
            if !take {
                return Choice::Covered;
            }
            let holder = holders.map.remove(&id).expect("held");
            holders.out = Some(id);
            return Choice::Use(Box::new(holder));
        }
        match (ended, outside) {
            (Some(code), _) => Choice::Ended(code),
            (None, Some(code)) => Choice::Outside(code),
            (None, None) => Choice::None,
        }
    }

    /// Act within a grant; `Err` is the grant code when the grant could not
    /// be used and no fallback ran.
    async fn act(
        &self,
        client: &GenesisMeshClient,
        mut holder: Box<GrantHolder>,
        request: &AuthorizeRequest,
        link: &Arc<Link>,
    ) -> Result<Finished, String> {
        // No fallback: when the grant cannot be used, the decision order
        // goes on (the NA, then break-glass, only when it does not answer).
        let grant_request =
            GrantRequest::new(&request.capability, request.request_parameters.clone())
                .on(&request.resource_id, &request.resource_action);
        let acted = holder
            .act(client, grant_request, |authority: GrantAuthority| {
                let granted = match authority {
                    GrantAuthority::Grant {
                        grant_id,
                        use_sequence,
                    } => Granted {
                        authority: "grant",
                        grant_id: Some(grant_id),
                        use_sequence: Some(use_sequence),
                        ..Granted::default()
                    },
                    GrantAuthority::Decision(decision) => Granted {
                        authority: "decision",
                        decision_id: decision["decision_id"].as_str().map(str::to_owned),
                        ..Granted::default()
                    },
                    GrantAuthority::BreakGlass => Granted {
                        authority: "break_glass",
                        ..Granted::default()
                    },
                };
                action(Arc::clone(link), granted)
            })
            .await;
        self.save_holder(&holder);
        {
            let mut holders = self.holders.lock().await;
            holders.out = None;
            holders.map.insert(holder.grant_id().to_owned(), *holder);
        }
        match acted {
            Ok(GrantActionOutcome::Used(used)) => Ok(Finished::Ran {
                record_kind: "grant_execution",
                record_id: used.record["use_id"].as_str().map(str::to_owned),
                queued: used.queued.is_some(),
                dropped: used.dropped,
            }),
            Ok(GrantActionOutcome::FellBack { outcome, .. }) => Ok(match *outcome {
                GovernedActionOutcome::Evaluated(result) => evaluated(result),
                GovernedActionOutcome::BrokeGlass(glass) => Finished::Ran {
                    record_kind: "break_glass",
                    record_id: glass.record["break_glass_id"].as_str().map(str::to_owned),
                    queued: glass.queued.is_some(),
                    dropped: glass.dropped,
                },
            }),
            Err(GenesisMeshError::GrantRefused { code, .. }) => Err(code),
            Err(err) => Ok(self.decision_error(err)),
        }
    }

    /// Break-glass: the NA gave no answer (or, with an expired certificate,
    /// cannot be asked). The change runs at once, and its record, signed with
    /// the executor key, names how the evaluation failed; the NA judges it
    /// when it arrives.
    async fn break_glass(
        &self,
        client: &GenesisMeshClient,
        recorder: &ExecutionRecorder,
        request: &AuthorizeRequest,
        evaluate: &Value,
        glass: BreakGlass,
        link: &Arc<Link>,
    ) -> Finished {
        let input = |report: ActionReport<()>| BreakGlassInput {
            attestation_id: evaluate["attestation_id"].as_str().map(str::to_owned),
            request_parameters: Some(request.request_parameters.clone()),
            attributes: Some(request.attributes.clone()),
            outcome: report.outcome,
            outcome_detail: report.outcome_detail,
            execution_parameters: report.execution_parameters,
            ..BreakGlassInput::new(
                &request.resource_id,
                &request.resource_action,
                &request.capability,
                glass.justification.clone(),
                evaluate.clone(),
                glass.failure,
            )
        };
        // Everything but the action's report is checked before it runs.
        if let Err(err) = recorder.sign_break_glass(input(ActionReport::default())) {
            return refused(err.code(), json!({"detail": err.to_string()}));
        }
        let report = action(
            Arc::clone(link),
            Granted {
                authority: "break_glass",
                code: Some(glass.grant_code.clone()),
                ..Granted::default()
            },
        )
        .await
        .unwrap_or_default();
        let (record, dropped) = match recorder.sign_break_glass(input(report.clone())) {
            Ok(record) => (record, Vec::new()),
            Err(_) => {
                // Reported metadata the secret guard refuses is left out.
                let cleaned = without_refused_metadata(
                    report.execution_parameters.as_ref().unwrap_or(&json!({})),
                    report.outcome_detail.as_deref(),
                );
                let report = ActionReport {
                    execution_parameters: Some(cleaned.execution_parameters),
                    outcome_detail: Some(cleaned.outcome_detail),
                    ..report
                };
                match recorder.sign_break_glass(input(report)) {
                    Ok(record) => (record, cleaned.dropped),
                    Err(err) => return Finished::Failed(err.to_string()),
                }
            }
        };
        match client.evidence_store.enqueue_record(record.clone()).await {
            Ok(delivery) => Finished::Ran {
                record_kind: "break_glass",
                record_id: record["break_glass_id"].as_str().map(str::to_owned),
                queued: delivery.queued.is_some(),
                dropped,
            },
            Err(err) => Finished::Failed(err.to_string()),
        }
    }
}

/// Break-glass for one request.
struct BreakGlass {
    justification: String,
    grant_code: String,
    failure: EvaluationFailure,
}

/// What asking the NA gave.
enum Asked {
    /// Its decision (the action ran or did not), or its refusal.
    Done(Finished),
    /// No answer: the NA could not be reached or did not answer in time.
    Unanswered(EvaluationFailure),
}

/// How a request that got no answer failed: no connection or a timeout.
/// Anything the NA answered (a `429`, a `5xx`, a refusal) is not this.
fn unanswered(err: &GenesisMeshError) -> Option<EvaluationFailure> {
    match err {
        GenesisMeshError::Network(_) => evaluation_failure(err),
        _ => None,
    }
}

/// Whether the NA answered (with an HTTP status).
fn answered(err: &GenesisMeshError) -> bool {
    matches!(
        err,
        GenesisMeshError::BadRequest { .. }
            | GenesisMeshError::Unauthorized { .. }
            | GenesisMeshError::NotFound { .. }
            | GenesisMeshError::Validation { .. }
            | GenesisMeshError::RateLimit { .. }
            | GenesisMeshError::Http { .. }
            | GenesisMeshError::ResponseBodyUnreadable { .. }
    )
}

/// What the decision order does with the grants.
enum Choice {
    /// Act within this holder's grant.
    Use(Box<GrantHolder>),
    /// A grant names the capability but does not cover the request.
    Outside(String),
    /// A grant covers the request (not taken: the snapshot is stale).
    Covered,
    /// A covering grant can no longer be used.
    Ended(String),
    /// No grant names the capability.
    None,
}

fn refused(code: &str, details: Value) -> Finished {
    Finished::Refused {
        code: code.to_owned(),
        details,
    }
}

fn refusal_detail(code: &str) -> &'static str {
    match code {
        "na_denied" => "the NA decided DENY",
        "na_refused" => "the NA refused the request",
        "decision_unverifiable" => "the NA's decision did not verify",
        "outside_grant" => "a grant names the capability but does not cover this request",
        "justification_required" => "no grant can be used; break-glass needs a justification",
        "no_attestation" => "no attestation issued to this node can be used",
        _ => "not allowed",
    }
}

fn evaluated<T>(result: genesis_mesh_sdk::GovernedActionResult<T>) -> Finished {
    if result.authorized {
        return Finished::Ran {
            record_kind: "execution",
            record_id: result
                .evidence
                .as_ref()
                .and_then(|e| e["evidence_id"].as_str())
                .map(str::to_owned),
            queued: result.queued.is_some(),
            dropped: Vec::new(),
        };
    }
    refused(
        "na_denied",
        json!({
            "denial_reason": result.summary.denial_reason,
            "decision_id": result.summary.decision_id,
        }),
    )
}

/// The SDK's action: hand the authority to the caller, then wait for the
/// outcome it reports; one not reported in time is recorded as a failure.
async fn action(link: Arc<Link>, granted: Granted) -> Result<ActionReport<()>, ActionError> {
    if let Some(sender) = lock(&link.granted).take() {
        let _ = sender.send(granted);
    }
    let receiver = lock(&link.outcome).take();
    let reported = match receiver {
        Some(receiver) => tokio::time::timeout(link.report_timeout, receiver)
            .await
            .ok()
            .and_then(Result::ok),
        None => None,
    };
    Ok(match reported {
        Some(outcome) => ActionReport {
            value: None,
            execution_parameters: outcome.execution_parameters,
            outcome: Some(outcome.outcome),
            outcome_detail: outcome.outcome_detail,
        },
        None => {
            link.expired.store(true, Ordering::Release);
            ActionReport {
                value: None,
                execution_parameters: None,
                outcome: Some("failure".into()),
                outcome_detail: Some(format!(
                    "not reported: no outcome within {} seconds",
                    link.report_timeout.as_secs()
                )),
            }
        }
    })
}

/// Why a holder's grant cannot be used now, whatever the request.
fn holder_code(holder: &GrantHolder, fresh: bool) -> Option<String> {
    let grant = holder.grant();
    let now = Utc::now().timestamp_micros();
    if holder.revoked() {
        return Some("grant_revoked".into());
    }
    if let Some(ended) = &holder.state().ended {
        return Some(ended.clone());
    }
    if micros(&grant["valid_until"]).is_none_or(|until| now > until) {
        return Some("grant_expired".into());
    }
    if micros(&grant["valid_from"]).is_none_or(|from| now < from) {
        return Some("grant_use_outside_validity".into());
    }
    if holder.remaining_uses() == 0 {
        return Some("grant_budget_exhausted".into());
    }
    (!fresh).then(|| "snapshot_stale".into())
}

/// Whether a CRL lists `cert_id`.
fn crl_names(crl: &Value, cert_id: &str) -> bool {
    crl["revoked_certificates"]
        .as_array()
        .is_some_and(|entries| entries.iter().any(|e| e["certificate_id"] == cert_id))
}

/// The attestations in a `/node/state` answer that verify, are the node's
/// and are active.
fn verified_attestations(
    node_state: &Value,
    na_keys: &[String],
    identity: &NodeIdentity,
) -> Vec<Value> {
    let sovereign = node_state["node"]["node_sovereign_id"].as_str();
    node_state["attestations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| {
            let attestation = &item["attestation"];
            let ours = attestation["subject_id"].as_str() == sovereign
                && (attestation["subject_public_key"].is_null()
                    || attestation["subject_public_key"] == identity.node_public_key());
            let verified = verify_attestation_signature(attestation, na_keys);
            if !(ours && verified) {
                log::warn(
                    "attestation_refused",
                    json!({"attestation_id": attestation["attestation_id"], "verified": verified}),
                );
            }
            ours && verified
        })
        .cloned()
        .collect()
}

/// A certificate without what the response added beside it.
fn strip_edge(cert: &Value) -> Value {
    let mut cert = cert.clone();
    if let Some(map) = cert.as_object_mut() {
        map.remove("edge");
    }
    cert
}

/// Check a certificate from `/join` or `/renew`: the NA signed it, it is this
/// node's, and the NA registered this executor key. Returns its `edge`
/// block.
fn check_certificate(
    cert: &Value,
    na_keys: &[String],
    node_public_key: &str,
    executor_public_key: &str,
) -> Result<Value, Exit> {
    if !verify_join_certificate(cert, na_keys) {
        return Err(Exit::Refused(
            "the certificate does not verify under the NA's keys".into(),
        ));
    }
    if cert["node_public_key"] != node_public_key {
        return Err(Exit::Refused(
            "the certificate names another node key".into(),
        ));
    }
    let edge = &cert["edge"];
    if edge.is_null() {
        return Err(Exit::Refused(
            "the NA does not register executor keys at join (needs 1.7.0)".into(),
        ));
    }
    let expected_id = executor_key_id(executor_public_key).map_err(internal)?;
    let key = &edge["executor_key"];
    if key["key_id"] != expected_id.as_str() || key["public_key"] != executor_public_key {
        return Err(Exit::Refused(
            "the NA registered another executor key than this node's".into(),
        ));
    }
    if !edge["node_sovereign_id"].is_string() || !key["resource_prefix"].is_string() {
        return Err(Exit::Refused(
            "the NA's edge block has no node_sovereign_id or resource_prefix".into(),
        ));
    }
    Ok(edge.clone())
}

/// Enrolment errors: unreachable (5) or refused (4).
fn unreachable_or_refused(err: &GenesisMeshError, doing: &str) -> Exit {
    if evaluation_failure(err).is_some() || err.code() == "response_body_unreadable" {
        Exit::Unreachable(format!("the NA could not be reached while {doing}: {err}"))
    } else {
        Exit::Refused(format!("the NA refused the enrolment while {doing}: {err}"))
    }
}
