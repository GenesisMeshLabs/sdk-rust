//! The agent: its enrolment, the trust snapshot, the schedule (heartbeat,
//! renewal, sync, uploads) and the decision order for one authorization
//! (docs/edge.md, "Decision order"; its rules are in `decision`).

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use genesis_mesh_sdk::{
    canonical::{parse_timestamp, python_timestamp},
    check_metadata_only, evaluation_failure, governed_action,
    grants::{envelope_problem, use_digest},
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
    db::{Db, DbError, SqliteOutbox, SqliteRecordOutbox},
    decision::{self, Answer, Candidate, GrantChoice, Next},
    log,
    state::{StateDir, StateError, DATABASE, ENROLLMENT, EXECUTOR_KEY, NODE_KEY, SNAPSHOT},
};

/// How far the device's clock may be behind the NA's signing time.
const CLOCK_SKEW_SECONDS: i64 = 300;

/// Records submitted per upload page: an upload never loads a whole backlog.
const UPLOAD_PAGE: usize = 200;

/// Pages a decision uploads before it asks the NA (sync uploads the rest).
const DECISION_PAGES: usize = 5;

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
            StateError::Busy(m) => Self::Usage(m),
            StateError::Io(m) => Self::Internal(m),
        }
    }
}

impl From<DbError> for Exit {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Newer(m) => Self::Usage(m),
            DbError::Io(e) => Self::Internal(e.to_string()),
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
    /// The client uploads go through: its outboxes list one page at a time.
    uploader: Option<GenesisMeshClient>,
    identity: Option<NodeIdentity>,
    recorder: Option<ExecutionRecorder>,
    snapshot: Value,
    na_keys: Vec<String>,
    revoked: bool,
    /// The NA's own last answer (not a proxy's page).
    last_contact: Option<DateTime<Utc>>,
    /// The NA's last accepted heartbeat: it trusts the certificate.
    heartbeat_ok: Option<DateTime<Utc>>,
    /// What the last failed exchange said, for `/v1/status`.
    last_answer: Option<Answer>,
    last_na_error: Option<Value>,
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
    /// One upload at a time.
    uploading: tokio::sync::Mutex<()>,
    /// One authorization at a time; others queue FIFO.
    slot: Arc<Semaphore>,
    open: Mutex<HashMap<String, Open>>,
    lost: AtomicU64,
}

/// An authorization handed to the caller, waiting for its outcome.
struct Open {
    /// The local client that asked (uid or token name): only it reports.
    client: String,
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
    expired: AtomicBool,
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

/// Aborts the decision task when the request that started it goes away
/// before the action was handed to it (the client disconnected): nothing
/// runs and nothing is signed.
struct AbortOnDrop(Option<tokio::task::AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
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

fn chrono(duration: Duration) -> chrono::Duration {
    chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::MAX)
}

/// A failed request to the NA that names a revoked node.
fn revoked_code(err: &GenesisMeshError) -> bool {
    matches!(err.code(), "certificate_revoked" | "edge_node_retired")
}

impl Agent {
    /// Open the state directory and what it holds. Refuses an enrolment with
    /// another NA than the configured one, and a database a newer agent
    /// wrote (exit 2).
    pub fn load(config: Config) -> Result<Arc<Self>, Exit> {
        let dir = StateDir::open(&config.state_dir)?;
        let db = Db::open(&dir.path(DATABASE))?;
        let lost = db.lose_open_authorizations().map_err(internal)?;
        let _ = db.prune_authorizations();
        let enrollment = dir.read_json(ENROLLMENT)?;
        if let Some(enrolled) = enrollment.as_ref().and_then(|e| e["na_url"].as_str()) {
            if enrolled.trim_end_matches('/') != config.na_url {
                return Err(Exit::Usage(format!(
                    "the agent is enrolled with {enrolled}, not the configured {}: run `genesis-mesh-edge reset` to enrol with another NA",
                    config.na_url
                )));
            }
        }
        let agent = Arc::new(Self {
            slot: Arc::new(Semaphore::new(1)),
            config,
            dir,
            db,
            shared: Mutex::new(Shared {
                enrollment: None,
                client: None,
                uploader: None,
                identity: None,
                recorder: None,
                snapshot: json!({}),
                na_keys: Vec::new(),
                revoked: false,
                last_contact: None,
                heartbeat_ok: None,
                last_answer: None,
                last_na_error: None,
            }),
            holders: tokio::sync::Mutex::new(Holders::default()),
            uploading: tokio::sync::Mutex::new(()),
            open: Mutex::new(HashMap::new()),
            lost: AtomicU64::new(lost),
        });
        if let Some(enrollment) = enrollment {
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

    /// Use an enrolment: the node identity, the clients acting as the node,
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
        let client_with = |outbox: SqliteOutbox, records: SqliteRecordOutbox| {
            GenesisMeshClient::new(
                self.client_options()
                    .with_audience(audience)
                    .with_outbox(Arc::new(outbox))
                    .with_record_outbox(Arc::new(records)),
            )
            .map(|c| c.with_node_identity(identity.clone()))
            .map_err(|e| Exit::Usage(e.to_string()))
        };
        let client = client_with(
            SqliteOutbox::new(self.db.clone()),
            SqliteRecordOutbox::new(self.db.clone()),
        )?;
        let uploader = client_with(
            SqliteOutbox::windowed(self.db.clone(), UPLOAD_PAGE),
            SqliteRecordOutbox::windowed(self.db.clone(), UPLOAD_PAGE),
        )?;
        let snapshot = self.dir.read_json(SNAPSHOT)?.unwrap_or_else(|| json!({}));
        let na_keys = self.keys_of(&snapshot["key_history"]).unwrap_or_default();
        let revoked = self.db.meta("revoked").map_err(internal)?.is_some()
            || crl_names(&snapshot["crl"], cert_id);
        let mut shared = lock(&self.shared);
        shared.enrollment = Some(enrollment);
        shared.client = Some(client);
        shared.uploader = Some(uploader);
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

    fn resource_prefix(&self) -> Option<String> {
        lock(&self.shared)
            .enrollment
            .as_ref()
            .and_then(|e| e["executor_key"]["resource_prefix"].as_str())
            .map(str::to_owned)
    }

    /// A holder's state advanced to the newest use of its grant the agent
    /// made (in the record outbox, or admitted): a crash between keeping a
    /// use and saving the holder never forks the chain.
    fn advance(&self, grant_id: &str, state: &mut GrantHolderState, uses: &[Value]) {
        let newest = uses
            .iter()
            .filter(|u| u["grant_id"].as_str() == Some(grant_id))
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
    }

    /// Restore the grant holders, each advanced to its newest use. A holder
    /// that does not restore is rebuilt at the next sync, from its uses.
    fn restore_holders(&self) -> Result<(), Exit> {
        let (recorder, keys) = {
            let shared = lock(&self.shared);
            (shared.recorder.clone(), shared.na_keys.clone())
        };
        let Some(recorder) = recorder else {
            return Ok(());
        };
        let prefix = self.resource_prefix();
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
            self.advance(&grant_id, &mut state, &uses);
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

    /// Where the agent stands now. A certificate the device's clock takes as
    /// expired is still in force while the NA accepts the node's heartbeats
    /// (the device's clock is ahead).
    pub fn state(&self) -> AgentState {
        let shared = lock(&self.shared);
        let Some(enrollment) = &shared.enrollment else {
            return AgentState::Unenrolled;
        };
        if shared.revoked {
            return AgentState::Revoked;
        }
        let now = Utc::now();
        match micros(&enrollment["cert"]["expires_at"]) {
            Some(expires) if expires > now.timestamp_micros() => AgentState::Active,
            _ if shared
                .heartbeat_ok
                .is_some_and(|at| now - at <= chrono(self.config.heartbeat_interval * 2)) =>
            {
                AgentState::Active
            }
            _ => AgentState::CertificateExpired,
        }
    }

    fn connected(&self) -> bool {
        let last = lock(&self.shared).last_contact;
        self.state() == AgentState::Active
            && last.is_some_and(|at| Utc::now() - at <= chrono(self.config.heartbeat_interval * 2))
    }

    /// Note an exchange with the NA: `Ok` or its error. Only the NA's own
    /// answers (not a proxy's page, not a timeout) count as contact.
    fn observe(&self, event: &str, result: Result<(), &GenesisMeshError>) {
        let mut shared = lock(&self.shared);
        let Err(err) = result else {
            shared.last_contact = Some(Utc::now());
            shared.last_answer = None;
            return;
        };
        let answer = decision::classify(err);
        if !matches!(answer, Answer::Unreachable(_)) {
            shared.last_contact = Some(Utc::now());
        }
        shared.last_na_error = Some(json!({
            "status": decision::status_of(err),
            "code": err.code(),
            "at": timestamp(Utc::now()),
        }));
        shared.last_answer = Some(answer);
        drop(shared);
        if revoked_code(err) {
            self.mark_revoked(err.code());
        } else if matches!(err.code(), "certificate_expired" | "node_auth_failed") {
            // A clock off by more than the NA's 300 s window, or an expired
            // certificate: the operator must see it.
            log::warn(event, json!({"code": err.code()}));
        } else {
            log::debug(event, json!({"code": err.code()}));
        }
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

    /// `(fresh, clock_behind)`: see `decision::freshness`.
    fn freshness(&self) -> (bool, bool) {
        decision::freshness(
            self.snapshot_age(),
            self.config.max_snapshot_age.as_secs() as i64,
            CLOCK_SKEW_SECONDS,
        )
    }

    fn snapshot_fresh(&self) -> bool {
        self.freshness().0
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

    /// Send a heartbeat (also with a certificate the device's clock takes as
    /// expired: the NA decides); true when the NA itself answered.
    pub async fn heartbeat(&self) -> bool {
        if !matches!(
            self.state(),
            AgentState::Active | AgentState::CertificateExpired
        ) {
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
                self.observe("heartbeat", Ok(()));
                lock(&self.shared).heartbeat_ok = Some(Utc::now());
                true
            }
            Err(err) => {
                self.observe("heartbeat_failed", Err(&err));
                !matches!(decision::classify(&err), Answer::Unreachable(_))
            }
        }
    }

    /// Renew the certificate when it expires within `renew_before`; keeps
    /// trying once it has expired (the NA refuses an expired certificate:
    /// docs/edge.md says how to recover). The new certificate is saved
    /// before it is used.
    pub async fn maybe_renew(&self) {
        if !matches!(
            self.state(),
            AgentState::Active | AgentState::CertificateExpired
        ) {
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
                self.observe("renewal_failed", Err(&err));
                return;
            }
        };
        self.observe("renewal", Ok(()));
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

    /// Upload the outboxes one page at a time, at most `pages` pages of
    /// each: break-glass records and grant uses (in chain order), then
    /// execution evidence. Records the NA asked to wait for
    /// (`Retry-After`) stay pending unless `ignore_backoff` (on reconnecting,
    /// once).
    async fn upload(&self, ignore_backoff: bool, pages: usize) -> Result<(), GenesisMeshError> {
        let Some(uploader) = lock(&self.shared).uploader.clone() else {
            return Ok(());
        };
        let _uploading = self.uploading.lock().await;
        let store = &uploader.evidence_store;
        let options = FlushOptions { ignore_backoff };
        let (mut admitted, mut quarantined, mut dead, mut first_error) = (0, 0, 0, None);
        for _ in 0..pages {
            match store.flush_records(options).await {
                Ok(report) => {
                    admitted += report.admitted.len();
                    quarantined += report.quarantined.len();
                    dead += report.dead_lettered.len();
                    if report.admitted.len() + report.dead_lettered.len() == 0 {
                        break;
                    }
                }
                Err(err) => {
                    first_error = Some(err);
                    break;
                }
            }
        }
        for _ in 0..pages {
            match store.flush_pending(options).await {
                Ok(report) => {
                    admitted += report.admitted.len();
                    dead += report.dead_lettered.len();
                    if report.admitted.len() + report.dead_lettered.len() == 0 {
                        break;
                    }
                }
                Err(err) => {
                    first_error.get_or_insert(err);
                    break;
                }
            }
        }
        if admitted + dead > 0 {
            log::info(
                "uploaded",
                json!({"admitted": admitted, "quarantined": quarantined, "dead_lettered": dead}),
            );
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Sync with the NA: the key history, the CRL, the revocation feed and
    /// the node's state; new grants get a holder; then the uploads (they run
    /// even when a read failed: records are signed with the executor key,
    /// not the node key) and a fresh time token for every usable holder.
    /// `reconnected` uploads past the NA's backoff once.
    pub async fn sync(&self, reconnected: bool) -> Result<(), GenesisMeshError> {
        let state = self.state();
        if !matches!(state, AgentState::Active | AgentState::CertificateExpired) {
            return Ok(());
        }
        let Some((client, identity)) = self.node() else {
            return Ok(());
        };
        let reads = self.read_snapshot(&client, &identity, state).await;
        if self.state() == AgentState::Revoked {
            return Ok(());
        }
        let uploaded = self.upload(reconnected, usize::MAX).await;
        let _ = self.db.prune_authorizations();
        let na_keys = lock(&self.shared).na_keys.clone();
        let mut holders = self.holders.lock().await;
        let outbox = SqliteRecordOutbox::new(self.db.clone());
        for holder in holders.map.values_mut() {
            let _ = holder.count_quarantined(&outbox).await;
            if reads.is_ok()
                && !holder.revoked()
                && holder.state().ended.is_none()
                && holder.remaining_uses() > 0
            {
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
        if reads.is_ok() {
            if let Ok(node_state) = &reads {
                let feed = lock(&self.shared).snapshot["revocation_feed"].clone();
                self.sync_grants(&client, node_state, &feed, &na_keys).await;
            }
        }
        reads.map(drop)?;
        uploaded
    }

    /// The reads of a sync, verified, into the snapshot. Returns the node
    /// state (the one held when the NA was not asked).
    async fn read_snapshot(
        &self,
        client: &GenesisMeshClient,
        identity: &NodeIdentity,
        state: AgentState,
    ) -> Result<Value, GenesisMeshError> {
        let transport = self.transport()?;
        let read = |result: Result<Value, GenesisMeshError>, event: &str| {
            self.observe(event, result.as_ref().map(drop));
            result
        };
        let key_history = read(
            transport.public_get("/na/key-history").await,
            "key_history_failed",
        )?;
        let Some(na_keys) = self.keys_of(&key_history) else {
            log::error("key_history_unverified", json!({}));
            return Err(GenesisMeshError::Verification(
                "the NA's key history does not verify".into(),
            ));
        };
        let crl = read(transport.public_get("/crl").await, "crl_failed")?;
        let feed = read(client.grants.revocation_feed().await, "feed_failed")?;
        if !verify_crl(&crl, &na_keys) {
            log::error("crl_unverified", json!({}));
            return Err(GenesisMeshError::Verification(
                "the CRL does not verify".into(),
            ));
        }
        if crl_names(&crl, identity.cert_id()) {
            self.mark_revoked("certificate_in_crl");
            return Ok(Value::Null);
        }
        let mut node_state = Value::Null;
        if state == AgentState::Active {
            let answer = read(client.node.state(identity).await, "node_state_failed");
            match answer {
                Ok(answer) => {
                    // An executor key retired another way than by revoking
                    // the node: its records would be refused.
                    if decision::executor_key_retired(&answer) {
                        self.mark_revoked("executor_key_retired");
                        return Ok(Value::Null);
                    }
                    node_state = answer;
                }
                Err(err) if revoked_code(&err) => return Ok(Value::Null),
                Err(err) => return Err(err),
            }
        }
        if !node_state.is_null() {
            node_state["attestations"] =
                Value::Array(verified_attestations(&node_state, &na_keys, identity));
        }
        let mut shared = lock(&self.shared);
        shared.na_keys = na_keys;
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
        Ok(node_state)
    }

    /// Holders for new grants: rebuilt from the uses the agent made of the
    /// grant when it made any (never from use 0 again), with a time token
    /// naming the newest; the resource prefix and the revocation feed for
    /// every holder.
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
            .or_else(|| self.resource_prefix());
        let uses = self.db.grant_uses().unwrap_or_default();
        let mut holders = self.holders.lock().await;
        for grant in node_state["grants"].as_array().into_iter().flatten() {
            let Some(grant_id) = grant["grant_id"].as_str() else {
                continue;
            };
            if holders.map.contains_key(grant_id) || holders.out.as_deref() == Some(grant_id) {
                continue;
            }
            let mut state: GrantHolderState = match serde_json::from_value(json!({
                "grant": grant, "time_token": {}, "uses": 0, "head_digest": null,
                "head_executed_at": null, "feed": null, "ended": null,
            })) {
                Ok(state) => state,
                Err(_) => continue,
            };
            self.advance(grant_id, &mut state, &uses);
            let request = match recorder.sign_time_token_request(
                grant_id,
                state.uses,
                state.head_digest.as_deref(),
                None,
            ) {
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
            state.time_token = token;
            match GrantHolder::restore(state, recorder.clone(), na_keys.to_vec()) {
                Ok(holder) => {
                    log::info(
                        "grant_held",
                        json!({"grant_id": grant_id, "capabilities": grant["capabilities"], "uses": holder.uses()}),
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
        let mut reconnected = true;
        loop {
            let now = tokio::time::Instant::now();
            if now >= next_heartbeat {
                self.maybe_renew().await;
                let answered = self.heartbeat().await;
                next_heartbeat = now + self.config.heartbeat_interval;
                if answered && !was_connected {
                    // Reconnected: sync now, past the NA's backoff once.
                    next_sync = now;
                    reconnected = true;
                }
                was_connected = answered;
            }
            if tokio::time::Instant::now() >= next_sync && self.enrolled() {
                match self.sync(reconnected).await {
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
                reconnected = false;
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
        let (fresh, clock_behind) = self.freshness();
        let (enrollment, snapshot, last_contact, last_answer, last_na_error) = {
            let shared = lock(&self.shared);
            (
                shared.enrollment.clone().unwrap_or(Value::Null),
                shared.snapshot.clone(),
                shared.last_contact,
                shared.last_answer.clone(),
                shared.last_na_error.clone(),
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
            "na_state": decision::na_state(last_answer.as_ref()),
            "last_na_error": last_na_error,
            "last_na_contact_at": last_contact.map(timestamp),
            "snapshot_synced_at": snapshot["synced_at"],
            "snapshot_age_seconds": self.snapshot_age().map(|age| age.max(0)),
            "snapshot_fresh": fresh,
            "clock_behind": clock_behind,
            "grants": grants,
            "pending_uploads": pending,
            "dead_letters": dead,
            "lost_authorizations": self.lost.load(Ordering::Relaxed),
        })
    }

    /// `POST /v1/authorize` from local `client`: decide, and when allowed
    /// hand the authority to the caller and wait for its outcome.
    pub async fn authorize(
        self: &Arc<Self>,
        request: AuthorizeRequest,
        client: &str,
    ) -> Result<Value, ApiError> {
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
        let prefix = self.resource_prefix().unwrap_or_default();
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
            expired: AtomicBool::new(false),
        });
        log::info(
            "authorization_requested",
            json!({
                "authorization_id": id,
                "client": client,
                "capability": request.capability,
                "resource_id": request.resource_id,
                "resource_action": request.resource_action,
                "justification_length": request.justification.as_ref().map(|j| j.chars().count()),
            }),
        );
        let agent = Arc::clone(self);
        let task_link = Arc::clone(&link);
        let mut task = tokio::spawn(async move { agent.decide(request, task_link, permit).await });
        // If this request goes away before the action is handed over (the
        // client disconnected), the decision is abandoned: nothing runs.
        let mut guard = AbortOnDrop(Some(task.abort_handle()));
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
        guard.0 = None;
        if let Some(granted) = answer {
            let report_by = Utc::now() + chrono(self.config.report_timeout);
            let _ = self
                .db
                .set_authorization(&id, "open", Some(granted.authority), None);
            lock(&self.open).insert(
                id.clone(),
                Open {
                    client: client.to_owned(),
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

    /// `POST /v1/authorizations/{id}/outcome` from local `client`: only the
    /// client that asked may report.
    pub async fn report(
        &self,
        id: &str,
        client: &str,
        outcome: Outcome,
    ) -> Result<Value, ApiError> {
        let open = {
            let mut open = lock(&self.open);
            match open.get(id) {
                Some(held) if held.client != client => None,
                Some(_) => open.remove(id),
                None => None,
            }
        };
        let Some(mut open) = open else {
            return Err(match self.authorization_state(id).as_deref() {
                _ if lock(&self.open).contains_key(id) => {
                    log::warn(
                        "outcome_refused",
                        json!({"authorization_id": id, "client": client}),
                    );
                    ApiError::new(404, "authorization_not_found", "no such authorization")
                }
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

    /// On SIGTERM: take no new authorization (the slot closes first, so a
    /// queued request is refused, never decided), wait up to `wait` for the
    /// open one, then record it as not reported (a failure).
    pub async fn shut_down(&self, wait: Duration) {
        self.slot.close();
        let start = tokio::time::Instant::now();
        while self.slot.available_permits() == 0 && start.elapsed() < wait {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let open: Vec<(String, Open)> = lock(&self.open).drain().collect();
        for (id, mut open) in open {
            if open.task.is_finished() {
                continue;
            }
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
        let (recorder, na_keys, node_state) = {
            let shared = lock(&self.shared);
            (
                shared.recorder.clone(),
                shared.na_keys.clone(),
                shared.snapshot["node_state"].clone(),
            )
        };
        let Some(recorder) = recorder else {
            return Finished::Failed("not enrolled".into());
        };
        let attestation = match self.attestation(&request, &node_state["attestations"]) {
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

        // 1. Connected: the NA decides. Its refusal is final; when it
        // throttles or fails, grants may still act; when it does not answer
        // (or a proxy answers for it), grants then break-glass.
        let mut asked = None;
        if state == AgentState::Active && self.connected() {
            if let Some(evaluate) = &evaluate {
                match self
                    .ask(&client, &recorder, params(evaluate.clone()), &link)
                    .await
                {
                    Ok(finished) => return finished,
                    Err(answer) => asked = Some(answer),
                }
            }
        }

        // 2. Grants. A request a grant names but does not cover is refused,
        // fresh snapshot or not; a covered one is acted on only while the
        // snapshot is fresh.
        let (fresh, clock_behind) = self.freshness();
        let choice = self
            .choose_holder(&request, &node_state, clock_behind)
            .await;
        if let (true, GrantChoice::Use(_)) = (fresh, &choice) {
            if let Some(holder) = self.take_holder(&request, clock_behind).await {
                match self.act(&client, holder, &request, &link).await {
                    Ok(finished) => return finished,
                    Err(code) => {
                        return self
                            .after_grants(
                                &client, &recorder, &request, evaluate, asked, state, code, &link,
                                params,
                            )
                            .await
                    }
                }
            }
        }
        let Some(grant_code) = decision::grant_code(&choice, fresh) else {
            let GrantChoice::Outside(code) = choice else {
                unreachable!("only outside_grant has no grant code");
            };
            return refused("outside_grant", json!({"grant_code": code}));
        };
        self.after_grants(
            &client, &recorder, &request, evaluate, asked, state, grant_code, &link, params,
        )
        .await
    }

    /// Steps 3 and 4: refuse, ask the NA, or break the glass.
    #[allow(clippy::too_many_arguments)]
    async fn after_grants(
        &self,
        client: &GenesisMeshClient,
        recorder: &ExecutionRecorder,
        request: &AuthorizeRequest,
        evaluate: Option<Value>,
        mut asked: Option<Answer>,
        state: AgentState,
        grant_code: String,
        link: &Arc<Link>,
        params: impl Fn(Value) -> GovernedActionParams,
    ) -> Finished {
        loop {
            let next = decision::after_grants(
                asked.as_ref(),
                &grant_code,
                request.justification.is_some(),
                evaluate.is_some(),
                state == AgentState::CertificateExpired,
            );
            match next {
                Next::Refuse(code, details) => return refused(code, details),
                Next::BreakGlass(failure) => {
                    let (Some(evaluate), Some(justification)) =
                        (evaluate.as_ref(), request.justification.clone())
                    else {
                        unreachable!("break-glass needs an attestation and a justification");
                    };
                    return self
                        .break_glass(
                            client,
                            recorder,
                            request,
                            evaluate,
                            BreakGlass {
                                justification,
                                grant_code,
                                failure,
                            },
                            link,
                        )
                        .await;
                }
                Next::Ask => {
                    let evaluate = evaluate.clone().unwrap_or_default();
                    match self.ask(client, recorder, params(evaluate), link).await {
                        Ok(finished) => return finished,
                        // Asked once: the next round refuses or breaks the glass.
                        Err(answer) => asked = Some(answer),
                    }
                }
            }
        }
    }

    /// Ask the NA to decide (`governed_action` through the node route):
    /// `Ok` when it decided or refused for good, `Err` with what its error
    /// means otherwise.
    async fn ask(
        &self,
        client: &GenesisMeshClient,
        recorder: &ExecutionRecorder,
        params: GovernedActionParams,
        link: &Arc<Link>,
    ) -> Result<Finished, Answer> {
        // Uses and break-glass records still pending go first, so a decision's
        // evidence follows them in the resource's chain (a few pages: the
        // schedule uploads the rest).
        let _ = self.upload(false, DECISION_PAGES).await;
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
                self.observe("decision", Ok(()));
                Ok(evaluated(result))
            }
            Err(err) => {
                self.observe("evaluate_failed", Err(&err));
                match decision::classify(&err) {
                    Answer::Refused => Ok(self.decision_error(err)),
                    answer => {
                        log::info(
                            "na_not_deciding",
                            json!({"code": err.code(), "status": decision::status_of(&err)}),
                        );
                        Err(answer)
                    }
                }
            }
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
            _ => refused(
                "na_refused",
                json!({"na_code": err.code(), "na_status": decision::status_of(&err)}),
            ),
        }
    }

    /// The candidates for a request, soonest end first: every held grant,
    /// and every grant the node state lists without a holder (by its
    /// capabilities and envelope only).
    fn candidates<'a>(
        holders: &'a Holders,
        request: &AuthorizeRequest,
        node_state: &Value,
    ) -> Vec<(Option<&'a String>, Candidate)> {
        let now = Utc::now();
        let mut ordered: Vec<(i64, Option<&String>, Candidate)> = holders
            .map
            .iter()
            .map(|(id, holder)| {
                let code = holder
                    .check(
                        &request.capability,
                        &request.request_parameters,
                        Some(&request.resource_id),
                        now,
                    )
                    .map(|check| check.code);
                (
                    micros(&holder.grant()["valid_until"]).unwrap_or(i64::MAX),
                    Some(id),
                    Candidate { held: true, code },
                )
            })
            .collect();
        for grant in node_state["grants"].as_array().into_iter().flatten() {
            let id = grant["grant_id"].as_str().unwrap_or_default();
            if holders.map.contains_key(id) || holders.out.as_deref() == Some(id) {
                continue;
            }
            let named = grant["capabilities"]
                .as_array()
                .is_some_and(|c| c.iter().any(|c| c == request.capability.as_str()));
            let code = if !named {
                Some("grant_capability_mismatch".to_owned())
            } else {
                envelope_problem(&grant["parameter_envelope"], &request.request_parameters)
                    .map(|_| "grant_envelope_mismatch".to_owned())
            };
            ordered.push((
                micros(&grant["valid_until"]).unwrap_or(i64::MAX),
                None,
                Candidate { held: false, code },
            ));
        }
        ordered.sort_by_key(|(until, _, _)| *until);
        ordered.into_iter().map(|(_, id, c)| (id, c)).collect()
    }

    /// Which grant decides the request (`decision::choose`).
    async fn choose_holder(
        &self,
        request: &AuthorizeRequest,
        node_state: &Value,
        clock_behind: bool,
    ) -> GrantChoice {
        let holders = self.holders.lock().await;
        let candidates = Self::candidates(&holders, request, node_state);
        let plain: Vec<Candidate> = candidates.into_iter().map(|(_, c)| c).collect();
        decision::choose(&plain, clock_behind)
    }

    /// Take the holder `decision::choose` picks out of the map while it acts.
    async fn take_holder(
        &self,
        request: &AuthorizeRequest,
        clock_behind: bool,
    ) -> Option<Box<GrantHolder>> {
        let node_state = lock(&self.shared).snapshot["node_state"].clone();
        let mut holders = self.holders.lock().await;
        let candidates = Self::candidates(&holders, request, &node_state);
        let plain: Vec<Candidate> = candidates.iter().map(|(_, c)| c.clone()).collect();
        let GrantChoice::Use(index) = decision::choose(&plain, clock_behind) else {
            return None;
        };
        let id = candidates[index].0?.clone();
        let holder = holders.map.remove(&id)?;
        holders.out = Some(id);
        Some(Box::new(holder))
    }

    /// Act within a grant; `Err` is the grant code when the grant could not
    /// be used.
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

fn refused(code: &str, details: Value) -> Finished {
    Finished::Refused {
        code: code.to_owned(),
        details,
    }
}

fn refusal_detail(code: &str) -> &'static str {
    match code {
        "na_denied" => "the NA decided DENY",
        "na_refused" => "the NA refused the request, or is throttling or failing",
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
/// When the caller is gone before the authority reaches it, nothing runs:
/// the action never returns, and the abandoned decision task is aborted
/// before anything is signed.
async fn action(link: Arc<Link>, granted: Granted) -> Result<ActionReport<()>, ActionError> {
    let sender = lock(&link.granted).take();
    if sender.is_none_or(|sender| sender.send(granted).is_err()) {
        log::warn("authorization_abandoned", json!({}));
        std::future::pending::<()>().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_closed_slot_decides_no_queued_request() {
        // shut_down closes the slot first: the request queued behind the
        // open authorization is refused, never handed the permit.
        let slot = Arc::new(Semaphore::new(1));
        let open = Arc::clone(&slot).acquire_owned().await.unwrap();
        let queued = tokio::spawn({
            let slot = Arc::clone(&slot);
            async move { slot.acquire_owned().await.is_ok() }
        });
        tokio::task::yield_now().await;
        slot.close();
        assert!(!queued.await.unwrap(), "a queued request got the slot");
        assert_eq!(slot.available_permits(), 0);
        drop(open);
        // The open authorization's end is still seen while stopping.
        assert_eq!(slot.available_permits(), 1);
    }
}
