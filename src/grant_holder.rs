//! A grant's holder (Genesis Mesh 1.6.0): acts within a pre-issued grant
//! while the Network Authority (NA) cannot be reached, records each use, and
//! uploads the uses when it can reach the NA again.
//!
//! The holder checks every use offline against what it holds: the
//! capability, the closed parameter envelope, the budget (the uses it made,
//! but those the NA quarantined once it said so, 1.7.0),
//! the validity, the uses its latest time token may still anchor, and the
//! revocation feed it last read. A use is signed with the grant's bearer key
//! (the executor key of the [`ExecutionRecorder`]), chained to the previous
//! use, kept in the record outbox and submitted; what the NA has not admitted
//! is uploaded by [`GrantHolder::sync`] (or
//! [`EvidenceStoreClient::flush_records`](crate::EvidenceStoreClient::flush_records)).
//!
//! When the grant has ended, its budget or time token is spent, or it is
//! revoked, the holder falls back, when told how
//! ([`GrantFallback`]), to [`governed_action_with_break_glass`]: the NA
//! decides when it answers (a DENY is never broken through), and when it
//! does not, the change runs under break-glass naming the capability and is
//! judged afterwards. An urgent change is recorded and judged, never blocked.

use std::future::Future;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    canonical::{parse_timestamp, python_timestamp},
    client::GenesisMeshClient,
    errors::{ActionValue, GenesisMeshError, Result},
    evidence_store::FlushOptions,
    execution::{resource_problem, ExecutionRecorder},
    governance::{
        evaluation_failure, governed_action_with_break_glass, without_refused_metadata,
        ActionError, ActionReport, BreakGlassOptions, GovernedActionOutcome, GovernedActionParams,
        GovernedVerification,
    },
    grant_client::GrantClient,
    grants::{envelope_problem, grant_digest, use_digest, use_secret_problem, GrantUseInput},
    outbox::{OutboxState, RecordFlushReport, RecordKind, RecordOutbox, RecordOutboxEntry},
    verify::{verify_record, verify_revocation_feed, VerifyRecordOptions},
};

/// What a holder keeps of its grant (1.6.0), to persist between runs: the
/// grant, its latest time token, the head of its use chain, the revocation
/// feed it last read, and what the NA told it about the grant. Serialize it
/// after every use ([`GrantHolder::state`]) and give it back to
/// [`GrantHolder::restore`]: a holder that forgets its uses would sign a
/// second use at a position it already used, which the NA refuses and keeps
/// (`grant_use_conflict`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GrantHolderState {
    /// The signed grant.
    pub grant: Value,
    /// The latest time token the NA signed for this holder.
    pub time_token: Value,
    /// Uses made so far: the last one's `use_sequence`.
    pub uses: u64,
    /// The last use's digest; `None` before the first.
    pub head_digest: Option<String>,
    /// When the last use was made (RFC 3339, UTC).
    pub head_executed_at: Option<String>,
    /// The last revocation feed read, verified.
    pub feed: Option<Value>,
    /// Why the NA said the grant can no longer be used, when it did
    /// (`grant_revoked`, `grant_expired`, `grant_budget_exhausted`,
    /// `grant_bearer_key_retired`).
    pub ended: Option<String>,
    /// The bearer key's `resource_prefix`, when the NA registered it with
    /// one ([`GrantHolder::set_resource_prefix`]): a use outside it is
    /// refused offline (`grant_use_out_of_scope`).
    #[serde(default)]
    pub resource_prefix: Option<String>,
}

/// Why a grant does not cover a request, or cannot be used for it now
/// ([`GrantHolder::check`]). `code` is the code the NA would give.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantCheck {
    /// `grant_capability_mismatch` or `grant_envelope_mismatch` (the grant
    /// does not cover the request), `grant_use_outside_validity` (not valid
    /// yet), or one that ends its use: `grant_revoked`, `grant_expired`,
    /// `grant_budget_exhausted`, `grant_bearer_key_retired`,
    /// `grant_time_token_exhausted`.
    pub code: String,
    /// What is wrong.
    pub detail: String,
}

/// The codes after which a holder falls back to a decision or break-glass.
const ENDED: [&str; 5] = [
    "grant_revoked",
    "grant_expired",
    "grant_budget_exhausted",
    "grant_bearer_key_retired",
    "grant_time_token_exhausted",
];

/// The refusals of a quarantined use that still counts against the budget
/// (1.7.0): a conflict or a chain mismatch did not continue the chain, and a
/// use refused as over budget means the holder's count is short of the NA's.
const STILL_COUNTED: [&str; 3] = [
    "grant_use_conflict",
    "grant_use_chain_mismatch",
    "grant_budget_exhausted",
];

/// What the NA answers to a time token request for a grant that can no
/// longer be used (`409`).
const NA_ENDED: [&str; 4] = [
    "grant_revoked",
    "grant_expired",
    "grant_budget_exhausted",
    "grant_bearer_key_retired",
];

impl GrantCheck {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            detail: detail.into(),
        }
    }

    /// Whether the grant can no longer be used (it ended, is spent or
    /// revoked, or its time token is spent and no new one came): the holder
    /// then falls back. A request the grant does not cover never falls back.
    pub fn ends_use(&self) -> bool {
        ENDED.contains(&self.code.as_str())
    }

    fn refusal(&self) -> GenesisMeshError {
        GenesisMeshError::GrantRefused {
            code: self.code.clone(),
            message: self.detail.clone(),
        }
    }
}

/// How an action under a grant is authorised, as the action receives it.
#[derive(Debug, Clone, PartialEq)]
pub enum GrantAuthority {
    /// The grant: the action runs as this use of it.
    Grant {
        /// The grant.
        grant_id: String,
        /// The use's place in the grant's chain.
        use_sequence: u64,
    },
    /// The fallback's decision: the NA allowed the change.
    Decision(Value),
    /// The fallback's break-glass: the NA could not be reached.
    BreakGlass,
}

/// What a holder falls back to when its grant can no longer be used.
#[derive(Debug, Clone)]
pub struct GrantFallback {
    /// Why the change cannot wait: 1 to 1024 characters, no secret values;
    /// recorded in a break-glass record.
    pub justification: String,
    /// How the NA's decision must verify when it answers.
    pub verify: GovernedVerification,
    /// The request's attributes for the evaluation. Defaults to `{}`.
    pub attributes: Option<Value>,
    /// The `/admin/boundary/evaluate` body. Defaults, for a grant on an
    /// attestation, to the capability under that attestation with the
    /// request's parameters; required for a grant on an agreement.
    pub evaluate: Option<Value>,
}

impl GrantFallback {
    /// Fall back with this justification, verifying decisions with `verify`.
    pub fn new(justification: impl Into<String>, verify: GovernedVerification) -> Self {
        Self {
            justification: justification.into(),
            verify,
            attributes: None,
            evaluate: None,
        }
    }
}

/// One action under a grant ([`GrantHolder::act`]).
#[derive(Debug, Clone, Default)]
pub struct GrantRequest {
    /// The capability, one of the grant's.
    pub capability: String,
    /// The request's parameters, inside the grant's envelope. Defaults to
    /// `{}`.
    pub request_parameters: Option<Value>,
    /// The resource acted on, e.g. `kv:<vault>/<secret>`; with
    /// `resource_action`.
    pub resource_id: Option<String>,
    /// `create`, `rotate`, `revoke`, `update` or `delete`.
    pub resource_action: Option<String>,
    /// What to do when the grant can no longer be used; `None` refuses
    /// ([`GenesisMeshError::GrantRefused`]).
    pub fallback: Option<GrantFallback>,
}

impl GrantRequest {
    /// A request for `capability` with these parameters.
    pub fn new(capability: impl Into<String>, request_parameters: Value) -> Self {
        Self {
            capability: capability.into(),
            request_parameters: Some(request_parameters),
            ..Self::default()
        }
    }

    /// On this resource.
    pub fn on(mut self, resource_id: impl Into<String>, action: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self.resource_action = Some(action.into());
        self
    }

    /// Falling back this way when the grant can no longer be used.
    pub fn with_fallback(mut self, fallback: GrantFallback) -> Self {
        self.fallback = Some(fallback);
        self
    }
}

/// The action ran as a use of the grant.
#[derive(Debug)]
#[non_exhaustive]
pub struct GrantUseResult<T> {
    /// The action's value.
    pub value: Option<T>,
    /// The signed use (`GrantExecutionEvidence`).
    pub record: Value,
    /// The NA's answer, when it was reachable (`status` `recorded`, with
    /// the `resource_sequence` it gave the use, or `duplicate`).
    pub submission: Option<Value>,
    /// The record outbox entry holding the use otherwise: pending for
    /// [`GrantHolder::sync`], or a dead letter.
    pub queued: Option<RecordOutboxEntry>,
    /// Reported metadata the secret guard refused, left out of the use
    /// (named in its `outcome_detail`); empty when none was.
    pub dropped: Vec<String>,
}

/// What [`GrantHolder::act`] did.
#[derive(Debug)]
// Boxing the use would change the public API; one outcome per action.
#[allow(clippy::large_enum_variant)]
pub enum GrantActionOutcome<T> {
    /// The action ran under the grant.
    Used(GrantUseResult<T>),
    /// The grant could no longer be used (`unusable`), and the holder fell
    /// back to a decision, or to break-glass when the NA did not answer.
    FellBack {
        /// Why the grant could not be used.
        unusable: GrantCheck,
        /// The governed action's outcome: an ALLOW that ran, a DENY that did
        /// not, or break-glass.
        outcome: Box<GovernedActionOutcome<T>>,
    },
}

/// What [`GrantHolder::sync`] did.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GrantSync {
    /// The revocation feed was read and verified.
    pub feed_read: bool,
    /// The feed lists the grant as revoked.
    pub revoked: bool,
    /// The record outbox's flush (the uses, and any other pending record).
    pub uploads: Option<RecordFlushReport>,
    /// A new time token was received.
    pub time_token_refreshed: bool,
    /// Why the NA said the grant can no longer be used, when it did.
    pub ended: Option<String>,
}

/// Holds one pre-issued grant and acts within it (1.6.0). See the module
/// documentation; take `&mut self`, so uses are made one at a time.
#[derive(Debug, Clone)]
pub struct GrantHolder {
    recorder: ExecutionRecorder,
    na_public_keys: Vec<String>,
    state: GrantHolderState,
    /// Of the uses made, those the NA quarantined after they continued the
    /// chain (1.7.0): read from the record outbox's dead letters.
    quarantined: u64,
}

fn micros_of(value: &Value, key: &str) -> Option<i64> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| parse_timestamp(s).ok())
        .map(|t| t.timestamp_micros())
}

fn invalid(detail: impl Into<String>) -> GenesisMeshError {
    GenesisMeshError::Verification(detail.into())
}

impl GrantHolder {
    /// A holder of `grant` with its first `time_token`, as
    /// [`GrantClient::issue`] returns them, signing uses with `recorder` (the
    /// grant's bearer key). The grant and the token must verify under
    /// `na_public_keys`, name this recorder's key, sovereign and public key
    /// as the bearer, and the token must be the grant's, before any use
    /// ([`GenesisMeshError::Verification`] otherwise).
    pub fn new(
        grant: Value,
        time_token: Value,
        recorder: ExecutionRecorder,
        na_public_keys: Vec<String>,
    ) -> Result<Self> {
        Self::restore(
            GrantHolderState {
                grant,
                time_token,
                uses: 0,
                head_digest: None,
                head_executed_at: None,
                feed: None,
                ended: None,
                resource_prefix: None,
            },
            recorder,
            na_public_keys,
        )
    }

    /// A holder of the grant [`GrantClient::issue`] answered with
    /// (`{grant, time_token, ...}`).
    pub fn from_issued(
        issued: &Value,
        recorder: ExecutionRecorder,
        na_public_keys: Vec<String>,
    ) -> Result<Self> {
        Self::new(
            issued["grant"].clone(),
            issued["time_token"].clone(),
            recorder,
            na_public_keys,
        )
    }

    /// A holder from its saved state ([`GrantHolder::state`]), checked as
    /// [`GrantHolder::new`] checks a new one.
    pub fn restore(
        state: GrantHolderState,
        recorder: ExecutionRecorder,
        na_public_keys: Vec<String>,
    ) -> Result<Self> {
        let holder = Self {
            recorder,
            na_public_keys,
            state,
            quarantined: 0,
        };
        holder.check_grant()?;
        holder.check_token(&holder.state.time_token)?;
        if holder.state.uses > 0
            && (holder.state.head_digest.is_none() || holder.state.head_executed_at.is_none())
        {
            return Err(invalid(
                "a holder with uses keeps its last use's digest and time",
            ));
        }
        if let Some(feed) = &holder.state.feed {
            holder.check_feed(feed)?;
        }
        Ok(holder)
    }

    fn options(&self) -> VerifyRecordOptions {
        VerifyRecordOptions {
            na_public_keys: self.na_public_keys.clone(),
            ..VerifyRecordOptions::default()
        }
    }

    fn check_grant(&self) -> Result<()> {
        let grant = &self.state.grant;
        let checked = verify_record("grant", grant, &self.options());
        if !checked.verified {
            return Err(invalid(format!(
                "the grant does not verify: {}",
                checked.reason
            )));
        }
        let field = |key: &str| grant[key].as_str().unwrap_or_default();
        if field("bearer_key_id") != self.recorder.key_id()
            || field("bearer_sovereign_id") != self.recorder.executor_sovereign_id()
            || field("bearer_public_key") != self.recorder.public_key()
        {
            return Err(invalid(
                "the grant's bearer is not this recorder's key and sovereign",
            ));
        }
        Ok(())
    }

    fn check_token(&self, token: &Value) -> Result<()> {
        let checked = verify_record("time_token", token, &self.options());
        if !checked.verified {
            return Err(invalid(format!(
                "the time token does not verify: {}",
                checked.reason
            )));
        }
        if token["grant_id"] != self.state.grant["grant_id"] {
            return Err(invalid("the time token is another grant's"));
        }
        if micros_of(token, "issued_at") < micros_of(&self.state.grant, "issued_at") {
            return Err(invalid("the time token is older than the grant"));
        }
        // It names the head of this holder's chain when it asked.
        let sequence = token["use_sequence"].as_u64().unwrap_or(u64::MAX);
        if sequence > self.state.uses {
            return Err(invalid(
                "the time token names uses this holder did not make",
            ));
        }
        if sequence == self.state.uses
            && token["use_head_digest"].as_str() != self.state.head_digest.as_deref()
        {
            return Err(invalid(
                "the time token names another use than this holder's last",
            ));
        }
        Ok(())
    }

    fn check_feed(&self, feed: &Value) -> Result<()> {
        if !verify_revocation_feed(feed, &self.na_public_keys) {
            return Err(invalid(
                "the revocation feed does not verify under the NA's keys",
            ));
        }
        if feed["issuer_sovereign_id"] != self.state.grant["issuer_sovereign_id"] {
            return Err(invalid("the revocation feed is another sovereign's"));
        }
        Ok(())
    }

    /// Apply the bearer key's `resource_prefix` (as
    /// [`EvidenceStoreClient::list_executor_keys`](crate::EvidenceStoreClient::list_executor_keys)
    /// lists it) offline: a use on a resource outside it, or without a
    /// resource, is refused (`grant_use_out_of_scope`), as the NA refuses
    /// and quarantines it.
    pub fn set_resource_prefix(&mut self, resource_prefix: Option<String>) {
        self.state.resource_prefix = resource_prefix;
    }

    /// What the holder keeps, to persist after every use.
    pub fn state(&self) -> &GrantHolderState {
        &self.state
    }

    /// The signed grant.
    pub fn grant(&self) -> &Value {
        &self.state.grant
    }

    /// The grant's id.
    pub fn grant_id(&self) -> &str {
        self.state.grant["grant_id"].as_str().unwrap_or_default()
    }

    /// The latest time token.
    pub fn time_token(&self) -> &Value {
        &self.state.time_token
    }

    /// Uses made so far.
    pub fn uses(&self) -> u64 {
        self.state.uses
    }

    /// Uses left in the grant's budget: every use made counts, but those
    /// the NA quarantined ([`GrantHolder::count_quarantined`]).
    pub fn remaining_uses(&self) -> u64 {
        self.state.grant["max_uses"]
            .as_u64()
            .unwrap_or(0)
            .saturating_sub(self.counted_uses())
    }

    /// The uses that count against the budget.
    fn counted_uses(&self) -> u64 {
        self.state.uses.saturating_sub(self.quarantined)
    }

    /// How many of this holder's uses the NA has quarantined after they
    /// continued the chain (1.7.0), read from `outbox`: the dead letters of
    /// this grant's uses the NA answered with a quarantine entry
    /// (`last_error.quarantine_id`), other than a conflict or a chain
    /// mismatch, which did not continue it, or an exhausted budget, which
    /// says the holder's count is short. Such a use keeps its place in
    /// the chain but is never admitted, and the NA's budget counts admitted
    /// uses only, so from now on it does not count against the budget
    /// ([`GrantHolder::check`]). Offline every use the holder made counts.
    /// [`GrantHolder::act`] and [`GrantHolder::sync`] call it; call it
    /// after flushing the record outbox yourself.
    pub async fn count_quarantined(&mut self, outbox: &dyn RecordOutbox) -> Result<u64> {
        let entries = outbox.list().await.map_err(GenesisMeshError::Outbox)?;
        self.quarantined = self.quarantined_in(&entries);
        Ok(self.quarantined)
    }

    fn quarantined_in(&self, entries: &[RecordOutboxEntry]) -> u64 {
        let mut positions = std::collections::BTreeSet::new();
        for entry in entries {
            let failure = entry.last_error.as_ref();
            let sequence = entry.record["use_sequence"].as_u64().unwrap_or(0);
            if entry.kind == RecordKind::GrantExecution
                && entry.state == OutboxState::DeadLetter
                && entry.record["grant_id"] == self.state.grant["grant_id"]
                && (1..=self.state.uses).contains(&sequence)
                && failure.is_some_and(|f| {
                    f.quarantine_id.is_some() && !STILL_COUNTED.contains(&f.code.as_str())
                })
            {
                positions.insert(sequence);
            }
        }
        positions.len() as u64
    }

    /// Whether the revocation feed held, or the NA, says the grant is
    /// revoked.
    pub fn revoked(&self) -> bool {
        self.state.ended.as_deref() == Some("grant_revoked")
            || self.state.feed.as_ref().is_some_and(|feed| {
                feed["revoked_grant_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().any(|id| id == &self.state.grant["grant_id"]))
            })
    }

    /// When the next use would be dated at `now`: never before the time
    /// token, nor the previous use.
    fn use_time(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let mut at = now.timestamp_micros();
        if let Some(issued) = micros_of(&self.state.time_token, "issued_at") {
            at = at.max(issued);
        }
        if let Some(last) = self
            .state
            .head_executed_at
            .as_deref()
            .and_then(|s| parse_timestamp(s).ok())
        {
            at = at.max(last.timestamp_micros());
        }
        DateTime::from_timestamp_micros(at).unwrap_or(now)
    }

    /// Why the grant does not cover a request for `capability` with these
    /// parameters on `resource_id`, or cannot be used for it at `now`, or
    /// `None` when the next use may be made, checked offline in the order
    /// the NA checks a use: the bearer key's resource prefix, the
    /// capability, the envelope, revocation (the feed held, or what the NA
    /// said), the validity, the budget (every use the holder made counts,
    /// but those the NA quarantined, 1.7.0: [`GrantHolder::count_quarantined`]),
    /// and the uses the latest time token may still anchor (at most
    /// `max_uses_per_time_token` after the use it names).
    pub fn check(
        &self,
        capability: &str,
        request_parameters: &Value,
        resource_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<GrantCheck> {
        let grant = &self.state.grant;
        if let Some(prefix) = &self.state.resource_prefix {
            if !resource_id.is_some_and(|r| r.starts_with(prefix.as_str())) {
                return Some(GrantCheck::new(
                    "grant_use_out_of_scope",
                    format!("the bearer key covers only resources starting with {prefix:?}"),
                ));
            }
        }
        let named = grant["capabilities"]
            .as_array()
            .is_some_and(|c| c.iter().any(|c| c.as_str() == Some(capability)));
        if !named {
            return Some(GrantCheck::new(
                "grant_capability_mismatch",
                format!("{capability} is not one of the grant's capabilities"),
            ));
        }
        if let Some(problem) = envelope_problem(&grant["parameter_envelope"], request_parameters) {
            return Some(GrantCheck::new("grant_envelope_mismatch", problem));
        }
        if self.revoked() {
            return Some(GrantCheck::new("grant_revoked", "the grant is revoked"));
        }
        if let Some(ended) = &self.state.ended {
            return Some(GrantCheck::new(
                ended,
                "the NA said the grant can no longer be used",
            ));
        }
        let at = self.use_time(now).timestamp_micros();
        if micros_of(grant, "valid_until").is_none_or(|until| at > until) {
            return Some(GrantCheck::new("grant_expired", "the grant has ended"));
        }
        if micros_of(grant, "valid_from").is_none_or(|from| at < from) {
            return Some(GrantCheck::new(
                "grant_use_outside_validity",
                "the grant is not valid yet",
            ));
        }
        let budget = grant["max_uses"].as_u64().unwrap_or(0);
        if self.counted_uses() >= budget {
            return Some(GrantCheck::new(
                "grant_budget_exhausted",
                format!("{budget} uses made"),
            ));
        }
        let limit = grant["max_uses_per_time_token"].as_u64().unwrap_or(0);
        let named = self.state.time_token["use_sequence"].as_u64().unwrap_or(0);
        if self.state.uses + 1 - named > limit {
            return Some(GrantCheck::new(
                "grant_time_token_exhausted",
                format!("{limit} uses already cite the time token"),
            ));
        }
        None
    }

    /// Ask the NA for a time token naming the head of this holder's chain,
    /// and keep it once it verifies. When the NA says the grant can no
    /// longer be used (`409` `grant_revoked`, `grant_expired`,
    /// `grant_budget_exhausted`, `grant_bearer_key_retired`), the holder
    /// keeps that and returns the error.
    pub async fn refresh_time_token(&mut self, grants: &GrantClient) -> Result<Value> {
        let request = self.recorder.sign_time_token_request(
            self.grant_id(),
            self.state.uses,
            self.state.head_digest.as_deref(),
            None,
        )?;
        let answer = match grants.request_time_token(request).await {
            Ok(answer) => answer,
            Err(err) => {
                if NA_ENDED.contains(&err.code()) {
                    self.state.ended = Some(err.code().to_owned());
                }
                return Err(err);
            }
        };
        let token = answer["time_token"].clone();
        self.check_token(&token)?;
        if token["use_sequence"].as_u64() != Some(self.state.uses) {
            return Err(invalid("the time token does not name this holder's head"));
        }
        self.state.time_token = token.clone();
        Ok(token)
    }

    /// Keep a revocation feed (`GET /sovereign-revocation-feed`) once it
    /// verifies under the NA's keys, is the grant issuer's, and is no older
    /// than the one held (its `sequence`). Returns whether it lists the
    /// grant as revoked.
    pub fn set_feed(&mut self, feed: Value) -> Result<bool> {
        self.check_feed(&feed)?;
        let held = self
            .state
            .feed
            .as_ref()
            .and_then(|f| f["sequence"].as_u64());
        if held.is_some_and(|held| feed["sequence"].as_u64().unwrap_or(0) < held) {
            return Err(invalid("the revocation feed is older than the one held"));
        }
        self.state.feed = Some(feed);
        Ok(self.revoked())
    }

    /// Read the NA's revocation feed and keep it ([`GrantHolder::set_feed`]).
    pub async fn refresh_feed(&mut self, grants: &GrantClient) -> Result<bool> {
        let feed = grants.revocation_feed().await?;
        self.set_feed(feed)
    }

    /// On reconnecting: read the revocation feed, upload the record outbox
    /// (this grant's uses in their chain's order, and any other pending
    /// record), and ask for a new time token while the grant can still be
    /// used. Stops at the first error the NA or the network gives.
    pub async fn sync(&mut self, client: &GenesisMeshClient) -> Result<GrantSync> {
        let mut report = GrantSync {
            revoked: self.refresh_feed(&client.grants).await?,
            feed_read: true,
            ..GrantSync::default()
        };
        if let Some(outbox) = client.evidence_store.record_outbox() {
            report.uploads = Some(
                client
                    .evidence_store
                    .flush_records(FlushOptions {
                        ignore_backoff: true,
                    })
                    .await?,
            );
            self.count_quarantined(outbox.as_ref()).await?;
        }
        if !self.revoked() && self.state.ended.is_none() {
            match self.refresh_time_token(&client.grants).await {
                Ok(_) => report.time_token_refreshed = true,
                Err(err) if NA_ENDED.contains(&err.code()) => {}
                Err(err) => return Err(err),
            }
        }
        report.ended = self.state.ended.clone();
        Ok(report)
    }

    /// Run `action` as a use of the grant, offline, or fall back.
    ///
    /// 1. The request is checked first: a resource with its action, the
    ///    parameters an object without secret material
    ///    (`grant_use_secret_material`), a record outbox that can be read
    ///    ([`GenesisMeshError::RecordOutboxRequired`]).
    /// 2. The grant is checked offline ([`GrantHolder::check`]). A request it
    ///    does not cover (`grant_use_out_of_scope`, `grant_capability_mismatch`,
    ///    `grant_envelope_mismatch`) or a grant not valid yet is refused
    ///    ([`GenesisMeshError::GrantRefused`]): nothing runs. When the time
    ///    token is spent, a new one is asked for.
    /// 3. When the grant can be used, the action runs
    ///    ([`GrantAuthority::Grant`]); the use is signed with the bearer key,
    ///    dated no earlier than the time token and the previous use, chained
    ///    to the previous use, kept in the record outbox and submitted:
    ///    [`GrantActionOutcome::Used`]. Persist [`GrantHolder::state`]
    ///    afterwards. A failed action is recorded as a use with outcome
    ///    `failure` ([`GenesisMeshError::ActionFailed`]).
    /// 4. When the grant has ended, its budget is spent, it is revoked, its
    ///    bearer key is retired, or its time token is spent and no new one
    ///    came (the NA did not answer), the request's
    ///    [`GrantFallback`] runs it as [`governed_action_with_break_glass`]
    ///    with the grant's capability: the NA's decision when it answers (a
    ///    DENY does not run the action), break-glass when it does not
    ///    ([`GrantActionOutcome::FellBack`]). Pending uses are uploaded first,
    ///    so a decision's evidence follows them in the resource's chain.
    ///    Without a fallback the request is refused
    ///    ([`GenesisMeshError::GrantRefused`] with the check's code).
    pub async fn act<T, F, Fut>(
        &mut self,
        client: &GenesisMeshClient,
        request: GrantRequest,
        action: F,
    ) -> Result<GrantActionOutcome<T>>
    where
        T: Send + 'static,
        F: FnOnce(GrantAuthority) -> Fut,
        Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
    {
        let store = &client.evidence_store;
        let outbox = store
            .record_outbox()
            .ok_or(GenesisMeshError::RecordOutboxRequired)?;
        let entries = outbox.list().await.map_err(GenesisMeshError::Outbox)?;
        self.quarantined = self.quarantined_in(&entries);
        if request.resource_id.is_some() != request.resource_action.is_some() {
            return Err(GenesisMeshError::Configuration(
                "resource_id and resource_action go together".into(),
            ));
        }
        if let Some(problem) = resource_problem(
            request.resource_id.as_deref(),
            request.resource_action.as_deref(),
        ) {
            return Err(GenesisMeshError::Configuration(problem));
        }
        let parameters = request
            .request_parameters
            .clone()
            .unwrap_or_else(|| json!({}));
        if !parameters.is_object() {
            return Err(GenesisMeshError::Configuration(
                "request_parameters must be a JSON object".into(),
            ));
        }
        // Checked before anything is signed or run (the NA never stores such a use).
        if let Some(secret) = use_secret_problem(&json!({"request_parameters": parameters})) {
            return Err(crate::out_of_band::refused(
                "grant_use_secret_material",
                secret,
            ));
        }
        if let Some(fallback) = &request.fallback {
            crate::out_of_band::check_justification(&fallback.justification)?;
        }

        let resource = request.resource_id.as_deref();
        let mut problem = self.check(&request.capability, &parameters, resource, Utc::now());
        if problem
            .as_ref()
            .is_some_and(|p| p.code == "grant_time_token_exhausted")
        {
            match self.refresh_time_token(&client.grants).await {
                Ok(_) => {
                    problem = self.check(&request.capability, &parameters, resource, Utc::now())
                }
                // Spent, and the NA did not answer: the grant cannot be used now.
                Err(err) if evaluation_failure(&err).is_some() => {}
                Err(err) if NA_ENDED.contains(&err.code()) => {
                    problem = self.check(&request.capability, &parameters, resource, Utc::now());
                }
                Err(err) => return Err(err),
            }
        }
        if let Some(problem) = problem {
            let Some(fallback) = request.fallback.clone().filter(|_| problem.ends_use()) else {
                return Err(problem.refusal());
            };
            let outcome = self
                .fall_back(client, &request, &parameters, fallback, action)
                .await?;
            return Ok(GrantActionOutcome::FellBack {
                unusable: problem,
                outcome: Box::new(outcome),
            });
        }
        self.use_grant(client, request, parameters, action).await
    }

    async fn fall_back<T, F, Fut>(
        &self,
        client: &GenesisMeshClient,
        request: &GrantRequest,
        parameters: &Value,
        fallback: GrantFallback,
        action: F,
    ) -> Result<GovernedActionOutcome<T>>
    where
        T: Send + 'static,
        F: FnOnce(GrantAuthority) -> Fut,
        Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
    {
        let grant = &self.state.grant;
        let evaluate = match fallback.evaluate {
            Some(evaluate) => evaluate,
            None if grant["basis_kind"] == "attestation" => json!({
                "requested_capability": request.capability,
                "attestation_id": grant["basis_id"],
                "context": {
                    "request_parameters": parameters,
                    "attributes": fallback.attributes.unwrap_or_else(|| json!({})),
                },
            }),
            None => {
                return Err(GenesisMeshError::Configuration(
                    "a grant on an agreement falls back with GrantFallback::evaluate".into(),
                ))
            }
        };
        // Uses still pending go first: a decision's evidence on the same
        // resource then follows them in its chain. Best effort: the NA may
        // not answer, which is what break-glass is for.
        let _ = client
            .evidence_store
            .flush_records(FlushOptions {
                ignore_backoff: true,
            })
            .await;
        governed_action_with_break_glass(
            &client.boundary,
            &client.evidence_store,
            &self.recorder,
            GovernedActionParams {
                evaluate,
                resource_id: request.resource_id.clone(),
                resource_action: request.resource_action.clone(),
                prior_resource: None,
                verify: fallback.verify,
            },
            BreakGlassOptions::new(fallback.justification),
            |decision: Option<Value>| {
                action(match decision {
                    Some(decision) => GrantAuthority::Decision(decision),
                    None => GrantAuthority::BreakGlass,
                })
            },
        )
        .await
    }

    async fn use_grant<T, F, Fut>(
        &mut self,
        client: &GenesisMeshClient,
        request: GrantRequest,
        parameters: Value,
        action: F,
    ) -> Result<GrantActionOutcome<T>>
    where
        T: Send + 'static,
        F: FnOnce(GrantAuthority) -> Fut,
        Fut: Future<Output = std::result::Result<ActionReport<T>, ActionError>>,
    {
        let use_sequence = self.state.uses + 1;
        let executed_at = self.use_time(Utc::now());
        let base = GrantUseInput {
            request_parameters: Some(parameters),
            resource_id: request.resource_id.clone(),
            resource_action: request.resource_action.clone(),
            executed_at: Some(executed_at),
            ..GrantUseInput::new(
                self.state.grant.clone(),
                self.state.time_token.clone(),
                use_sequence,
                self.state.head_digest.clone(),
                request.capability.clone(),
            )
        };
        // Everything but the action's report is checked before it runs.
        self.recorder.sign_grant_use(base.clone())?;
        let sign = |outcome: Option<String>, parameters: Option<Value>, detail: Option<String>| {
            self.recorder.sign_grant_use(GrantUseInput {
                outcome,
                execution_parameters: parameters,
                outcome_detail: detail.map(|d| clip(&d)),
                ..base.clone()
            })
        };
        let authority = GrantAuthority::Grant {
            grant_id: self.grant_id().to_owned(),
            use_sequence,
        };
        let report = match action(authority).await {
            Ok(report) => report,
            Err(source) => {
                // The error text is not recorded: it may carry secret material.
                let record = match sign(Some("failure".into()), None, Some("action failed".into()))
                {
                    Ok(record) => record,
                    Err(evidence_error) => {
                        return Err(GenesisMeshError::ActionUnrecorded {
                            source,
                            evidence_error: Box::new(evidence_error),
                            evidence: None,
                        })
                    }
                };
                self.advance(&record)?;
                return Err(
                    match client.evidence_store.enqueue_record(record.clone()).await {
                        Ok(delivery) => GenesisMeshError::ActionFailed {
                            source,
                            evidence: Some(Box::new(record)),
                            queued: None,
                            queued_record: delivery.queued.map(Box::new),
                        },
                        Err(evidence_error) => GenesisMeshError::ActionUnrecorded {
                            source,
                            evidence_error: Box::new(evidence_error),
                            evidence: Some(Box::new(record)),
                        },
                    },
                );
            }
        };
        // The action ran: from here on its use is always recorded.
        let ActionReport {
            value,
            execution_parameters,
            outcome,
            outcome_detail,
        } = report;
        let not_kept = |source: GenesisMeshError, record: Option<Value>, value: Option<T>| {
            GenesisMeshError::EvidenceNotKept {
                source: Box::new(source),
                evidence: record.map(Box::new),
                value: ActionValue::new(value),
            }
        };
        let (record, dropped) = match sign(
            outcome.clone(),
            execution_parameters.clone(),
            outcome_detail.clone(),
        ) {
            Ok(record) => (record, Vec::new()),
            Err(err) if refused_report(&err) => {
                let cleaned = without_refused_metadata(
                    execution_parameters.as_ref().unwrap_or(&json!({})),
                    outcome_detail.as_deref(),
                );
                match sign(
                    outcome,
                    Some(cleaned.execution_parameters),
                    Some(cleaned.outcome_detail),
                ) {
                    Ok(record) => (record, cleaned.dropped),
                    Err(err) => return Err(not_kept(err, None, value)),
                }
            }
            Err(err) => return Err(not_kept(err, None, value)),
        };
        if let Err(err) = self.advance(&record) {
            return Err(not_kept(err, Some(record), value));
        }
        let delivery = match client.evidence_store.enqueue_record(record.clone()).await {
            Ok(delivery) => delivery,
            Err(err) => return Err(not_kept(err, Some(record), value)),
        };
        Ok(GrantActionOutcome::Used(GrantUseResult {
            value,
            record,
            submission: delivery.submission,
            queued: delivery.queued,
            dropped,
        }))
    }

    /// The chain's head after a signed use.
    fn advance(&mut self, record: &Value) -> Result<()> {
        let digest = use_digest(record)?;
        let executed = record["executed_at"]
            .as_str()
            .and_then(|s| parse_timestamp(s).ok())
            .map(python_timestamp);
        self.state.uses = record["use_sequence"]
            .as_u64()
            .unwrap_or(self.state.uses + 1);
        self.state.head_digest = Some(digest);
        self.state.head_executed_at = executed;
        Ok(())
    }

    /// The grant's digest, which its uses name.
    pub fn grant_digest(&self) -> Result<String> {
        grant_digest(&self.state.grant)
    }
}

/// Whether signing refused what the action reported (secret material, its
/// size, or values nested too deep): the use is then recorded without it.
fn refused_report(err: &GenesisMeshError) -> bool {
    matches!(err, GenesisMeshError::OutOfBandRecord { code, .. } if code == "grant_use_secret_material")
        || matches!(err, GenesisMeshError::StrictJson { .. })
}

/// An outcome detail cut to 1024 characters, the last an ellipsis when cut.
fn clip(text: &str) -> String {
    if text.chars().count() <= 1024 {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(1023).collect();
    cut.push('\u{2026}');
    cut
}
