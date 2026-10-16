//! The NA's pre-issued grant routes (Genesis Mesh 1.6.0, beta): issuing,
//! reading and revoking grants (operators), and the holder's time tokens and
//! uses. Off unless the NA runs with `EVIDENCE_GRANTS=on`: every route then
//! answers `404 grants_disabled`.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::{
    transport::{segment, HttpTransport},
    Result,
};

/// A page of `GET /admin/grants` ([`GrantClient::list`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantQuery {
    /// `active`, `expired` or `revoked`; `None` for every grant.
    pub status: Option<String>,
    /// Only the grants this executor key bears.
    pub bearer_key_id: Option<String>,
    /// 1 to 500; the NA's default is 100.
    pub limit: Option<u32>,
    /// The previous page's `next_before`: a grant id (grants are ordered by
    /// `issued_at`, then `grant_id`); an unknown one is `400 invalid_page`.
    pub before: Option<String>,
}

/// Pre-issued grants (1.6.0, beta routes; the records are stable).
#[derive(Debug, Clone)]
pub struct GrantClient {
    http: Arc<HttpTransport>,
}

impl GrantClient {
    pub(crate) fn new(http: Arc<HttpTransport>) -> Self {
        Self { http }
    }

    /// Issue a grant (admin, privileged): `bearer_key_id` (a registered
    /// executor key), `capabilities`, `attestation_id` or `agreement`,
    /// `valid_until` (and `valid_from`, by default now; at most 24 hours
    /// apart), `max_uses`, `max_uses_per_time_token`, `parameter_envelope`
    /// and, for an agreement, `context_freshness_seq`. The NA checks every
    /// active policy over the whole envelope and validity first. `201` with
    /// `{grant, time_token, entry, entry_digest}`: the signed grant and its
    /// first time token (`use_sequence` 0), which a
    /// [`GrantHolder`](crate::GrantHolder) is made from. Refusals: `400`
    /// (`unexpected_field`, `ambiguous_basis`, `invalid_grant_validity`,
    /// `invalid_grant_request`, `grant_limit_exceeded`,
    /// `invalid_grant_envelope`, `invalid_agreement`), `422` for the bearer
    /// key (`grant_bearer_key_unknown`, `grant_bearer_key_not_executor`,
    /// `grant_bearer_key_retired`) and the issuance refusals
    /// ([`ISSUANCE_REFUSALS`](crate::grants::ISSUANCE_REFUSALS)); `409
    /// grant_issuance_conflict` (another issuance took the store's position:
    /// issue again), `503 evidence_store_unavailable` or
    /// `grant_store_integrity_failed`.
    pub async fn issue(&self, request: Value) -> Result<Value> {
        self.http.admin_post("/admin/grants", request).await
    }

    /// One page of grants, newest first (admin, read tier):
    /// `{grants: [summary], next_before}`; `400 invalid_grant_filter` or
    /// `invalid_page`. A summary names `grant_id`, `status` (`active`,
    /// `scheduled`, `exhausted`, `expired`, `revoked`), the bearer, the
    /// capabilities, the basis, the validity, `max_uses`, `uses`,
    /// `issued_at`, `issued_by_operator`, `store_sequence`, `revoked_at` and
    /// `revocation_reason`.
    pub async fn list(&self, query: &GrantQuery) -> Result<Value> {
        let mut pairs = Vec::new();
        if let Some(status) = &query.status {
            pairs.push(("status".to_owned(), status.clone()));
        }
        if let Some(bearer) = &query.bearer_key_id {
            pairs.push(("bearer_key_id".to_owned(), bearer.clone()));
        }
        if let Some(limit) = query.limit {
            pairs.push(("limit".to_owned(), limit.to_string()));
        }
        if let Some(before) = &query.before {
            pairs.push(("before".to_owned(), before.clone()));
        }
        self.http.admin_get("/admin/grants", &pairs).await
    }

    /// One grant (admin, read tier): its summary, `remaining_uses`,
    /// `chain_length` (its use chain's length: admitted uses and quarantined
    /// uses that continued it), the signed `grant`, the policy versions it is
    /// bound to and its `revocation` (or `null`); `404 grant_not_found`.
    pub async fn get(&self, grant_id: &str) -> Result<Value> {
        self.http
            .admin_get(&format!("/admin/grants/{}", segment(grant_id)?), &[])
            .await
    }

    /// One page of a grant's use chain, newest first (admin, read tier,
    /// beta): `{grant_id, uses, next_before}`, each use with `use_id`,
    /// `use_sequence`, `state` (`admitted` or `quarantined`, with its
    /// `rejection_code`), `executed_at`, `recorded_at`, `store_sequence`,
    /// `resource_id`, `resource_sequence` and `outcome`. `before` is the
    /// previous page's `next_before` (a `use_sequence`); `limit` 1 to 500.
    /// `404 grant_not_found`, `400 invalid_page`.
    pub async fn uses(
        &self,
        grant_id: &str,
        before: Option<u64>,
        limit: Option<u32>,
    ) -> Result<Value> {
        let mut pairs = Vec::new();
        if let Some(before) = before {
            pairs.push(("before".to_owned(), before.to_string()));
        }
        if let Some(limit) = limit {
            pairs.push(("limit".to_owned(), limit.to_string()));
        }
        self.http
            .admin_get(
                &format!("/admin/grants/{}/uses", segment(grant_id)?),
                &pairs,
            )
            .await
    }

    /// Revoke a grant from now on (admin, privileged), with an optional
    /// reason of 1 to 1024 characters recorded as the revocation's `detail`
    /// (its `reason` is `operator`):
    /// `{grant_id, status: "revoked", revocation, entry, entry_digest}`. A
    /// use dated before the revocation stands; one at or after it is refused.
    /// `409 grant_already_revoked`, `404 grant_not_found`,
    /// `400 invalid_grant_revocation`.
    pub async fn revoke(&self, grant_id: &str, reason: Option<&str>) -> Result<Value> {
        let body = match reason {
            Some(reason) => json!({ "reason": reason }),
            None => json!({}),
        };
        self.http
            .admin_post(
                &format!("/admin/grants/{}/revoke", segment(grant_id)?),
                body,
            )
            .await
    }

    /// Ask for a time token with a `TimeTokenRequest` signed by the grant's
    /// bearer key
    /// ([`ExecutionRecorder::sign_time_token_request`](crate::ExecutionRecorder::sign_time_token_request)):
    /// `201 {time_token}`. Refusals: `422` `time_token_request_malformed`,
    /// `time_token_request_invalid_signature`, `time_token_request_stale`;
    /// `409` `grant_bearer_key_retired`, `grant_revoked`, `grant_expired`,
    /// `grant_budget_exhausted`, `time_token_request_behind`,
    /// `time_token_request_mismatch` (compared with the chain's length,
    /// which counts quarantined uses).
    pub async fn request_time_token(&self, request: Value) -> Result<Value> {
        self.http
            .public_post("/grants/time-tokens", json!({ "request": request }))
            .await
    }

    /// Submit one signed use (`GrantExecutionEvidence`): `201` with
    /// `{entry, entry_digest, payload, status: "recorded",
    /// resource_sequence}` (the position the NA gave it in its resource's
    /// chain), `200` with `status: "duplicate"` for a use it holds. The use
    /// rejections ([`USE_REJECTION_CODES`](crate::grants::USE_REJECTION_CODES))
    /// are `422` (`409 grant_use_conflict`); an authentic use refused for
    /// good is kept as a quarantine entry (`error.details.quarantine_id`, the
    /// same on a re-upload), and still takes its place in the chain when it
    /// continues it. Keep uses in the record outbox
    /// ([`EvidenceStoreClient::enqueue_record`](crate::EvidenceStoreClient::enqueue_record))
    /// to submit them in their chain's order.
    pub async fn submit_use(&self, evidence: Value) -> Result<Value> {
        self.http
            .public_post(
                "/evidence/grant-executions",
                json!({ "evidence": evidence }),
            )
            .await
    }

    /// The NA's signed revocation feed (`GET /sovereign-revocation-feed`):
    /// with grants on, `revoked_grant_ids` lists the revoked grants not yet
    /// past their end. Verify it with
    /// [`verify_revocation_feed`](crate::verify::verify_revocation_feed).
    pub async fn revocation_feed(&self) -> Result<Value> {
        self.http.public_get("/sovereign-revocation-feed").await
    }
}
