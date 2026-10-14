#![cfg_attr(feature = "client", doc = include_str!("../README.md"))]
// The README's examples call the NA: without `client` (1.7.0) the crate is
// documented by this line and its modules.
#![cfg_attr(
    not(feature = "client"),
    doc = "The Genesis Mesh Rust SDK without its HTTP client (the `client` feature): offline verification, canonical forms, signing, the outboxes and the grant rules."
)]
#![forbid(unsafe_code)]
// Without `client` (1.7.0), helpers only the HTTP clients call are unused.
#![cfg_attr(not(feature = "client"), allow(dead_code))]

#[cfg(feature = "client")]
mod agreement;
#[cfg(feature = "client")]
mod attestation;
pub mod audit_pack;
mod auth;
#[cfg(feature = "client")]
mod boundary;
pub mod canonical;
#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
mod consensus;
#[cfg(feature = "client")]
mod data_usage;
#[cfg(feature = "client")]
mod disclosure;
mod errors;
#[cfg(feature = "client")]
mod evidence;
#[cfg(feature = "client")]
mod evidence_store;
mod execution;
#[cfg(feature = "client")]
mod governance;
#[cfg(feature = "client")]
mod grant_client;
#[cfg(feature = "client")]
mod grant_holder;
pub mod grants;
#[cfg(feature = "client")]
mod health;
pub mod key_history;
#[cfg(feature = "client")]
mod node;
pub mod node_auth;
mod out_of_band;
mod outbox;
#[cfg(feature = "client")]
mod policy;
pub mod remediation;
pub mod strict;
mod strict_json;
pub mod verify;

#[cfg(feature = "client")]
pub use agreement::AgreementClient;
#[cfg(feature = "client")]
pub use attestation::AttestationClient;
pub use auth::{
    admin_signing_payload, build_admin_headers, build_admin_headers_at, canonical_digest,
    canonical_json, load_signing_key, public_key_from_seed, sign_canonical, verify_canonical,
    AdminHeaders, AdminRequest, ADMIN_SIGNATURE_VERSION,
};
#[cfg(feature = "client")]
pub use boundary::BoundaryClient;
#[cfg(feature = "client")]
pub use client::{ClientOptions, GenesisMeshClient, HttpTransport};
#[cfg(feature = "client")]
pub use consensus::ConsensusClient;
#[cfg(feature = "client")]
pub use data_usage::DataUsageClient;
#[cfg(feature = "client")]
pub use disclosure::DisclosureClient;
pub use errors::{ActionValue, GenesisMeshError, Result};
#[cfg(feature = "client")]
pub use evidence::EvidenceClient;
#[cfg(feature = "client")]
pub use evidence_store::{
    EvidenceStoreClient, FlushOptions, RemediationQuery, ReviewDecision, MAX_PAGE,
    MAX_REMEDIATION_PAGE,
};
pub use execution::{
    check_metadata_only, ExecutionRecorder, PriorResource, RecordExecution, ResourceHead,
    MAX_METADATA_BYTES,
};
#[cfg(feature = "client")]
pub use governance::{
    evaluation_failure, governed_action, governed_action_with_break_glass, summarize_decision,
    without_refused_metadata, ActionError, ActionReport, BreakGlassOptions, BreakGlassResult,
    DecisionSummary, GateFailure, GovernedActionOutcome, GovernedActionParams,
    GovernedActionResult, GovernedVerification, RefusedMetadata,
};
#[cfg(feature = "client")]
pub use governance::{
    rotate_forward_then_disable, urgent_action, EmergencyOptions, RotateForwardParams,
    RotateForwardResult, RotatedVersion, UrgentActionResult, UrgentPath,
};
#[cfg(feature = "client")]
pub use grant_client::{GrantClient, GrantQuery};
#[cfg(feature = "client")]
pub use grant_holder::{
    GrantActionOutcome, GrantAuthority, GrantCheck, GrantFallback, GrantHolder, GrantHolderState,
    GrantRequest, GrantSync, GrantUseResult,
};
pub use grants::GrantUseInput;
#[cfg(feature = "client")]
pub use health::HealthClient;
#[cfg(feature = "client")]
pub use node::{NodeClient, NodeIdentity, NodeJoin};
#[doc(hidden)]
pub use out_of_band::record_metadata_problem;
pub use out_of_band::{
    observation_from_finding, observation_id, BreakGlassInput, EvaluationFailure,
    FindingObservationOptions, ObservationInput, ObservationRecorder,
};
pub use outbox::{
    classify_record_submission_error, classify_submission_error, retry_delay, Delivery,
    EvidenceOutbox, FileOutbox, FileRecordOutbox, FlushReport, MemoryOutbox, MemoryRecordOutbox,
    OutboxEntry, OutboxFuture, OutboxState, RecordDelivery, RecordFlushReport, RecordKind,
    RecordOutbox, RecordOutboxEntry, SubmissionFailure, GRANT_USE_PERMANENT_REFUSALS,
    PERMANENT_REFUSALS, PREDECESSOR_DEAD_LETTERED, RECORD_PERMANENT_REFUSALS,
};
#[cfg(feature = "client")]
pub use policy::PolicyClient;
pub use remediation::{
    RemediationInput, RemediationSteps, RemediationSubject, REMEDIATION_PERMANENT_REFUSALS,
};
pub use serde_json::{json, Value};
pub use strict_json::{check_strict_json, parse_strict_json};
