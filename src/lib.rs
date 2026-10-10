#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod agreement;
mod attestation;
mod auth;
mod boundary;
pub mod canonical;
mod client;
mod consensus;
mod data_usage;
mod disclosure;
mod errors;
mod evidence;
mod evidence_store;
mod execution;
mod governance;
mod health;
mod outbox;
mod policy;
pub mod strict;
mod strict_json;
pub mod verify;

pub use agreement::AgreementClient;
pub use attestation::AttestationClient;
pub use auth::{
    admin_signing_payload, build_admin_headers, build_admin_headers_at, canonical_digest,
    canonical_json, load_signing_key, public_key_from_seed, sign_canonical, verify_canonical,
    AdminHeaders, AdminRequest, ADMIN_SIGNATURE_VERSION,
};
pub use boundary::BoundaryClient;
pub use client::{ClientOptions, GenesisMeshClient, HttpTransport};
pub use consensus::ConsensusClient;
pub use data_usage::DataUsageClient;
pub use disclosure::DisclosureClient;
pub use errors::{ActionValue, GenesisMeshError, Result};
pub use evidence::EvidenceClient;
pub use evidence_store::{EvidenceStoreClient, FlushOptions, ResourceHead, MAX_PAGE};
pub use execution::{
    check_metadata_only, ExecutionRecorder, PriorResource, RecordExecution, MAX_METADATA_BYTES,
};
pub use governance::{
    governed_action, summarize_decision, without_refused_metadata, ActionError, ActionReport,
    DecisionSummary, GateFailure, GovernedActionParams, GovernedActionResult, GovernedVerification,
    RefusedMetadata,
};
pub use health::HealthClient;
pub use outbox::{
    classify_submission_error, retry_delay, Delivery, EvidenceOutbox, FileOutbox, FlushReport,
    MemoryOutbox, OutboxEntry, OutboxFuture, OutboxState, SubmissionFailure, PERMANENT_REFUSALS,
    PREDECESSOR_DEAD_LETTERED,
};
pub use policy::PolicyClient;
pub use serde_json::{json, Value};
pub use strict_json::{check_strict_json, parse_strict_json};
