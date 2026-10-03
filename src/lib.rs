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
mod policy;
pub mod verify;

pub use agreement::AgreementClient;
pub use attestation::AttestationClient;
pub use auth::{
    build_admin_headers, canonical_digest, canonical_json, load_signing_key, public_key_from_seed,
    sign_canonical, verify_canonical, AdminHeaders,
};
pub use boundary::BoundaryClient;
pub use client::{ClientOptions, GenesisMeshClient, HttpTransport};
pub use consensus::ConsensusClient;
pub use data_usage::DataUsageClient;
pub use disclosure::DisclosureClient;
pub use errors::{GenesisMeshError, Result};
pub use evidence::EvidenceClient;
pub use evidence_store::{EvidenceStoreClient, ResourceHead, MAX_PAGE};
pub use execution::{
    check_metadata_only, ExecutionRecorder, PriorResource, RecordExecution, MAX_METADATA_BYTES,
};
pub use governance::{
    governed_action, summarize_decision, ActionError, ActionReport, DecisionSummary, GateFailure,
    GovernedActionParams, GovernedActionResult, GovernedVerification,
};
pub use health::HealthClient;
pub use policy::PolicyClient;
pub use serde_json::{json, Value};
