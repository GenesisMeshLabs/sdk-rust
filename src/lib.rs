//! Rust SDK for the Genesis Mesh Network Authority HTTP API.
//!
//! This crate is an MVP client for the stable Trust API routes. It provides
//! admin request signing, HTTP transport, typed SDK errors, and thin
//! domain-specific clients over JSON request and response bodies.

mod agreement;
mod attestation;
mod auth;
mod boundary;
mod client;
mod consensus;
mod data_usage;
mod disclosure;
mod errors;
mod evidence;

pub use agreement::AgreementClient;
pub use attestation::AttestationClient;
pub use auth::{build_admin_headers, canonical_json, load_signing_key, AdminHeaders};
pub use boundary::BoundaryClient;
pub use client::{ClientOptions, GenesisMeshClient, HttpTransport};
pub use consensus::ConsensusClient;
pub use data_usage::DataUsageClient;
pub use disclosure::DisclosureClient;
pub use errors::{GenesisMeshError, Result};
pub use evidence::EvidenceClient;
pub use serde_json::{json, Value};
