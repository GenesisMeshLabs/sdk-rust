//! The client: one transport shared by every sub-client.

use std::sync::Arc;

use crate::{
    agreement::AgreementClient,
    attestation::AttestationClient,
    boundary::BoundaryClient,
    consensus::ConsensusClient,
    data_usage::DataUsageClient,
    disclosure::DisclosureClient,
    errors::Result,
    evidence::EvidenceClient,
    evidence_store::EvidenceStoreClient,
    grant_client::GrantClient,
    health::HealthClient,
    node::{NodeClient, NodeIdentity},
    policy::PolicyClient,
    transport::{ClientOptions, HttpTransport},
};

/// Entry point for the Genesis Mesh Rust SDK.
#[derive(Debug, Clone)]
pub struct GenesisMeshClient {
    /// Agreement lifecycle: offer, counter, accept, verify.
    pub agreement: AgreementClient,
    /// Membership attestations: issue, revoke, recognition policy.
    pub attestation: AttestationClient,
    /// Capability boundary decisions: decide, evaluate, verify.
    pub boundary: BoundaryClient,
    /// Consensus voting and proofs: vote, proof, verify.
    pub consensus: ConsensusClient,
    /// Data usage licensing: policy, intent, verify.
    pub data_usage: DataUsageClient,
    /// Selective capability disclosure: commit, nullifier, prove, verify.
    pub disclosure: DisclosureClient,
    /// Trust evidence: build, verify.
    pub evidence: EvidenceClient,
    /// Execution evidence store: submission, search, history, export,
    /// executor keys, retention and resource heads; observations,
    /// break-glass records and their judgements (v1.3.0).
    pub evidence_store: EvidenceStoreClient,
    /// Pre-issued grants (1.6.0): issue, list, read and revoke them; a
    /// holder's time tokens and uses; the revocation feed.
    pub grants: GrantClient,
    /// Liveness, readiness and health.
    pub health: HealthClient,
    /// A node's own routes, signed by its node key (1.7.0, beta): join,
    /// heartbeat, renew, and an edge node's state, decisions and resource
    /// heads.
    pub node: NodeClient,
    /// Boundary policy lifecycle: validate, publish, activate, history, verify.
    pub policy: PolicyClient,
}

impl GenesisMeshClient {
    /// Construct a client from options.
    pub fn new(options: ClientOptions) -> Result<Self> {
        let outbox = options.outbox.clone();
        let record_outbox = options.record_outbox.clone();
        let transport = Arc::new(HttpTransport::new(options)?);

        Ok(Self {
            agreement: AgreementClient::new(Arc::clone(&transport)),
            attestation: AttestationClient::new(Arc::clone(&transport)),
            boundary: BoundaryClient::new(Arc::clone(&transport)),
            consensus: ConsensusClient::new(Arc::clone(&transport)),
            data_usage: DataUsageClient::new(Arc::clone(&transport)),
            disclosure: DisclosureClient::new(Arc::clone(&transport)),
            evidence: EvidenceClient::new(Arc::clone(&transport)),
            evidence_store: EvidenceStoreClient::new(Arc::clone(&transport), outbox, record_outbox),
            grants: GrantClient::new(Arc::clone(&transport)),
            health: HealthClient::new(Arc::clone(&transport)),
            node: NodeClient::new(Arc::clone(&transport)),
            policy: PolicyClient::new(transport),
        })
    }

    /// The same client acting as an enrolled edge node (1.7.0, beta):
    /// [`BoundaryClient::evaluate`](crate::BoundaryClient::evaluate) calls
    /// `POST /node/boundary/evaluate`, and
    /// [`EvidenceStoreClient::resource_head`](crate::EvidenceStoreClient::resource_head)
    /// and `resource_head_entry` call `POST /node/evidence/resource-head`,
    /// signed by the node key instead of an operator key. The outboxes are
    /// kept. [`governed_action`](crate::governed_action) and the grant
    /// holder then need no operator key.
    pub fn with_node_identity(mut self, identity: NodeIdentity) -> Self {
        let identity = Arc::new(identity);
        self.boundary = self
            .boundary
            .with_node(self.node.clone(), Arc::clone(&identity));
        self.evidence_store = self.evidence_store.with_node(self.node.clone(), identity);
        self
    }
}
