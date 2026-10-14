### Added

- **Node request signatures (beta), with or without the `client` feature.**
  `node_auth::node_signing_payload`, `sign_node_request`,
  `executor_proof_payload`, `sign_executor_proof` and `executor_key_id` sign
  a node's requests as the NA verifies them (`/join`, `/heartbeat`, `/renew`
  and the 1.7.0 `/node/*` routes, which also sign a `purpose` and the NA's
  public key as `audience`). An edge node's executor key co-signs its `/join`
  as proof of possession; the NA registers it under the key ID `edge-` and
  32 hex characters of the key's SHA-256. The core's `node` conformance
  suite (`tests/fixtures/node.json`) is reproduced byte for byte.
- **`verify::verify_join_certificate` and `verify::verify_crl` (beta).** A
  `JoinCertificate` verifies over exactly its signed fields (what a response
  adds beside them, such as an edge node's `edge` block, is ignored); a CRL
  (`GET /crl`) over everything but its signatures.
- **The node client (beta).** `GenesisMeshClient.node` (`NodeClient`) joins
  (`NodeJoin`, optionally with an executor key), heartbeats (with an edge
  agent's `agent` block), renews, and reads an edge node's state
  (`POST /node/state`) and resource heads. `NodeIdentity` holds a node's
  certificate ID, key and NA; its debug output never shows the key.
- **A client acting as an edge node (beta).**
  `GenesisMeshClient::with_node_identity` sends `BoundaryClient::evaluate`
  to `POST /node/boundary/evaluate` and `EvidenceStoreClient::resource_head`
  and `resource_head_entry` to `POST /node/evidence/resource-head`, signed by
  the node key: `governed_action`, break-glass and the grant holder then run
  on a device with no operator key. These routes need an NA from 1.7.0.
