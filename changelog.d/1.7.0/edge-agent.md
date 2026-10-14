### Added

- **The edge agent, `genesis-mesh-edge` (beta).** A device's agent, built on
  this crate and released with it as static Linux binaries (x86-64 and
  arm64, with `SHA256SUMS-edge` and Sigstore bundles), a systemd unit, an
  example configuration and the image `ghcr.io/genesismeshlabs/genesis-mesh-edge`
  (signed by digest, tagged with the version only while beta). It enrols with
  an edge invite, registering its executor key at join; asks the NA for a
  decision while connected; acts within pre-issued grants while not, as long
  as its trust snapshot is fresh; refuses a request a grant names but does
  not cover, even with a justification; breaks the glass with a
  justification; and uploads every record in order when the NA is back. It
  renews its certificate, sends heartbeats with its status, and stops when
  the NA revokes the node. Local workloads ask it through a local API on a
  Unix socket (allowed by uid or gid) or a loopback port (bearer tokens); the
  device never holds an operator key. It needs an NA from 1.7.0 with the
  evidence store and out-of-band records on (grants need `EVIDENCE_GRANTS=on`).
  See docs/edge.md.
