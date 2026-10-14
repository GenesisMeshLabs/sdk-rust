### Added

- **The edge agent, `genesis-mesh-edge` (beta).** A device's agent, built on
  this crate and released with it as static Linux binaries (x86-64 and
  arm64, with `SHA256SUMS-edge` and Sigstore bundles), a systemd unit, an
  example configuration and the image `ghcr.io/genesismeshlabs/genesis-mesh-edge`
  (signed by digest, tagged with the version only while beta). It enrols with
  an edge invite, registering its executor key at join; asks the NA for a
  decision while connected; acts within pre-issued grants while not, as long
  as its trust snapshot is fresh; refuses a request a grant names but does
  not cover, even with a justification; and uploads every record in order,
  200 at a time, when the NA is back. It renews its certificate, sends
  heartbeats with its status, and stops when the NA revokes the node. Local
  workloads ask it through a local API on a Unix socket (allowed by uid or
  gid) or a loopback port (bearer tokens); the device never holds an
  operator key. It needs an NA from 1.7.0 with the evidence store and
  out-of-band records on (grants need `EVIDENCE_GRANTS=on`). See
  docs/edge.md.
- **What an NA error means, in three classes.** A refusal of the NA (a DENY,
  or its JSON error with a 4xx other than 429) is final. The NA throttling or
  failing (its JSON error with 429 or 5xx) lets a grant act but never breaks
  the glass. Only no answer (no connection, a timeout, or a gateway's own
  502, 503, 504 or 52x page) breaks the glass, with a justification. So a
  flood of local requests, or a host at the same NAT, can never turn a DENY
  into break-glass, and an NA stopped behind a reverse proxy is treated as
  down. `/v1/status` shows `na_state` and `last_na_error`.
- **Operating the agent.** `init` creates the keys and prints the node key
  for a recipient-bound invite; enrolment needs https or a loopback NA;
  `reset` starts again (refused while records are not uploaded, unless
  `--discard-pending`, and while the agent runs: a lock in the state
  directory); `outbox export [--dead-letters]` writes the records not
  uploaded as JSON lines; outside systemd `enroll` reads
  `/etc/genesis-mesh-edge/invite-token`. The agent refuses to start against
  another NA than the one it enrolled with, or on a database a newer agent
  wrote.
- **A local API that holds up.** At most 64 connections, a 10-second limit to
  send a request's headers, accept errors logged and survived, 30
  authorizations per minute per client (`429 local_rate_limited`), outcomes
  reported only by the client that asked, and nothing run or signed for a
  client that disconnects before its answer.
