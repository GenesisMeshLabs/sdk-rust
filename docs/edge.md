# genesis-mesh-edge: the edge agent

*Unreleased.*

`genesis-mesh-edge` (Genesis Mesh 1.7.0, **beta**) runs on a device that must
make governed changes whether or not it can reach its Network Authority (NA).
It holds the device's node key and executor key, asks the NA for a decision
while it is connected, acts within pre-issued grants while it is not, breaks
the glass when it must, and uploads every record in order when the NA is
back. Local workloads ask it through a local API; they never hold a key.

It is built from this crate (the SDK with its `client` feature) and released
with it, as static Linux binaries and a container image. Linux is the release
target; it builds on macOS; Windows is not supported.

The agent's configuration keys, its local API, its exit codes and its state
files are beta: they may change in a minor release, with a changelog entry.

## What the device holds, and what it never holds

The device holds two keys, both generated on the device and never sent
anywhere:

- **The node key** signs the agent's requests to the NA: `/join`,
  `/heartbeat`, `/renew` and the node-scoped routes (`/node/state`,
  `/node/boundary/evaluate`, `/node/evidence/resource-head`), which also sign
  the route's `purpose` and the NA's public key as `audience`.
- **The executor key** signs the device's records: execution evidence, grant
  uses and break-glass records. The NA registers it when the node joins with
  an edge invite, under the key ID `edge-` and 32 hex characters of its
  SHA-256, with the resource prefix the invite names.

The device never holds an operator key. `edge/clippy.toml` refuses the SDK's
admin signing in the agent's code, and the scenario tests check that no
request from the agent carries an `X-Admin-*` header.

## Enrolment

An operator creates an **edge invite** with the privileged tier:

```sh
genesis-mesh admin invite --node-sovereign-id site7-17 --executor-resource-prefix edge:site7-17/
```

The invite token is a bearer secret for a privileged act. To bind the
invite to the device, run `genesis-mesh-edge init` on the device first: it
creates the state directory and both keys and prints the node public key
(`--json` adds the executor key) for the invite's `recipient_public_key`.
`enroll` then uses those keys.

The agent enrols with the invite's token (`genesis-mesh-edge enroll`, or on
its first `run`):

1. It checks its configuration and state directory. Enrolment needs https,
   or an NA on a loopback address: `allow_insecure_http` does not cover
   `enroll` (the invite token would cross the network in clear text), only
   `run`.
2. It reads `GET /na/key-history` and verifies it from the configured root
   public key. The NA's audience is the genesis block's
   `network_authority.public_key`.
3. It generates the node and executor keys if they are absent.
4. It joins (`POST /join`): the executor key co-signs the request as proof of
   possession, then the node key signs it.
5. It verifies the certificate under the NA's keys and checks that the NA
   registered its executor key, with a sovereign and a resource prefix. An NA
   that does not (older than 1.7.0) is refused: exit 4.
6. It writes `enrollment.json` and syncs once (a failure here is not fatal).

The invite token comes from `--invite-token-file`, `GM_EDGE_INVITE_TOKEN_FILE`,
`$CREDENTIALS_DIRECTORY/invite-token` (systemd's `LoadCredential`) or
`GM_EDGE_INVITE_TOKEN`, in that order. It is never written to the state
directory and never logged.

`enroll --reset` deletes the keys and every state file and enrols again. It
refuses while records are not uploaded unless `--discard-pending` is given.

## Configuration

The configuration file is `--config`, or `GM_EDGE_CONFIG`, or
`/etc/genesis-mesh-edge/edge.toml` when it exists; it is optional when the
environment gives the required keys. The environment wins over the file,
the file over the defaults. `edge/packaging/edge.toml.example` (released as
`edge.toml.example`) shows every key. `genesis-mesh-edge check-config`
prints the effective configuration without secrets.

### `[authority]`

| Key | Environment | Default |
|---|---|---|
| `url` | `GM_EDGE_NA_URL` | required; https, or http only to a loopback host or with `allow_insecure_http` |
| `root_public_key` | `GM_EDGE_ROOT_PUBLIC_KEY` | required; pins the NA's key history |
| `timeout_seconds` | `GM_EDGE_NA_TIMEOUT_SECONDS` | 5 |
| `allow_insecure_http` | `GM_EDGE_ALLOW_INSECURE_HTTP` | false |

HTTPS uses the bundled web PKI roots. A private certificate authority is not
supported in 1.7.0.

### `[node]` and `[snapshot]`

| Key | Environment | Default |
|---|---|---|
| `node.state_dir` | `GM_EDGE_STATE_DIR` | `/var/lib/genesis-mesh-edge` |
| `node.validity_hours` | `GM_EDGE_VALIDITY_HOURS` | 168 |
| `node.heartbeat_interval_seconds` | `GM_EDGE_HEARTBEAT_INTERVAL_SECONDS` | 30 |
| `node.renew_before_seconds` | `GM_EDGE_RENEW_BEFORE_SECONDS` | 86400 |
| `snapshot.sync_interval_seconds` | `GM_EDGE_SYNC_INTERVAL_SECONDS` | 60 |
| `snapshot.retry_interval_seconds` | `GM_EDGE_RETRY_INTERVAL_SECONDS` | 15, doubling up to 60 |
| `snapshot.max_snapshot_age_seconds` | `GM_EDGE_MAX_SNAPSHOT_AGE_SECONDS` | 86400 (60 to 604800) |

### `[decisions]`, `[local_api]` and `[log]`

| Key | Environment | Default |
|---|---|---|
| `decisions.attestation_id` | `GM_EDGE_ATTESTATION_ID` | none; pins the attestation decisions are asked under |
| `local_api.listen` | `GM_EDGE_LISTEN` | `unix:/run/genesis-mesh-edge/agent.sock`, or `tcp://127.x.x.x:port` |
| `local_api.allowed_uids`, `allowed_gids` | `GM_EDGE_ALLOWED_UIDS`, `GM_EDGE_ALLOWED_GIDS` (comma lists) | `[]` |
| `local_api.socket_mode`, `socket_group` | `GM_EDGE_SOCKET_MODE`, `GM_EDGE_SOCKET_GROUP` | `0660`, none |
| `[[local_api.tokens]]` `name`, `sha256` | `GM_EDGE_TOKENS="name:hex,..."` | none |
| `local_api.report_timeout_seconds` | `GM_EDGE_REPORT_TIMEOUT_SECONDS` | 300 |
| `local_api.queue_timeout_seconds` | `GM_EDGE_QUEUE_TIMEOUT_SECONDS` | 30 |
| `local_api.rate_limit_per_minute` | `GM_EDGE_RATE_LIMIT_PER_MINUTE` | 60 authorizations per minute per local client |
| `log.level` | `GM_EDGE_LOG_LEVEL` | `info` |

The agent refuses to start (exit 2) when the listener is a Unix socket and
both allow-lists are empty, when it is TCP on an address that is not
loopback or has no token, or when the NA's URL is plain http to a host that
is not loopback without `allow_insecure_http`.

## Local API

HTTP/1.1 with JSON bodies of at most 64 KiB, read as strict JSON. Errors are
`{"error": {"code", "message"}}`.

- **Unix socket**: the agent reads the peer's credentials on each connection
  and refuses it (`403 local_peer_refused`, then closes it) unless its uid is
  in `allowed_uids` or its gid in `allowed_gids`. Root is not implied, and
  only the peer's **primary** gid is checked: a user in an allowed group
  through a supplementary group is refused (fails closed). The socket gets
  `socket_mode` and `socket_group` after it is bound.
- **Loopback**: `Authorization: Bearer <token>`, compared in constant time by
  its SHA-256; a missing or wrong token is `401 local_auth_required`.
  `genesis-mesh-edge token new --name controller` prints a new 32-byte token
  and the line for the configuration.

### `GET /v1/status`

`agent_version`, `state` (`unenrolled`, `active`, `certificate_expired`,
`revoked`), the node (`node_public_key`, `node_sovereign_id`,
`executor_key_id`, `resource_prefix`, `cert_id`, `cert_expires_at`), the
connection (`connected`, `last_na_contact_at`), the snapshot
(`snapshot_synced_at`, `snapshot_age_seconds`, `snapshot_fresh`,
`clock_behind`), `grants`
(each with `grant_id`, `capabilities`, `valid_until`, `uses`, `max_uses`,
`usable` and `code`) and the uploads (`pending_uploads`, `dead_letters`,
`lost_authorizations`).

### `POST /v1/authorize`

```json
{"capability": "secret.rotate", "request_parameters": {"lifetime_days": 30},
 "resource_id": "edge:site7-17/kv/db", "resource_action": "rotate",
 "attributes": {}, "attestation_id": null, "justification": null}
```

The resource and its action are required; the resource must start with the
node's resource prefix (`400 resource_out_of_scope`). Parameters and
attributes carry identifiers and versions only (`400 secret_material`). The
answer:

```json
{"authorization_id": "…", "allowed": true, "authority": "decision", "code": null,
 "detail": "…", "decision_id": "…", "grant_id": null, "use_sequence": null,
 "report_by": "…"}
```

`authority` is `decision`, `grant` or `break_glass`. When `allowed` is
false, `code` says why:

| `code` | Meaning |
|---|---|
| `na_denied` | The NA decided DENY (`denial_reason`) |
| `na_refused` | The NA refused the request (`na_code`) |
| `decision_unverifiable` | The decision did not verify (`verification_reason`) |
| `outside_grant` | A held grant names the capability but does not cover the request (`grant_code`) |
| `justification_required` | No grant can be used and there is no justification (`grant_code`) |
| `no_attestation` | No attestation issued to the node can be used |

### `POST /v1/authorizations/{id}/outcome`

```json
{"outcome": "success", "execution_parameters": {"version_id": "v8"}, "outcome_detail": "rotated"}
```

The answer names the record: `{authorization_id, record_kind` (`execution`,
`grant_execution` or `break_glass`)`, record_id, queued, dropped}`.
Metadata the secret guard refuses is left out and named in `dropped`.

One authorization is open at a time; others wait, first come first served,
for up to `queue_timeout_seconds` (then `503 agent_busy` with
`Retry-After: 1`). An outcome not reported within `report_timeout_seconds`
is recorded as `failure`, with a detail saying it was not reported; reporting
it later is `410 authorization_expired`. Other errors: `400 invalid_request`,
`403 node_revoked`, `404 authorization_not_found`,
`409 outcome_already_reported`, `413 request_too_large`,
`429 local_rate_limited` (more than `rate_limit_per_minute` authorizations
from one client, by uid or token name, counted before the NA is asked),
`503 not_enrolled`.

## Decision order

The attestation a request is decided under is the request's
`attestation_id` (one issued to the node), else the configured one, else the
single active attestation whose `claims.capabilities` names the capability,
latest expiry first. Decisions are verified under the NA's keys from the key
history, against that attestation, accepting the policy versions the decision
binds (the device holds no policies).

Only a request that got **no answer** counts as the NA being unreachable:
no connection, or no response within `timeout_seconds`. Anything the NA
answers is final, a `429` or a `5xx` included (`na_refused`, with
`na_code`): a local client that floods the NA, or a host sharing the
device's address, cannot turn a DENY into a grant use or break-glass.

1. **Connected** (an NA answer within two heartbeat intervals, state
   `active`): the NA decides through the node route. ALLOW runs the action
   (`decision`); DENY is final (`na_denied`); any other answer is
   `na_refused`. Only an unanswered request goes on.
2. **Grants**: the held grants, soonest end first. A grant that names the
   capability but does not cover the parameters or the resource refuses the
   request, `outside_grant`, **even with a justification, and whether or not
   the snapshot is fresh**. A covering grant is used (`grant`) while the
   snapshot is fresh; otherwise `grant_code` is `snapshot_stale`. A covering
   grant that has ended, is spent or is revoked, or no grant naming the
   capability, goes on with its `grant_code`.
3. **Break-glass**: without a justification, `justification_required`. With
   one (1 to 1024 characters, logged by its length only), the NA is asked (if
   step 1 did not just ask it); if it answers, its answer stands, otherwise
   the change runs under break-glass, recorded with how the evaluation
   failed, and the NA judges it afterwards.

A `revoked` agent refuses every request (`403 node_revoked`). With an expired
certificate the NA is not asked: grants, break-glass and uploads still work,
because the executor key is still registered. Break-glass then records that
no decision could be had (`evaluation_failure` `network_error`).

## The schedule

| Activity | When |
|---|---|
| Heartbeat | Every `heartbeat_interval_seconds`, with the agent's version, snapshot age, pending uploads and dead letters |
| Renewal | When the certificate expires within `renew_before_seconds`; the new certificate is saved before it is used |
| Sync | Every `sync_interval_seconds` while connected and at once on reconnecting; every `retry_interval_seconds`, doubling up to 60, while not |
| Stop | On SIGTERM it stops accepting, waits up to 10 s for an open authorization, records it as not reported, and exits 0 |

A sync reads the key history, the CRL (`GET /crl`) and the revocation feed,
then `POST /node/state`: the attestations and grants issued to the node, each
verified. Each new grant gets a holder and a first time token. Then the
record outbox is uploaded (break-glass records, then grant uses in chain
order), then execution evidence, and every usable grant gets a fresh time
token. The agent moves to `revoked` when the CRL lists its certificate, the
NA refuses it as revoked (`certificate_revoked`, `edge_node_retired`), or
`/node/state` shows its executor key retired. Uploads the NA throttles
(`429`) stay pending and are retried after its `Retry-After`.

The **snapshot** is fresh while `now − min(synced_at, feed.issued_at)` is at
most `max_snapshot_age_seconds`. A stale snapshot stops all grant use. The
age is measured with the device's clock: freshness assumes a clock that does
not go backwards. When the clock is more than 300 s behind the time the NA
signed the snapshot, the snapshot counts as stale and `/v1/status` reports
`clock_behind`. A clock that runs slow is not detected; offline, the hard
bound on a grant is its `max_uses_per_time_token`.

## State

The state directory (0700, owned by the service user) holds:

| File | Mode | What |
|---|---|---|
| `node.key`, `executor.key` | 0600 | Base64 Ed25519 seeds (`#` comments allowed) |
| `enrollment.json` | 0600 | The NA, its audience, the certificate, the sovereign, the executor key |
| `snapshot.json` | 0600 | The key history, the CRL, the revocation feed, the node state, `synced_at` |
| `agent.db` | 0600 | SQLite (WAL, `synchronous=FULL`): the outboxes, the grant holders, the authorizations |

The agent refuses to start (exit 6) when a key file is group- or
world-accessible. JSON files are written whole: a temporary file, synced,
then renamed. On start each grant holder is advanced to the newest use of
its grant the agent made, so a crash between keeping a use and saving the
holder never signs a second use at the same place. Authorizations a previous
run left open are counted as `lost_authorizations`.

`genesis-mesh-edge status [--json]` reads the state files without the agent
running.

### Commands

`init [--json]`, `enroll [--invite-token-file F] [--reset [--discard-pending]]`,
`run`, `status [--json]`, `token new --name N`, `check-config`, `--version`.

## Logging and exit codes

Logs are JSON lines on stderr: `ts`, `level`, `event`, `fields`. They never
hold keys, invite or local tokens, parameter values or justification text;
they do name capabilities, resources, authorities, codes, record IDs and the
uid of a refused peer.

| Exit | Meaning |
|---|---|
| 0 | OK |
| 1 | Internal error |
| 2 | Usage or configuration error |
| 3 | Not enrolled (`run` without a token) |
| 4 | Enrolment refused for good |
| 5 | The NA could not be reached during `enroll` |
| 6 | Insecure permissions on the keys |

## Install

### Release files

Each release attaches, beside the verifier's files:

| File | What it is |
|---|---|
| `genesis-mesh-edge-<version>-x86_64-unknown-linux-musl` | The static binary for x86-64 |
| `genesis-mesh-edge-<version>-aarch64-unknown-linux-musl` | The static binary for arm64 |
| `genesis-mesh-edge.service` | The systemd unit |
| `edge.toml.example` | The example configuration |
| `SHA256SUMS-edge` | The SHA-256 of each file above |
| `*.sigstore.json` | Sigstore bundles of the binaries and of `SHA256SUMS-edge` |

Verify a download:

```sh
V=1.7.0
cosign verify-blob --bundle SHA256SUMS-edge.sigstore.json \
  --certificate-identity "https://github.com/GenesisMeshLabs/sdk-rust/.github/workflows/edge.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS-edge
sha256sum --check --ignore-missing SHA256SUMS-edge
```

### systemd

`genesis-mesh-edge.service` runs the agent as the `genesis-mesh-edge` user
with `StateDirectory`, `RuntimeDirectory` and `ConfigurationDirectory`,
`UMask=0077`, the invite token through `LoadCredential=invite-token:…`,
`Restart=on-failure` (not after exit 2, 3, 4 or 6), and a hardened sandbox
(no capabilities, a read-only system, no new privileges, a system call
filter, `MemoryMax=64M`, `TasksMax=16`).

### Container image

`ghcr.io/genesismeshlabs/genesis-mesh-edge`, for linux/amd64 and linux/arm64,
built from the released binaries (`FROM scratch`, user `65532`, volumes
`/var/lib/genesis-mesh-edge` and `/run/genesis-mesh-edge`, command `run`).
It is pushed by digest, the digest is signed with the identity above and
named in the release notes, and it is tagged with the version only: no
`X.Y` or `latest` tag while the agent is beta.

```sh
cosign verify --certificate-identity "https://github.com/GenesisMeshLabs/sdk-rust/.github/workflows/edge.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/genesismeshlabs/genesis-mesh-edge@sha256:…
```

## Size and memory

`edge/footprint-budgets.json` holds fixed targets: a binary of at most
12 MiB and a maximum resident set size of at most 32 MiB, per architecture.
CI builds both binaries on native runners and fails when a binary, or the
agent's maximum resident set size over the 120-second offline scenario,
exceeds them; the measured values are uploaded with each run
(`footprint-<target>.json`) and recorded with each release, apart from the
targets.

The pull request scenarios cover an NA that refuses connections (120 s), a
blackholed network (connections open, nothing answers), an NA that answers
`429`, and a stale snapshot. The weekly soak (and every release pull request)
runs the refused-connection scenario for two hours of real time: it shows
that memory stays flat and the uploads still finish in order within 120 s.
With the default limits nothing expires within those two hours (time tokens,
grants, certificates and the snapshot all outlast it), so expiry is covered
by the stale-snapshot scenario, not by the soak.

## Limits

- Keys are files protected by their permissions; platform key stores (TPM,
  PKCS#11) are not supported. armv7 is not built.
- One authorization is open at a time.
- An authorization open when the agent stopped without SIGTERM is lost
  (`lost_authorizations`): the change may have been made without a record.
- Treaties are not held on the device: it does not verify peers or evaluate
  policies itself.
