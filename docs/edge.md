# genesis-mesh-edge: the edge agent

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

[examples/edge-agent.md](examples/edge-agent.md) walks through a real run:
enrolment with a bound invite, a decision, the NA stopped (a grant, then
break-glass), and the uploads once it is back.

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
genesis-mesh admin invite --role client \
  --node-sovereign-id site7-17 --executor-resource-prefix edge:site7-17/ \
  --recipient-key <node public key printed by genesis-mesh-edge init>
```

The invite token is a bearer secret for a privileged act. To bind the
invite to the device, run `genesis-mesh-edge init` on the device first: it
creates the state directory and both keys and prints the node public key
(`--json` adds the executor key) for the invite's `recipient_public_key`
(`--recipient-key`). `enroll` then uses those keys, and the NA refuses the
invite from any other node key.

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
`$CREDENTIALS_DIRECTORY/invite-token` (systemd's `LoadCredential`; the value
`none` is no token), `GM_EDGE_INVITE_TOKEN`, then
`/etc/genesis-mesh-edge/invite-token`, in that order. It is never written to
the state directory and never logged. Once enrolled, the agent never reads it
again: the file may be removed.

### Starting again

`genesis-mesh-edge reset` deletes the keys and every state file. It refuses
while records are not uploaded unless `--discard-pending` is given
(`outbox export` saves them first), and while the agent runs: `run` holds a
lock in the state directory (`agent.lock`), and `enroll`, `init` and `reset`
take it too. To start again with a recipient-bound invite:

1. Stop the agent.
2. `genesis-mesh-edge reset`.
3. `genesis-mesh-edge init`: it prints the new node key.
4. The operator creates the invite bound to that key (`--recipient-key`).
5. `genesis-mesh-edge enroll`.

`enroll --reset` deletes the state and enrols at once, with new keys: it
checks that a token is available before it deletes anything, but no invite
can be bound to keys that do not exist yet. Use it only with an invite that
is not bound to a node key.

The agent refuses to start (exit 2) when `enrollment.json` names another NA
than the configured `authority.url` (reset to enrol with another NA), and
when `agent.db` was written by a newer agent.

## Configuration

The configuration file is `--config`, or `GM_EDGE_CONFIG`, or
`/etc/genesis-mesh-edge/edge.toml` when it exists; it is optional when the
environment gives the required keys. The environment wins over the file,
the file over the defaults. `edge/packaging/edge.toml.example` (released as
`edge.toml.example`) shows every key; the tables below give each key's
environment variable and bounds. `genesis-mesh-edge check-config`
prints the effective configuration without secrets.

### `[authority]`

| Key | Environment | Default |
|---|---|---|
| `url` | `GM_EDGE_NA_URL` | required; https, or http only to a loopback host or with `allow_insecure_http` |
| `root_public_key` | `GM_EDGE_ROOT_PUBLIC_KEY` | required; pins the NA's key history |
| `timeout_seconds` | `GM_EDGE_NA_TIMEOUT_SECONDS` | 5 (at most 300) |
| `allow_insecure_http` | `GM_EDGE_ALLOW_INSECURE_HTTP` | false |

HTTPS uses the bundled web PKI roots. A private certificate authority is not
supported in 1.7.0.

### `[node]` and `[snapshot]`

| Key | Environment | Default |
|---|---|---|
| `node.state_dir` | `GM_EDGE_STATE_DIR` | `/var/lib/genesis-mesh-edge` |
| `node.validity_hours` | `GM_EDGE_VALIDITY_HOURS` | 168 (1 to 8760) |
| `node.heartbeat_interval_seconds` | `GM_EDGE_HEARTBEAT_INTERVAL_SECONDS` | 30 (at most 3600) |
| `node.renew_before_seconds` | `GM_EDGE_RENEW_BEFORE_SECONDS` | 86400 (at most 30 days) |
| `snapshot.sync_interval_seconds` | `GM_EDGE_SYNC_INTERVAL_SECONDS` | 60 (at most 86400) |
| `snapshot.retry_interval_seconds` | `GM_EDGE_RETRY_INTERVAL_SECONDS` | 15, doubling up to 60 (at most 3600) |
| `snapshot.max_snapshot_age_seconds` | `GM_EDGE_MAX_SNAPSHOT_AGE_SECONDS` | 86400 (60 to 604800) |

### `[decisions]`, `[local_api]` and `[log]`

| Key | Environment | Default |
|---|---|---|
| `decisions.attestation_id` | `GM_EDGE_ATTESTATION_ID` | none; pins the attestation decisions are asked under |
| `local_api.listen` | `GM_EDGE_LISTEN` | `unix:/run/genesis-mesh-edge/agent.sock`, or `tcp://127.x.x.x:port` |
| `local_api.allowed_uids`, `allowed_gids` | `GM_EDGE_ALLOWED_UIDS`, `GM_EDGE_ALLOWED_GIDS` (comma lists) | `[]` |
| `local_api.socket_mode`, `socket_group` | `GM_EDGE_SOCKET_MODE`, `GM_EDGE_SOCKET_GROUP` | `0660`, none |
| `[[local_api.tokens]]` `name`, `sha256` | `GM_EDGE_TOKENS="name:hex,..."` | none |
| `local_api.report_timeout_seconds` | `GM_EDGE_REPORT_TIMEOUT_SECONDS` | 300 (at most 86400) |
| `local_api.queue_timeout_seconds` | `GM_EDGE_QUEUE_TIMEOUT_SECONDS` | 30 (at most 3600) |
| `local_api.rate_limit_per_minute` | `GM_EDGE_RATE_LIMIT_PER_MINUTE` | 30 authorizations per minute per local client (1 to 100000) |
| `log.level` | `GM_EDGE_LOG_LEVEL` | `info` |

The agent refuses to start (exit 2) when the listener is a Unix socket and
both allow-lists are empty, when it is TCP on an address that is not
loopback or has no token, or when the NA's URL is plain http to a host that
is not loopback without `allow_insecure_http`.

## Local API

HTTP/1.1 with JSON bodies of at most 64 KiB, read as strict JSON. Errors are
`{"error": {"code", "message"}}`. The API holds at most 64 connections at once
(more are closed at once) and closes a connection that has not sent a
request's headers within 10 seconds, so idle clients cannot take it down; an
accept error is logged and the agent keeps serving.

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
connection (`connected`, `last_na_contact_at`; `na_state`: `answering`,
`throttled`, `failing` or `unreachable`, from the last exchange; and
`last_na_error`, `{status, code, at}`), the snapshot
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

The capability, the resource and its action are required; the action is
`create`, `rotate`, `revoke`, `update` or `delete`, and the resource must
start with the node's resource prefix (`400 resource_out_of_scope`). Text
fields (`capability`, `resource_id`, `attestation_id`, `justification`) are
1 to 1024 characters. Unknown fields are refused (`400 invalid_request`).
Parameters and attributes are JSON objects that carry identifiers and
versions only (`400 secret_material`). The answer:

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
| `na_refused` | The NA refused the request, or throttles or fails and no grant covers it (`na_code`, `na_status`) |
| `decision_unverifiable` | The decision did not verify (`verification_reason`) |
| `outside_grant` | A held grant names the capability but does not cover the request (`grant_code`) |
| `justification_required` | No grant can be used and there is no justification (`grant_code`) |
| `no_attestation` | No attestation issued to the node can be used |

### `POST /v1/authorizations/{id}/outcome`

```json
{"outcome": "success", "execution_parameters": {"version_id": "v8"}, "outcome_detail": "rotated"}
```

`outcome` is `success`, `failure` or `partial`; `execution_parameters` is
a JSON object; `outcome_detail` is 1 to 1024 characters. The answer names
the record: `{authorization_id, record_kind` (`execution`,
`grant_execution` or `break_glass`)`, record_id, queued, dropped}`.
Metadata the secret guard refuses is left out and named in `dropped`. Only the
client that asked (the same uid, or the same token) may report the outcome;
another gets `404 authorization_not_found`. A client that goes away before
its authorization was answered abandons it: nothing runs and nothing is
signed.

One authorization is open at a time; others wait, first come first served,
for up to `queue_timeout_seconds` (then `503 agent_busy` with
`Retry-After: 1`). An outcome not reported within `report_timeout_seconds`
is recorded as `failure`, with a detail saying it was not reported; reporting
it later is `410 authorization_expired`. Other errors: `400 invalid_request`,
`403 node_revoked`, `404 authorization_not_found`,
`409 outcome_already_reported`, `413 request_too_large`,
`429 local_rate_limited` (more than `rate_limit_per_minute` authorizations
from one client, by uid or token name, counted in a fixed one-minute window
that starts with the client's first request, before the NA is asked),
`404 not_found` (an unknown route), `503 not_enrolled`.

## Decision order

The attestation a request is decided under is the request's
`attestation_id` (one issued to the node), else the configured one, else the
single active attestation whose `claims.capabilities` names the capability,
latest expiry first. Decisions are verified under the NA's keys from the key
history, against that attestation, accepting the policy versions the decision
binds (the device holds no policies).

What an NA error means falls in three classes:

| Class | What the agent got | Grants | Break-glass |
|---|---|---|---|
| **Refused** | A DENY, or an error with the NA's JSON error body and a 4xx status other than 429 | No: final | No |
| **Throttled or failing** | A `429` or `5xx` that is not a gateway's own page (see the next row), with or without the NA's JSON error body | Yes (bounded by the operator) | No: `na_refused` |
| **Unreachable** | No connection, no response within `timeout_seconds`, or a gateway's own page (`502`, `503`, `504`, `520` to `527` without the NA's JSON error body) | Yes | Yes, with a justification |

So a local client that floods the NA, or a host sharing the device's address
at a NAT, can never turn a DENY into break-glass, while an NA stopped behind
nginx or a load balancer (whose own 502 page answers) is treated as down. A
`500` page without the NA's body counts as the NA failing, not as a gateway.

The SDK's own break-glass (`governed_action_with_break_glass`, the grant
holder's fallback and `urgent_action`) is wider by design: it counts any
`429` or `5xx` as no answer, apart from `429 admin_auth_throttled`,
`503 evidence_store_unavailable` and an unreadable body (the README's
*Break-glass*). The agent applies the stricter rule above.

1. **Connected** (an answer of the NA itself within two heartbeat intervals,
   state `active`): the NA decides through the node route. ALLOW runs the
   action (`decision`); DENY is final (`na_denied`); a refusal is final
   (`na_refused`). Throttled, failing or unreachable go on.
2. **Grants**: the held grants, soonest end first, and the grants the node
   state lists without a holder (by their envelope). A grant that names the
   capability but does not cover the parameters or the resource refuses the
   request, `outside_grant`, **even with a justification, whether or not the
   snapshot is fresh, and even when another such grant has ended**. A
   covering grant is used (`grant`) while the snapshot is fresh; otherwise
   `grant_code` is `snapshot_stale`. A covering grant that has ended, is
   spent or is revoked, or no grant naming the capability, goes on with its
   `grant_code`. With `clock_behind`, a grant "not valid yet" counts as ended,
   never as not covering.
3. **The NA throttling or failing**: `na_refused`, never break-glass.
4. **Break-glass**: without a justification, `justification_required`. With
   one (1 to 1024 characters, logged by its length only), the NA is asked (if
   step 1 did not just ask it); if it answers, its answer stands as above;
   if it is unreachable, the change runs under break-glass, recorded with how
   the evaluation failed (`network_error`, `timeout`, or `server_error` for a
   gateway's page), and the NA judges it afterwards.

A `revoked` agent refuses every request (`403 node_revoked`). With an expired
certificate the NA is not asked for decisions: grants, break-glass and
uploads still work, because the executor key is still registered. The record
format has no `certificate_expired` failure, so such a break-glass record
says `evaluation_failure` `network_error`, the closest value: the device
could not get a decision. The agent keeps trying `/renew`; the NA refuses an
expired certificate, so the state stays `certificate_expired` until the
device is recovered: let its records upload (`pending_uploads` reaches 0,
checked with `status` on the device), stop it, have the operator revoke the
old certificate, then `reset`, `init` and `enroll` with a new invite. Records
made between the check and the revocation are refused, so stop the agent
before the operator revokes.

## The schedule

| Activity | When |
|---|---|
| Heartbeat | Every `heartbeat_interval_seconds`, with the agent's version, snapshot age, pending uploads and dead letters; also with a certificate the device's clock takes as expired: while the NA accepts it, the agent stays `active` (the clock is ahead, the NA decides) |
| Renewal | When the certificate expires within `renew_before_seconds`, and again at every heartbeat once it has expired; the new certificate is saved before it is used. Also once a key succession has taken effect, for a certificate the succeeded key signed (1.8.1): each agent at its own share of the 10 minutes after the succession, and within half the grace |
| Sync | Every `sync_interval_seconds` while connected and at once on reconnecting; every `retry_interval_seconds`, doubling up to 60, while not |
| Stop | On SIGTERM it takes no new authorization (queued ones are refused, never decided), waits up to 10 s for an open one, records it as not reported, and exits 0 |

A sync reads the key history, the CRL (`GET /crl`) and the revocation feed,
then `POST /node/state`: the attestations and grants issued to the node, each
verified. Then the record outbox is uploaded (break-glass records, then
grant uses in chain order), then execution evidence, 200 records at a time.
After the uploads every usable grant already held gets a fresh time token,
and each new grant gets a holder and its first time token; a grant the
agent already used (its holder lost) is rebuilt from those uses, never from
use 0. The uploads run even when a read failed: records are signed with the
executor key, not the node key; the time tokens and new holders wait for a
sync whose reads succeeded. Records
the NA throttled (`429`, its `Retry-After`) wait for it, except once on
reconnecting; a decision uploads a few pages first, so its evidence follows
the records before it. The agent moves to `revoked` when the CRL lists its
certificate, the NA refuses it as revoked (`certificate_revoked`,
`edge_node_retired`), or `/node/state` shows its executor key retired.

**Across a key succession** (1.8.1), what the agent relies on must be
signed by an NA key valid at the record's own time that still vouches now:
the CRL and each attestation are refused once their key's vouching horizon
has passed (its end, the 300-second hand-over and the grace, which the NA's
`vouching_grace_seconds` may only shorten). Grant holders get the key
history: a grant past its key's horizon ends as `grant_expired`, and a
revocation feed of a later key replaces one of an earlier key. A sync that
brings a new succession, or a new grace, rebuilds every holder with the
NA's keys, so time tokens and feeds the new key signs are accepted.

The **snapshot** is fresh while `now − min(synced_at, feed.issued_at)` is at
most `max_snapshot_age_seconds`. A stale snapshot stops all grant use. The
age is measured with the device's clock: freshness assumes a clock that does
not go backwards. When the clock is more than 300 s behind the time the NA
signed the snapshot, the snapshot counts as stale and `/v1/status` reports
`clock_behind`. A clock that runs slow is not detected; offline, the hard
bound on a grant is its `max_uses_per_time_token`.

### The device's clock

The device's clock must be within ±5 minutes of the NA's: run NTP, and on a
board with no real-time clock, `fake-hwclock` (or equivalent) so a reboot
offline does not go back in time. Otherwise:

- **More than 5 minutes off, NA reachable**: the NA refuses the node's
  requests (`401 node_auth_failed`, logged at warn and shown in
  `last_na_error`), so every decision is refused (`na_refused`). Uploads
  still run.
- **Behind the NA's signing time by more than 300 s**: the snapshot is stale
  (`clock_behind`), so no grant is used; break-glass with a justification
  remains.
- **Ahead of the certificate's end**: the agent keeps heartbeating; while the
  NA accepts the certificate it stays `active`.

## State

The state directory (0700, owned by the service user) holds:

| File | Mode | What |
|---|---|---|
| `node.key`, `executor.key` | 0600 | Base64 Ed25519 seeds (`#` comments allowed) |
| `enrollment.json` | 0600 | The NA, its audience, the certificate, the sovereign, the executor key |
| `snapshot.json` | 0600 | The key history, the CRL, the revocation feed, the node state, `synced_at` |
| `agent.db` | 0600 | SQLite (WAL, `synchronous=FULL`): the outboxes, the grant holders, the authorizations (kept 7 days), `schema_version` |
| `agent.lock` | 0600 | Held by the process that changes the state |

The agent refuses to start (exit 6) when a key file is group- or
world-accessible, or the directory is group- or world-writable. JSON files are written whole: a temporary file, synced,
then renamed. On start each grant holder is advanced to the newest use of
its grant the agent made, so a crash between keeping a use and saving the
holder never signs a second use at the same place. Authorizations a previous
run left open are counted as `lost_authorizations`.

`genesis-mesh-edge status [--json]` reads the state files without the agent
running, and `outbox export [--dead-letters]` writes every record not
uploaded (or the dead letters only) as JSON lines on stdout, read-only: dead
letters are evidence of actions that ran.

### Commands

`init [--json]`, `enroll [--invite-token-file F] [--reset [--discard-pending]]`,
`run [--invite-token-file F]`, `reset [--discard-pending]`, `status [--json]`,
`outbox export [--dead-letters]`, `token new --name N`, `check-config`,
`--version`.

## Logging and exit codes

Logs are JSON lines on stderr: `ts`, `level`, `event`, `fields`. They never
hold keys, invite or local tokens, parameter values or justification text;
they do name capabilities, resources, authorities, codes, record IDs and the
uid of a refused peer.

| Exit | Meaning |
|---|---|
| 0 | OK |
| 1 | Internal error, or a runtime failure (the service manager restarts it) |
| 2 | Usage or configuration error (also: another process holds the state, another NA, a newer database) |
| 3 | Not enrolled (`run` without a token) |
| 4 | Enrolment refused for good |
| 5 | The NA could not be reached during `enroll`, or answered `429` or `5xx` (try again later) |
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

The binaries are built by `scripts/build_edge.sh` with the verifier's pinned
toolchain, `SOURCE_DATE_EPOCH` and path remapping; the script writes a
`.buildinfo` file beside the binary, which the release does not attach.
Unlike the verifier's, CI builds each edge binary once: it does not check
that two builds are identical.

### systemd

`genesis-mesh-edge.service` runs the agent as the `genesis-mesh-edge` user
with `StateDirectory`, `RuntimeDirectory` and `ConfigurationDirectory`,
`UMask=0077`, the invite token through `LoadCredential=invite-token:…` with
`SetCredential=invite-token:none` as its fallback (so the unit still starts
once the token file is removed after enrolment), `Restart=on-failure` (not
after exit 2, 3, 4 or 6), and a hardened sandbox (no capabilities, a
read-only system, no new privileges, a system call filter that allows
`@chown` for `socket_group`, `MemoryMax=64M`, `TasksMax=16`; checked with
systemd 255).

The socket's directory, `/run/genesis-mesh-edge`, is
`RuntimeDirectoryMode=0750`: only the agent's group may enter it. Give a
client access by adding it to that group (and to `allowed_gids`), or, with
`socket_group`, widen the directory with a drop-in
(`RuntimeDirectoryMode=0755`; the socket itself keeps `socket_mode`).

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
agent's maximum resident set size over the 120-second offline scenario or
over a backlog of 2000 records made offline and then uploaded, exceeds them;
the measured values are uploaded with each run (`footprint-<target>.json`)
and recorded with each release, apart from the targets. Counts come from
SQLite and uploads go 200 records at a time, so a backlog is never loaded
whole to count or upload it.

The pull request scenarios cover an NA that refuses connections (120 s), a
blackholed network (connections open, nothing answers), a reverse proxy's 502
page, an NA that answers `429`, a stale snapshot, a client that disconnects,
idle connections at a low file limit, and the backlog. The weekly soak (and
every release pull request) runs the refused-connection scenario for two
hours of real time on x86-64: it shows that memory stays flat and the
uploads still finish in order within 120 s.
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
