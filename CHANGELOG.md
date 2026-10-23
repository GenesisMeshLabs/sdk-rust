# Changelog

## 1.8.0 - 2026-10-23

### Security

- **The edge agent checks each record with the NA keys valid at its time.**
  The agent flattened the NA's key history into every key it ever had, valid
  at any time. After a key succession, whoever still held the outgoing key
  could sign a CRL, a join certificate or an attestation the agent accepted.
  Each of these is now checked with the keys valid at its own `issued_at`.
  Decisions are checked with the keys valid now. A grant holder gets the
  keys of its grant's issue time and of now.
- **TLS certificate checks updated (RUSTSEC-2026-0381, RUSTSEC-2026-0382).**
  The lockfile moves `rustls-webpki` to 0.103.16 and `webpki-roots` to
  1.0.10, so the HTTP client and the edge agent no longer accept the
  distrusted emSign intermediates. Applications that build with their own
  `Cargo.lock` run `cargo update -p rustls-webpki -p webpki-roots`.

### Added

- **Two walkthroughs, each with a recorded run.** `docs/examples/edge-agent.md`
  takes `genesis-mesh-edge` from a bound invite through a decision, an
  outage (a grant, then break-glass) and the uploads afterwards;
  `docs/examples/verify-audit-pack.md` verifies the frozen audit pack, the
  same pack with one byte changed, and compares the Python reference's
  verdict. The new `edge_site` example issues the walkthrough's policy,
  attestation and grant. `edge/` and `verifier/` gained a README.

### Changed

- **Documentation corrected against the code.** `enroll --reset` is
  documented as unusable with an invite bound to a node key (reset, `init`,
  a new invite, then `enroll`). The edge agent's "throttled or failing"
  class covers any `429` or `5xx` that is not a gateway's page, with or
  without the NA's body, and exit 5 covers an NA that answers `429` or
  `5xx` during `enroll`. The README states that the SDK's break-glass counts
  a `429` or `5xx` as no answer while the edge agent does not; both are
  deliberate. The API table lists `node`, `grants.uses` and the outbox
  methods; the verifier page pins 1.7.0, describes itself as a port of the
  Python reference rather than an independent implementation, and names the
  functions its clippy rules refuse. `edge.toml.example` shows
  `rate_limit_per_minute` and says the allow-lists must not both be empty.
- **Security policy.** Acknowledgement within 5 business days and a
  remediation plan within 30 days for confirmed issues, as for the core; a
  verifier that accepts what the reference refuses is in scope.
- **Live tests no longer pass when they did not run.** `tests/live_na.rs`
  and the edge agent's scenarios (`edge/tests/scenario.rs`) are
  `#[ignore]`d, so a plain `cargo test` reports them as ignored instead of
  `ok`; run them with `--include-ignored`. With `GM_E2E_REQUIRED=1`, which
  CI sets, a missing NA, an NA that cannot exercise a part, or (for the
  verifier's differential test) a missing `GM_VERIFY_CORPUS` fails the run.

### Fixed

- **`genesis-mesh-edge --help` prints the usage.** `--help`, `-h` and `help`
  print the usage and exit 0; they were an unknown option (exit 2).

### Upgrading

- Contributors who run the live tests locally add `--include-ignored`, for
  example `GM_E2E_PYTHON=python cargo test --test live_na -- --include-ignored`.
  The crate's API is unchanged.

## 1.7.0 - 2026-10-15

### Security

- **rustls 0.23.46.** The HTTP client (the `client` feature) and the edge agent link rustls 0.23.46, which fixes
  RUSTSEC-2026-0346 (`Debug` output of client session values exposed TLS secrets), RUSTSEC-2026-0347 (buffered
  data sent to the outer server after an ECH rejection), RUSTSEC-2026-0348 (Brotli certificate decompression could
  allocate up to 1 GiB before authentication) and RUSTSEC-2026-0349 (an unauthenticated ServerHello could downgrade
  later connections to classical key exchange). The verifier links no TLS.

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

### Changed

- **The HTTP client is the default feature `client`.** `reqwest`,
  `percent-encoding`, every client that calls the NA (`GenesisMeshClient`,
  the sub-clients, `governed_action` and the rest of the governance
  composition, `GrantHolder`), and the error variants that hold a transport
  error (`GenesisMeshError::Network`, `GenesisMeshError::ResponseBodyUnreadable`)
  need it. Without it the crate is its offline modules only: verification,
  canonical forms, signing, the outboxes, the grant rules, audit packs and
  node request signatures, with no HTTP stack, no `tokio` and no TLS.
  `genesis-mesh-verify` now depends on the SDK without it, so its build no
  longer compiles the HTTP stack at all. With the default features the API is
  unchanged (apart from `GovernedVerification`, see below).
- **`ResourceHead` is defined with the offline modules.** It is still
  `genesis_mesh_sdk::ResourceHead`; only its source module moved, so it is
  available without the `client` feature.

### Fixed

- **A grant holder no longer counts a use the NA quarantined against the
  grant's budget.** The NA's budget counts admitted uses only, but
  `GrantHolder` counted every use it had signed, so a holder with a
  quarantined use fell back with `grant_budget_exhausted` while the grant
  still had uses left. Offline the holder still counts every use it signed,
  since it cannot know which the NA will admit; once the NA has answered a
  use as quarantined after it continued the chain, that use stops counting
  and keeps its place in the chain. A use quarantined as a conflict or a
  chain mismatch (it did not continue the chain) or as
  `grant_budget_exhausted` (the NA counted more admitted uses than the
  holder knew of) still counts.
  `GrantHolder::act` and `GrantHolder::sync` read this from the record
  outbox; after flushing it yourself, call
  `GrantHolder::count_quarantined`.
- **A dead letter names the NA's quarantine entry.** When the NA keeps a
  refused record as a quarantine entry, the record outbox entry's
  `last_error.quarantine_id` now holds its ID (the NA's
  `error.details.quarantine_id`), as the TypeScript SDK writes it. Older
  outbox files still read.

### Changed (breaking)

- **`GovernedVerification.any_bound_policies` (beta, default `false`).** When
  `true`, a governed action accepts whatever policy versions the NA's
  decision binds instead of comparing them with `expected_policies`; the
  NA's signature, the context and the attestation are still checked. A
  device that holds no policies, such as the edge agent, sets it. Code that
  builds `GovernedVerification` with a struct literal naming every field must
  add the field, or use `..GovernedVerification::default()`.

### Upgrading

- `default-features = false` now drops the HTTP client. If you turned the
  default features off for another reason and call the NA, add
  `features = ["client"]`.

## 1.6.0 - 2026-10-14

### Added

- **Pre-issued grants.** `GenesisMeshClient::grants` (`GrantClient`, beta routes) issues, lists, reads and revokes grants (`issue`, `list` with `GrantQuery` and its grant-id cursor, `get` with `chain_length`, `uses` for a grant's use chain with each use admitted or quarantined, `revoke`), asks for a holder's time tokens (`request_time_token`), submits a holder's uses (`submit_use`) and reads the revocation feed (`revocation_feed`). The routes answer `404 grants_disabled` unless the NA runs with `EVIDENCE_GRANTS=on`. `EvidenceStoreClient::search` takes `grant_id`, and `resource_head_entry` names what a resource's head is (`entry_kind`, `record_id`: execution evidence or a grant use).
- **Acting within a grant offline.** `GrantHolder` holds one grant for the device whose executor key is the grant's bearer. `act` checks each use offline (the bearer key's resource prefix, `GrantHolder::set_resource_prefix`; the capability, the closed envelope with the 1.6.0 number rules, revocation from the feed it holds, the validity, the budget, and at most `max_uses_per_time_token` uses after the use its time token names), runs the action (`GrantAuthority`), signs a `GrantExecutionEvidence` chained to the previous use, keeps it in the record outbox and submits it (`GrantActionOutcome::Used`). A request the grant does not cover (`grant_use_out_of_scope`, `grant_capability_mismatch`, `grant_envelope_mismatch`), a grant not valid yet, or secret material in the parameters is refused before anything runs (`GenesisMeshError::GrantRefused`, `grant_use_secret_material`). `sync` reads the feed, uploads the uses in their chain's order and asks for a new time token; `state` and `restore` keep the holder's chain across restarts.
- **Expiry is not a block.** When a grant has ended, its budget or time token is spent, it is revoked or its bearer key retired, `act` falls back with the request's `GrantFallback` to `governed_action_with_break_glass` naming the capability: the NA's decision when it answers (a DENY does not run the action), break-glass when it does not (`GrantActionOutcome::FellBack`). Without a fallback the request is refused with the reason.
- **Signing the bearer's records.** `ExecutionRecorder::sign_grant_use` (`GrantUseInput`, a `use_id` a lowercase UUID) and `sign_time_token_request` sign a use and a time token request with the bearer key, refusing before signing what the NA would refuse (`grant_use_malformed`, `grant_use_secret_material`, `time_token_request_malformed`); `ExecutionRecorder::public_key` names the key a grant's `bearer_public_key` must be.
- **Grant uses in the record outbox.** `RecordKind::GrantExecution` keeps a use until the NA admits it; `flush_records` submits uses one at a time in their chain's order, after break-glass records and before observations, and dead-letters the refusals in `GRANT_USE_PERMANENT_REFUSALS` (the NA keeps such a use as a quarantine entry, and a quarantined use that continues the chain still takes its place in it, so the uses after it are submitted and judged on their own). An earlier use not uploaded yet (`grant_use_chain_gap`) and a use dated ahead of the NA's clock (`grant_use_in_future`) are retried.
- **Verifying grants.** The `grants` module holds the records' rules: `normalize_parameter`, `envelope_problem`, `in_range`, `scalar_equal`, `normalize_number`, `use_problem` (`UseContext`, with the last admitted use and the admitted count; `PreviousUse`, `next_previous`, `continues_chain`), `grant_digest`, `use_digest`, `valid_use_id`, `signed_as_received` and the codes (`USE_REJECTION_CODES`, `QUARANTINED_USE_CODES`, `ISSUANCE_REFUSALS`, `REVOCATION_REASONS` with `agreement_untrusted`). The use rules are the reference's: the budget over admitted uses, at most `max_uses_per_time_token` uses after the use a time token names, a use dated up to 300 s before its token, a token not older than its grant, order and regression against the last admitted use. `verify_evidence_events` and `verify_audit_pack` check the entry kinds `grant`, `grant_execution` and `grant_revocation` with the reference's reasons (`grant_use_chain_break`, which a quarantined use continuing the chain satisfies; `grant_missing`, also for a grant whose signature fails; `grant_bearer_mismatch`, `grant_use_out_of_scope` for a bearer key with a `resource_prefix`, `grant_mismatch`, `duplicate_grant_revocation`, `duplicate_record` for a `use_id` that is an execution or break-glass record's id, then the use rules, the resource position the NA assigned, and in a pack `cited_record_missing`), count them (`grants`, `grant_executions`, `grant_revocations`), accept a judgement `governed_by: grant` and a quarantined grant use, check a grant's policy binding and basis in a pack (an attestation, or an agreement in the optional `trust/agreements.jsonl`: `cited_agreement_missing`, `cited_agreement_mismatch`, `agreement_invalid_signature`), and render the pack report's *Grants* and *Grant revocations* sections. `verify_record` verifies a grant, a grant use, a revocation and a time token; `verify::verify_revocation_feed` a feed listing `revoked_grant_ids`; `verify::valid_grant_record` a record's form. The shared conformance suite `grants` runs (99 of its 158 vectors: the 59 issuance vectors are its `na_only_kinds`).
- **`genesis-mesh-verify`.** `record` verifies the kinds `grant`, `grant-execution`, `grant-revocation` and `time-token`; `export` and `pack` check stores and packs holding grants, and the readable output counts grants, uses and revocations.

### Changed

- **The 1.6.0 suites.** The field registry knows the grant records, the entry kinds and the feed's `revoked_grant_ids`; the `audit` suite's record times include a grant (`issued_at`), a time token (`issued_at`) and a grant revocation (`revoked_at`).
- **Governed changes.** `remediation::judgement_state` reads a judgement `governed_by: grant` as matched, as one governed by a prior decision.

### Upgrading

- Update every verifier that reads your exports, packs and revocation feed before the NA turns `EVIDENCE_GRANTS=on`: a 1.5 SDK refuses the new entry kinds and the feed's `revoked_grant_ids`.
- `RecordKind` has a new variant, `GrantExecution`, and `GenesisMeshError` a new one, `GrantRefused`: a `match` over them needs an arm. Record outbox files of a grant use carry `"kind": "grant_execution"`; 1.5 SDKs do not read them. `RECORD_KINDS`, `NA_RECORD_TIME_FIELDS` and `EvidenceVerification` grow with the new kinds.
- Persist `GrantHolder::state` after every use and restore it on start: a holder that forgets its uses signs a second use at a position it already used, which the NA refuses.

## 1.5.0 - 2026-10-13

### Added

- **A decision judged as of its own time.**
  `VerifyDecisionOptions::at_record_time` (the reference's name) judges a
  decision as of its `decision_made_at` instead of now, so an archived
  decision still verifies when it is audited years later. It is off by
  default: a decision about to be acted on is judged as of now, as before.
  `verify_record` and `genesis-mesh-verify record decision` judge as of the
  decision's own time unless given one.
- **`genesis-mesh-verify`, the independent offline verifier.** A binary built
  from this crate verifies an audit pack as `genesis-mesh audit verify` does
  (`pack <dir> --anchor <root key>`, with `--known-anchors`,
  `--require-anchors`, `--prior`, `--prior-entries`, `--period`, `--report`,
  `--executor-keys`, `--changes` and `--tolerance-seconds`; the report it
  renders byte for byte and the differences from the pack's own
  `checks.json`), one signed
  record of any kind (`record <kind> <file>`), an evidence export (`export
  <file>`, with `--key-history`/`--root-key` or `--na-key`,
  `--executor-keys`, `--known-anchors`, `--checkpoint`, `--partial`,
  `--from-anchor` and `--cited` for a pack's range) and a key history (`key-history <file> --root-key`), with
  the Python reference's verdicts and reason codes, as readable text or JSON
  (`--json`), and one exit code per verdict: 0 verified, 1 not verified, 2
  usage error, 3 unreadable input. It passes the core's verification corpus
  (169 cases) and verifies the frozen 1.5.0 pack. It never needs a private
  key and never contacts a network: clippy rules, tests and CI enforce both.
  See `docs/verifier.md`.
- **Static, signed and reproducible release binaries.** Each release attaches
  `genesis-mesh-verify` for x86-64 and arm64 Linux (musl, statically linked),
  with SHA-256 checksums, Sigstore bundles and build info.
  `scripts/build_verifier.sh` pins the toolchain, the crates, the build time
  and the recorded paths, so a security team can rebuild a release and
  compare digests; CI builds each binary twice and compares them.
- **`verify::verify_record`** verifies one record as an export verifies it,
  with the same reason codes and order: every entry kind, a policy or an
  attestation (`VerifyRecordOptions`, `RecordVerification`,
  `verify::RECORD_KINDS`).
- **NA key succession.** `key_history::verify_key_history` verifies the
  genesis block (held to the rules of every signed record) and the key
  successions, each signed by the root key, the new key and the outgoing
  key, from the root key held, with the reference's checks and reason codes
  in its order: `genesis_invalid`, `genesis_root_mismatch`, `unknown_field`,
  `non_canonical_form`, `genesis_invalid_signature`; then per succession
  `payload_invalid`, `unknown_field` or `invalid_signature`,
  `non_canonical_form`, `succession_sovereign_mismatch`,
  `succession_chain_break`, `succession_key_reused` (also the root key),
  `succession_backdated`, `succession_not_increasing`,
  `succession_after_expiry`, `succession_invalid_root_signature`,
  `succession_invalid_new_key_signature`,
  `succession_invalid_previous_signature`. Given the history, exports,
  anchors, decisions and records accept an NA signature only by the key
  valid at the record's own time (in the store, also at the latest earlier
  entry's time), with the 300-second hand-over (`na_key_not_valid_at_time`);
  a decision may not outlive its key by more than the hand-over and the
  300-second lifetime cap (`decision_outlives_key`); entries are in time
  order within 300 seconds (`recorded_at_out_of_order`); key succession
  entries must be the history's (`succession_not_in_history`) and recorded
  60 seconds ahead (`succession_backdated`). Executor and observer keys are
  placed where the NA-signed registry records registered and retired them
  (`evidence_unknown_executor`, `evidence_executor_key_retired`; a key given
  with `--executor-keys` is not placed), and a record
  read alone is placed at its own time (`key_history::NA_RECORD_TIME_FIELDS`).
- **Audit packs.** `audit_pack::verify_audit_pack` checks a pack offline as
  the reference does, its check groups in order with their reason codes
  (among them `manifest_unknown_file`, `manifest_backdated`,
  `cited_entry_mismatch`, `report_mismatch`, `pack_period_not_covered`, and
  the warnings `cited_entry_unanchored`, `changes_outside_period`,
  `change_duplicate`); `render_report` renders `report.md` byte for byte;
  a report cell writes a number with an integral value as an integer
  (`1.0` is `1`), as every SDK renders it; `check_completeness` matches a
  pack against a log of changes kept elsewhere (strict RFC 3339 times, duplicates set aside, the best overall
  pairing).
- **Store anchors, as the reference checks them.**
  `verify::verify_store_anchors`, `verify::check_events_against_anchors`,
  `verify::parse_anchors`, `verify::check_anchors`, `verify::export_checkpoint`,
  `canonical::anchor_canonical` and `canonical::anchor_digest`, with the
  reference's reason codes (`anchor_invalid_signature`,
  `anchor_sovereign_mismatch`, `anchor_sequence_gap`, `anchor_chain_break`,
  `anchor_not_increasing`, `anchor_mismatch`, `anchor_entry_missing`,
  `export_not_linked_to_anchors`, `export_ends_before_anchor`), checked
  against vectors the reference generated (`tests/fixtures/anchors.json`).

### Fixed

- **A record with a field outside its signature is refused.** A retention
  checkpoint, and every record kind from 1.3.0 on, holding one is
  `payload_invalid`, as the reference refuses it; this crate warned
  `unsigned_field` for a checkpoint and verified the rest. Justifications and
  execution evidence keep the warning.

### Upgrading

- `VerifyDecisionOptions` gains `at_record_time` and `key_history`;
  `VerifyEvidenceOptions` gains `key_history` and `prior`; and
  `EvidenceVerification` gains the counts `key_successions` and `archives`:
  code that builds them field by field must name the new fields (`false` and
  `None` keep the behaviour of 1.4). `VerifyEvidenceOptions::new` sets them.

## 1.4.0 - 2026-10-12

### Added

- **Remediation records.** `ExecutionRecorder::sign_remediation` signs what a controller did about a judged change (`RemediationInput`, `RemediationSubject`, `RemediationSteps`), refusing before signing what the NA would refuse (`remediation_malformed`, `remediation_secret_material`). `EvidenceStoreClient::submit_remediation` submits one; the record outbox keeps them too (`RecordKind::Remediation`), retries a record whose subject or forward rotation the NA does not hold yet, and dead-letters the refusals in `REMEDIATION_PERMANENT_REFUSALS`. `flush_records` submits them after break-glass records and observations.
- **Cancel without breaking readers.** `rotate_forward_then_disable` rotates a resource forward under a governed decision, disables the denied version, then keeps a remediation record linked to the rotation's execution evidence (in the record outbox, or submitted directly without one). Given the remediation state (`RotateForwardParams::state`), it refuses before anything runs a plan other than a forward rotation (`remediation_steps_mismatch`), a change that is not due or overdue (`remediation_not_due`, `remediation_already_recorded`) and another denied version than the change made (`remediation_subject_mismatch`). Once the rotation ran, a disable that fails or a record that cannot be kept returns `RemediationNotRecorded` (`remediation_not_recorded`) with the rotation's evidence: do not rotate again.
- **Urgent changes.** `urgent_action` runs an urgent change under the ordinary capability when it is allowed, under the emergency capability (`EmergencyOptions`, with the justification in its justification parameter) after a DENY or an unanswered evaluation, and under break-glass naming the emergency capability when the NA does not answer (`UrgentPath`).
- **The due queue, notices and reviews.** `EvidenceStoreClient::remediations` and `remediations_all` read the due queue page by page (`RemediationQuery`; `state` a stored state or `review_pending`, the flag a pending review sets beside the state), `remediation` one subject's state, `mark_notified` records that the actor was told, and `request_review`, `review` and `decide_review` (`ReviewDecision`: uphold, deny, or waive until a time) open, read and decide reviews.
- **A resource's changes, page by page.** `resource_changes` follows the NA's pages (1.4.0); `resource_changes_page` reads one (`limit`, `after_sequence`).
- **Offline verification of the new entry kinds.** `verify_evidence_events` verifies `remediation` and `review` entries with the reference's reasons (`duplicate_remediation`, `remediation_subject_mismatch`, `remediation_subject_missing`, `remediation_rotation_missing`, `remediation_rotation_mismatch`, `remediation_rotation_other_executor`, `remediation_rotation_before_change`, `remediation_rotation_reused`, `review_approval_invalid`, `review_approval_key_mismatch`, `review_same_holder`, `review_subject_mismatch`, `review_subject_missing`, `review_waiver_after_remediation`) and counts them in `remediations` and `reviews`. A missing subject or rotation is reported in a run from entry 1 or right after the checkpoint passed, and only registry records the NA signed bind an operator key. `verify_out_of_band_record` verifies a single remediation or review record.
- **The reference's rules, in `remediation`.** `remediation_plan`, `decision_plan` (`not_executed` for a decision whose change never ran), `cancel_steps`, `guidance`, `change_facts`, `due_after_denial`, `due_after_waiver`, `steps_problem`, `next_state` (the state, the event and whether a review is pending, with the stable refusal codes), `check_remediation` (the record's exact form first), `admin_approval_valid`, `review_approval_problem`, `review_holder_problem`, `review_request_problem`, `rfc3339` (the strict grammar of `waive_until` and embedded admin timestamps), `emergency_map` and `policy_section_issues`, checked against the shared conformance suite `remediation` (340 vectors).

### Changed

- **Policies with the 1.4.0 sections.** A boundary policy's `remediation`, `review_required` and `emergency` sections are left out of its signed form when absent or `null`, so a policy without them keeps its 1.3 digest and a decision under a policy received with them `null` still verifies. The field registry knows the new records and entry kinds.

### Upgrading

- `RecordKind` has a new variant, `Remediation`: a `match` over it needs an arm for it. The record outbox files of a remediation record carry `"kind": "remediation"`; 1.3 SDKs do not read them.
- The remediation and review routes are beta until 1.5.0. They need an NA with `EVIDENCE_REMEDIATION=on`; until then they answer `404 remediation_disabled`, and remediation records in the record outbox wait.

## 1.3.1 - 2026-10-11

### Changed

- `enqueue` and `flush_pending` no longer dead-letter the records behind a
  refused record without submitting them. Each is submitted in turn and
  settled by the NA's answer.
- **An outbox file that cannot be read no longer stops every action.**
  `FileOutbox` and `FileRecordOutbox` failed every read, and so every governed
  action, while one entry file was not readable. They now move the file aside
  as `<name>.unreadable` and fail the read that found it, once
  (`GenesisMeshError::Outbox`, code `outbox_file_unreadable`), as the
  TypeScript SDK does. The record it held is not submitted, so inspect the
  file. A file of the other outbox's format is still refused, and left where
  it is.
- `flush_records` submits break-glass records first, then observations, each
  in the order they were added, as the TypeScript SDK does. They share the
  NA's submission rate, and an observation of the same change then finds its
  break-glass record.

### Fixed

- **`verify_evidence_events` verifies an export as the reference does**
  (the conformance suite `out_of_band`, now 80 vectors).
  - An export that starts after entry 1 (a later page, an export since a
    position) takes the first record it holds of each resource as that
    chain's start. It reported `resource_chain_break` for a correct store.
  - A record copied later in the store is refused as `duplicate_record`. Ids
    are compared within one kind.
  - Every envelope field the NA derives from a record of a change made
    outside the controlled path must name what the record says:
    `envelope_mismatch`, at most once per entry. Only the record and resource
    ids were checked.
  - A judgement's subject is looked up by its kind and id, and so is a
    `duplicate_judgement`. A record of another kind with the same id is not
    its subject.
  - A judgement whose matched record is not in an export from entry 1 is
    refused as `judgement_match_missing`.
  - A retention checkpoint must have removed as many entries as positions,
    counted from the checkpoint before it when the export holds that one:
    `retention_count_mismatch`.
  - A record with fields outside its signature is checked for its form as
    its signer signed it (`non_canonical_form`). Its form was not checked
    before.
- **A record without a field the reference writes as `null`** (an execution
  record's `outcome_detail` or `prev_evidence_digest`, a justification's
  `trace.short_circuited_at`, a checkpoint's `previous_checkpoint_id`, the
  nullable fields of a decision's bindings) is refused for its signature
  (`invalid_signature`) or its form, as the reference refuses it. It was
  `payload_invalid`.
- **Floats are written as Python writes them, ties included.** For a float
  exactly halfway between two shortest forms (`13509655414498.0625`),
  `canonical_json` wrote the larger one (`...498.063`) where the reference
  writes the one ending in an even digit (`...498.062`). Such a value in
  signed metadata gave a different canonical form, so an honest record failed
  verification here, and a record this crate signed failed it everywhere
  else. The digits are now exactly Python's `repr`.
- **Observations and break-glass records are guarded exactly as the NA
  guards them.** The secret guard now applies the reference's
  `metadata_problem`. It covers an observation's `actor`, `source_event_id` and
  `version_id` with its `metadata`, and a break-glass record's justification
  with its parameters, attributes and outcome detail. It counts their size as
  the NA does: text outside ASCII escaped (`é` is six bytes, an emoji twelve)
  and floats in Python's form. Before, such a record was signed after its
  action ran, then refused for good (`*_secret_material`) and dead-lettered.
  Now it is refused before signing. `governed_action_with_break_glass` keeps
  room for the report measured the same way before the action runs. A report
  that leaves no room with the justification is left out of the record
  (`dropped`), which is still kept.
- A string ending in a newline is checked as the reference checks it: a token
  or key followed by `\n` is refused as secret material, as the NA refuses it.
- **An observation of one source event always has the same id.**
  `ObservationRecorder::record` used a random `observation_id`, so recording
  one finding again (`observation_from_finding` after a restart, a second run
  over one scan) signed a different record for the same source event. The NA
  refused it for good as `observation_conflict` and it was dead-lettered. The
  default id is now `observation_id(observer, source, source_event_id)`: the
  SHA-256, in hex, of the observer sovereign, source and source event id
  joined by NUL characters, as in the TypeScript SDK. The same record signed
  again is a `duplicate`. An id you give is kept.
- **A record behind a dead letter no longer waits forever.** When a record's
  predecessor had been dead-lettered by an earlier run (or its dead-lettering
  was not stored), `flush_pending` submitted the record. The NA answered
  `resource_chain_gap`, which was retried on every run, and the record held
  back its resource. A record that chains from a dead letter is still
  submitted, as in the TypeScript SDK, so the NA can quarantine it when it
  refuses it for good on its own account. When the NA refuses it for the gap
  (`evidence_chain_gap`, `resource_chain_gap`), it becomes a dead letter with
  `evidence_predecessor_dead_lettered` and the NA's answer in its message.
- **A record outbox no longer deletes an execution outbox's crash
  leftovers.** Opened on a directory of the other outbox's files,
  `FileRecordOutbox` (or `FileOutbox`) removed that outbox's temporary files
  before refusing the directory. A crash during an add leaves such a file, so
  a signed record that its own outbox would have recovered was lost. A
  directory with a temporary file of the other format is now refused before
  anything in it changes.
- The outbox documentation says plainly that nothing stops two processes from
  sharing one outbox directory. Two processes that share one submit each
  other's records and overwrite each other's changes, so give each process a
  directory of its own.
- **One record the NA cannot read no longer blocks an outbox.** The NA's
  strict JSON reader refuses a whole request with `400 invalid_json`. The
  outboxes retried that answer, and `flush_records` sent the same batch of up
  to 100 observations every time, so one such record held back every
  observation behind it. `invalid_json` is now a refusal no retry can
  overcome (`PERMANENT_REFUSALS`, `RECORD_PERMANENT_REFUSALS`). A batch the NA
  refuses as a whole is split in halves until the record it refuses is tried
  alone; that record becomes a dead letter and the rest are admitted. A
  response this crate cannot read is not the NA's refusal and is still
  retried.
- **A rate-limited record backlog drains.** `flush_records` sent batches of
  100 observations, and the NA counts each observation in a batch against
  `NA_RATE_LIMIT_OBSERVATIONS_PER_MINUTE`. With a limit below 100 every batch
  was refused with `429` and sent again unchanged, so the backlog never
  drained. A batch answered `429` now halves the batches the client sends
  after it.
- **Outboxes wait as long as the NA asks.** After a refusal with a
  `Retry-After` header (seconds or an HTTP date), the next attempt of the
  record waits at least that long, at most 15 minutes. This holds for
  `flush_pending`, `flush_records`, `enqueue` and `enqueue_record`. Since every
  record shares the NA's submission rate, `flush_records` also submits no
  record of the outbox until then (unless `ignore_backoff`).
- **A record the NA would refuse as malformed is not signed.**
  `ObservationRecorder::record` and `ExecutionRecorder::sign_break_glass`
  refuse the following before signing (`observation_malformed`,
  `break_glass_malformed`): an action other than `create`, `rotate`,
  `revoke`, `update` or `delete`; a field longer or shorter than the reference
  takes (`resource_id`, `capability`, `source`, `actor`, ...); and a time
  outside the years 1 to 9999. `ExecutionRecorder::record` and
  `governed_action` refuse an unknown `resource_action` or a `resource_id` over
  256 characters (`Configuration`) before anything is evaluated or run.
  Before, these records were signed and then refused for good after the
  action had run.
- **A record no reader would take is not signed.** A record nested more than
  64 deep where it is submitted or kept in an outbox file is refused as
  `StrictJson` (`invalid_json`). Such a record was signed, then refused by the
  NA's strict reader on every attempt. After an action has run, its outcome
  is recorded without the parameters nested too deep: `MetadataRefused`, or
  `dropped` under break-glass.

### Upgrading

- `PERMANENT_REFUSALS` is now a `[&str; 14]` and `RECORD_PERMANENT_REFUSALS` a
  `[&str; 15]`. Code that names their array types changes with them.

## 1.3.0 - 2026-10-10

### Added

- **Changes made outside the controlled path** (Genesis Mesh 1.3.0, NA with
  `EVIDENCE_OUT_OF_BAND=on`). See *Changes outside the controlled path* in
  the README.
  - `ObservationRecorder` signs an observation with an observer key;
    `observation_from_finding` turns a reconciliation finding into one, known
    within the window between two scans.
  - `governed_action_with_break_glass` (with `BreakGlassOptions { justification }`)
    runs the action when the evaluation fails transiently (network error,
    timeout, `5xx`, `429`; `evaluation_failure`) and keeps a signed
    break-glass record; the outcome is
    `GovernedActionOutcome::BrokeGlass(BreakGlassResult)`. Never on a DENY.
    `governed_action` is unchanged and never breaks the glass.
    `ExecutionRecorder::sign_break_glass` signs a record directly
    (`BreakGlassInput`, `EvaluationFailure`).
  - A record outbox (`ClientOptions::with_record_outbox`, `FileRecordOutbox`,
    format `gm.evidence.record-outbox.v1` shared with the TypeScript SDK,
    `MemoryRecordOutbox`, the `RecordOutbox` trait) keeps observations and
    break-glass records until the NA admits them:
    `EvidenceStoreClient::enqueue_record` and `flush_records`, observations
    up to 100 per request (`RecordDelivery`, `RecordFlushReport`,
    `RECORD_PERMANENT_REFUSALS`, `classify_record_submission_error`).
  - `EvidenceStoreClient::submit_observation`, `submit_observations`,
    `submit_break_glass`, `judge_observation`, `judge_break_glass`,
    `resource_changes`, `operator_holders`, `propose_holder` and
    `approve_holder`; `register_executor_key` takes `role` and
    `resource_prefix`.
  - `verify_evidence_events` verifies the entry kinds `observation`,
    `break_glass`, `judgement`, `quarantine` and `registry`, with the reasons
    `envelope_mismatch`, `observation_chain_break`, `duplicate_judgement`,
    `judgement_subject_mismatch`, `judgement_subject_missing`,
    `match_reused`, `quarantine_digest_mismatch` and
    `evidence_cites_judgement`, and counts them
    (`EvidenceVerification::observations`, `break_glass`, `judgements`,
    `quarantined`, left out of the JSON form when zero). The conformance
    suite `out_of_band` runs in the tests, and CI checks it against the
    core's.
  - `canonical::out_of_band_canonical`, `canonical::out_of_band_digest` and
    `verify::verify_out_of_band_record` for the records' signed forms.
  - `GenesisMeshError::OutOfBandRecord` (a record refused before signing,
    with the NA's code) and `GenesisMeshError::RecordOutboxRequired`.

### Changed

- An execution record verifies only under an executor key: a key listed with
  `"role": "observer"` signs observations only (a key without `role` is an
  executor key).
- The embedded field registry lists the 1.3.0 records and the envelope fields
  `record_id`, `subject_id`, `matched_evidence_id` and
  `observation_sequence`, left out of the entry digest when absent
  (`canonical::ENVELOPE_OMITTED_WHEN_ABSENT`), and the checkpoint's
  `observation_heads` (`canonical::CHECKPOINT_OMITTED_WHEN_ABSENT`).
- `ClientOptions` gains `record_outbox`, `EvidenceVerification` the four
  counts, and `GenesisMeshError::ActionFailed` `queued_record`: code that
  builds the two structs field by field must name the new fields.
- `FileOutbox` and `FileRecordOutbox`, `MemoryOutbox` and
  `MemoryRecordOutbox` share their storage code; the outbox format and
  behaviour are unchanged.
- The NA refuses execution evidence from a retired key as
  `evidence_executor_key_retired`, and from a key whose role or resource
  prefix does not cover it as `evidence_out_of_scope` (they were
  `evidence_unknown_executor`, which the outbox retried forever, holding
  every later record of the resource behind it). Both are in
  `PERMANENT_REFUSALS`, as `observation_key_retired` and
  `break_glass_key_retired` are in `RECORD_PERMANENT_REFUSALS`.
- `governed_action_with_break_glass` breaks the glass only under an
  attestation-based evaluation (an agreement-based one cannot be judged after
  the fact; refused before anything runs with `break_glass_malformed`), and
  `evaluation_failure` never reports `429 admin_auth_throttled` or
  `503 evidence_store_unavailable`, so neither breaks the glass.
- `EvidenceStoreClient::status` documents `unjudged_records`: observations
  and break-glass records not judged yet, which hold retention back.

### Fixed

- **Verifiers refuse a record that leaves out a field the reference always
  writes** (`non_canonical_form`), as the reference does: a decision signed
  without `denial_reason` used to verify here and was refused by the NA. The
  new `strict::non_canonical_fields` (non-canonical timestamps, and fields
  left out that the reference does not omit; absent and `null` read the same
  for the fields it omits) replaces `non_canonical_timestamps` in
  `verify_boundary_decision`, `verify_evidence_events` and
  `verify_out_of_band_record`.
- `verify_evidence_events` reports a stored record signed over a form the
  reference does not write as `non_canonical_form` (it verified here), for
  every entry kind: decisions, justifications, execution evidence, retention
  checkpoints and the 1.3.0 records. A record whose signature does not cover
  it as received stays `invalid_signature`. The form is not checked when
  unsigned fields were set aside.
- A file outbox's add no longer scans every entry for the next file
  sequence; it keeps the highest one. Changes to a file outbox already run
  one at a time under its lock, so an update never renames a record back over
  one a removal deleted (now covered by a test).
- A flush while `enqueue` or `enqueue_record` submits a record leaves that
  record to it and reports it pending; it could submit it a second time and
  settle it twice.
- A response the NA sent but whose body could not be read is the new
  `GenesisMeshError::ResponseBodyUnreadable` (code
  `response_body_unreadable`), not `Network`: it never breaks the glass (the
  NA may have decided, even denied). An outbox retries a submission that ended
  so.
- `governed_action_with_break_glass` checks, before anything runs, that
  `attestation_id` and `requested_capability` are non-empty strings, that the
  context's `request_parameters` and `attributes` are objects, and that with
  the justification they leave room for the record (`break_glass_malformed`).
  Once the action ran a record is always kept: an outcome detail is cut to
  1024 characters, and a report the guard still refuses after
  `without_refused_metadata` is left out whole (`execution_parameters: {}`,
  every reported field in `dropped`).
- 1.3.0 records verify as the reference reads them: an unsigned extra field is
  `payload_invalid` (and the entry is not counted); a field the reference
  fills when absent (`metadata`, `request_parameters`, `attributes`,
  `execution_parameters`, `gate_results`, `detail`) is `non_canonical_form`;
  timestamps must be UTC (`Z` or `±00:00`). An unknown signed field is named
  (`unknown_field`) under the key the signature names, whatever its role.
  `verify_out_of_band_record` checks the record's form and fields too.
- `flush_records` sends a batch the NA refuses as too large (`413`) one
  observation at a time.
- Outbox files the TypeScript SDK now writes as one line of canonical JSON
  (`{"entry":...,"format":...}`) are read, and a record's integral floats
  (`1.0`) keep their spelling when this crate writes the file back.

## 1.2.0 - 2026-10-10

Coordinated Genesis Mesh v1.2.0 release, *Nothing Lost, Anchored*: an
evidence outbox for governed actions, verifiers that refuse what they do not
know, strict input and records only in canonical form.

### Changed (breaking)

- **Verifiers refuse signed fields they do not know.** This crate used to
  copy every received field into the signed form, so a field a newer signer
  covered verified here and could change what a record means. It now embeds
  the field registry of signed records (generated from the Python reference,
  shipped in the shared conformance suite `field_registry`). Verifiers check
  the signature over the record as received first; an authentic record with a
  signed field the registry does not list is then refused as `unknown_field`,
  meaning this crate must be upgraded: `verify_boundary_decision` (also for
  the expected policies and attestation), the signature helpers (which return
  `false`) and `verify_evidence_events`. Only the signed projection is
  checked; free-form fields (`claims`, `execution_parameters`, ...) stay open.
- `verify_evidence_events` names an entry of an unknown kind
  (`unknown_entry_kind`, previously `payload_invalid`) and keeps it in the
  chain; `parse_export_lines` accepts entries of any kind. A field outside a
  stored record's signature (records stored before 1.1.1) is reported in the
  new `EvidenceVerification::warnings` as `unsigned_field` and the record is
  verified without it. `EvidenceVerification` gains the `warnings` field.
- `GenesisMeshError` and its `ActionFailed`, `ActionUnrecorded`,
  `MetadataRefused` and `EvidenceNotKept` variants are `#[non_exhaustive]`:
  match with a wildcard arm and `..`. `ActionFailed` carries the failure
  record and its outbox entry; `ActionUnrecorded` carries the record when it
  was signed.
- `GovernedActionResult` is `#[non_exhaustive]` and gains `queued`.
  `ClientOptions` gains `outbox`. `governed_action`'s value type must be
  `Send + 'static`.

- **Records are valid only in their canonical form.** `verify_boundary_decision`
  refuses a decision signed over a timestamp the reference does not write
  (`+00:00` rather than `Z`, a fraction `.000`) as `non_canonical_form`.
  Records the NA signs are always canonical.
- **JSON is read strictly.** HTTP responses and `parse_export_lines` refuse
  JSON every implementation would not read alike with the new
  `GenesisMeshError::StrictJson` (`code()` is the reason): `duplicate_key`,
  `non_finite_number` (`1e400`), `integer_out_of_range` (outside
  `-2**63 .. 2**64 - 1`; `serde_json` read a larger integer as a float),
  `negative_zero`, `lone_surrogate` or `invalid_json` (not JSON, a byte
  order mark, text that is not UTF-8, or arrays and objects nested more than
  64 deep). A malformed response is now `StrictJson` rather than `Json`.
  The new variant is a breaking change for an exhaustive `match` on
  `GenesisMeshError`; the enum becomes `#[non_exhaustive]` with the outbox
  (*Changed (breaking)*), so later variants are not.
- **A decision without `denial_reason` or `freshness_proof` is no longer
  `payload_invalid`.** The NA signs both as `null`, so one received without
  them fails as `invalid_signature`, as in every implementation.
- `parse_export_lines` strips only JSON whitespace around a line (`trim`
  also removed other Unicode spaces, which every other implementation
  refuses).

### Added

- `check_strict_json`, `parse_strict_json`, `strict::canonical_timestamp`
  and `strict::non_canonical_timestamps`; the shared conformance suite
  `canonical`, compared with the core's in CI.
- `genesis_mesh_sdk::strict::{unknown_fields, is_known_entry_kind}` and
  `canonical::DECISION_OMITTED_WHEN_ABSENT`;
  `scripts/sync_canonical_registry.py` regenerates the embedded registry from
  a new copy of the suite, and CI checks the suite against the core's.
- **An evidence outbox keeps signed evidence until the NA admits it.** With
  `ClientOptions::with_outbox`, `governed_action` writes each signed record to
  the outbox before submitting it and removes it once admitted. A failed
  submission then is not an error: `GovernedActionResult::queued` is the
  outbox entry, pending after a failure a later attempt can overcome or a dead
  letter after a refusal no retry can overcome (`PERMANENT_REFUSALS`). Dead
  letters are kept, never dropped. A resource with pending records chains from
  the newest of them, which the next action on it submits first. Without an
  outbox, `governed_action` behaves as in 1.1.
- `FileOutbox` (one file per record, synced and renamed into place, crash
  leftovers recovered, private permissions on Unix, the TypeScript SDK's
  format), `MemoryOutbox` for tests, and the `EvidenceOutbox` trait, whose
  methods return boxed futures (`OutboxFuture`) so other storage can be
  asynchronous.
- `EvidenceStoreClient::flush_pending`, `enqueue` and `pending_head`.
- With an outbox, a secret-guard refusal of the metadata an action reported
  still records the outcome, with the accepted parameters and a note naming
  the dropped ones, and returns `MetadataRefused`; a failure to keep the
  record returns `EvidenceNotKept`. Both carry the action's value
  (`GenesisMeshError::take_action_value`). `Outbox`, `OutboxRequired` and
  `FlushInProgress` errors.

## 1.1.1 - 2026-10-09

Coordinated Genesis Mesh v1.1.1 release: security fixes in the Network
Authority. No API change in this SDK.

### Changed

- A 1.1.1 Network Authority decides under an agreement only if two parties it
  recognises signed it, binds the requester and provider to the agreement's
  parties, needs a privileged key to counter an offer, and admits execution
  evidence only in its exact signed form with UTC timestamps. Requests this
  SDK builds are unchanged; see *Upgrading to 1.1.1* in the core upgrade
  guide.

## 1.1.0 - 2026-10-08

Coordinated Genesis Mesh v1.1.0 release: signed container images and a local
governed Network Authority. No API change in this SDK.

### Fixed

- `ExecutionRecorder` no longer stamps evidence before its decision. Evidence
  recorded in the decision's millisecond, or on a host whose clock is behind
  the Network Authority's, could come out before `decision_made_at`, and the
  NA refused it with `evidence_outside_decision_window`. Without an explicit
  `executed_at`, the recorder now uses the later of the clock and the
  decision time. An explicit `executed_at` is signed unchanged.

### Changed

- The README links *Develop Against a Local Network Authority*: a governed
  Network Authority on a developer's machine, with a privileged setup key and
  a standard controller key (`genesis-mesh` 1.1.0).
- CI pins its actions to commits and runs with a read-only token; the
  security policy follows the core.

## 1.0.2 - 2026-10-05

Coordinated Genesis Mesh v1.0.2 release: fixes from external testing.

### Changed

- **Admin signatures cover the whole request (signature version 2):** the
  client signs the HTTP method, the decoded path, the query parameters and the
  target NA's public key, read once from `/sovereign.json` or given with
  `ClientOptions::with_audience`. Network Authorities from 1.0.2 accept only
  version 2 by default.
- **Breaking:** `build_admin_headers` takes an
  `AdminRequest` (`method`, `path`, `query`, `audience`, `body`) instead of a
  body, and `ClientOptions` has a new public `audience` field. New:
  `admin_signing_payload`, `build_admin_headers_at`, `ADMIN_SIGNATURE_VERSION`.
  Shared conformance vectors: `tests/fixtures/admin_auth.json`.

## 1.0.1 - 2026-10-04

Coordinated Genesis Mesh v1.0.1 release: gateway console fixes. No changes in
this SDK.

## 1.0.0 - 2026-10-04

Coordinated Genesis Mesh v1.0.0 release: the public contract is stable for
the 1.x line and Genesis Mesh is ready for an independently operated pilot.
No functional changes in this SDK; its documented stable surface follows the
1.x compatibility rules.

## 0.65.0 - 2026-10-04

Coordinated Genesis Mesh v0.65.0 release. No functional changes.

## 0.64.1 - 2026-10-03

Coordinated Genesis Mesh v0.64.1 release. No functional changes.

## 0.64.0 - 2026-10-03

Governed-action parity with the TypeScript SDK.

- `policy`: boundary policy lifecycle (validate, publish, list, active,
  history, activate, deactivate, verify).
- `boundary.evaluate`: policy-aware evaluation under one basis
  (`attestation_id` or `agreement`).
- `evidence_store`: submission, search (paged), status, verification,
  resource and vendor histories, resource heads (with the fallback for NAs
  before 0.63.1), JSON Lines export (paged), executor keys and retention.
- `health`: liveness and readiness (a not-ready NA is `ready: false`).
- `ExecutionRecorder` and `governed_action`: verify the decision offline, act
  only on ALLOW, sign and submit execution evidence linked to the resource
  chain; failures are recorded without their error text.
- `verify` and `canonical`: offline verification and canonical digests ported
  from the Python reference with the same reason codes, tested against
  Python-produced vectors.
- Transport: signed admin GETs, query parameters, text responses, and
  identifiers encoded once per path segment (dot segments refused).
- `tests/live_na.rs`: the governed lifecycle against a live NA; CI runs it
  against core main.

## 0.63.1 - 2026-10-02

Coordinated Genesis Mesh v0.63.1 release. No functional changes.

## 0.63.0 - 2026-10-02

Coordinated Genesis Mesh v0.63.0 release (pilot readiness). No functional
changes.

## 0.62.0 - 2026-10-02

Coordinated Genesis Mesh v0.62.0 release (v1 public contract and security
review). No functional changes; this crate is classified beta in the v1
contract.

## 0.61.1 - 2026-10-02

Coordinated Genesis Mesh v0.61.1 release. No functional changes; the Go, .NET
and TypeScript SDKs fix their consensus types, and the core revises its
formal models and RFCs.

## 0.61.0 - 2026-10-02

Coordinated Genesis Mesh v0.61.0 release. No functional changes; the core adds
the cross-language interoperability proof, in which the Go, TypeScript and .NET
SDKs verify Network Authority records offline. This SDK is not a leg of that
scenario yet.

## 0.60.0 - 2026-10-01

Coordinated Genesis Mesh v0.60.0 release. No functional changes; the core adds
optional high availability for the Network Authority (PostgreSQL, several
instances behind a load balancer). This SDK keeps using one NA URL, which can
be the load balancer.

## 0.59.1 - 2026-10-01

Coordinated Genesis Mesh v0.59.1 release. No functional changes; the TypeScript
SDK adds attestation-backed evaluation, the boundary policy lifecycle and the
evidence store client. This SDK does not wrap them yet.

## 0.59.0 - 2026-10-01

Coordinated Genesis Mesh v0.59.0 release. No functional changes; the core adds
the Network Authority evidence store, which this SDK does not wrap yet.

## 0.58.1 - 2026-09-29

Coordinated Genesis Mesh v0.58.1 release. No functional changes; the core adds
attestation-backed boundary evaluation, which this SDK does not wrap yet.

## 0.58.0 - 2026-09-29

First release in the coordinated Genesis Mesh train (0.57 was skipped across the
train; see the core `docs/development/versioning.md`).

- CI and publishing now fail if this component's version is ahead of the Genesis Mesh core version.

- Match server canonical JSON for Unicode, DEL, and floating-point values.
- Reduce temporary allocations in canonical serialization and response decoding.
- Redact signing seeds from client option debug output.
- Validate URLs, key IDs, timeouts, and route paths before requests.
- Disable HTTP redirects and encode attestation IDs as path segments.
- Preserve HTTP errors when the response body is plain text, HTML, or empty.
- Resolve and lock Rust 1.85-compatible dependencies.
- Add Python interoperability fixtures, HTTP contract tests for all 22 domain
  methods, compiled examples, and README doctests.
- Add multi-platform CI, dependency auditing, and release metadata/package checks.

## 0.56.0

- Initial Rust MVP SDK for the Genesis Mesh Network Authority HTTP API.
- Added admin Ed25519 request signing.
- Added async HTTP transport with typed SDK errors.
- Added Agreement, Attestation, Boundary, Consensus, DataUsage, Disclosure, and
  Evidence sub-clients over JSON request and response bodies.
