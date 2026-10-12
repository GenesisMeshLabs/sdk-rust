# Changelog

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
