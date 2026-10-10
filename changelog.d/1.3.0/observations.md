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
