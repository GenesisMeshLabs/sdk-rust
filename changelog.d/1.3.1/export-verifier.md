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
