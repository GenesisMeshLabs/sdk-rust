### Added

- **Remediation records.** `ExecutionRecorder::sign_remediation` signs what a controller did about a judged change (`RemediationInput`, `RemediationSubject`, `RemediationSteps`), refusing before signing what the NA would refuse (`remediation_malformed`, `remediation_secret_material`). `EvidenceStoreClient::submit_remediation` submits one; the record outbox keeps them too (`RecordKind::Remediation`), retries a record whose subject or forward rotation the NA does not hold yet, and dead-letters the refusals in `REMEDIATION_PERMANENT_REFUSALS`. `flush_records` submits them after break-glass records and observations.
- **Cancel without breaking readers.** `rotate_forward_then_disable` rotates a resource forward under a governed decision, disables the denied version, then keeps a remediation record linked to the rotation's execution evidence. A disable that fails after the rotation returns `RemediationIncomplete` (`remediation_incomplete`) with the rotation's evidence.
- **The due queue, notices and reviews.** `EvidenceStoreClient::remediations` and `remediations_all` read the due queue page by page (`RemediationQuery`), `remediation` one subject's state, `mark_notified` records that the actor was told, and `request_review`, `review` and `decide_review` (`ReviewDecision`: uphold, deny, or waive until a time) open, read and decide reviews.
- **Offline verification of the new entry kinds.** `verify_evidence_events` verifies `remediation` and `review` entries with the reference's reasons (`duplicate_remediation`, `remediation_subject_mismatch`, `remediation_subject_missing`, `remediation_rotation_missing`, `remediation_rotation_mismatch`, `review_approval_invalid`, `review_approval_key_mismatch`, `review_same_holder`, `review_subject_mismatch`, `review_subject_missing`, `review_waiver_after_remediation`) and counts them in `remediations` and `reviews`. `verify_out_of_band_record` verifies a single remediation or review record.
- **The reference's rules, in `remediation`.** `remediation_plan`, `cancel_steps`, `guidance`, `change_facts`, `due_after_denial`, `due_after_waiver`, `steps_problem`, `next_state` (with the stable refusal codes), `check_remediation`, `admin_approval_valid`, `review_approval_problem`, `review_holder_problem` and `policy_section_issues`, checked against the shared conformance suite `remediation` (195 vectors).

### Changed

- **Policies with the 1.4.0 sections.** A boundary policy's `remediation`, `review_required` and `emergency` sections are left out of its signed form when absent or `null`, so a policy without them keeps its 1.3 digest and a decision under a policy received with them `null` still verifies. The field registry knows the new records and entry kinds.

### Upgrading

- `RecordKind` has a new variant, `Remediation`: a `match` over it needs an arm for it. The record outbox files of a remediation record carry `"kind": "remediation"`; 1.3 SDKs do not read them.
- The remediation and review routes are beta until 1.5.0. They need an NA with `EVIDENCE_REMEDIATION=on`; until then they answer `404 remediation_disabled`, and remediation records in the record outbox wait.
