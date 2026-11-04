### Security

- **A record without its own time is signed by no key of the NA's key history.** Given the key history (1.5.0), a record's own time picks the NA keys that may have signed it. For a record whose time was absent or null, `verify_record` for an `attestation` or a `policy` (`issued_at`, with or without `verify_record_for_present`) and `verify_store_anchors` (`anchored_at`) took every key of the history. A succeeded key's signature over such a record therefore verified forever, past the key's window and its vouching horizon. The reference's models require these times; such a record now verifies under no key of a history (`NaKeys::at_record`, new). A list of keys is still valid at every time.

### Changed

- **The other lookups by a record's own time take the same rule:**
  - `NaKeys::vouching_at`;
  - the time token of a grant use in `verify_record` and `verify_evidence_events`;
  - `audit_pack::received_signature_reason`;
  - the grant holder's revocation feed signer.

  The edge agent's own key selection already gave an undated record no key.
