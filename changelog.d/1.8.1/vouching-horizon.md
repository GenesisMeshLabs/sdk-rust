### Added

- **The vouching horizon (Genesis Mesh 1.8.0).** Judged for the present, a
  record signed by an NA key that has ended vouches only until that key's end,
  the 300-second hand-over and a grace of at most 24 hours. Judged at its own
  time, it is unchanged.
  - `SUCCESSION_VOUCHING_GRACE_SECONDS`, and `key_history::vouching_grace`:
    the grace from the NA's published `vouching_grace_seconds`, which may
    only shorten it.
  - `NaKey::end`, and on `NaKeyHistory`: `vouches_until`,
    `record_outlives_key` and `keys_vouching_at`, each given the grace.
  - On `NaKeys`: `vouching_at`, `outlives` and `key_sequence`;
    `From<Vec<String>>` and `From<NaKeyHistory>`.
  - `verify::verify_record_for_present`: an attestation or a grant of a key
    past its horizon is `outlives_key`. `verify_record`, and
    `genesis-mesh-verify`, keep judging records at their own time.
  - `vouching::na_record_refusal` and `model_times_accepted`, with the shared
    `vouching` conformance suite (32 vectors).

### Changed

- **`GrantHolder` takes the NA's key history** (`impl Into<NaKeys>`; a
  `Vec<String>` still works).
  - With the history, the grant is checked with the key valid at its time
    and judged for the present. A grant past its key's horizon is refused
    when the holder is built, and ends as `grant_expired` when it passes the
    horizon later. `GrantHolder::with_vouching_grace` shortens its grace.
  - Revocation feeds are ordered by their signer's key sequence, then by
    `sequence`, so a feed with a forged high `sequence` signed by a
    succeeded key no longer blocks the NA's later feeds.
- **A grant must start within 24 hours of its issue**, as the reference
  requires since 1.8.0. The grant checks refuse a `valid_from` earlier than
  `issued_at` minus the 5-minute clock skew, or more than 24 hours and the
  skew after it. The NA never issued one outside that window.

### Upgrading

- **Upgrade the Network Authority to 1.8.0 first** and let it re-issue its
  records (`reissue_pending: false` on its `/readyz`) before judging records
  for the present with `verify_record_for_present` or a key history in
  `GrantHolder`.
- The public API is compatible with 1.8.0: no struct gains a field.
