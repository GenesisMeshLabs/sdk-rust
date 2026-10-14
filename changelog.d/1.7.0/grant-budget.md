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
