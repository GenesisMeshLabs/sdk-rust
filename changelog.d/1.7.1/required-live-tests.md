### Changed

- **Live tests no longer pass when they did not run.** `tests/live_na.rs`
  and the edge agent's scenarios (`edge/tests/scenario.rs`) are
  `#[ignore]`d, so a plain `cargo test` reports them as ignored instead of
  `ok`; run them with `--include-ignored`. With `GM_E2E_REQUIRED=1`, which
  CI sets, a missing NA, an NA that cannot exercise a part, or (for the
  verifier's differential test) a missing `GM_VERIFY_CORPUS` fails the run.

### Upgrading

- Contributors who run the live tests locally add `--include-ignored`, for
  example `GM_E2E_PYTHON=python cargo test --test live_na -- --include-ignored`.
  The crate's API is unchanged.
