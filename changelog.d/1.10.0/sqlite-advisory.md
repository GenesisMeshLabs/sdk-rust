### Security

- **The edge agent's SQLite is updated (RUSTSEC-2026-0459).** The edge
  agent bundles SQLite through `rusqlite`. `rusqlite` 0.37 pulled
  `libsqlite3-sys` 0.35, whose bundled SQLite has CVE-2026-119375. The edge
  agent now uses `rusqlite` 0.41 with `libsqlite3-sys` 0.39.1. The SDK crate
  itself does not use SQLite and is unaffected. The edge agent still needs
  Rust 1.89.
