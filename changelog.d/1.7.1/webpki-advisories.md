### Security

- **TLS certificate checks updated (RUSTSEC-2026-0381, RUSTSEC-2026-0382).**
  The lockfile moves `rustls-webpki` to 0.103.16 and `webpki-roots` to
  1.0.10, so the HTTP client and the edge agent no longer accept the
  distrusted emSign intermediates. Applications that build with their own
  `Cargo.lock` run `cargo update -p rustls-webpki -p webpki-roots`.
