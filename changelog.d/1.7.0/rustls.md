### Security

- **rustls 0.23.46.** The HTTP client (the `client` feature) and the edge agent link rustls 0.23.46, which fixes
  RUSTSEC-2026-0346 (`Debug` output of client session values exposed TLS secrets), RUSTSEC-2026-0347 (buffered
  data sent to the outer server after an ECH rejection), RUSTSEC-2026-0348 (Brotli certificate decompression could
  allocate up to 1 GiB before authentication) and RUSTSEC-2026-0349 (an unauthenticated ServerHello could downgrade
  later connections to classical key exchange). The verifier links no TLS.
