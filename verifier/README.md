# genesis-mesh-verify

The offline verifier for Genesis Mesh records, evidence exports, key
histories and audit packs. It is a static Linux binary built on the SDK's
`verify`, `key_history` and `audit_pack` modules, without the SDK's HTTP
client: it never needs a private key and never contacts a network. It gives
the Python reference's verdicts and reason codes.

Build a release binary (reproducible: the same commit gives the same bytes):

```sh
sh scripts/build_verifier.sh x86_64-unknown-linux-musl dist
```

For a local build, `cargo build --release -p genesis-mesh-verify`.

[docs/verifier.md](../docs/verifier.md) describes the commands, what is
checked, the exit codes and how to rebuild a release;
[docs/examples/verify-audit-pack.md](../docs/examples/verify-audit-pack.md)
verifies an audit pack step by step.
