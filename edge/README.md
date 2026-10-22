# genesis-mesh-edge

The edge agent (beta, 1.7.0): it runs on a device that must make governed
changes whether or not it can reach its Network Authority. It holds the
device's node and executor keys, asks the NA for decisions while connected,
acts within pre-issued grants while it is not, breaks the glass when it
must, and uploads every record in order when the NA is back. Local
workloads ask it through a local API. Linux is the release target; it
builds on macOS; Windows is not supported.

Build a release binary (static, musl; SQLite's C code needs `musl-gcc`, or a
cross compiler for arm64, on the path):

```sh
sh scripts/build_edge.sh x86_64-unknown-linux-musl dist
```

For a local build, `cargo build --release -p genesis-mesh-edge`.
`packaging/` holds the systemd unit and the example configuration.

[docs/edge.md](../docs/edge.md) describes enrolment, the configuration, the
local API, the decision order and the install;
[docs/examples/edge-agent.md](../docs/examples/edge-agent.md) walks through a
real run, online and offline.
