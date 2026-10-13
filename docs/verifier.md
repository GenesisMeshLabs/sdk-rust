# genesis-mesh-verify: independent verification

`genesis-mesh-verify` verifies Genesis Mesh records and evidence exports
offline, on the auditor's own machines, from keys and anchors the auditor
holds. It is built from this crate's `verify` module, the code the Rust SDK
verifies with, and ships from Genesis Mesh 1.5.0 as static Linux binaries
(x86-64 and arm64) with checksums, Sigstore bundles and a documented
reproducible build.

"Independent" means separate code by the same project: the Python reference
(`genesis-mesh evidence verify-export`, `genesis-mesh audit verify`) and this
verifier are two implementations of one specification. Each verdict and
reason code is the reference's; a difference between them is a bug in one of
them, resolved against the specification (see
[Reading a mismatch](#reading-a-mismatch)).

## What it never does

The verifier never needs a private key and never contacts a network. Every
key, record, export and anchor is given on the command line, as a file or a
value. This is enforced, not only intended:

- `verifier/clippy.toml` refuses, in the binary's code, the SDK's HTTP
  clients, network sockets (`std::net`), the recorders that sign and every
  function that reads a private key or signs; CI runs clippy with
  `-D warnings`.
- A test refuses any mention of an HTTP or network crate, a socket, a signing
  key, or an `allow` of those clippy rules in the binary's sources.
- The released binary is checked to link no HTTP or network crate (the SDK's
  HTTP client is a dependency of the library, never called by the binary,
  and left out at link time).
- CI runs the verifier's tests against each released binary inside a network
  namespace with no network.

## Install

Each release attaches, per architecture:

| File | What it is |
|---|---|
| `genesis-mesh-verify-<version>-x86_64-unknown-linux-musl` | The binary for x86-64 Linux |
| `genesis-mesh-verify-<version>-aarch64-unknown-linux-musl` | The binary for arm64 Linux |
| `<binary>.sha256` | Its SHA-256 |
| `<binary>.sigstore.json` | Its Sigstore bundle |
| `<binary>.buildinfo` | The commit, toolchain, compiler and linker that built it |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | Every binary's digest, signed |

The binaries are statically linked (musl): they run on any Linux of their
architecture and need no shared library. Check the signature and the digest
before you use one:

```sh
version=1.5.0
binary=genesis-mesh-verify-$version-x86_64-unknown-linux-musl
cosign verify-blob --bundle "$binary.sigstore.json" \
  --certificate-identity "https://github.com/GenesisMeshLabs/sdk-rust/.github/workflows/verifier.yml@refs/tags/v$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$binary"
sha256sum --check "$binary.sha256"
chmod +x "$binary"
```

For a stronger check, rebuild it from source and compare digests
([Rebuild and compare](#rebuild-and-compare)).

## Usage

```text
genesis-mesh-verify record <kind> <file> [options]
genesis-mesh-verify export <file> [options]
genesis-mesh-verify pack <dir> --anchor <key> --known-anchors <path>
```

A key is a base64 Ed25519 public key, given inline or as a file holding it
(`#` lines ignored), as `genesis-mesh` reads one. `--json` prints the result
as JSON; without it the result is readable text.

### One record

```sh
genesis-mesh-verify record decision decision.json --na-key na.pub
genesis-mesh-verify record execution evidence.json --executor-keys executor-keys.json
```

`<kind>` is one of the kinds in [What is checked](#what-is-checked)
(`checkpoint` for a retention checkpoint; `break-glass` and `break_glass`
alike). `--na-key` (repeatable) gives the NA's keys; `--executor-keys` the
JSON from `GET /admin/evidence/executor-keys` (or a list of its keys). A
decision as the NA returns it (`{"decision": ..., ...}`) is read as the
decision it holds.

For a decision only: `--at <time>` judges its expiry at an RFC 3339 time
instead of its own; `--freshness-key` (repeatable) checks its freshness proof;
`--expect-policy <file>` (repeatable) and `--expect-attestation <file>` check
that it binds exactly those policy versions and that attestation.

### An evidence export

```sh
genesis-mesh-verify export export.jsonl --na-key na.pub \
    --executor-keys executor-keys.json --known-anchors /audit/anchors
```

The same checks, options and JSON as `genesis-mesh evidence verify-export`:

- `--known-anchors <path>`: anchors held outside the NA, a directory written
  by `genesis-mesh evidence anchors fetch` or a JSON or JSON Lines file;
- `--checkpoint <file>`: the retention checkpoint the export continues from
  (by default the one the export holds, if it starts right after one);
- `--partial`: the export is a deliberate slice, so its ends are not checked
  against the anchors;
- `--from-anchor`: the export starts right after a held anchor.

### An audit pack

`pack` is not available yet: it follows the 1.5.0 audit pack format and
exits with code 4 until then. Verify the pack's export with `export`.

### Output and exit codes

| Code | Meaning |
|---|---|
| 0 | Verified |
| 1 | Not verified: each failure names its reason code |
| 2 | Usage error: an unknown option, kind or command, or a key that is not one |
| 3 | An input could not be read: missing, not UTF-8, not strict JSON, or not the document it should be |
| 4 | Not available in this version |

Anything but 0 means the input is not verified. A genuine decision that denies
its action is verified (0): `authorized` is `false` and the reason is the
reference's `unauthorized_...` code.

With `--json`, `record` prints `kind`, `record_id`, `verified`, `reason` (the
first failure's code, `verified`, or a decision's `authorized` or
`unauthorized_...`), `authorized` for a decision, `failures` and `warnings`;
`export` prints the reference CLI's JSON (`verified`, `checked_entries`, the
counts, `failures` with `store_sequence`, `reason` and `detail`, `warnings`,
and `anchors` with `--known-anchors`). A usage or input error prints
`{"error": {"exit_code", "message"}}`.

## What is checked

### A single record

`record` checks a record as an export checks it as one of its entries, with
the same reason codes, in the same order: fields the crate does not know
(`unknown_field`), its form (`payload_invalid`), its signature
(`invalid_signature`) and the form the reference writes
(`non_canonical_form`). Each kind is signed by its own signer:

| Signed by | Kinds |
|---|---|
| The NA (`--na-key`) | `decision`, `justification`, `checkpoint`, `judgement`, `quarantine`, `registry`, `review`, `policy`, `attestation` |
| An executor key of the record's sovereign (`--executor-keys`) | `execution`, `break-glass`, `remediation` |
| An observer key of the record's sovereign (`--executor-keys`) | `observation` |

Some kinds carry checks of their own:

- a decision: expiry, its freshness proof and the bindings expected, as
  `verify_boundary_decision` checks them, then its verdict;
- a quarantine record: the digest of the record it holds
  (`quarantine_digest_mismatch`);
- a first retention checkpoint: the entries it removed
  (`retention_count_mismatch`);
- a review: its embedded admin approvals (`review_approval_invalid`) and a
  second holder (`review_same_holder`).

What needs the rest of the store (chains, the subject of a judgement,
remediation or review, matched evidence) is checked in an export.

### As of the record's own time

A decision's expiry is judged as of its own time, `decision_made_at`, not as
of the day of the audit: an archived decision verifies years later. `--at`
judges it at another time. Its freshness proof is judged at
`decision_made_at`, and execution evidence must fall within its decision's
validity (`evidence_outside_decision_window`). Nothing else depends on the
time the verifier runs.

### An export

`export` checks every line's envelope, digests and the store chain; every
record's signature under the keys its kind needs; the decision, resource and
observation chains; judgements, matches, remediations and reviews against
what they cite; retention checkpoints. The reason codes are the reference's
(`verify_evidence_events`).

With `--known-anchors` the export is also checked against anchors held
outside the NA: the anchors' signatures, chain and positions
(`anchor_invalid_signature`, `anchor_chain_break`, `anchor_sequence_gap`,
`anchor_not_increasing`); each anchored entry as anchored (`anchor_mismatch`,
`anchor_entry_missing`); and the export tied to the anchors at both ends
(`export_not_linked_to_anchors`, `export_ends_before_anchor`).

### What it does not prove

- Without anchors held outside the NA, an export proves the integrity of what
  it holds, not that nothing was removed: whoever controls the NA's database
  can rewrite and re-link its history. Keep anchors with
  `genesis-mesh evidence anchors fetch` on storage the NA's operators cannot
  change.
- Keys inside a pack or export prove nothing alone: the NA key, and the
  anchors, come from you.
- The verifier checks what the records say, not that the change they describe
  happened; the completeness check of an audit pack compares them with other
  logs.

## Rebuild and compare

The binaries are reproducible: the same commit, built by
`scripts/build_verifier.sh`, gives the same bytes in any directory. The script
pins the Rust toolchain (`RUST_TOOLCHAIN`), builds with `--locked`, sets
`SOURCE_DATE_EPOCH` to the commit's time, maps the source, Cargo home and
target paths to fixed names (`--remap-path-prefix`), and sets the release
profile (one codegen unit, LTO, symbols stripped). CI builds each binary twice,
in two directories, and fails unless they are identical.

To rebuild a release on Ubuntu 24.04 (x86-64 or arm64), as CI does:

```sh
git clone https://github.com/GenesisMeshLabs/sdk-rust && cd sdk-rust
git checkout v1.5.0
target=x86_64-unknown-linux-musl            # or aarch64-unknown-linux-musl
toolchain="$(sed -n 's/^RUST_TOOLCHAIN=//p' scripts/build_verifier.sh)"
rustup toolchain install "$toolchain" --profile minimal --target "$target"
sudo apt-get install -y musl-tools          # musl-gcc, for C code in the SDK's dependencies
CC_x86_64_unknown_linux_musl=musl-gcc CC_aarch64_unknown_linux_musl=musl-gcc \
  sh scripts/build_verifier.sh "$target" rebuilt
grep "genesis-mesh-verify-1.5.0-$target\$" SHA256SUMS   # from the release, signature checked
cat rebuilt/genesis-mesh-verify-1.5.0-$target.sha256
```

The two digests must be equal. The rebuild also writes a `.buildinfo` file:
the commit, `SOURCE_DATE_EPOCH`, toolchain, C compiler, linker and system that
built it, to compare with the release's.

Only the unsigned binaries are reproducible; the Sigstore bundles record when
and by which workflow run they were signed.

## Reading a mismatch

### A verdict that differs from the reference

Run both on the same inputs, with JSON output:

```sh
genesis-mesh evidence verify-export --file export.jsonl --na-public-key na.pub \
    --executor-keys executor-keys.json --known-anchors anchors/ --format json > python.json
genesis-mesh-verify export export.jsonl --na-key na.pub \
    --executor-keys executor-keys.json --known-anchors anchors/ --json > rust.json
```

Compare `verified`, then the failures' `store_sequence` and `reason`; the
`detail` text may differ. A failure only one of them reports names the entry
and the check: read that entry and the rule its reason code stands for in the
specification. Whichever implementation departs from the specification has
the bug; report it (a verifier that accepts what it should refuse is a
security issue: see `SECURITY.md`). Until it is fixed, treat the entry as not
verified.

### A digest that differs from the release

Compare your `.buildinfo` with the release's: the commit, the toolchain
(`rustc` must be the pinned version), and the target. Then check that you
built from a clean checkout of the tag (no local changes, no
`.cargo/config.toml` of your own, no `RUSTFLAGS` set) on Ubuntu 24.04 with its
`binutils`, which links the binary. If they all agree and the digests still
differ, compare the two binaries (`diffoscope` shows where) and report it: the
build is meant to be reproducible, and the signed binary is then not the one
the source describes.

## The differential harness

`cargo test -p genesis-mesh-verify --test differential` runs the binary on the
reference's vectors (`tests/fixtures`) and compares each verdict and reason
code with the reference's. `GM_VERIFY_CORPUS=<file>` also runs the core's
verification corpus (`scripts/export_reference_corpus.py --suite
verification`), and `GM_VERIFY_BINARY=<path>` runs a release binary instead of
the one cargo built:

```sh
GM_VERIFY_BINARY=./genesis-mesh-verify-1.5.0-x86_64-unknown-linux-musl \
GM_VERIFY_CORPUS=verification.json \
  cargo test -p genesis-mesh-verify --test differential
```

The vectors are read through a format adapter
(`verifier/tests/adapter/mod.rs`); a vector kind without one is reported as
skipped, and `GM_VERIFY_CORPUS_STRICT=1` fails the run on a skip.
