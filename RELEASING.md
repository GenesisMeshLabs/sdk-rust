# Release checklist

The crate is distributed from this repository by tag (`git = ...`,
`tag = "v<VERSION>"`); it is not published to crates.io, and neither are
`genesis-mesh-verify` and `genesis-mesh-edge` (`publish = false`).

1. On a branch `release/<VERSION>`, update `Cargo.toml`, `verifier/Cargo.toml`
   and `edge/Cargo.toml` (both ship at the crate's version), `VERSION`,
   `Cargo.lock` and the supported versions in `SECURITY.md` together, and fold
   the changelog fragments: `python scripts/changelog.py release <VERSION>
   --heading "## <VERSION> - YYYY-MM-DD"` (see `changelog.d/README.md`).
2. Run the checks in CONTRIBUTING.md, including `python scripts/check_release.py`.
   Inspect `cargo package --locked --list` for unintended files and run
   `cargo audit`.
3. Push the reviewed commit and require the complete CI matrix to pass. Local
   Docker/Linux checks do not establish Windows or macOS compatibility.
4. Confirm repository visibility, license and private vulnerability reporting.
5. Run `cargo package --locked` from the clean release commit.
6. Release only after release approval, and only once the Genesis Mesh core
   release `v<VERSION>` is tagged: `python scripts/check_release.py --publish`
   checks the core tag. Tag the merged release commit as `v<VERSION>`. The
   tag CI checks its version and the core tag, runs the crate against that
   core release, and only then creates the GitHub release. The `Verifier`
   workflow builds the static `genesis-mesh-verify` binaries for the tag,
   signs them (Sigstore) and attaches them, their checksums and build info to
   that release; check that a rebuild reproduces their digests
   (docs/verifier.md). The `Edge agent` workflow does the same for
   `genesis-mesh-edge` and pushes its signed image (docs/edge.md).
7. Check the GitHub release (notes, assets, the image digest), then test the
   installation in a fresh project with `tag = "v<VERSION>"`.

The workflows validate releases but do not publish crates or create tags.
Tests use a local HTTP server and Python reference fixtures; production NA
acceptance, real treaty workflows, and registry publication require separate
verification against the intended deployment.
