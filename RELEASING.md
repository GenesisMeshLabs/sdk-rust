# Release checklist

1. Update `Cargo.toml`, `VERSION`, `Cargo.lock`, the changelog, and supported
   versions in `SECURITY.md` together. Move reviewed changes out of `Unreleased`.
2. Run the checks in the README, including `python scripts/check_release.py`.
   Inspect `cargo package --list` for unintended files and run `cargo audit`.
3. Push the reviewed commit and require the complete CI matrix to pass. Local
   Docker/Linux checks do not establish Windows or macOS compatibility.
4. Confirm repository visibility, license, private vulnerability reporting,
   crate ownership, and package name availability in the publishing account.
5. Run `cargo publish --dry-run --locked` from the clean release commit.
6. Publish only after release approval, and only once the Genesis Mesh core
   release `v<VERSION>` is tagged: `python scripts/check_release.py --publish`
   checks the tag, then `cargo publish --locked`. Tag that exact commit as
   `v<VERSION>`. The tag CI checks its version and the core tag, runs the crate
   against that core release, and only then creates the GitHub release.
7. Verify the registry artifact and docs.rs build, then update installation
   instructions with the published version. Test installation in a fresh project.

The workflows validate releases but do not publish crates or create tags.
Tests use a local HTTP server and Python reference fixtures; production NA
acceptance, real treaty workflows, and registry publication require separate
verification against the intended deployment.
