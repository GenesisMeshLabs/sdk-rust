"""Check release declarations locally and in CI (Python 3.11+).

    python scripts/check_release.py            # the declarations agree
    python scripts/check_release.py --publish  # and the core release is tagged

Run it with ``--publish`` before ``cargo publish``: the Genesis Mesh core
leads every version, so nothing is published before the core's ``v<VERSION>``
tag exists. A tag build checks that too.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

CORE = "https://github.com/GenesisMeshLabs/genesismesh.git"

root = Path(__file__).resolve().parents[1]
manifest = tomllib.loads((root / "Cargo.toml").read_text())
version = (root / "VERSION").read_text().strip()
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "Invalid VERSION"
assert manifest["package"]["version"] == version, "Cargo.toml and VERSION differ"
# This crate's headings are "## X.Y.Z - YYYY-MM-DD" (see changelog.d/README.md).
heading = re.compile(rf"^## {re.escape(version)} - \d{{4}}-\d{{2}}-\d{{2}}$", re.MULTILINE)
assert heading.search((root / "CHANGELOG.md").read_text(encoding="utf-8")), (
    f"Missing changelog heading '## {version} - YYYY-MM-DD'"
)
lock = tomllib.loads((root / "Cargo.lock").read_text())
package = next(p for p in lock["package"] if p["name"] == manifest["package"]["name"])
assert package["version"] == version, "Cargo.lock version differs"
tag_build = os.environ.get("GITHUB_REF_TYPE") == "tag"
if tag_build:
    assert os.environ["GITHUB_REF_NAME"] == f"v{version}", "Release tag and VERSION differ"
if tag_build or "--publish" in sys.argv[1:]:
    core_tag = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--tags", CORE, f"refs/tags/v{version}"],
        capture_output=True,
        check=False,
    )
    assert core_tag.returncode == 0, f"The Genesis Mesh core has no tag v{version}: release the core first"
print(f"Release declarations agree: {version}")
