"""Check release declarations locally and in CI (Python 3.11+)."""
import os
from pathlib import Path
import re
import tomllib

root = Path(__file__).resolve().parents[1]
manifest = tomllib.loads((root / "Cargo.toml").read_text())
version = (root / "VERSION").read_text().strip()
assert re.fullmatch(r"0\.[0-9]+\.[0-9]+", version), "Invalid VERSION"
assert manifest["package"]["version"] == version, "Cargo.toml and VERSION differ"
assert f"## {version}" in (root / "CHANGELOG.md").read_text(), "Missing changelog version"
lock = tomllib.loads((root / "Cargo.lock").read_text())
package = next(p for p in lock["package"] if p["name"] == manifest["package"]["name"])
assert package["version"] == version, "Cargo.lock version differs"
if os.environ.get("GITHUB_REF_TYPE") == "tag":
    assert os.environ["GITHUB_REF_NAME"] == f"v{version}", "Release tag and VERSION differ"
print(f"Release declarations agree: {version}")
