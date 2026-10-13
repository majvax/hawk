#!/usr/bin/env python3
"""Sets Hawk's version everywhere it's written down.

    python scripts/bump-version.py 1.1.0
    python scripts/bump-version.py 1.2.0-rc.1
    python scripts/bump-version.py --check      # CI: all in step?

VERSION is the source; CMake reads it directly. This copies it into the
places that can't read a file: the Cargo workspace (which the relay, the
installer and the app inherit, and Tauri takes the app's version from), its
entries in Cargo.lock, and
the package.json files. Tag the commit `v<version>` to release it.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
PACKAGES = [ROOT / "src/server/package.json", ROOT / "src/server/frontend/package.json"]
CARGO = ROOT / "Cargo.toml"
CARGO_VERSION = re.compile(r'(?m)^(\[workspace\.package\][^\[]*?^version = ")([^"]*)(")', re.S)
# The workspace's own entries in Cargo.lock, which CI's --locked builds check.
LOCK = ROOT / "Cargo.lock"
LOCK_VERSION = re.compile(r'(?m)^(name = "hawk-(?:relay|update|setup|app)"\nversion = ")([^"]*)(")')


def current() -> dict[str, str]:
    versions = {"VERSION": (ROOT / "VERSION").read_text().strip()}
    match = CARGO_VERSION.search(CARGO.read_text())
    versions["Cargo.toml"] = match.group(2) if match else "missing"
    locked = {match.group(2) for match in LOCK_VERSION.finditer(LOCK.read_text())}
    versions["Cargo.lock"] = locked.pop() if len(locked) == 1 else "differs or missing"
    for package in PACKAGES:
        versions[str(package.relative_to(ROOT))] = json.loads(package.read_text())["version"]
    return versions


def set_version(version: str) -> None:
    # newline="\n": LF on Windows too, as the repository keeps them.
    (ROOT / "VERSION").write_text(version + "\n", newline="\n")
    cargo = CARGO.read_text()
    cargo, count = CARGO_VERSION.subn(lambda m: m.group(1) + version + m.group(3), cargo)
    if count != 1:
        sys.exit("Cargo.toml: no version under [workspace.package]")
    CARGO.write_text(cargo, newline="\n")
    lock, count = LOCK_VERSION.subn(lambda m: m.group(1) + version + m.group(3), LOCK.read_text())
    if count != 4:
        sys.exit(f"Cargo.lock: found {count} of the 4 workspace packages")
    LOCK.write_text(lock, newline="\n")
    for package in PACKAGES:
        text = package.read_text()
        text, count = re.subn(r'(?m)^(  "version": ")[^"]*(")', lambda m: m.group(1) + version + m.group(2), text, 1)
        if count != 1:
            sys.exit(f"{package}: no version")
        package.write_text(text, newline="\n")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    if sys.argv[1] == "--check":
        versions = current()
        if len(set(versions.values())) != 1:
            for where, version in versions.items():
                print(f"  {where}: {version}")
            sys.exit("versions differ: run scripts/bump-version.py <version>")
        print(versions["VERSION"])
        return
    version = sys.argv[1].removeprefix("v")
    if not SEMVER.match(version):
        sys.exit(f"{version} isn't a version like 1.2.3 or 1.2.3-rc.1")
    set_version(version)
    print(f"Hawk is now {version}. Commit, then tag it: git tag v{version}")


if __name__ == "__main__":
    main()
