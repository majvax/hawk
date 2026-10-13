#!/usr/bin/env python3
"""Writes a release's update manifests from its built files (run by CI).

    python scripts/release/make-manifest.py --version 1.1.0 --repo owner/hawk dist/

For each channel the release goes to (a plain version: stable and beta; one
with a suffix like -rc.1: beta only) this writes, into the same folder:

  hawk-<channel>.json   what hawk-setup reads: every artifact with its
                        SHA-256 and size. Signed later, offline, by
                        release-sign.py: the one signature covers them all.
  app-<channel>.json    the same release in the format the desktop app's
                        updater (Tauri) reads. Its signature field is filled
                        in by release-sign.py.

a PKGBUILD for Arch Linux (from packaging/arch/PKGBUILD.in, with the
.deb's checksum), and SHA256SUMS for people checking downloads by hand.

Artifacts are recognised by name (see ARTIFACTS); a release missing one is
refused, so a half-built release never goes out.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Artifact name in the manifest -> file name pattern ({v} is the version).
ARTIFACTS = {
    "machine-windows-x64": "hawk-machine-{v}-windows-x64.zip",
    "setup-windows-x64": "hawk-setup-{v}-windows-x64.exe",
    "app-windows-x64": "hawk-app-{v}-windows-x64-setup.exe",
    "app-linux-x64": "hawk-app-{v}-linux-x64.AppImage",
    "app-linux-x64-deb": "hawk-app-{v}-linux-x64.deb",
    "relay-linux-x64": "hawk-relay-{v}-linux-x64.tar.gz",
    "relay-linux-arm64": "hawk-relay-{v}-linux-arm64.tar.gz",
    "setup-linux-x64": "hawk-setup-{v}-linux-x64",
    "setup-linux-arm64": "hawk-setup-{v}-linux-arm64",
    "dashboard": "hawk-dashboard-{v}.tar.gz",
}
# The app's updater platforms (Tauri's names) -> their artifact. Keep in
# step with APP_FILES in release-sign.py, which signs them.
APP_PLATFORMS = {"windows-x86_64": "app-windows-x64", "linux-x86_64": "app-linux-x64"}
PROTOCOL = 1  # PROTOCOL_VERSION in src/server/relay/src/protocol.rs


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repo", required=True, help="owner/name on GitHub")
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()

    version = args.version.removeprefix("v")
    if not re.match(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$", version):
        sys.exit(f"{version} isn't a version")
    channels = ["beta"] if "-" in version else ["stable", "beta"]
    base = f"https://github.com/{args.repo}/releases/download/v{version}"
    released_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    notes = f"https://github.com/{args.repo}/releases/tag/v{version}"

    artifacts = {}
    sums = []
    for name, pattern in ARTIFACTS.items():
        file_name = pattern.format(v=version)
        path = args.folder / file_name
        if not path.is_file():
            sys.exit(f"missing {file_name}: the release isn't complete")
        digest = sha256(path)
        artifacts[name] = {"url": f"{base}/{file_name}", "sha256": digest, "size": path.stat().st_size}
        sums.append(f"{digest}  {file_name}")

    for channel in channels:
        manifest = {
            "version": version,
            "channel": channel,
            "protocol": PROTOCOL,
            "released_at": released_at,
            "notes_url": notes,
            "artifacts": artifacts,
        }
        (args.folder / f"hawk-{channel}.json").write_text(json.dumps(manifest, indent=2) + "\n")
        app = {
            "version": version,
            "notes": f"Hawk {version}: {notes}",
            "pub_date": released_at,
            "platforms": {
                platform: {"signature": "", "url": artifacts[artifact]["url"]}
                for platform, artifact in APP_PLATFORMS.items()
            },
        }
        (args.folder / f"app-{channel}.json").write_text(json.dumps(app, indent=2) + "\n")

    # Arch Linux: a PKGBUILD for the .deb, its checksum filled in.
    template = Path(__file__).resolve().parents[2] / "packaging" / "arch" / "PKGBUILD.in"
    pkgbuild = (
        template.read_text()
        .replace("@PKGVER@", version.replace("-", ""))  # pacman versions have no '-'
        .replace("@VERSION@", version)
        .replace("@REPO@", args.repo)
        .replace("@SHA256@", artifacts["app-linux-x64-deb"]["sha256"])
    )
    (args.folder / "PKGBUILD").write_text(pkgbuild, newline="\n")
    sums.append(f"{sha256(args.folder / 'PKGBUILD')}  PKGBUILD")

    (args.folder / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print(f"manifests for {', '.join(channels)}; {len(artifacts)} artifacts")


if __name__ == "__main__":
    main()
