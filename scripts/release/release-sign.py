#!/usr/bin/env python3
"""Signs a release CI built, publishes it, and points the update feed at it.

    python scripts/release/release-sign.py v1.1.0
    python scripts/release/release-sign.py v1.1.0 --key D:/keys/hawk.key

Run it on the machine that holds the signing key, never in CI: that key is
what every install trusts to ship it code. Needs `gh` (signed in, with write
access to the repository) and `minisign`.

What it does, stopping at the first problem:

1. Downloads the draft release's manifests and the desktop app's packages
   (the Windows installer, the Linux AppImage), and checks them against the
   manifest.
2. Signs each hawk-<channel>.json, and each app package for its updater,
   with minisign (it asks for the key's password).
3. Checks every signature against the public key the builds were made with
   (the HAWK_UPDATE_PUBKEY repository variable), so a wrong key is caught
   here and not by every install refusing the update.
4. Uploads the signatures, publishes the release, then copies the signed
   manifests to the `feed` release, which is where installs look.

Until step 4 nothing is public: a draft's files can't be downloaded by
installs, and the feed still names the previous release.
"""

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FEED_TAG = "feed"
# The app's packages, each signed for Tauri's updater: platform -> (artifact
# in the manifest, file name). Keep in step with APP_PLATFORMS in
# make-manifest.py.
APP_FILES = {
    "windows-x86_64": ("app-windows-x64", "hawk-app-{v}-windows-x64-setup.exe"),
    "linux-x86_64": ("app-linux-x64", "hawk-app-{v}-linux-x64.AppImage"),
}


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(args, check=False, text=True, capture_output=capture)
    if result.returncode != 0:
        detail = (result.stderr or "").strip() if capture else ""
        sys.exit(f"failed: {' '.join(args)}{': ' + detail if detail else ''}")
    return result.stdout if capture else ""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tag", help="the release's tag, e.g. v1.1.0")
    parser.add_argument("--key", default=str(Path.home() / ".minisign" / "minisign.key"), help="minisign secret key")
    parser.add_argument("--repo", help="owner/name; defaults to this checkout's GitHub repository")
    args = parser.parse_args()

    for tool in ("gh", "minisign"):
        if shutil.which(tool) is None:
            sys.exit(f"{tool} isn't installed")
    repo = args.repo or run("gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner", capture=True).strip()
    tag = args.tag if args.tag.startswith("v") else f"v{args.tag}"
    version = tag[1:]
    beta = "-" in version
    channels = ["beta"] if beta else ["stable", "beta"]

    public_key = run("gh", "variable", "get", "HAWK_UPDATE_PUBKEY", "--repo", repo, capture=True).strip()
    if not public_key:
        sys.exit("the HAWK_UPDATE_PUBKEY repository variable is empty: the builds trust no key")

    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        print(f"Downloading {tag} from {repo}")
        patterns = [f"hawk-{c}.json" for c in channels] + [f"app-{c}.json" for c in channels]
        patterns += [file.format(v=version) for _, file in APP_FILES.values()]
        download = ["gh", "release", "download", tag, "--repo", repo, "--dir", str(work)]
        for pattern in patterns:
            download += ["--pattern", pattern]
        run(*download)

        manifest = json.loads((work / f"hawk-{channels[0]}.json").read_text())
        if manifest["version"] != version:
            sys.exit(f"the manifest says {manifest['version']}, not {version}")
        for artifact, file in APP_FILES.values():
            if sha256(work / file.format(v=version)) != manifest["artifacts"][artifact]["sha256"]:
                sys.exit(f"{file.format(v=version)} doesn't match the manifest")

        public_key_file = work / "release.pub"
        public_key_file.write_text(f"untrusted comment: minisign public key\n{public_key}\n")

        def sign(path: Path, comment: str) -> Path:
            run("minisign", "-S", "-s", args.key, "-m", str(path), "-t", comment)
            run("minisign", "-V", "-q", "-p", str(public_key_file), "-m", str(path))
            return path.with_name(path.name + ".minisig")

        print("Signing (minisign asks for the key's password)")
        # Tauri's updater wants each package's minisign signature, base64'd.
        app_signatures = {}
        for platform, (_, file) in APP_FILES.items():
            signature = sign(work / file.format(v=version), f"hawk-app {version} {platform}")
            app_signatures[platform] = base64.b64encode(signature.read_bytes()).decode()

        uploads = []
        for channel in channels:
            uploads.append(sign(work / f"hawk-{channel}.json", f"hawk {version} {channel}"))
            app_manifest_path = work / f"app-{channel}.json"
            app_manifest = json.loads(app_manifest_path.read_text())
            for platform, signature in app_signatures.items():
                app_manifest["platforms"][platform]["signature"] = signature
            app_manifest_path.write_text(json.dumps(app_manifest, indent=2) + "\n")
            uploads.append(app_manifest_path)

        print(f"Publishing {tag}")
        run("gh", "release", "upload", tag, "--repo", repo, "--clobber", *map(str, uploads))
        edit = ["gh", "release", "edit", tag, "--repo", repo, "--draft=false"]
        edit += ["--prerelease"] if beta else ["--latest"]
        run(*edit)

        print(f"Pointing the {FEED_TAG} release at {tag}")
        exists = subprocess.run(["gh", "release", "view", FEED_TAG, "--repo", repo], capture_output=True).returncode == 0
        if not exists:
            run(
                "gh", "release", "create", FEED_TAG, "--repo", repo, "--prerelease", "--title", "Update feed",
                "--notes", "Signed manifests of the newest release on each channel, read by hawk-setup and the app. "
                "Not a release itself: download releases from the list.",
            )
        feed_files = []
        for channel in channels:
            feed_files += [work / f"hawk-{channel}.json", work / f"hawk-{channel}.json.minisig", work / f"app-{channel}.json"]
        run("gh", "release", "upload", FEED_TAG, "--repo", repo, "--clobber", *map(str, feed_files))

    print(f"Done: {tag} is out on {' and '.join(channels)}.")


if __name__ == "__main__":
    main()
