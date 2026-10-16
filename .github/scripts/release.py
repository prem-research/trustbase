"""Tag-only publication; create a draft, then expose it after every upload succeeds."""
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import trustbase as t


def tag():
    value = os.environ.get("GITHUB_REF_NAME", "")
    t.require(os.environ.get("GITHUB_EVENT_NAME") == "push" and
              os.environ.get("GITHUB_REF_TYPE") == "tag",
              "publication is allowed only for tag push events")
    t.require(re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value),
              "release tag must be vX.Y.Z")
    return value


def check():
    version = tag()
    repository, revision = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    catalog = t.load_json(Path("dist/measurements.json").read_bytes())
    t.require(catalog["release"] == t.release_metadata(version, repository, revision),
              "release candidate does not match this tag, repository, and source commit")
    t.require(catalog["workloads"], "cannot publish an empty catalog")
    endpoint = f"https://api.github.com/repos/{repository}/releases/tags/{urllib.parse.quote(version)}"
    request = urllib.request.Request(endpoint, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json", "User-Agent": "trustbase-release",
    })
    try:
        with urllib.request.urlopen(request, timeout=30):
            raise t.Error(f"release {version} already exists; published assets are never overwritten")
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code != 404:
            raise t.Error(f"cannot check release existence: HTTP {exc.code}") from exc
    return version, repository, revision


def run(command):
    subprocess.run(command, check=True)


def main():
    command = sys.argv[1]
    if command == "version":
        release_tag = os.environ.get("RELEASE_TAG", "")
        version = tag() if release_tag else "preview-" + os.environ["GITHUB_SHA"][:12]
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"value={version}\n")
        return
    version, repository, revision = check()
    if command == "check":
        return
    t.require(command == "publish", "unknown release command")
    assets = sorted(Path("dist").iterdir())
    for asset in assets:
        run(["gh", "attestation", "verify", str(asset), "--repo", repository,
             "--source-digest", revision, "--source-ref", "refs/tags/" + version,
             "--signer-workflow", repository + "/.github/workflows/release.yml"])
    run(["gh", "release", "create", version, "--repo", repository, "--verify-tag",
         "--draft", "--title", version, "--generate-notes", *map(str, assets)])
    run(["gh", "release", "edit", version, "--repo", repository, "--draft=false"])


if __name__ == "__main__":
    try:
        main()
    except (t.Error, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"trustbase release: {exc}", file=sys.stderr)
        raise SystemExit(1)
