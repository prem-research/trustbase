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

STABLE_TAG = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
PREVIOUS = Path("build/previous")


def tag():
    value = os.environ.get("GITHUB_REF_NAME", "")
    t.require(os.environ.get("GITHUB_EVENT_NAME") == "push" and
              os.environ.get("GITHUB_REF_TYPE") == "tag",
              "publication is allowed only for tag push events")
    t.require(re.fullmatch(STABLE_TAG, value), "release tag must be vX.Y.Z")
    return value


def api(path):
    request = urllib.request.Request("https://api.github.com/" + path, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json", "User-Agent": "trustbase-release",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return t.load_json(response.read(t.MAX_FILE))
    except urllib.error.HTTPError as exc:
        exc.close()
        raise t.Error(f"GitHub API {path}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise t.Error(f"GitHub API {path}: {exc}") from exc


def check():
    version = tag()
    repository, revision = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    catalog = t.load_json(Path("dist/measurements.json").read_bytes())
    expected = t.release_metadata(version, repository, revision)
    t.require({key: catalog["release"].get(key) for key in expected} == expected,
              "release candidate does not match this tag, repository, and source commit")
    t.require("previous" in catalog["release"] and "revoked" in catalog,
              "release candidate lacks the previous/revoked chain fields")
    t.require(catalog["workloads"], "cannot publish an empty catalog")
    if t.TRUSTBASE_REPOSITORY_ID is None:
        print("trustbase release: warning: TRUSTBASE_REPOSITORY_ID is unset; repository id not checked",
              file=sys.stderr)
    else:
        t.require(os.environ.get("GITHUB_REPOSITORY_ID") == str(t.TRUSTBASE_REPOSITORY_ID),
                  "workflow is running in an unexpected repository")
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
    tags = published_releases(repository)
    latest = max(tags, key=lambda value: t.Version(value[1:])) if tags else None
    previous = catalog["release"]["previous"]
    linked = previous["version"] if previous is not None else None
    t.require(linked == latest,
              f"release candidate links to {linked or 'no release'}, but latest published release is "
              f"{latest or 'none'}; rebuild this tag before publishing")
    return version, repository, revision


def run(command):
    subprocess.run(command, check=True)


def published_releases(repository):
    """Stable, published release tags of this repository."""
    tags = []
    for page in range(1, 101):
        batch = api(f"repos/{repository}/releases?per_page=100&page={page}")
        t.require(isinstance(batch, list), "invalid GitHub release response")
        tags += [item["tag_name"] for item in batch
                 if not item["draft"] and not item["prerelease"] and re.fullmatch(STABLE_TAG, item["tag_name"])]
        if len(batch) < 100:
            return tags
    raise t.Error("GitHub release pagination limit exceeded")


def previous():
    """Download and verify the latest published release so the new one can chain to it."""
    repository = os.environ["GITHUB_REPOSITORY"]
    tags = published_releases(repository)
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        if not tags:
            output.write("previous=\n")
            print("No published release yet; building the first chained release")
            return
        latest = max(tags, key=lambda value: t.Version(value[1:]))
        t.require(not PREVIOUS.exists(), f"{PREVIOUS} already exists")
        run(["gh", "release", "download", latest, "--repo", repository, "--dir", str(PREVIOUS)])
        if (PREVIOUS / "SHA256SUMS").exists():
            # Legacy release: no bundle asset, so authenticate every asset through the API.
            catalog = t.load_json((PREVIOUS / "measurements.json").read_bytes())
            revision = catalog["release"]["source_revision"]
            for asset in sorted(PREVIOUS.iterdir()):
                run(["gh", "attestation", "verify", str(asset), "--repo", repository,
                     "--source-ref", "refs/tags/" + latest, "--source-digest", revision,
                     "--signer-workflow", repository + "/.github/workflows/release.yml"])
            result = t.verify_package(PREVIOUS)
        else:
            result = t.verify_package(PREVIOUS, require_provenance=True)
        t.require(result["release"]["version"] == latest, "downloaded release names another version")
        output.write(f"previous={PREVIOUS}\n")
        print(f"Previous release {latest} verified")


def main():
    command = sys.argv[1]
    if command == "version":
        release_tag = os.environ.get("RELEASE_TAG", "")
        version = tag() if release_tag else "preview-" + os.environ["GITHUB_SHA"][:12]
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write(f"value={version}\n")
        return
    if command == "previous":
        previous()
        return
    version, repository, _ = check()
    if command == "check":
        return
    t.require(command == "publish", "unknown release command")
    assets = sorted(Path("dist").iterdir())
    expected = {"measurements.json", t.archive_name({"version": version}), t.BUNDLE_NAME}
    t.require({asset.name for asset in assets} == expected,
              "release must contain exactly the two payloads and the provenance bundle")
    run(["gh", "release", "create", version, "--repo", repository, "--verify-tag",
         "--draft", "--title", version, "--generate-notes", *map(str, assets)])
    run(["gh", "release", "edit", version, "--repo", repository, "--draft=false"])


if __name__ == "__main__":
    try:
        main()
    except (t.Error, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"trustbase release: {exc}", file=sys.stderr)
        raise SystemExit(1)
