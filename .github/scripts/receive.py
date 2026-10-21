"""Receive a fleet dispatch, prepare its candidate, then publish in a separate job.

The event payload only names a candidate: the fleet repository, a commit on its main branch,
the path `candidates/<sha256>.toml`, and the SHA-256 of the exact TOML bytes. Nothing in the
payload is trusted; this script fetches the bytes at that exact commit with a read-only token,
checks their digest and identity, imports them as `init-data/<sha256>.toml`, runs the admission
gate, and packages a candidate release. The separate publish job applies the prepared patch
and pushes the import commit and next `vX.Y.Z` tag atomically with the release bot's token.
"""
import base64
import datetime
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import admission
import trustbase as t

ROOT = t.ROOT
EVENT_TYPE = "init-data-candidate"
STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
OUTPUT = Path("build/admission")


def api(repository, path, token, accept="application/vnd.github+json"):
    url = f"https://api.github.com/repos/{repository}/{path}"
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token, "Accept": accept,
        "User-Agent": "trustbase-admission", "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read(t.MAX_FILE + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise t.Error(f"GitHub API {repository}/{path}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as exc:
        raise t.Error(f"GitHub API {repository}/{path}: {exc}") from exc
    t.require(len(raw) <= t.MAX_FILE, f"GitHub API response too large: {path}")
    return raw


def payload_from_event(path):
    event = t.load_json(Path(path).read_bytes())
    t.require(event.get("action") == EVENT_TYPE, f"unexpected dispatch event type: {event.get('action')!r}")
    payload = event.get("client_payload")
    t.require(isinstance(payload, dict), "dispatch carries no client_payload object")
    t.check_schema(payload, "dispatch.schema.json")
    return payload


def validate_payload(payload, config, manifest):
    source = config["source"]
    t.require(payload["repository"] == source["repository"],
              f"candidate repository {payload['repository']} is not {source['repository']}")
    t.require(payload["path"] == source["path_prefix"] + payload["sha256"] + ".toml",
              f"candidate path must be {source['path_prefix']}<sha256>.toml")
    selections = config.get("floor", {}).get("podvm_selections", [])
    t.require(payload["podvm"] in selections,
              f"{payload['workload']}: PodVM selection is not in the reviewed admission floor")
    return next((p for p in manifest["profiles"] if p["id"] == payload["workload"]), None)


def fetch_candidate(payload, config, token):
    """The exact bytes at the named commit, which must already be part of fleet's main history."""
    repository, commit = payload["repository"], payload["commit"]
    branch = urllib.parse.quote(config["source"]["branch"], safe="")
    compare = t.load_json(api(repository, f"compare/{commit}...{branch}", token))
    t.require(compare.get("status") in ("identical", "ahead"),
              f"commit {commit} is not on {config['source']['branch']} of {repository}")
    raw = api(repository, f"contents/{urllib.parse.quote(payload['path'])}?ref={commit}", token,
              accept="application/vnd.github.raw+json")
    t.require(t.sha256(raw) == payload["sha256"], "candidate bytes do not match the dispatched SHA-256")
    return raw


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def overlap_deadline(config):
    """When the Init-Data replaced by this import stops being acceptable."""
    seconds = config["floor"]["rollout_overlap_seconds"]
    return (utcnow() + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def import_candidate(root, payload, raw):
    """Place the TOML and create or update its registration within the reviewed floor.

    A replaced Init-Data is kept as the profile's `previous` with an absolute `not_after`
    deadline, so a rollout can overlap old and new pods; the definition it displaces in turn
    is deleted.
    """
    root = Path(root)
    ident, digest = payload["workload"], payload["sha256"]
    manifest = t.validate(root)
    config = admission.load_config(root)
    profile = validate_payload(payload, config, manifest)
    t.require(t.sha256(raw) == digest, "candidate bytes do not match the dispatched SHA-256")
    t.initdata(raw, ident)
    t.require(digest not in {entry["sha256"] for entry in t.load_revoked(root)}, "candidate is revoked")
    target = f"init-data/{digest}.toml"
    path = root / target
    if path.exists() or path.is_symlink():
        t.require(not path.is_symlink() and path.read_bytes() == raw,
                  f"{target} already exists with different bytes")
        if profile is not None and profile["initdata"] == target and profile["podvm"] == payload["podvm"]:
            return False
    manifest_path = root / "measurements.yaml"
    retired = None
    if profile is None:
        profile = {"id": ident, "initdata": target, "podvm": payload["podvm"]}
        manifest["profiles"].append(profile)
    else:
        current = profile["initdata"]
        if current != target:
            retired = profile.get("previous", {}).get("initdata")
            profile["previous"] = {"initdata": current, "not_after": overlap_deadline(config)}
        profile["initdata"] = target
        profile["podvm"] = payload["podvm"]
    path.write_bytes(raw)
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
    if retired is not None and retired not in t.initdata_paths(profile):
        (root / retired).unlink()
    updated = t.validate(root)
    t.require(next(p for p in updated["profiles"] if p["id"] == ident) == profile,
              "registration did not take effect")
    return True


def run(command, **kwargs):
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, check=True, **kwargs)


def next_tag(repository, token):
    tags = []
    for page in range(1, 101):
        batch = t.load_json(api(repository, f"tags?per_page=100&page={page}", token))
        tags += [item["name"] for item in batch if STABLE_TAG.fullmatch(item["name"])]
        if len(batch) < 100:
            break
    else:
        raise t.Error("tag pagination limit exceeded")
    if not tags:
        return "v1.0.0"
    latest = max(tags, key=lambda name: t.Version(name[1:]))
    version = t.Version(latest[1:])
    return f"v{version.major}.{version.minor}.{version.patch + 1}"


def latest_published_tag(repository, token):
    """Find the latest stable release, ignoring drafts and prereleases."""
    tags = []
    for page in range(1, 101):
        batch = t.load_json(api(repository, f"releases?per_page=100&page={page}", token))
        t.require(isinstance(batch, list), "invalid GitHub release response")
        tags.extend(item["tag_name"] for item in batch
                    if not item["draft"] and not item["prerelease"] and
                    STABLE_TAG.fullmatch(item["tag_name"]))
        if len(batch) < 100:
            return max(tags, key=lambda name: t.Version(name[1:])) if tags else None
    raise t.Error("GitHub release pagination limit exceeded")


def await_predecessor(timeout=2700, interval=15):
    """Wait until the release behind this prepared patch is public before minting another tag."""
    prepared = t.load_json((OUTPUT / "prepared.json").read_bytes())
    repository = os.environ["GITHUB_REPOSITORY"]
    t.require(prepared["repository"] == repository, "prepared change belongs to another repository")
    deadline = time.monotonic() + timeout
    while True:
        latest = latest_published_tag(repository, os.environ["GH_TOKEN"])
        if latest is None:
            expected = "v1.0.0"
        else:
            version = t.Version(latest[1:])
            expected = f"v{version.major}.{version.minor}.{version.patch + 1}"
        if expected == prepared["tag"]:
            t.require(next_tag(repository, os.environ["GH_TOKEN"]) == prepared["tag"],
                      "a different stable tag was created while admission waited")
            return
        t.require(t.Version(expected[1:]) < t.Version(prepared["tag"][1:]),
                  "a newer release already supersedes the prepared tag")
        t.require(time.monotonic() < deadline,
                  f"timed out waiting for the release before {prepared['tag']}")
        time.sleep(interval)


def candidate_release(root, version, revision, previous):
    """Resolve, package, and verify the would-be release into build/admission/dist."""
    python = sys.executable
    tool = str(t.ROOT / "trustbase.py")
    run([python, tool, "--root", str(root), "resolve", "--output", str(OUTPUT / "inputs")])
    chain = ["--previous-dist", previous] if previous else ["--no-previous"]
    run([python, tool, "package", "--inputs", str(OUTPUT / "inputs"), "--output", str(OUTPUT / "dist"),
         "--release-version", version, "--source-repository", os.environ["GITHUB_REPOSITORY"],
         "--source-revision", revision, "--require-workloads", *chain])
    run([python, tool, "verify", "--dist", str(OUTPUT / "dist"), "--require-workloads"])


def previous_release(root):
    with tempfile.NamedTemporaryFile("r", prefix="trustbase-previous-", suffix=".txt") as output:
        run([sys.executable, str(Path(__file__).resolve().with_name("release.py")), "previous"],
            env={**os.environ, "GITHUB_OUTPUT": output.name})
        output.seek(0)
        values = dict(line.rstrip("\n").split("=", 1) for line in output if "=" in line)
    return values.get("previous") or None


def publish(root, repository, token, tag, message):
    git = ["git", "-c", "user.name=trustbase-bot", "-c", "user.email=trustbase-bot@users.noreply.github.com"]
    subprocess.run(git + ["add", "-A", "--", "init-data", "measurements.yaml"], check=True, cwd=root)
    subprocess.run(git + ["commit", "-q", "-m", message], check=True, cwd=root)
    subprocess.run(git + ["tag", tag], check=True, cwd=root)
    print(f"+ git push --atomic origin HEAD:main refs/tags/{tag}", flush=True)
    auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {**os.environ, "GIT_CONFIG_COUNT": "1",
           "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
           "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {auth}"}
    subprocess.run(git + ["push", "--atomic", f"https://github.com/{repository}", "HEAD:refs/heads/main",
                          f"refs/tags/{tag}"], check=True, cwd=root, env=env)


def prepared_change(root, payload, repository, tag, message):
    """Save the validated change for a separate, write-capable publish job."""
    run(["git", "add", "-A", "--", "init-data", "measurements.yaml"], cwd=root)
    patch = subprocess.run(["git", "diff", "--cached", "--binary", "HEAD", "--",
                            "init-data", "measurements.yaml"], check=True, capture_output=True,
                           cwd=root).stdout
    t.require(patch, "candidate import produced no commit patch")
    (OUTPUT / "changes.patch").write_bytes(patch)
    (OUTPUT / "prepared.json").write_bytes(t.json_bytes({
        "repository": repository, "source_sha": os.environ["GITHUB_SHA"],
        "sha256": payload["sha256"], "workload": payload["workload"],
        "tag": tag, "message": message, "patch_sha256": t.sha256(patch),
    }))


def changed_paths(root):
    """Every path that differs from HEAD, including new files, after a patch is applied."""
    raw = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                         check=True, capture_output=True, cwd=root).stdout
    fields = raw.split(b"\0")
    paths = set()
    index = 0
    while index < len(fields) and fields[index]:
        entry = fields[index].decode()
        paths.add(entry[3:])
        if entry[0] in "RC":
            index += 1
            paths.add(fields[index].decode())
        index += 1
    return paths


def apply_prepared():
    """Apply only the change produced by this run's read-only preparation job."""
    payload = payload_from_event(os.environ["GITHUB_EVENT_PATH"])
    prepared = t.load_json((OUTPUT / "prepared.json").read_bytes())
    t.require(prepared["repository"] == os.environ["GITHUB_REPOSITORY"] and
              prepared["source_sha"] == os.environ["GITHUB_SHA"] and
              prepared["sha256"] == payload["sha256"] and
              prepared["workload"] == payload["workload"],
              "prepared change does not match this dispatch and source revision")
    t.require(STABLE_TAG.fullmatch(prepared["tag"]), "invalid prepared release tag")
    patch = OUTPUT / "changes.patch"
    t.require(t.sha256(patch.read_bytes()) == prepared["patch_sha256"],
              "prepared patch digest mismatch")
    before = t.validate(ROOT)
    target = f"init-data/{payload['sha256']}.toml"
    registered = next((p for p in before["profiles"] if p["id"] == payload["workload"]), None)
    allowed = {"measurements.yaml", target} | set(t.initdata_paths(registered) if registered else [])
    run(["git", "apply", "--check", str(patch)], cwd=ROOT)
    run(["git", "apply", str(patch)], cwd=ROOT)
    changed = changed_paths(ROOT)
    t.require(changed and changed <= allowed,
              f"prepared patch touches files outside the candidate import: {sorted(changed - allowed)}")
    manifest = t.validate(ROOT)
    others = [p for p in before["profiles"] if p["id"] != payload["workload"]]
    t.require([p for p in manifest["profiles"] if p["id"] != payload["workload"]] == others,
              "prepared patch changes workloads other than the dispatched one")
    profile = next((p for p in manifest["profiles"] if p["id"] == payload["workload"]), None)
    t.require(profile is not None and profile["initdata"] == target
              and profile["podvm"] == payload["podvm"],
              "prepared import does not register the dispatched candidate")
    validate_payload(payload, admission.load_config(ROOT), manifest)
    t.require(t.sha256((ROOT / profile["initdata"]).read_bytes()) == payload["sha256"],
              "prepared candidate bytes do not match the dispatch")


def publish_prepared():
    prepared = t.load_json((OUTPUT / "prepared.json").read_bytes())
    t.require(os.environ["GITHUB_REPOSITORY"] == prepared["repository"] and
              os.environ["GITHUB_SHA"] == prepared["source_sha"],
              "prepared change belongs to a different repository revision")
    publish(ROOT, prepared["repository"], os.environ["RELEASE_TOKEN"],
            prepared["tag"], prepared["message"])


def main():
    root = ROOT
    repository = os.environ["GITHUB_REPOSITORY"]
    payload = payload_from_event(os.environ["GITHUB_EVENT_PATH"])
    config = admission.load_config(root)
    validate_payload(payload, config, t.validate(root))
    raw = fetch_candidate(payload, config, os.environ["FLEET_TOKEN"])
    t.initdata(raw, payload["workload"])
    t.require(not OUTPUT.exists(), f"{OUTPUT} already exists")
    OUTPUT.mkdir(parents=True)
    imported = import_candidate(root, payload, raw)
    if not imported:
        print(f"Candidate {payload['sha256']} is already the registered Init-Data for {payload['workload']}")
        (OUTPUT / "status.txt").write_text("already-imported\n")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write("changed=false\n")
        return
    report = admission.admit(raw, payload["workload"], config, admission.KataPolicyEvaluator())
    (OUTPUT / "admission-report.json").write_bytes(t.json_bytes(report))
    diff = subprocess.run(["git", "status", "--porcelain=v1", "--", "init-data", "measurements.yaml"],
                          check=True, capture_output=True, text=True, cwd=root).stdout
    (OUTPUT / "changes.txt").write_text(diff)
    tag = next_tag(repository, os.environ["GH_TOKEN"])
    candidate_release(root, tag, os.environ["GITHUB_SHA"], previous_release(root))
    message = (f"Import {payload['workload']} candidate {payload['sha256'][:12]} "
               f"from {payload['repository']}@{payload['commit']}")
    prepared_change(root, payload, repository, tag, message)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            output.write("changed=true\n")
    (OUTPUT / "status.txt").write_text(f"prepared\nwould publish {tag}\n{message}\n")
    print(f"Prepared: {message}; would publish {tag}")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            main()
        elif sys.argv[1:] == ["apply-prepared"]:
            apply_prepared()
        elif sys.argv[1:] == ["await-predecessor"]:
            await_predecessor()
        elif sys.argv[1:] == ["publish-prepared"]:
            publish_prepared()
        else:
            raise t.Error("unknown receiver command")
    except (t.Error, OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"trustbase admission: {exc}", file=sys.stderr)
        shutil.rmtree(OUTPUT / "inputs", ignore_errors=True)
        raise SystemExit(1)
