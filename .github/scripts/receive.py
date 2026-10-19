"""Receive a fleet dispatch, prepare its candidate, then publish in a separate job.

The event payload only names a candidate: the fleet repository, a commit on its main branch,
the path `candidates/<sha256>.toml`, and the SHA-256 of the exact TOML bytes. Nothing in the
payload is trusted; this script fetches the bytes at that exact commit with a read-only token,
checks their digest and identity, imports them as `init-data/<sha256>.toml`, runs the admission
gate, and packages a candidate release. The separate publish job applies the prepared patch
and pushes the import commit and next `vX.Y.Z` tag atomically with the release bot's token.
"""
import base64
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

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
    profile = next((p for p in manifest["profiles"] if p["id"] == payload["workload"]), None)
    t.require(profile is not None, f"{payload['workload']}: not registered in measurements.yaml")
    t.require(payload["podvm"] == profile["podvm"],
              f"{payload['workload']}: PodVM selection differs from measurements.yaml")
    return profile


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


def import_candidate(root, payload, raw):
    """Place the TOML and repoint the workload registration; everything else stays byte-identical."""
    root = Path(root)
    ident, digest = payload["workload"], payload["sha256"]
    manifest = t.validate(root)
    profile = next((p for p in manifest["profiles"] if p["id"] == ident), None)
    t.require(profile is not None, f"{ident}: not registered in measurements.yaml")
    t.require(digest not in {entry["sha256"] for entry in t.load_revoked(root)}, "candidate is revoked")
    target = f"init-data/{digest}.toml"
    path = root / target
    if path.exists() or path.is_symlink():
        t.require(not path.is_symlink() and path.read_bytes() == raw,
                  f"{target} already exists with different bytes")
        if profile["initdata"] == target:
            return False
    manifest_path = root / "measurements.yaml"
    text = manifest_path.read_text()
    pattern = re.compile(rf"(^  - id: {re.escape(ident)}\n    initdata: )init-data/[0-9a-f]{{64}}\.toml$", re.M)
    t.require(len(pattern.findall(text)) == 1,
              f"{ident}: cannot locate a single registration line in measurements.yaml")
    path.write_bytes(raw)
    manifest_path.write_text(pattern.sub(lambda match: match.group(1) + target, text, count=1))
    previous = profile["initdata"]
    still_used = any(p["initdata"] == previous for p in manifest["profiles"] if p["id"] != ident)
    if previous != target and not still_used:
        (root / previous).unlink()
    updated = t.validate(root)
    t.require(next(p for p in updated["profiles"] if p["id"] == ident)["initdata"] == target,
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
    auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    git = ["git", "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {auth}",
           "-c", "user.name=trustbase-bot", "-c", "user.email=trustbase-bot@users.noreply.github.com"]
    subprocess.run(git + ["add", "-A", "--", "init-data", "measurements.yaml"], check=True, cwd=root)
    subprocess.run(git + ["commit", "-q", "-m", message], check=True, cwd=root)
    subprocess.run(git + ["tag", tag], check=True, cwd=root)
    print(f"+ git push --atomic origin HEAD:main refs/tags/{tag}", flush=True)
    subprocess.run(git + ["push", "--atomic", f"https://github.com/{repository}", "HEAD:refs/heads/main",
                          f"refs/tags/{tag}"], check=True, cwd=root)


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
    run(["git", "apply", "--check", str(patch)], cwd=ROOT)
    run(["git", "apply", str(patch)], cwd=ROOT)
    manifest = t.validate(ROOT)
    profile = next((p for p in manifest["profiles"] if p["id"] == payload["workload"]), None)
    t.require(profile is not None and profile["initdata"] == f"init-data/{payload['sha256']}.toml",
              "prepared import does not register the dispatched candidate")
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
        elif sys.argv[1:] == ["publish-prepared"]:
            publish_prepared()
        else:
            raise t.Error("unknown receiver command")
    except (t.Error, OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"trustbase admission: {exc}", file=sys.stderr)
        shutil.rmtree(OUTPUT / "inputs", ignore_errors=True)
        raise SystemExit(1)
