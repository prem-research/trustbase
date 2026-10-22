#!/usr/bin/env python3
"""Build exact-byte Init-Data measurements and attestation policy releases."""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

import jsonschema
from semantic_version import NpmSpec, Version
import yaml

ROOT = Path(__file__).resolve().parent
PODVM_REPO = "prem-research/podvm"
PODVM_WORKFLOW = PODVM_REPO + "/.github/workflows/podvm.yml"
TRUSTBASE_REPO = "prem-research/trustbase"
TRUSTBASE_WORKFLOW = TRUSTBASE_REPO + "/.github/workflows/release.yml"
BUNDLE_NAME = "provenance.sigstore.json"
# Only this authenticated, pre-policy release may bridge into the policy format.
# Digests are the immutable v1.0.0 release assets, not hashes supplied by a caller.
POLICY_TRANSITION_PREDECESSOR = {
    "version": "v1.0.0",
    "source_revision": "d8525fb042f3ad96f3f7bfb481138b3661f282bf",
    "files": {
        "measurements.json": "c41fa8acd7139e34c31b821deb79dde544b84152f7696f0ea5e53b0ae5107018",
        "trustbase-inputs-v1.0.0.tar.gz": "f311fe2bf3a8ac689188f974195fbd59b325f457ea7f2fec39baf10d5492d201",
    },
}
KATA_REVISION = "cf82bb35c80320178bf7570252fe75d6fb263209"
MAX_FILE = 16 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
ID_PATTERN = r"[a-z0-9][a-z0-9._-]{0,63}"
SHA_PATTERN = r"[0-9a-f]{64}"


class Error(Exception):
    """A user-facing validation or generation failure."""


def require(condition, message):
    if not condition:
        raise Error(message)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                       allow_nan=False) + "\n").encode()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(isinstance(key, str), "mapping keys must be strings")
        require(key not in result, f"duplicate mapping key: {key}")
        result[key] = value
    return result


class UniqueLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node):
    return unique_pairs((loader.construct_object(k), loader.construct_object(v))
                        for k, v in node.value)


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def load_json(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs)


def check_schema(value, name):
    schema = load_json((ROOT / "schemas" / name).read_bytes())
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as exc:
        location = ".".join(str(x) for x in exc.absolute_path) or "<root>"
        raise Error(f"{name}: {location}: {exc.message}") from exc


def relative_path(name):
    require(isinstance(name, str) and name, "expected a relative file path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and "\\" not in name and
            all(part not in ("", ".", "..") for part in name.split("/")),
            f"unsafe relative path: {name!r}")
    return path


def source_file(root, name):
    relative_path(name)
    root = root.resolve()
    current = root
    for part in PurePosixPath(name).parts:
        current = current / part
        require(not current.is_symlink(), f"symlinks are not allowed: {name}")
    require(current.is_file() and current.resolve().is_relative_to(root),
            f"missing or escaping file: {name}")
    require(current.stat().st_size <= MAX_FILE, f"file too large: {name}")
    return current


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_file(path):
    return sha256(path.read_bytes())


def initdata(raw, workload_id):
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise Error(f"{workload_id}: invalid UTF-8 TOML: {exc}") from exc
    check_schema(doc, "initdata.schema.json")
    require(doc["data"]["id"] == workload_id,
            f"{workload_id}: data.id must exactly match the manifest id")
    if "model-mounts.json" in doc["data"]:
        try:
            mounts = load_json(doc["data"]["model-mounts.json"])
        except json.JSONDecodeError as exc:
            raise Error(f"{workload_id}: invalid model-mounts.json: {exc}") from exc
        check_schema(mounts, "vendor/podvm-model-mounts.schema.json")
        seen = []
        for entry in mounts:
            path = entry["mount_path"]
            require(not any(p in (".", "..") for p in path.split("/")[1:]),
                    f"{workload_id}: non-normalized model mount_path: {path}")
            require(all(path != prev and not path.startswith(prev + "/")
                        and not prev.startswith(path + "/") for prev in seen),
                    f"{workload_id}: duplicate or overlapping model mount_path: {path}")
            seen.append(path)
            offset = int(entry["info"].split("_")[1])
            require(0 < offset <= (1 << 62) and offset % 4096 == 0,
                    f"{workload_id}: invalid hash_offset in model-mounts.json: {offset}")
    digest = hashlib.new(doc["algorithm"], raw).digest()
    return {
        "algorithm": doc["algorithm"],
        "digest": digest.hex(),
        "sha256": sha256(raw),
        "host_data": (digest + bytes(32))[:32].hex(),
        "mr_config_id": (digest + bytes(48))[:48].hex(),
    }


def constraint(value):
    require(isinstance(value, str) and value.strip(), "empty PodVM version constraint")
    try:
        return NpmSpec(value)
    except ValueError as exc:
        raise Error(f"invalid PodVM semver constraint: {value!r}") from exc


def stable_version(tag):
    if not isinstance(tag, str) or "/" in tag:
        return None
    try:
        version = Version(tag.removeprefix("v"))
    except ValueError:
        return None
    return None if version.prerelease else version


def load_revoked(root):
    """Cumulative revocations from revoked.yaml; an absent file means none."""
    root = Path(root)
    if not (root / "revoked.yaml").exists() and not (root / "revoked.yaml").is_symlink():
        return []
    doc = yaml.load(source_file(root, "revoked.yaml").read_bytes(), Loader=UniqueLoader)
    check_schema(doc, "revoked.schema.json")
    entries = sorted(doc["entries"], key=lambda entry: (entry["sha256"], entry["id"]))
    digests = [entry["sha256"] for entry in entries]
    require(len(set(digests)) == len(digests), "duplicate revoked Init-Data digest")
    return entries


def parse_not_after(value):
    """The absolute UTC deadline after which a replaced Init-Data is no longer acceptable."""
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError) as exc:
        raise Error(f"invalid not_after timestamp: {value!r}") from exc


def initdata_paths(profile):
    """The current Init-Data path and, during a rollout overlap, the replaced one."""
    paths = [profile["initdata"]]
    if "previous" in profile:
        paths.append(profile["previous"]["initdata"])
    return paths


def policy_payloads(root):
    """Public policy names and bytes, read only from this authoring root or snapshot."""
    root = Path(root)
    doc = yaml.load(source_file(root, "policies/policies.yaml").read_bytes(), Loader=UniqueLoader)
    check_schema(doc, "policies.schema.json")
    payloads = {"policies.json": json_bytes(doc)}
    for name in doc["policies"]:
        path = relative_path(name.removeprefix("/"))
        require(all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", part) for part in path.parts),
                f"unsafe policy path: {name!r}")
        require(path.parts[0] not in ("measurements.json", "policies.json", BUNDLE_NAME),
                f"policy path conflicts with a Pages file: {name}")
        payloads[name] = source_file(root, "policies" + name).read_bytes()
    found = set()
    for path in (root / "policies").rglob("*"):
        require(not path.is_symlink(), f"symlinks are not allowed: {path}")
        if path.is_file() and path.suffix == ".rego":
            found.add("/" + path.relative_to(root / "policies").as_posix())
    require(found == set(doc["policies"]), f"unlisted Rego policies: {sorted(found - set(doc['policies']))}")
    return payloads


def validate(root, require_workloads=False):
    root = Path(root)
    manifest = yaml.load(source_file(root, "measurements.yaml").read_bytes(),
                         Loader=UniqueLoader)
    check_schema(manifest, "manifest.schema.json")
    ids = set()
    paths = set()
    digests = set()

    def register(ident, path):
        match = re.fullmatch(r"init-data/([0-9a-f]{64})\.toml", path)
        require(match is not None, f"{ident}: expected init-data/<sha256>.toml")
        require(path not in paths, f"{ident}: Init-Data file is already assigned: {path}")
        paths.add(path)
        raw = source_file(root, path).read_bytes()
        require(match.group(1) == sha256(raw), f"{ident}: Init-Data filename SHA-256 mismatch")
        digests.add(match.group(1))
        initdata(raw, ident)

    for profile in manifest["profiles"]:
        ident = profile["id"]
        require(ident not in ids, f"duplicate workload id: {ident}")
        ids.add(ident)
        for path in initdata_paths(profile):
            register(ident, path)
        if "previous" in profile:
            parse_not_after(profile["previous"]["not_after"])
        constraint(profile["podvm"]["version"])
    # Every production definition must be represented in the catalog.
    directory = root / "init-data"
    require(not directory.is_symlink(), "init-data must not be a symlink")
    found = {p.relative_to(root).as_posix() for p in directory.rglob("*.toml")}
    require(found == paths, f"unlisted Init-Data definitions: {sorted(found - paths)}")
    revoked = {entry["sha256"] for entry in load_revoked(root)}
    require(not revoked & digests,
            f"revoked Init-Data is still registered: {sorted(revoked & digests)}")
    require(not require_workloads or ids, "publication requires at least one production workload")
    return manifest


class GitHub:
    def get(self, url, api=False):
        headers = {"User-Agent": "prem-research/trustbase"}
        if api:
            require(url.startswith("https://api.github.com/"), "unexpected GitHub API host")
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                        timeout=60) as response:
                chunks = []
                total = 0
                while total <= MAX_FILE:
                    chunk = response.read(min(1 << 20, MAX_FILE + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                raw = b"".join(chunks)
                declared = response.headers.get("Content-Length")
        except (urllib.error.URLError, TimeoutError, http.client.HTTPException) as exc:
            raise Error(f"download failed: {url}: {exc}") from exc
        require(len(raw) <= MAX_FILE, f"download too large: {url}")
        require(declared is None or int(declared) == len(raw), f"truncated download: {url}")
        return raw

    def api(self, path):
        return load_json(self.get("https://api.github.com/" + path, api=True))

    def releases(self):
        result = []
        for page in range(1, 10001):
            batch = self.api(f"repos/{PODVM_REPO}/releases?per_page=100&page={page}")
            require(isinstance(batch, list), "invalid GitHub release response")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise Error("GitHub release pagination limit exceeded")

    def tag_revision(self, tag):
        ref = self.api(f"repos/{PODVM_REPO}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
        obj = ref["object"]
        for _ in range(10):
            if obj["type"] == "commit":
                require(re.fullmatch(r"[0-9a-f]{40}", obj["sha"]), "invalid tag commit")
                return obj["sha"]
            require(obj["type"] == "tag", f"{tag}: tag does not point to a commit")
            obj = self.api(f"repos/{PODVM_REPO}/git/tags/{obj['sha']}")["object"]
        raise Error(f"{tag}: excessive annotated-tag nesting")

    def bundles(self, digest):
        bundles = []
        for page in range(1, 101):
            data = self.api(f"repos/{PODVM_REPO}/attestations/sha256:{digest}"
                            f"?per_page=100&page={page}")
            batch = data["attestations"]
            bundles.extend(item["bundle"] for item in batch)
            if len(batch) < 100:
                require(bundles, f"no PodVM attestations for sha256:{digest}")
                # Stable ordering preserves a frozen snapshot across API ordering changes.
                return b"".join(json.dumps(b, sort_keys=True, separators=(",", ":")).encode()
                                + b"\n" for b in sorted(bundles, key=lambda b: json_bytes(b)))
        raise Error("GitHub attestation pagination limit exceeded")


def github_repository_id(repository):
    record = GitHub().api(f"repos/{repository}")
    ident = record.get("id") if isinstance(record, dict) else None
    require(type(ident) is int and ident > 0,
            f"invalid GitHub repository id for {repository}")
    return str(ident)


def select_releases(manifest, releases):
    candidates = {}
    versions = {}
    for release in releases:
        tag = release["tag_name"]
        version = stable_version(tag)
        if release["draft"] or release["prerelease"] or version is None:
            continue
        require(tag not in candidates, f"duplicate PodVM release tag: {tag}")
        # v1.2.3 and 1.2.3 cannot both ambiguously represent the same version.
        normalized = str(version)
        require(normalized not in versions,
                f"ambiguous PodVM semver tags: {versions.get(normalized)} and {tag}")
        versions[normalized] = tag
        candidates[tag] = release
    selections = {}
    ordered = sorted(candidates, key=lambda tag: (stable_version(tag).precedence_key, tag))
    for profile in manifest["profiles"]:
        spec = constraint(profile["podvm"]["version"])
        matches = [tag for tag in ordered if spec.match(stable_version(tag))]
        require(matches, f"{profile['id']}: no published stable PodVM release matches "
                         f"{profile['podvm']['version']!r}")
        selections[profile["id"]] = matches
    return selections, candidates


def parse_sums(raw):
    result = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
        require(match is not None, "invalid SHA256SUMS line")
        digest, name = match.groups()
        require(name not in result, f"duplicate checksum entry: {name}")
        result[name] = digest
    return result


def verify_attestation(artifact, bundle, tag, revision, trusted_root=None,
                       repo=PODVM_REPO, workflow=PODVM_WORKFLOW):
    """Run GitHub's verifier against a saved bundle and return its parsed results."""
    command = [
        "gh", "attestation", "verify", str(artifact), "--bundle", str(bundle),
        "--repo", repo, "--signer-workflow", workflow,
        "--source-ref", "refs/tags/" + tag, "--source-digest", revision,
        "--format", "json",
    ]
    if trusted_root:
        command += ["--custom-trusted-root", str(Path(trusted_root).resolve())]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"{tag}: cannot run GitHub attestation verifier: {exc}") from exc
    require(result.returncode == 0,
            f"{tag}: provenance verification failed for {artifact.name}:\n{result.stderr.strip()}")
    results = load_json(result.stdout)
    require(isinstance(results, list) and results, f"{tag}: verifier returned no attestations")
    return results


def podvm_variants(doc):
    """Map legacy and unified catalogs to their bundle artifacts and build inputs."""
    if "artifact" in doc:
        return {"cpu": {"artifact": doc["artifact"], "inputs": doc["inputs"]}}
    return {variant: {"artifact": artifact, "inputs": doc["inputs"][variant]}
            for variant, artifact in doc["artifacts"].items()}


def validate_podvm(doc, tag, revision):
    check_schema(doc, "vendor/podvm-measurements.schema.json" if "artifact" in doc
                 else "vendor/podvm-measurements-variants.schema.json")
    require(doc["release"] == {
        "version": tag, "source_repository": PODVM_REPO, "source_revision": revision,
    }, f"{tag}: PodVM release identity does not match the resolved tag")
    expected_schema = (f"https://raw.githubusercontent.com/{PODVM_REPO}/{revision}"
                       "/schemas/measurements.schema.json")
    require(doc["schema"] == expected_schema, f"{tag}: unexpected PodVM schema URL")
    # Profile GPU metadata selects the bundle, as in PodVM's unified catalog.
    variants = {podvm_variant(profile) for profile in doc["profiles"].values()}
    bundles = podvm_variants(doc)
    require(set(bundles) == variants and
            ("artifact" in doc or set(doc["inputs"]) == variants),
            f"{tag}: PodVM artifacts/inputs differ from profile variants")
    for variant in sorted(variants):
        # Both guest variants must use the contract covered by the Kata oracle.
        require(bundles[variant]["inputs"].get("sources", {}).get("kata_containers", {}).get("revision")
                == KATA_REVISION, f"{tag}: {variant}: unsupported Kata revision; review Init-Data "
                                  "semantics and update the compatibility pin before accepting it")
        prefix = "podvm-nvidia-ubuntu" if variant == "nvidia" else "podvm-ubuntu"
        safe_tag = re.sub(r"[^A-Za-z0-9._-]", "_", tag)
        require(bundles[variant]["artifact"]["name"] == f"{prefix}-24.04-x86_64-{safe_tag}.tar.zst",
                f"{tag}: {variant}: bundle name differs from release identity")


def podvm_variant(profile):
    return "nvidia" if "gpu" in profile else "cpu"


def verify_podvm(directory, tag, revision, trusted_root=None):
    measurement = source_file(directory, "measurements.json")
    sums_file = source_file(directory, "SHA256SUMS")
    for asset in (measurement, sums_file):
        verify_attestation(asset, source_file(directory, asset.name + ".sigstore.jsonl"),
                           tag, revision, trusted_root)
    doc = load_json(measurement.read_bytes())
    validate_podvm(doc, tag, revision)
    sums = parse_sums(sums_file.read_bytes())
    require(sums.get("measurements.json") == hash_file(measurement),
            f"{tag}: measurements.json checksum mismatch")
    for variant, bundle in podvm_variants(doc).items():
        artifact = bundle["artifact"]
        require(sums.get(artifact["name"]) == artifact["sha256"],
                f"{tag}: {variant}: PodVM bundle digest differs from SHA256SUMS")
    return doc


def write_file(root, name, raw):
    relative_path(name)
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"snapshot contains symlink: {path}")
        if path.is_file() and path != root / "resolution.json":
            require(path.stat().st_size <= MAX_FILE, f"snapshot file too large: {path}")
            result[path.relative_to(root).as_posix()] = hash_file(path)
    return result


def fresh_directory(path):
    path = Path(path).resolve()
    require(not path.exists(), f"output already exists: {path}; choose a fresh directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def resolve(root, output, github=None, trusted_root=None):
    manifest = validate(root)
    policies = policy_payloads(ROOT)
    output = fresh_directory(output)
    github = github or GitHub()
    selections, releases = select_releases(manifest, github.releases()) if manifest["profiles"] else ({}, {})
    with tempfile.TemporaryDirectory(prefix=".trustbase-resolve-", dir=output.parent) as temporary:
        staging = Path(temporary)
        write_file(staging, "policies/policies.yaml",
                   source_file(ROOT, "policies/policies.yaml").read_bytes())
        for name, raw in policies.items():
            if name.startswith("/"):
                write_file(staging, "policies" + name, raw)
        write_file(staging, "measurements.yaml", source_file(root, "measurements.yaml").read_bytes())
        if (root / "revoked.yaml").exists() or (root / "revoked.yaml").is_symlink():
            write_file(staging, "revoked.yaml", source_file(root, "revoked.yaml").read_bytes())
        for profile in manifest["profiles"]:
            for path in initdata_paths(profile):
                write_file(staging, path, source_file(root, path).read_bytes())
        for schema in sorted((ROOT / "schemas").rglob("*.json")):
            write_file(staging, schema.relative_to(ROOT).as_posix(), schema.read_bytes())
        locked = {}
        tags = sorted({tag for values in selections.values() for tag in values},
                      key=lambda tag: (stable_version(tag).precedence_key, tag))
        for tag in tags:
            print(f"Resolving PodVM {tag}", file=sys.stderr, flush=True)
            revision = github.tag_revision(tag)
            assets = releases[tag]["assets"]
            for name in ("measurements.json", "SHA256SUMS"):
                found = [a for a in assets if a["name"] == name]
                require(len(found) == 1, f"{tag}: missing or duplicate release asset {name}")
                expected = f"https://github.com/{PODVM_REPO}/releases/download/{tag}/{name}"
                require(found[0]["browser_download_url"] == expected,
                        f"{tag}: unexpected asset URL for {name}")
                raw = github.get(expected)
                write_file(staging, f"podvm/{tag}/{name}", raw)
                write_file(staging, f"podvm/{tag}/{name}.sigstore.jsonl", github.bundles(sha256(raw)))
            doc = verify_podvm(staging / "podvm" / tag, tag, revision, trusted_root)
            for profile in manifest["profiles"]:
                if tag in selections[profile["id"]]:
                    require(profile["podvm"]["profile"] in doc["profiles"],
                            f"{profile['id']}: PodVM {tag} lacks profile "
                            f"{profile['podvm']['profile']}")
            locked[tag] = {"source_revision": revision,
                           "measurements_sha256": hash_file(staging / "podvm" / tag / "measurements.json")}
        lock = {"schema_version": 1, "repository": PODVM_REPO, "workloads": selections,
                "releases": locked, "files": inventory(staging)}
        write_file(staging, "resolution.json", json_bytes(lock))
        # Revalidate the copied bytes to detect authoring input changes during resolution.
        copied = validate(staging)
        require(copied == manifest, "manifest changed during resolution")
        require(policy_payloads(staging) == policies, "policies changed during resolution")
        shutil.copytree(staging, output)
    return lock


def read_snapshot(inputs, trusted_root=None):
    inputs = Path(inputs).resolve()
    lock = load_json(source_file(inputs, "resolution.json").read_bytes())
    check_schema(lock, "resolution.schema.json")
    require(lock["repository"] == PODVM_REPO, "unexpected PodVM repository in resolution")
    require(inventory(inputs) == lock["files"], "frozen input inventory/checksum mismatch")
    archived = sorted(p for p in (inputs / "schemas").rglob("*.json") if p.is_file())
    require(archived, "snapshot carries no schema documents")
    for path in archived:
        load_json(source_file(inputs, path.relative_to(inputs).as_posix()).read_bytes())
    manifest = validate(inputs)
    policy_payloads(inputs)
    ids = {profile["id"] for profile in manifest["profiles"]}
    require(set(lock["workloads"]) == ids, "resolution workload set differs from manifest")
    selected = {tag for tags in lock["workloads"].values() for tag in tags}
    require(selected == set(lock["releases"]), "resolution release set differs from workloads")
    documents = {}
    for tag, entry in lock["releases"].items():
        require(stable_version(tag) is not None, f"invalid stable PodVM tag: {tag}")
        directory = inputs / "podvm" / tag
        require(hash_file(source_file(directory, "measurements.json")) == entry["measurements_sha256"],
                f"{tag}: resolution measurement digest mismatch")
        documents[tag] = verify_podvm(directory, tag, entry["source_revision"], trusted_root)
    for profile in manifest["profiles"]:
        tags = lock["workloads"][profile["id"]]
        require(tags and len(tags) == len(set(tags)), f"{profile['id']}: empty or duplicate resolution")
        spec = constraint(profile["podvm"]["version"])
        for tag in tags:
            require(spec.match(stable_version(tag)), f"{profile['id']}: locked tag {tag} is outside constraint")
            require(profile["podvm"]["profile"] in documents[tag]["profiles"],
                    f"{profile['id']}: {tag} lacks selected profile")
    return manifest, lock, documents


def release_metadata(version, repository, revision):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", version),
            "invalid release version")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository),
            "invalid source repository")
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "source revision must be a full Git commit")
    return {"version": version, "source_repository": repository, "source_revision": revision}


def previous_link(previous):
    """Normalize a previous-release reference to the fields recorded in the catalog."""
    if previous is None:
        return None
    link = {"version": previous["version"], "measurements_sha256": previous["measurements_sha256"]}
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", link["version"]) and
            re.fullmatch(SHA_PATTERN, link["measurements_sha256"]), "invalid previous release reference")
    return link


def check_succession(previous, release, revoked):
    """A chained release must follow its predecessor and keep every revocation."""
    if previous is None:
        return
    older, newer = stable_version(previous["version"]), stable_version(release["version"])
    if older is not None and newer is not None:
        require(older < newer, f"release {release['version']} does not follow {previous['version']}")
    if "revoked" in previous:
        dropped = {e["sha256"] for e in previous["revoked"]} - {e["sha256"] for e in revoked}
        require(not dropped, f"revocations from {previous['version']} were dropped: {sorted(dropped)}")


def catalog(inputs, release, previous=None, trusted_root=None):
    manifest, lock, documents = read_snapshot(inputs, trusted_root)
    revoked = load_revoked(inputs)
    check_succession(previous, release, revoked)
    workloads = {}
    for profile in sorted(manifest["profiles"], key=lambda p: p["id"]):
        ident, path = profile["id"], profile["initdata"]
        values = initdata(source_file(inputs, path).read_bytes(), ident)
        releases = {}
        for tag in sorted(lock["workloads"][ident],
                          key=lambda tag: (stable_version(tag).precedence_key, tag)):
            selected = documents[tag]["profiles"][profile["podvm"]["profile"]]
            entry = releases.setdefault(tag, {})
            if "tdx" in selected:
                measurement = selected["tdx"]["measurement"]
                entry["tdx"] = {key: measurement[key]
                                for key in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")}
            if selected["sev"]:
                entry["snp"] = {cpu: data["measurement"]
                                for cpu, data in sorted(selected["sev"].items())}
        def reference(path, values):
            return {"path": path, **{key: values[key]
                    for key in ("algorithm", "digest", "sha256", "host_data", "mr_config_id")}}

        workloads[ident] = {"initdata": reference(path, values), "releases": releases}
        if "previous" in profile:
            previous_path = profile["previous"]["initdata"]
            previous_values = initdata(source_file(inputs, previous_path).read_bytes(), ident)
            workloads[ident]["previous_initdata"] = {
                **reference(previous_path, previous_values),
                "not_after": profile["previous"]["not_after"],
            }
    result = {
        "schema_version": 1,
        "schema": f"https://raw.githubusercontent.com/{release['source_repository']}/"
                  f"{release['source_revision']}/schemas/measurements.schema.json",
        "release": dict(release),
        "workloads": workloads,
    }
    result["release"]["previous"] = previous_link(previous)
    result["revoked"] = revoked
    check_schema(result, "measurements.schema.json")
    return result


def archive_bytes(inputs):
    output = io.BytesIO()
    # Normalize tar headers and gzip timestamp/name; source bytes remain untouched.
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(Path(inputs).rglob("*")):
                require(not path.is_symlink(), f"cannot archive symlink: {path}")
                if path.is_file():
                    raw = path.read_bytes()
                    info = tarfile.TarInfo(path.relative_to(inputs).as_posix())
                    info.size, info.mode, info.mtime = len(raw), 0o644, 0
                    archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def archive_name(release):
    return f"trustbase-inputs-{release['version']}.tar.gz"


def release_assets(release):
    return ("measurements.json", "policies.json", archive_name(release))


def release_payloads(dist):
    """Export subjects from a candidate already checked by verify_package.

    The publish and Pages jobs exchange the verified release artifact, never
    policies read from a later checkout. Extraction still validates paths and
    checks that the public index agrees with the frozen YAML.
    """
    dist = Path(dist)
    result = load_json(source_file(dist, "measurements.json").read_bytes())
    check_schema(result, "measurements.schema.json")
    release = result["release"]
    assets = {name: source_file(dist, name).read_bytes() for name in release_assets(release)}
    require({p.name for p in dist.iterdir()} in (set(assets), set(assets) | {BUNDLE_NAME}),
            "unexpected release assets")
    with tempfile.TemporaryDirectory(prefix="trustbase-policies-") as temporary:
        inputs = Path(temporary)
        unpack(source_file(dist, archive_name(release)), inputs)
        policies = policy_payloads(inputs)
        require(assets["policies.json"] == policies["policies.json"],
                "policy index differs from frozen inputs")
        assets.update(policies)
    return assets


def package(inputs, output, release, previous=None, trusted_root=None, require_workloads=False):
    """Write three release assets; policies are also frozen inside the input archive."""
    output = fresh_directory(output)
    result = catalog(inputs, release, previous, trusted_root)
    require(not require_workloads or result["workloads"],
            "publication requires at least one production workload")
    assets = {"measurements.json": json_bytes(result), archive_name(release): archive_bytes(inputs),
              "policies.json": policy_payloads(inputs)["policies.json"]}
    with tempfile.TemporaryDirectory(prefix=".trustbase-package-", dir=output.parent) as temporary:
        staging = Path(temporary)
        for key, raw in assets.items():
            write_file(staging, key, raw)
        shutil.copytree(staging, output)
    return result


def previous_release(dist, trusted_root=None):
    """Read a downloaded release as the predecessor of the one being built."""
    dist = Path(dist)
    raw = source_file(dist, "measurements.json").read_bytes()
    transition = POLICY_TRANSITION_PREDECESSOR
    if sha256(raw) == transition["files"]["measurements.json"]:
        require({p.name for p in dist.iterdir()} == set(transition["files"]) | {BUNDLE_NAME},
                "unexpected policy-transition predecessor assets")
        for name, digest in transition["files"].items():
            require(hash_file(source_file(dist, name)) == digest,
                    f"policy-transition predecessor digest mismatch: {name}")
        result = load_json(raw)
        check_schema(result, "measurements.schema.json")
        release = result["release"]
        require(release["version"] == transition["version"] and
                release["source_revision"] == transition["source_revision"] and
                release["source_repository"] == TRUSTBASE_REPO,
                "unexpected policy-transition predecessor identity")
        # The exact signed historical bytes are pinned. No old snapshot schemas
        # or policy-free archives are accepted by the normal package verifier.
        verify_release_subjects(dist, release, transition["files"], trusted_root)
    else:
        result = verify_package(dist, trusted_root, require_provenance=True)
    return {"version": result["release"]["version"],
            "measurements_sha256": hash_file(source_file(dist, "measurements.json")),
            "revoked": result["revoked"]}


def unpack(archive_path, destination):
    total = 0
    seen = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            relative_path(member.name)
            require(member.isfile() and member.name not in seen,
                    f"unsupported or duplicate archive member: {member.name}")
            seen.add(member.name)
            total += member.size
            require(0 <= member.size <= MAX_FILE and total <= MAX_ARCHIVE,
                    "input archive exceeds size limit")
            stream = archive.extractfile(member)
            require(stream is not None, f"cannot read archive member: {member.name}")
            write_file(destination, member.name, stream.read())


def parse_timestamp(value):
    """RFC 3339 timestamps as emitted by the Go verifier, including nanoseconds."""
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})", value or "")
    require(match is not None, f"invalid verifier timestamp: {value!r}")
    fraction = (match.group(2) or ".0")[:7].ljust(7, "0")
    return datetime.datetime.fromisoformat(match.group(1) + fraction + match.group(3).replace("Z", "+00:00"))


def verify_release_provenance(dist, release, policies, trusted_root=None):
    """Authenticate every release subject; return the signing time."""
    expected = {name: hash_file(source_file(dist, name))
                for name in release_assets(release)}
    expected.update({name: sha256(raw) for name, raw in policies.items() if name.startswith("/")})
    return verify_release_subjects(dist, release, expected, trusted_root)


def verify_release_subjects(dist, release, expected, trusted_root=None):
    """Authenticate the complete expected statement, including archived policies."""
    require(release["source_repository"] == TRUSTBASE_REPO,
            f"provenance is only verified for {TRUSTBASE_REPO} releases")
    bundle = source_file(dist, BUNDLE_NAME)
    repository_id = github_repository_id(TRUSTBASE_REPO)
    timestamps = []
    # All subjects share one statement. Verifying the uploaded assets authenticates
    # that statement; its exact subject set also binds every archived policy byte.
    for name in expected:
        if name.startswith("/"):
            continue
        for item in verify_attestation(dist / name, bundle, release["version"], release["source_revision"],
                                       trusted_root, repo=TRUSTBASE_REPO, workflow=TRUSTBASE_WORKFLOW):
            verification = item["verificationResult"]
            listed = verification["statement"]["subject"]
            subjects = {s["name"]: s["digest"]["sha256"] for s in listed}
            require(len(listed) == len(expected) and subjects == expected,
                    f"{name}: attestation subjects differ from the release payloads")
            certificate = verification["signature"]["certificate"]
            require(certificate.get("sourceRepositoryIdentifier") == repository_id,
                    f"{name}: attestation was issued for another repository id")
            stamps = verification.get("verifiedTimestamps") or []
            require(stamps, f"{name}: attestation has no verified signing timestamp")
            timestamps.extend(parse_timestamp(stamp.get("timestamp")) for stamp in stamps)
    return min(timestamps)


def verify_chain(result, previous_dist, trusted_root=None):
    """The catalog's `previous` link must name exactly the given predecessor release."""
    previous = previous_release(previous_dist, trusted_root)
    link = {key: previous[key] for key in ("version", "measurements_sha256")}
    require(result["release"].get("previous") == link,
            "release does not chain to the given previous release")
    check_succession(previous, result["release"], result["revoked"])


def verify_package(dist, trusted_root=None, require_workloads=False, require_provenance=False,
                   min_version=None, max_age=None, previous_dist=None):
    dist = Path(dist)
    names = {p.name for p in dist.iterdir()}
    require("SHA256SUMS" not in names, "legacy Trustbase release format is unsupported")
    raw_catalog = source_file(dist, "measurements.json").read_bytes()
    result = load_json(raw_catalog)
    check_schema(result, "measurements.schema.json")
    require(not require_workloads or result["workloads"],
            "publication requires at least one production workload")
    release = release_metadata(**{
        "version": result["release"]["version"],
        "repository": result["release"]["source_repository"],
        "revision": result["release"]["source_revision"],
    })
    archive = archive_name(release)
    assets = set(release_assets(release))
    require(names in (assets, assets | {BUNDLE_NAME}),
            "unexpected release assets")
    require("previous" in result["release"] and "revoked" in result,
            "release lacks the previous/revoked chain fields")
    previous = result["release"]["previous"]
    revoked = {entry["sha256"] for entry in result["revoked"]}
    referenced = {w[key]["sha256"] for w in result["workloads"].values()
                  for key in ("initdata", "previous_initdata") if key in w}
    require(not revoked & referenced, "revoked Init-Data is still referenced by the catalog")
    if min_version is not None:
        floor, actual = stable_version(min_version), stable_version(release["version"])
        require(floor is not None, f"invalid minimum version: {min_version!r}")
        require(actual is not None and actual >= floor,
                f"release {release['version']} is below the minimum version {min_version}")
    require(max_age is None or require_provenance, "a maximum age requires provenance verification")
    with tempfile.TemporaryDirectory(prefix="trustbase-verify-") as temporary:
        inputs = Path(temporary)
        unpack(dist / archive, inputs)
        policies = policy_payloads(inputs)
        require(source_file(dist, "policies.json").read_bytes() == policies["policies.json"],
                "policy index differs from frozen inputs")
        if require_provenance:
            signed_at = verify_release_provenance(dist, release, policies, trusted_root)
            age = time.time() - signed_at.timestamp()
            if max_age is not None:
                require(age <= max_age,
                        f"release signing event is {int(age)} s old, above the maximum {int(max_age)} s")
        expected = catalog(inputs, release, previous, trusted_root)
        require(json_bytes(expected) == raw_catalog, "catalog differs from frozen inputs")
        require(sha256(archive_bytes(inputs)) == hash_file(dist / archive),
                "input archive is not reproducibly packaged")
    if previous_dist is not None:
        verify_chain(result, previous_dist, trusted_root)
    return result


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--root", type=Path, default=ROOT, help="authoring root containing measurements.yaml")
    cli.add_argument("--trusted-root", type=Path,
                     help="independently trusted Sigstore roots for offline verification")
    commands = cli.add_subparsers(dest="command", required=True)
    validate_cmd = commands.add_parser("validate", help="validate committed workload definitions")
    validate_cmd.add_argument("--require-workloads", action="store_true")
    resolve_cmd = commands.add_parser("resolve", help="verify PodVM releases and freeze all inputs")
    resolve_cmd.add_argument("--output", type=Path, required=True)
    for name in ("measure", "package"):
        command = commands.add_parser(name)
        command.add_argument("--inputs", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--release-version", required=True)
        command.add_argument("--source-repository", default=TRUSTBASE_REPO)
        command.add_argument("--source-revision", required=True)
        chain = command.add_mutually_exclusive_group(required=True)
        chain.add_argument("--previous-dist", type=Path,
                           help="downloaded release that this one supersedes")
        chain.add_argument("--no-previous", action="store_true",
                           help="this is the first chained release")
        if name == "package":
            command.add_argument("--require-workloads", action="store_true")
    verify = commands.add_parser("verify", help="verify payloads, provenance, chain, and reproducibility")
    verify.add_argument("--dist", type=Path, required=True)
    verify.add_argument("--require-workloads", action="store_true")
    verify.add_argument("--require-provenance", action="store_true",
                        help="authenticate all payloads with the published Sigstore bundle")
    verify.add_argument("--min-version", help="reject releases below this stable version")
    verify.add_argument("--max-age", type=float,
                        help="reject releases whose verified signing event is older than this many seconds")
    verify.add_argument("--previous-dist", type=Path,
                        help="downloaded predecessor release that this one must chain to")
    annotation = commands.add_parser("annotation", help="encode the original bytes as cc_init_data")
    annotation.add_argument("id")
    admit = commands.add_parser("admit", help="run the admission gate on registered workloads")
    admit.add_argument("ids", nargs="*", help="workload ids (default: --all)")
    admit.add_argument("--all", action="store_true", help="gate every registered workload")
    admit.add_argument("--config", type=Path, help="admission rules (default: <root>/admission.yaml)")
    admit.add_argument("--evaluator", type=Path, help="kata-policy-eval binary")
    admit.add_argument("--static-only", action="store_true",
                       help="skip the behavioral replay (local iteration only; CI never passes this)")
    admit.add_argument("--report", type=Path, help="write the admission report JSON here")
    return cli


def main():
    args = parser().parse_args()
    try:
        if args.command == "validate":
            manifest = validate(args.root, args.require_workloads)
            policy_payloads(ROOT)
            print(f"Validated {len(manifest['profiles'])} workload(s)")
        elif args.command == "resolve":
            lock = resolve(args.root, args.output, trusted_root=args.trusted_root)
            print(f"Frozen {len(lock['releases'])} PodVM release(s) in {args.output}")
        elif args.command in ("measure", "package"):
            release = release_metadata(args.release_version, args.source_repository, args.source_revision)
            previous = None if args.no_previous else previous_release(args.previous_dist, args.trusted_root)
            if args.command == "package":
                package(args.inputs, args.output, release, previous, args.trusted_root, args.require_workloads)
            else:
                require(not args.output.exists(), f"output already exists: {args.output}")
                result = catalog(args.inputs, release, previous, args.trusted_root)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_bytes(json_bytes(result))
            print(f"Wrote {args.output}")
        elif args.command == "verify":
            result = verify_package(args.dist, args.trusted_root, args.require_workloads,
                                    args.require_provenance, args.min_version, args.max_age,
                                    args.previous_dist)
            print(f"Verified {result['release']['version']}: {len(result['workloads'])} workload(s)")
        elif args.command == "annotation":
            manifest = validate(args.root)
            profiles = [p for p in manifest["profiles"] if p["id"] == args.id]
            require(len(profiles) == 1, f"unknown workload: {args.id}")
            raw = source_file(args.root, profiles[0]["initdata"]).read_bytes()
            print(base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii"))
        elif args.command == "admit":
            require(args.all or args.ids, "select workload ids or pass --all")
            import admission
            admission.cli(args)
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, yaml.YAMLError, tarfile.TarError) as exc:
        print(f"trustbase: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Run through the importable module so helpers such as admission.py share one Error class.
    import trustbase
    raise SystemExit(trustbase.main())
