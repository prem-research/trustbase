#!/usr/bin/env python3
"""Build exact-byte Init-Data and PodVM reference measurements."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
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
    require(set(doc) == {"version", "algorithm", "data"},
            f"{workload_id}: Init-Data requires only version, algorithm, and data")
    require(doc["version"] == "0.1.0", f"{workload_id}: unsupported Init-Data version")
    require(doc["algorithm"] in ("sha256", "sha384", "sha512"),
            f"{workload_id}: unsupported Init-Data algorithm")
    require(isinstance(doc["data"], dict) and
            all(isinstance(v, str) for v in doc["data"].values()),
            f"{workload_id}: data must be a string-to-string map")
    require(doc["data"].get("id") == workload_id,
            f"{workload_id}: data.id must exactly match the manifest id")
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


def validate(root, require_workloads=False):
    root = Path(root)
    manifest = yaml.load(source_file(root, "measurements.yaml").read_bytes(),
                         Loader=UniqueLoader)
    check_schema(manifest, "manifest.schema.json")
    ids = set()
    paths = set()
    for profile in manifest["profiles"]:
        ident = profile["id"]
        require(ident not in ids, f"duplicate workload id: {ident}")
        ids.add(ident)
        path = profile["initdata"]
        require(path.startswith("init-data/") and path.endswith("/init-data.toml"),
                f"{ident}: expected init-data/<workload>/init-data.toml")
        require(path not in paths, f"{ident}: Init-Data file is already assigned: {path}")
        paths.add(path)
        initdata(source_file(root, path).read_bytes(), ident)
        constraint(profile["podvm"]["version"])
    # Every production definition must be represented in the catalog.
    directory = root / "init-data"
    require(not directory.is_symlink(), "init-data must not be a symlink")
    found = {p.relative_to(root).as_posix() for p in directory.rglob("*.toml")}
    require(found == paths, f"unlisted Init-Data definitions: {sorted(found - paths)}")
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
                raw = response.read(MAX_FILE + 1)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise Error(f"download failed: {url}: {exc}") from exc
        require(len(raw) <= MAX_FILE, f"download too large: {url}")
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


def verify_attestation(artifact, bundle, tag, revision, trusted_root=None):
    command = [
        "gh", "attestation", "verify", str(artifact), "--bundle", str(bundle),
        "--repo", PODVM_REPO, "--signer-workflow", PODVM_WORKFLOW,
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
    require(bool(load_json(result.stdout)), f"{tag}: verifier returned no attestations")


def validate_podvm(doc, tag, revision):
    check_schema(doc, "vendor/podvm-measurements.schema.json")
    require(doc["release"] == {
        "version": tag, "source_repository": PODVM_REPO, "source_revision": revision,
    }, f"{tag}: PodVM release identity does not match the resolved tag")
    expected_schema = (f"https://raw.githubusercontent.com/{PODVM_REPO}/{revision}"
                       "/schemas/measurements.schema.json")
    require(doc["schema"] == expected_schema, f"{tag}: unexpected PodVM schema URL")
    # This is the contract actually reviewed and covered by the Kata oracle.
    require(doc["inputs"].get("sources", {}).get("kata_containers", {}).get("revision")
            == KATA_REVISION, f"{tag}: unsupported Kata revision; review Init-Data semantics "
                              "and update the compatibility pin before accepting it")


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
    require(sums.get(doc["artifact"]["name"]) == doc["artifact"]["sha256"],
            f"{tag}: PodVM bundle digest differs from SHA256SUMS")
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
    output = fresh_directory(output)
    github = github or GitHub()
    selections, releases = select_releases(manifest, github.releases()) if manifest["profiles"] else ({}, {})
    with tempfile.TemporaryDirectory(prefix=".trustbase-resolve-", dir=output.parent) as temporary:
        staging = Path(temporary)
        write_file(staging, "measurements.yaml", source_file(root, "measurements.yaml").read_bytes())
        for profile in manifest["profiles"]:
            write_file(staging, profile["initdata"],
                       source_file(root, profile["initdata"]).read_bytes())
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
        shutil.copytree(staging, output)
    return lock


def read_snapshot(inputs, trusted_root=None):
    inputs = Path(inputs).resolve()
    lock = load_json(source_file(inputs, "resolution.json").read_bytes())
    check_schema(lock, "resolution.schema.json")
    require(lock["repository"] == PODVM_REPO, "unexpected PodVM repository in resolution")
    require(inventory(inputs) == lock["files"], "frozen input inventory/checksum mismatch")
    # Never let schemas supplied by an input archive redefine our validation rules.
    for path in (ROOT / "schemas").rglob("*.json"):
        name = path.relative_to(ROOT).as_posix()
        require(source_file(inputs, name).read_bytes() == path.read_bytes(),
                f"snapshot schema differs from this Trustbase version: {name}")
    manifest = validate(inputs)
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


def catalog(inputs, release, trusted_root=None):
    manifest, lock, documents = read_snapshot(inputs, trusted_root)
    workloads = {}
    for profile in sorted(manifest["profiles"], key=lambda p: p["id"]):
        ident, path = profile["id"], profile["initdata"]
        values = initdata(source_file(inputs, path).read_bytes(), ident)
        records = []
        for tag in sorted(lock["workloads"][ident],
                          key=lambda tag: (stable_version(tag).precedence_key, tag)):
            selected = documents[tag]["profiles"][profile["podvm"]["profile"]]
            common = {
                "podvm_version": tag, "podvm_profile": profile["podvm"]["profile"],
                "podvm_source_revision": lock["releases"][tag]["source_revision"],
                "podvm_measurements_sha256": lock["releases"][tag]["measurements_sha256"],
                "podvm_artifact": documents[tag]["artifact"],
            }
            records.append({
                **common, "tee": "tdx", "configuration": selected["tdx"]["configuration"],
                "measurements": {**selected["tdx"]["measurement"],
                                 "mr_config_id": values["mr_config_id"]},
            })
            for cpu, data in sorted(selected["sev"].items()):
                records.append({
                    **common, "tee": "snp", "cpu_model": cpu, "configuration": data["configuration"],
                    "measurements": {"measurement": data["measurement"],
                                     "host_data": values["host_data"]},
                })
        workloads[ident] = {
            "initdata": {"path": path, **{k: values[k] for k in ("algorithm", "digest", "sha256")}},
            "podvm": {"repository": PODVM_REPO, **profile["podvm"]},
            "references": records,
        }
    result = {
        "schema_version": 1,
        "schema": f"https://raw.githubusercontent.com/{release['source_repository']}/"
                  f"{release['source_revision']}/schemas/measurements.schema.json",
        "release": release, "resolution_sha256": hash_file(Path(inputs) / "resolution.json"),
        "workloads": workloads,
    }
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


def package(inputs, output, release, trusted_root=None, require_workloads=False):
    output = fresh_directory(output)
    result = catalog(inputs, release, trusted_root)
    require(not require_workloads or result["workloads"],
            "publication requires at least one production workload")
    name = f"trustbase-inputs-{release['version']}.tar.gz"
    assets = {"measurements.json": json_bytes(result), name: archive_bytes(inputs)}
    sums = "".join(f"{sha256(raw)}  {key}\n" for key, raw in sorted(assets.items()))
    with tempfile.TemporaryDirectory(prefix=".trustbase-package-", dir=output.parent) as temporary:
        staging = Path(temporary)
        for key, raw in assets.items():
            write_file(staging, key, raw)
        write_file(staging, "SHA256SUMS", sums.encode())
        shutil.copytree(staging, output)
    return result


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


def verify_package(dist, trusted_root=None, require_workloads=False):
    dist = Path(dist)
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
    archive_name = f"trustbase-inputs-{release['version']}.tar.gz"
    sums = parse_sums(source_file(dist, "SHA256SUMS").read_bytes())
    require(set(sums) == {"measurements.json", archive_name}, "unexpected release checksums")
    require({p.name for p in dist.iterdir()} == set(sums) | {"SHA256SUMS"},
            "unexpected release assets")
    for name, digest in sums.items():
        require(hash_file(source_file(dist, name)) == digest, f"release checksum mismatch: {name}")
    with tempfile.TemporaryDirectory(prefix="trustbase-verify-") as temporary:
        inputs = Path(temporary)
        unpack(dist / archive_name, inputs)
        expected = catalog(inputs, release, trusted_root)
        require(json_bytes(expected) == raw_catalog, "catalog differs from frozen inputs")
        require(sha256(archive_bytes(inputs)) == sums[archive_name],
                "input archive is not reproducibly packaged")
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
        command.add_argument("--source-repository", default="prem-research/trustbase")
        command.add_argument("--source-revision", required=True)
        if name == "package":
            command.add_argument("--require-workloads", action="store_true")
    verify = commands.add_parser("verify", help="verify checksums, provenance, and reproducibility")
    verify.add_argument("--dist", type=Path, required=True)
    verify.add_argument("--require-workloads", action="store_true")
    annotation = commands.add_parser("annotation", help="encode the original bytes as cc_init_data")
    annotation.add_argument("id")
    return cli


def main():
    args = parser().parse_args()
    try:
        if args.command == "validate":
            manifest = validate(args.root, args.require_workloads)
            print(f"Validated {len(manifest['profiles'])} workload(s)")
        elif args.command == "resolve":
            lock = resolve(args.root, args.output, trusted_root=args.trusted_root)
            print(f"Frozen {len(lock['releases'])} PodVM release(s) in {args.output}")
        elif args.command in ("measure", "package"):
            release = release_metadata(args.release_version, args.source_repository, args.source_revision)
            if args.command == "package":
                package(args.inputs, args.output, release, args.trusted_root, args.require_workloads)
            else:
                require(not args.output.exists(), f"output already exists: {args.output}")
                result = catalog(args.inputs, release, args.trusted_root)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_bytes(json_bytes(result))
            print(f"Wrote {args.output}")
        elif args.command == "verify":
            result = verify_package(args.dist, args.trusted_root, args.require_workloads)
            print(f"Verified {result['release']['version']}: {len(result['workloads'])} workload(s)")
        elif args.command == "annotation":
            manifest = validate(args.root)
            profiles = [p for p in manifest["profiles"] if p["id"] == args.id]
            require(len(profiles) == 1, f"unknown workload: {args.id}")
            raw = source_file(args.root, profiles[0]["initdata"]).read_bytes()
            print(base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii"))
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, yaml.YAMLError, tarfile.TarError) as exc:
        print(f"trustbase: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
