"""Offline contract tests. Only external GitHub and signature verification are mocked."""
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trustbase as t

FIXTURE = Path(__file__).parent / "fixtures" / "podvm-v0.1.6.json"
REVISION = "b57d5e92583388169743bc0084673f0249d64a34"
RELEASE = t.release_metadata("v1.0.0", "prem-research/trustbase", "a" * 40)


def upstream(tag="v0.1.6"):
    doc = t.load_json(FIXTURE.read_bytes())
    doc["release"]["version"] = tag
    doc["artifact"]["name"] = f"podvm-ubuntu-24.04-x86_64-{tag}.tar.zst"
    if t.stable_version(tag) < t.Version("0.3.9"):
        return doc
    # Per-variant format (v0.3.9+), derived from the public fixture: a CPU bundle plus
    # an NVIDIA bundle whose GPU profile publishes SNP measurements only.
    cpu = doc.pop("artifact")
    nvidia = {**cpu, "name": f"podvm-nvidia-ubuntu-24.04-x86_64-{tag}.tar.zst", "sha256": "e" * 64}
    inputs = {**doc["inputs"], "launch_profiles_sha256": "d" * 64}
    doc["artifacts"] = {"cpu": cpu, "nvidia": nvidia}
    doc["inputs"] = {"cpu": inputs, "nvidia": copy.deepcopy(inputs)}
    sev = copy.deepcopy(doc["profiles"]["2vcpu-8g"]["sev"])
    for entry in sev.values():
        entry["configuration"].update(cpus=8, memory="96G")
    doc["profiles"]["h100-pcie-1-96g"] = {
        "gpu": {"family": "H100", "platform": "pcie", "count": 1, "nvswitch_count": 0},
        "sev": sev,
    }
    return doc


def release(tag, draft=False, prerelease=False):
    return {
        "tag_name": tag, "draft": draft, "prerelease": prerelease,
        "assets": [{"name": name, "browser_download_url":
                    f"https://github.com/{t.PODVM_REPO}/releases/download/{tag}/{name}"}
                   for name in ("measurements.json", "SHA256SUMS")],
    }


class FakeGitHub:
    def __init__(self, tags=("v0.1.6", "v0.1.10")):
        self.items = [release(tag) for tag in tags]
        self.docs = {tag: upstream(tag) for tag in tags}
        self.fetched = []

    def releases(self):
        return copy.deepcopy(self.items)

    def tag_revision(self, tag):
        return REVISION

    def get(self, url):
        self.fetched.append(url)
        tag, name = url.rsplit("/", 2)[1:]
        doc = self.docs[tag]
        raw = t.json_bytes(doc)
        if name == "measurements.json":
            return raw
        return (f"{t.sha256(raw)}  measurements.json\n" + "".join(
            f"{v['artifact']['sha256']}  {v['artifact']['name']}\n"
            for v in t.podvm_variants(doc).values())).encode()

    def bundles(self, digest):
        return b'{"test_only":true}\n'


class Workspace(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "authoring"
        shutil.copytree(t.ROOT / "examples", self.root)
        self.gh = FakeGitHub()

    def change_manifest(self, function):
        doc = t.validate(self.root)
        function(doc)
        (self.root / "measurements.yaml").write_bytes(t.json_bytes(doc))

    def snapshot(self):
        target = self.base / "inputs"
        with patch.object(t, "verify_attestation"):
            t.resolve(self.root, target, self.gh)
        return target

    def refresh_inventory(self, inputs, edit=lambda x: None):
        lock = t.load_json((inputs / "resolution.json").read_bytes())
        edit(lock)
        lock["files"] = t.inventory(inputs)
        (inputs / "resolution.json").write_bytes(t.json_bytes(lock))


class AuthoringTests(Workspace):
    def test_examples_and_empty_production(self):
        self.assertEqual(len(t.validate(self.root)["profiles"]), 2)
        empty = self.base / "empty-authoring"
        empty.mkdir()
        (empty / "measurements.yaml").write_text("schema_version: 1\nprofiles: []\n")
        self.assertEqual(t.validate(empty)["profiles"], [])
        with self.assertRaisesRegex(t.Error, "at least one"):
            t.validate(empty, require_workloads=True)

    def test_duplicate_yaml_keys_and_non_string_keys(self):
        for raw in ("schema_version: 1\nprofiles: []\nprofiles: []\n",
                    "schema_version: 1\nprofiles: []\n1: value\n"):
            (self.root / "measurements.yaml").write_text(raw)
            with self.assertRaises(t.Error):
                t.validate(self.root)

    def test_duplicate_ids_and_unknown_fields(self):
        for edit in (
            lambda m: m["profiles"].append(m["profiles"][0]),
            lambda m: m["profiles"][0].update(unexpected=True),
        ):
            with self.subTest(edit=edit):
                shutil.copyfile(t.ROOT / "examples/measurements.yaml", self.root / "measurements.yaml")
                self.change_manifest(edit)
                with self.assertRaises(t.Error):
                    t.validate(self.root)

    def test_missing_mismatched_invalid_and_unlisted_toml(self):
        path = self.root / "init-data/model-router/init-data.toml"
        original = path.read_bytes()
        for raw in (original.replace(b'model-router', b'wrong'),
                    original.replace(b'sha384', b'md5'),
                    original.replace(b'0.1.0', b'9.0.0'),
                    original + b"broken = [",
                    original + b"number = 42\n",
                    original + b"\xff"):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises(t.Error):
                    t.validate(self.root)
        path.unlink()
        with self.assertRaisesRegex(t.Error, "missing"):
            t.validate(self.root)
        path.write_bytes(original)
        path.with_name("orphan.toml").write_bytes(original)
        with self.assertRaisesRegex(t.Error, "unlisted"):
            t.validate(self.root)

    def test_paths_and_symlinks(self):
        for value in ("../outside/init-data.toml", "/tmp/init-data.toml",
                      "init-data/../init-data/model-router/init-data.toml"):
            shutil.copyfile(t.ROOT / "examples/measurements.yaml", self.root / "measurements.yaml")
            self.change_manifest(lambda m: m["profiles"][0].update(initdata=value))
            with self.assertRaises(t.Error):
                t.validate(self.root)
        shutil.copyfile(t.ROOT / "examples/measurements.yaml", self.root / "measurements.yaml")
        path = self.root / "init-data/model-router/init-data.toml"
        path.unlink()
        path.symlink_to(t.ROOT / "examples/init-data/model-router/init-data.toml")
        with self.assertRaisesRegex(t.Error, "symlink"):
            t.validate(self.root)

    def test_invalid_constraint(self):
        for value in ("", "not-a-version", ">=potato"):
            with self.subTest(value=value), self.assertRaises(t.Error):
                t.constraint(value)

    def test_raw_bytes_and_transport(self):
        original = (self.root / "init-data/model-router/init-data.toml").read_bytes()
        value = t.initdata(original, "model-router")
        self.assertEqual(len(value["host_data"]), 64)
        self.assertEqual(len(value["mr_config_id"]), 96)
        self.assertEqual(value["host_data"], value["digest"][:64])
        self.assertEqual(value["mr_config_id"], value["digest"])
        for raw in (original + b"\n", original + b"# comment\n",
                    original.replace(b"\n", b"\r\n"),
                    original.replace(b"false", b"true")):
            self.assertNotEqual(t.initdata(raw, "model-router")["digest"], value["digest"])
        changed = original.replace(b'model-router', b'another-router')
        self.assertNotEqual(t.initdata(changed, "another-router")["digest"], value["digest"])
        command = [sys.executable, str(t.ROOT / "trustbase.py"), "--root",
                   str(self.root), "annotation", "model-router"]
        encoded = subprocess.check_output(command).strip()
        self.assertEqual(gzip.decompress(base64.b64decode(encoded)), original)

    def test_sha256_padding_and_sha512_truncation(self):
        raw = (self.root / "init-data/model-router/init-data.toml").read_bytes()
        short = t.initdata(raw.replace(b"sha384", b"sha256"), "model-router")
        self.assertEqual(short["mr_config_id"], short["digest"] + "00" * 16)
        long = t.initdata(raw.replace(b"sha384", b"sha512"), "model-router")
        self.assertEqual(long["host_data"], long["digest"][:64])
        self.assertEqual(long["mr_config_id"], long["digest"][:96])


class ResolutionTests(Workspace):
    def test_all_matches_ordering_and_prerelease_exclusion(self):
        manifest = t.validate(self.root)
        releases = [release(v) for v in ("v0.2.0", "v0.1.10", "v0.1.6", "v0.1.5",
                                         "v0.1.7-rc.1", "dev")]
        releases += [release("v0.1.8", draft=True), release("v0.1.9", prerelease=True)]
        selected, _ = t.select_releases(manifest, releases)
        self.assertEqual(selected["model-router"], ["v0.1.6", "v0.1.10"])
        self.assertEqual(selected["example-model"], selected["model-router"])

    def test_semver_syntax(self):
        cases = {"0.1.6": ["0.1.6"], "~0.1.6": ["0.1.6", "0.1.9"],
                 "^0.1.6": ["0.1.6", "0.1.9"], ">=0.1.6 <0.2.0": ["0.1.6", "0.1.9"]}
        for spec, expected in cases.items():
            actual = [v for v in ("0.1.5", "0.1.6", "0.1.9", "0.2.0")
                      if t.constraint(spec).match(t.Version(v))]
            self.assertEqual(actual, expected)

    def test_no_matches_and_ambiguous_tags(self):
        manifest = t.validate(self.root)
        with self.assertRaisesRegex(t.Error, "no published stable"):
            t.select_releases(manifest, [release("v0.1.0")])
        with self.assertRaisesRegex(t.Error, "ambiguous"):
            t.select_releases(manifest, [release("v0.1.6"), release("0.1.6")])

    def test_github_pagination(self):
        gh = t.GitHub()
        with patch.object(gh, "api", side_effect=[[release(f"v1.0.{i}") for i in range(100)],
                                                 [release("v2.0.0")]]) as api:
            self.assertEqual(len(gh.releases()), 101)
        self.assertIn("page=2", api.call_args_list[1].args[0])

    def test_tag_dereference(self):
        gh = t.GitHub()
        with patch.object(gh, "api", side_effect=[
                {"object": {"type": "tag", "sha": "a" * 40}},
                {"object": {"type": "commit", "sha": REVISION}}]):
            self.assertEqual(gh.tag_revision("v0.1.6"), REVISION)

    def test_download_once_for_multiple_workloads(self):
        inputs = self.snapshot()
        self.assertEqual(len(self.gh.fetched), 4)
        with patch.object(t, "verify_attestation"):
            manifest, lock, _ = t.read_snapshot(inputs)
        self.assertEqual(len(manifest["profiles"]), 2)
        self.assertEqual(len(lock["releases"]), 2)

    def test_missing_asset_and_missing_profile(self):
        self.gh.items[0]["assets"].pop()
        with self.assertRaisesRegex(t.Error, "missing or duplicate"):
            self.snapshot()
        self.gh = FakeGitHub()
        self.change_manifest(lambda m: m["profiles"][0]["podvm"].update(profile="missing"))
        with self.assertRaisesRegex(t.Error, "model-router.*lacks profile"):
            self.snapshot()

    def test_failure_on_one_selected_release(self):
        self.gh.docs["v0.1.10"]["release"]["source_revision"] = "f" * 40
        with self.assertRaisesRegex(t.Error, "identity"):
            self.snapshot()
        self.assertFalse((self.base / "inputs").exists())

    def test_checksum_and_provenance_failures(self):
        inputs = self.snapshot()
        directory = inputs / "podvm/v0.1.6"
        (directory / "SHA256SUMS").write_text("0" * 64 + "  measurements.json\n")
        with patch.object(t, "verify_attestation"), self.assertRaisesRegex(t.Error, "checksum"):
            t.verify_podvm(directory, "v0.1.6", REVISION)
        with patch.object(t.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "bad signature")):
            with self.assertRaisesRegex(t.Error, "provenance verification failed"):
                t.verify_attestation(directory / "measurements.json", directory / "bundle", "v0.1.6", REVISION)

    def test_verifier_binds_repository_tag_commit_and_workflow(self):
        with patch.object(t.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "[{}]", "")) as run:
            t.verify_attestation(Path("asset"), Path("bundle"), "v0.1.6", REVISION, Path("trusted"))
        command = run.call_args.args[0]
        for flag, value in (("--repo", t.PODVM_REPO), ("--source-ref", "refs/tags/v0.1.6"),
                            ("--source-digest", REVISION), ("--signer-workflow", t.PODVM_WORKFLOW)):
            self.assertEqual(command[command.index(flag) + 1], value)

    def test_upstream_contract_and_kata_pin(self):
        doc = upstream()
        t.validate_podvm(doc, "v0.1.6", REVISION)
        doc["inputs"]["sources"]["kata_containers"]["revision"] = "f" * 40
        with self.assertRaisesRegex(t.Error, "unsupported Kata revision"):
            t.validate_podvm(doc, "v0.1.6", REVISION)
        doc = upstream()
        doc["profiles"]["2vcpu-8g"]["tdx"]["measurement"]["mr_td"] = "bad"
        with self.assertRaises(t.Error):
            t.validate_podvm(doc, "v0.1.6", REVISION)

    def test_variant_contract_and_kata_pin(self):
        doc = upstream("v0.3.13")
        t.validate_podvm(doc, "v0.3.13", REVISION)
        doc["inputs"]["nvidia"]["sources"]["kata_containers"]["revision"] = "f" * 40
        with self.assertRaisesRegex(t.Error, "unsupported Kata revision in nvidia"):
            t.validate_podvm(doc, "v0.3.13", REVISION)
        doc = upstream("v0.3.13")
        del doc["artifacts"]["nvidia"], doc["inputs"]["nvidia"]
        with self.assertRaises(t.Error):  # A GPU profile requires its NVIDIA bundle.
            t.validate_podvm(doc, "v0.3.13", REVISION)


class PackagingTests(Workspace):
    def test_roundtrip_reproducibility_and_complete_records(self):
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            first = t.package(inputs, self.base / "dist1", RELEASE, require_workloads=True)
            t.package(inputs, self.base / "dist2", RELEASE)
            verified = t.verify_package(self.base / "dist1", require_workloads=True)
        self.assertEqual(first, verified)
        for file in (self.base / "dist1").iterdir():
            self.assertEqual(file.read_bytes(), (self.base / "dist2" / file.name).read_bytes())
        workload = first["workloads"]["model-router"]
        records = workload["references"]
        self.assertEqual(len(records), 10)  # Two versions: one TDX + four SNP models each.
        for tag in ("v0.1.6", "v0.1.10"):
            group = [r for r in records if r["podvm_version"] == tag]
            tdx = [r for r in group if r["tee"] == "tdx"][0]
            self.assertEqual(set(tdx["measurements"]),
                             {"mr_td", "rtmr_0", "rtmr_1", "rtmr_2", "mr_config_id"})
            snp = [r for r in group if r["tee"] == "snp"]
            self.assertEqual({r["cpu_model"] for r in snp},
                             set(upstream(tag)["profiles"]["2vcpu-8g"]["sev"]))
            for record in snp:
                self.assertEqual(record["configuration"]["vcpu_type"], record["cpu_model"])
                self.assertEqual(len(record["measurements"]["host_data"]), 64)
        with self.assertRaisesRegex(t.Error, "output already exists"):
            t.package(inputs, self.base / "dist1", RELEASE)

    def test_gpu_profile_is_snp_only_with_nvidia_bundle(self):
        self.gh = FakeGitHub(("v0.1.6", "v0.3.13"))
        ident = "gpu-model"
        self.change_manifest(lambda m: m["profiles"].append({
            "id": ident, "initdata": f"init-data/{ident}/init-data.toml",
            "podvm": {"profile": "h100-pcie-1-96g", "version": "0.3.13"}}))
        path = self.root / "init-data" / ident / "init-data.toml"
        path.parent.mkdir()
        path.write_bytes(f'version = "0.1.0"\nalgorithm = "sha384"\n\n[data]\nid = "{ident}"\n'.encode())
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            result = t.package(inputs, self.base / "dist", RELEASE)
            self.assertEqual(t.verify_package(self.base / "dist"), result)
        records = result["workloads"][ident]["references"]
        self.assertEqual({r["tee"] for r in records}, {"snp"})
        self.assertEqual({r["cpu_model"] for r in records},
                         set(upstream("v0.3.13")["profiles"]["h100-pcie-1-96g"]["sev"]))
        expected = t.initdata(path.read_bytes(), ident)["host_data"]
        for record in records:
            self.assertEqual(record["podvm_artifact"]["name"],
                             "podvm-nvidia-ubuntu-24.04-x86_64-v0.3.13.tar.zst")
            self.assertEqual(record["configuration"]["cpus"], 8)
            self.assertEqual(record["measurements"]["host_data"], expected)
        # The legacy-format CPU workload keeps resolving against its own releases.
        router = result["workloads"]["model-router"]["references"]
        self.assertEqual({r["podvm_version"] for r in router}, {"v0.1.6"})
        sums = (inputs / "podvm/v0.3.13/SHA256SUMS").read_text()
        (inputs / "podvm/v0.3.13/SHA256SUMS").write_text(sums.replace("e" * 64, "0" * 64))
        with patch.object(t, "verify_attestation"), self.assertRaisesRegex(t.Error, "bundle digest"):
            t.verify_podvm(inputs / "podvm/v0.3.13", "v0.3.13", REVISION)

    def test_modified_frozen_inputs(self):
        inputs = self.snapshot()
        path = inputs / "init-data/model-router/init-data.toml"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(t.Error, "inventory"):
            t.read_snapshot(inputs)

    def test_locked_tag_outside_constraint(self):
        inputs = self.snapshot()
        manifest = t.validate(inputs)
        manifest["profiles"][0]["podvm"]["version"] = "0.1.6"
        (inputs / "measurements.yaml").write_bytes(t.json_bytes(manifest))
        self.refresh_inventory(inputs)
        with patch.object(t, "verify_attestation"), self.assertRaisesRegex(t.Error, "outside constraint"):
            t.read_snapshot(inputs)

    def test_release_catalog_cannot_mix_cpu_variants(self):
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            t.package(inputs, self.base / "dist", RELEASE)
            dist = self.base / "dist"
            doc = t.load_json((dist / "measurements.json").read_bytes())
            records = doc["workloads"]["model-router"]["references"]
            snp = [r for r in records if r["tee"] == "snp"]
            snp[0]["measurements"]["measurement"] = snp[1]["measurements"]["measurement"]
            (dist / "measurements.json").write_bytes(t.json_bytes(doc))
            sums = t.parse_sums((dist / "SHA256SUMS").read_bytes())
            sums["measurements.json"] = t.hash_file(dist / "measurements.json")
            (dist / "SHA256SUMS").write_text("".join(f"{v}  {k}\n" for k, v in sorted(sums.items())))
            with self.assertRaisesRegex(t.Error, "catalog differs"):
                t.verify_package(dist)

    def test_empty_catalog_preview_and_publication_guard(self):
        inputs = self.base / "empty"
        empty = self.base / "empty-authoring"
        empty.mkdir()
        (empty / "measurements.yaml").write_text("schema_version: 1\nprofiles: []\n")
        with patch.object(t.GitHub, "releases", side_effect=AssertionError("unexpected network")):
            t.resolve(empty, inputs)
        t.package(inputs, self.base / "preview", RELEASE)
        t.verify_package(self.base / "preview")
        with self.assertRaisesRegex(t.Error, "at least one"):
            t.package(inputs, self.base / "production", RELEASE, require_workloads=True)
        with self.assertRaisesRegex(t.Error, "at least one"):
            t.verify_package(self.base / "preview", require_workloads=True)

    def test_archive_rejects_traversal_symlinks_and_duplicates(self):
        for name, kind, duplicate in (("../escape", tarfile.REGTYPE, False),
                                       ("link", tarfile.SYMTYPE, False),
                                       ("duplicate", tarfile.REGTYPE, True)):
            archive = self.base / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "/tmp/escape" if kind == tarfile.SYMTYPE else ""
                output.addfile(member, io.BytesIO())
                if duplicate:
                    output.addfile(member, io.BytesIO())
            destination = self.base / ("unpack-" + kind.decode() + str(duplicate))
            destination.mkdir(exist_ok=True)
            with self.assertRaises(t.Error):
                t.unpack(archive, destination)


if __name__ == "__main__":
    unittest.main()
