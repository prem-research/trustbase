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

FIXTURE = Path(__file__).parent / "fixtures" / "podvm-v0.3.13.json"
REVISION = "98fb81edf7284bc44f503ce21347f440acb0e3a6"
LEGACY_REVISION = "b57d5e92583388169743bc0084673f0249d64a34"
RELEASE = t.release_metadata("v1.0.0", "prem-research/trustbase", "a" * 40)


def upstream(tag="v0.3.13"):
    legacy = t.stable_version(tag) < t.Version("0.3.9")
    path = FIXTURE.with_name("podvm-v0.1.6.json") if legacy else FIXTURE
    doc = t.load_json(path.read_bytes())
    doc["release"]["version"] = tag
    for variant, values in t.podvm_variants(doc).items():
        artifact = values["artifact"]
        prefix = "podvm-nvidia-ubuntu" if variant == "nvidia" else "podvm-ubuntu"
        artifact["name"] = f"{prefix}-24.04-x86_64-{tag}.tar.zst"
    return doc


def release(tag, draft=False, prerelease=False):
    return {
        "tag_name": tag, "draft": draft, "prerelease": prerelease,
        "assets": [{"name": name, "browser_download_url":
                    f"https://github.com/{t.PODVM_REPO}/releases/download/{tag}/{name}"}
                   for name in ("measurements.json", "SHA256SUMS")],
    }


class FakeGitHub:
    def __init__(self, tags=("v0.3.13", "v0.3.14")):
        self.items = [release(tag) for tag in tags]
        self.docs = {tag: upstream(tag) for tag in tags}
        self.fetched = []

    def releases(self):
        return copy.deepcopy(self.items)

    def tag_revision(self, tag):
        return LEGACY_REVISION if t.stable_version(tag) < t.Version("0.3.9") else REVISION

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
        path = self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml"
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

    def test_content_addressed_filename(self):
        path = self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml"
        raw = path.read_bytes()
        path.write_bytes(raw + b"\n")
        with self.assertRaisesRegex(t.Error, "filename SHA-256 mismatch"):
            t.validate(self.root)

    def test_paths_and_symlinks(self):
        for value in ("../outside/init-data.toml", "/tmp/init-data.toml",
                      "init-data/../init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml"):
            shutil.copyfile(t.ROOT / "examples/measurements.yaml", self.root / "measurements.yaml")
            self.change_manifest(lambda m: m["profiles"][0].update(initdata=value))
            with self.assertRaises(t.Error):
                t.validate(self.root)
        shutil.copyfile(t.ROOT / "examples/measurements.yaml", self.root / "measurements.yaml")
        path = self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml"
        path.unlink()
        path.symlink_to(t.ROOT / "examples/init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml")
        with self.assertRaisesRegex(t.Error, "symlink"):
            t.validate(self.root)

    def test_invalid_constraint(self):
        for value in ("", "not-a-version", ">=potato"):
            with self.subTest(value=value), self.assertRaises(t.Error):
                t.constraint(value)

    def test_raw_bytes_and_transport(self):
        original = (self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml").read_bytes()
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
        raw = (self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml").read_bytes()
        short = t.initdata(raw.replace(b"sha384", b"sha256"), "model-router")
        self.assertEqual(short["mr_config_id"], short["digest"] + "00" * 16)
        long = t.initdata(raw.replace(b"sha384", b"sha512"), "model-router")
        self.assertEqual(long["host_data"], long["digest"][:64])
        self.assertEqual(long["mr_config_id"], long["digest"][:96])

    def test_model_mounts_schema_and_invariants(self):
        base = (self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml").read_text()
        valid_info = "e" * 64 + "_4096_07074027-62a4-548d-bbf6-3ba2f85aa868"
        valid = base + f'\n"model-mounts.json" = \'\'\'\n[{{"modelid":"org/m@rev","mount_path":"/models/m","info":"{valid_info}"}}]\n\'\'\'\n'
        self.assertEqual(len(t.initdata(valid.encode(), "model-router")["digest"]), 96)
        for bad_mounts in (
            "not-json",
            "{}",
            json.dumps([{"modelid": "no-at", "mount_path": "/models/m", "info": valid_info}]),
            json.dumps([{"modelid": "org/m@rev", "mount_path": "/other/m", "info": valid_info}]),
            json.dumps([{"modelid": "org/m@rev", "mount_path": "/models/../m", "info": valid_info}]),
            json.dumps([{"modelid": "org/m@rev", "mount_path": "/models/m",
                         "info": "e" * 64 + "_100_07074027-62a4-548d-bbf6-3ba2f85aa868"}]),
            json.dumps([{"modelid": "org/m@rev", "mount_path": "/models/m", "info": valid_info},
                        {"modelid": "org/m2@rev", "mount_path": "/models/m/sub", "info": valid_info}]),
        ):
            raw = (base + f"\n'model-mounts.json' = '''{bad_mounts}'''\n").encode()
            with self.subTest(bad_mounts=bad_mounts), self.assertRaises(t.Error):
                t.initdata(raw, "model-router")


class ResolutionTests(Workspace):
    def test_all_matches_ordering_and_prerelease_exclusion(self):
        manifest = t.validate(self.root)
        releases = [release(v) for v in ("v0.4.0", "v0.3.14", "v0.3.13", "v0.3.12",
                                         "v0.3.15-rc.1", "dev")]
        releases += [release("v0.3.16", draft=True), release("v0.3.17", prerelease=True)]
        selected, _ = t.select_releases(manifest, releases)
        self.assertEqual(selected["model-router"], ["v0.3.13", "v0.3.14"])
        self.assertEqual(selected["example-model"], selected["model-router"])

    def test_semver_syntax(self):
        cases = {"0.3.13": ["0.3.13"], "~0.3.13": ["0.3.13", "0.3.17"],
                 "^0.3.13": ["0.3.13", "0.3.17"], ">=0.3.13 <0.4.0": ["0.3.13", "0.3.17"]}
        for spec, expected in cases.items():
            actual = [v for v in ("0.3.12", "0.3.13", "0.3.17", "0.4.0")
                      if t.constraint(spec).match(t.Version(v))]
            self.assertEqual(actual, expected)

    def test_no_matches_and_ambiguous_tags(self):
        manifest = t.validate(self.root)
        with self.assertRaisesRegex(t.Error, "no published stable"):
            t.select_releases(manifest, [release("v0.1.0")])
        with self.assertRaisesRegex(t.Error, "ambiguous"):
            t.select_releases(manifest, [release("v0.3.13"), release("0.3.13")])

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
            self.assertEqual(gh.tag_revision("v0.3.13"), REVISION)

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
        self.gh.docs["v0.3.14"]["release"]["source_revision"] = "f" * 40
        with self.assertRaisesRegex(t.Error, "identity"):
            self.snapshot()
        self.assertFalse((self.base / "inputs").exists())

    def test_checksum_and_provenance_failures(self):
        inputs = self.snapshot()
        directory = inputs / "podvm/v0.3.13"
        (directory / "SHA256SUMS").write_text("0" * 64 + "  measurements.json\n")
        with patch.object(t, "verify_attestation"), self.assertRaisesRegex(t.Error, "checksum"):
            t.verify_podvm(directory, "v0.3.13", REVISION)
        with patch.object(t.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "bad signature")):
            with self.assertRaisesRegex(t.Error, "provenance verification failed"):
                t.verify_attestation(directory / "measurements.json", directory / "bundle", "v0.3.13", REVISION)

    def test_verifier_binds_repository_tag_commit_and_workflow(self):
        with patch.object(t.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "[{}]", "")) as run:
            t.verify_attestation(Path("asset"), Path("bundle"), "v0.3.13", REVISION, Path("trusted"))
        command = run.call_args.args[0]
        for flag, value in (("--repo", t.PODVM_REPO), ("--source-ref", "refs/tags/v0.3.13"),
                            ("--source-digest", REVISION), ("--signer-workflow", t.PODVM_WORKFLOW)):
            self.assertEqual(command[command.index(flag) + 1], value)

    def test_upstream_contract_and_kata_pin(self):
        t.validate_podvm(upstream(), "v0.3.13", REVISION)
        for variant in ("cpu", "nvidia"):
            doc = upstream()
            doc["inputs"][variant]["sources"]["kata_containers"]["revision"] = "f" * 40
            with self.subTest(variant=variant), self.assertRaisesRegex(t.Error, "unsupported Kata revision"):
                t.validate_podvm(doc, "v0.3.13", REVISION)
        doc = upstream()
        doc["profiles"]["2vcpu-8g"]["tdx"]["measurement"]["mr_td"] = "bad"
        with self.assertRaises(t.Error):
            t.validate_podvm(doc, "v0.3.13", REVISION)

    def test_unified_variant_coverage_and_gpu_tdx_rejection(self):
        for edit in (
            lambda d: d["artifacts"].pop("nvidia"),
            lambda d: d["inputs"].pop("cpu"),
            lambda d: d["profiles"]["2vcpu-8g"].pop("tdx"),
            lambda d: d["profiles"]["h100-pcie-1-96g"].update(
                tdx=d["profiles"]["2vcpu-8g"]["tdx"]),
            lambda d: d["artifacts"]["nvidia"].update(
                name="podvm-nvidia-ubuntu-24.04-x86_64-wrong.tar.zst"),
        ):
            doc = upstream()
            edit(doc)
            with self.subTest(edit=edit), self.assertRaises(t.Error):
                t.validate_podvm(doc, "v0.3.13", REVISION)

    def test_each_variant_bundle_checksum_is_verified(self):
        inputs = self.snapshot()
        directory = inputs / "podvm/v0.3.13"
        original = (directory / "SHA256SUMS").read_text()
        for variant, artifact in upstream()["artifacts"].items():
            with self.subTest(variant=variant):
                (directory / "SHA256SUMS").write_text(original.replace(artifact["sha256"], "0" * 64))
                with patch.object(t, "verify_attestation"), self.assertRaisesRegex(t.Error, variant + ".*bundle digest"):
                    t.verify_podvm(directory, "v0.3.13", REVISION)

    def test_single_variant_catalogs(self):
        for variant in ("cpu", "nvidia"):
            doc = upstream()
            doc["profiles"] = {k: p for k, p in doc["profiles"].items() if t.podvm_variant(p) == variant}
            doc["artifacts"] = {variant: doc["artifacts"][variant]}
            doc["inputs"] = {variant: doc["inputs"][variant]}
            t.validate_podvm(doc, "v0.3.13", REVISION)
            other = "nvidia" if variant == "cpu" else "cpu"
            doc["artifacts"][other] = upstream()["artifacts"][other]
            with self.assertRaises(t.Error):
                t.validate_podvm(doc, "v0.3.13", REVISION)

    def test_legacy_contract_and_kata_pin(self):
        doc = upstream("v0.1.6")
        t.validate_podvm(doc, "v0.1.6", LEGACY_REVISION)
        doc["inputs"]["sources"]["kata_containers"]["revision"] = "f" * 40
        with self.assertRaisesRegex(t.Error, "unsupported Kata revision"):
            t.validate_podvm(doc, "v0.1.6", LEGACY_REVISION)


class PackagingTests(Workspace):
    def test_legacy_cpu_and_unified_gpu_can_share_a_release(self):
        self.gh = FakeGitHub(("v0.1.6", "v0.3.13"))
        self.change_manifest(lambda m: m["profiles"][0]["podvm"].update(version="0.1.6"))
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            result = t.package(inputs, self.base / "mixed", RELEASE)
            self.assertEqual(t.verify_package(self.base / "mixed"), result)
        router = result["workloads"]["model-router"]["releases"]
        self.assertEqual(set(router), {"v0.1.6"})
        self.assertEqual(set(router["v0.1.6"]), {"tdx", "snp"})
        selected = upstream("v0.1.6")["profiles"]["2vcpu-8g"]
        self.assertEqual(router["v0.1.6"]["tdx"],
                         {key: selected["tdx"]["measurement"][key]
                          for key in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")})
        self.assertEqual(router["v0.1.6"]["snp"],
                         {cpu: data["measurement"] for cpu, data in selected["sev"].items()})
        gpu = result["workloads"]["example-model"]["releases"]
        self.assertEqual(set(gpu), {"v0.3.13"})
        self.assertEqual(set(gpu["v0.3.13"]), {"snp"})
        path = self.root / "init-data/f541d90ef872c2822fe3f73b83b5326782c845d9a13469c18a2d1d3eb8a8ee20.toml"
        expected = t.initdata(path.read_bytes(), "example-model")["host_data"]
        self.assertEqual(result["workloads"]["example-model"]["initdata"]["host_data"], expected)
        self.assertEqual(gpu["v0.3.13"]["snp"],
                         {cpu: data["measurement"] for cpu, data
                          in upstream()["profiles"]["h100-pcie-1-96g"]["sev"].items()})

    def test_roundtrip_reproducibility_and_reference_measurements(self):
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            first = t.package(inputs, self.base / "dist1", RELEASE, require_workloads=True)
            t.package(inputs, self.base / "dist2", RELEASE)
            verified = t.verify_package(self.base / "dist1", require_workloads=True)
        self.assertEqual(first, verified)
        for file in (self.base / "dist1").iterdir():
            self.assertEqual(file.read_bytes(), (self.base / "dist2" / file.name).read_bytes())
        workload = first["workloads"]["model-router"]
        self.assertEqual(set(workload["initdata"]),
                         {"algorithm", "digest", "sha256", "path", "host_data", "mr_config_id"})
        self.assertEqual(workload["initdata"]["path"], "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml")
        self.assertEqual(set(workload["releases"]), {"v0.3.13", "v0.3.14"})
        for tag in ("v0.3.13", "v0.3.14"):
            entry = workload["releases"][tag]
            selected = upstream(tag)["profiles"]["2vcpu-8g"]
            self.assertEqual(set(entry["tdx"]), {"mr_td", "rtmr_0", "rtmr_1", "rtmr_2"})
            self.assertEqual(set(entry["snp"]), set(selected["sev"]))
            for cpu, measurement in entry["snp"].items():
                self.assertEqual(measurement, selected["sev"][cpu]["measurement"])
        gpu = first["workloads"]["example-model"]["releases"]
        self.assertEqual(set(gpu), {"v0.3.13", "v0.3.14"})
        self.assertEqual(sum(len(entry["snp"]) for entry in gpu.values()), 8)
        for tag, entry in gpu.items():
            self.assertEqual(set(entry), {"snp"})
            self.assertEqual(set(entry["snp"]),
                             set(upstream(tag)["profiles"]["h100-pcie-1-96g"]["sev"]))
        with self.assertRaisesRegex(t.Error, "output already exists"):
            t.package(inputs, self.base / "dist1", RELEASE)

    def test_every_current_profile_preserves_measurements(self):
        manifest = t.validate(self.root)
        template = (self.root / "init-data/f541d90ef872c2822fe3f73b83b5326782c845d9a13469c18a2d1d3eb8a8ee20.toml").read_bytes()
        shutil.rmtree(self.root / "init-data")
        manifest["profiles"] = []
        for ident in upstream()["profiles"]:
            raw = template.replace(b"example-model", ident.encode())
            path = f"init-data/{t.sha256(raw)}.toml"
            t.write_file(self.root, path, raw)
            manifest["profiles"].append({"id": ident, "initdata": path,
                                         "podvm": {"profile": ident, "version": "0.3.13"}})
        (self.root / "measurements.yaml").write_bytes(t.json_bytes(manifest))
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            result = t.package(inputs, self.base / "all-profiles", RELEASE)
            self.assertEqual(t.verify_package(self.base / "all-profiles"), result)
        for ident, workload in result["workloads"].items():
            selected = upstream()["profiles"][ident]
            self.assertEqual(set(workload["releases"]), {"v0.3.13"})
            entry = workload["releases"]["v0.3.13"]
            self.assertEqual(set(entry["snp"]), set(selected["sev"]))
            for cpu, data in selected["sev"].items():
                self.assertEqual(entry["snp"][cpu], data["measurement"])
            if "tdx" in selected:
                self.assertEqual(entry["tdx"],
                                 {key: selected["tdx"]["measurement"][key]
                                  for key in ("mr_td", "rtmr_0", "rtmr_1", "rtmr_2")})
            else:
                self.assertNotIn("tdx", entry)

    def test_catalog_schema_rejects_malformed_measurements(self):
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            original = t.catalog(inputs, RELEASE)
        for edit in (
            lambda w: w["releases"]["v0.3.13"]["tdx"].pop("rtmr_1"),
            lambda w: w["releases"]["v0.3.13"].update(snp={}),
            lambda w: w["releases"]["v0.3.13"].update(snp={"NOT-A-CPU": "a" * 96}),
            lambda w: w["releases"]["v0.3.13"].update(tdx={"mr_td": "bad"}),
            lambda w: w["initdata"].pop("host_data"),
            lambda w: w["releases"].update({"not a version": {"snp": {"EPYC": "a" * 96}}}),
        ):
            doc = copy.deepcopy(original)
            edit(doc["workloads"]["model-router"])
            with self.subTest(edit=edit), self.assertRaises(t.Error):
                t.check_schema(doc, "measurements.schema.json")

    def test_modified_frozen_inputs(self):
        inputs = self.snapshot()
        path = inputs / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(t.Error, "inventory"):
            t.read_snapshot(inputs)

    def test_locked_tag_outside_constraint(self):
        inputs = self.snapshot()
        manifest = t.validate(inputs)
        manifest["profiles"][0]["podvm"]["version"] = "0.3.13"
        (inputs / "measurements.yaml").write_bytes(t.json_bytes(manifest))
        self.refresh_inventory(inputs)
        with patch.object(t, "verify_attestation"), self.assertRaisesRegex(t.Error, "outside constraint"):
            t.read_snapshot(inputs)

    def test_release_catalog_tampering_is_detected(self):
        inputs = self.snapshot()
        with patch.object(t, "verify_attestation"):
            t.package(inputs, self.base / "dist", RELEASE)
            dist = self.base / "dist"
            doc = t.load_json((dist / "measurements.json").read_bytes())
            snp = doc["workloads"]["model-router"]["releases"]["v0.3.13"]["snp"]
            first, second = sorted(snp)[:2]
            snp[first] = snp[second]
            (dist / "measurements.json").write_bytes(t.json_bytes(doc))
            with self.assertRaisesRegex(t.Error, "catalog differs"):
                t.verify_package(dist)

    def test_package_has_two_payloads_and_provenance_needs_the_bundle(self):
        inputs = self.snapshot()
        dist = self.base / "dist"
        with patch.object(t, "verify_attestation"):
            result = t.package(inputs, dist, RELEASE)
            self.assertEqual({p.name for p in dist.iterdir()},
                             {"measurements.json", "trustbase-inputs-v1.0.0.tar.gz"})
            self.assertIsNone(result["release"]["previous"])
            self.assertEqual(result["revoked"], [])
            self.assertEqual(t.verify_package(dist), result)
            with self.assertRaisesRegex(t.Error, "missing or escaping file: provenance.sigstore.json"):
                t.verify_package(dist, require_provenance=True)
            with self.assertRaisesRegex(t.Error, "maximum age requires provenance"):
                t.verify_package(dist, max_age=10)
            (dist / "SHA256SUMS").write_text("")
            with self.assertRaisesRegex(t.Error, "chained-format fields"):
                t.verify_package(dist)

    def legacy_dist(self, inputs, name="legacy"):
        with patch.object(t, "verify_attestation"):
            result = t.catalog(inputs, RELEASE, legacy=True)
        dist = self.base / name
        dist.mkdir()
        assets = {"measurements.json": t.json_bytes(result),
                  "trustbase-inputs-v1.0.0.tar.gz": t.archive_bytes(inputs)}
        for key, raw in assets.items():
            (dist / key).write_bytes(raw)
        (dist / "SHA256SUMS").write_text("".join(f"{t.sha256(raw)}  {key}\n"
                                                 for key, raw in sorted(assets.items())))
        return dist

    def test_legacy_release_still_verifies_without_chain_fields(self):
        dist = self.legacy_dist(self.snapshot())
        with patch.object(t, "verify_attestation"):
            result = t.verify_package(dist)
            self.assertNotIn("previous", result["release"])
            self.assertNotIn("revoked", result)
            with self.assertRaisesRegex(t.Error, "legacy releases have no provenance bundle"):
                t.verify_package(dist, require_provenance=True)
            with self.assertRaisesRegex(t.Error, "legacy releases are not chained"):
                t.verify_package(dist, previous_dist=dist)
            (dist / "SHA256SUMS").write_text("0" * 64 + "  measurements.json\n")
            with self.assertRaises(t.Error):
                t.verify_package(dist)

    def test_release_chain_ordering_and_revocation_monotonicity(self):
        inputs = self.snapshot()
        first, second = self.base / "first", self.base / "second"
        with patch.object(t, "verify_attestation"):
            t.package(inputs, first, RELEASE)
            previous = t.previous_release(first)
            self.assertEqual(previous["version"], "v1.0.0")
            self.assertEqual(previous["revoked"], [])
            newer = t.release_metadata("v1.0.1", "prem-research/trustbase", "b" * 40)
            result = t.package(inputs, second, newer, previous)
            self.assertEqual(result["release"]["previous"],
                             {"version": "v1.0.0", "measurements_sha256": t.hash_file(first / "measurements.json")})
            t.verify_package(second, previous_dist=first)
            with self.assertRaisesRegex(t.Error, "does not chain"):
                t.verify_package(first, previous_dist=second)
            with self.assertRaisesRegex(t.Error, "does not follow"):
                t.package(inputs, self.base / "older",
                          t.release_metadata("v0.9.0", "prem-research/trustbase", "c" * 40), previous)
            dropped = {**previous, "revoked": [{"id": "gone", "sha256": "0" * 64, "reason": "test"}]}
            with self.assertRaisesRegex(t.Error, "revocations from v1.0.0 were dropped"):
                t.package(inputs, self.base / "dropped", newer, dropped)
            preview = t.release_metadata("preview-abc", "prem-research/trustbase", "d" * 40)
            t.package(inputs, self.base / "preview", preview, previous)

    def test_revoked_definitions_are_rejected_when_registered_and_carried_otherwise(self):
        path = self.root / "init-data/a72fe3e72cdbe2f66b500527c585d76ffcf020b1bbc59ae5ed87c28bba26c403.toml"
        (self.root / "revoked.yaml").write_text(
            f"schema_version: 1\nentries:\n  - id: model-router\n    sha256: {t.sha256(path.read_bytes())}\n"
            "    reason: test\n")
        with self.assertRaisesRegex(t.Error, "revoked Init-Data is still registered"):
            t.validate(self.root)
        (self.root / "revoked.yaml").write_text(
            "schema_version: 1\nentries:\n  - id: old\n    sha256: '" + "0" * 64 + "'\n    reason: superseded\n"
            "  - id: old\n    sha256: '" + "0" * 64 + "'\n    reason: twice\n")
        with self.assertRaisesRegex(t.Error, "duplicate revoked"):
            t.validate(self.root)
        (self.root / "revoked.yaml").write_text(
            "schema_version: 1\nentries:\n  - id: old\n    sha256: " + "0" * 64 + "\n    reason: superseded\n")
        with self.assertRaisesRegex(t.Error, "not of type 'string'"):
            t.validate(self.root)  # an unquoted all-digit digest is a YAML integer
        (self.root / "revoked.yaml").write_text(
            "schema_version: 1\nentries:\n  - id: old\n    sha256: '" + "0" * 64 + "'\n    reason: superseded\n")
        inputs = self.snapshot()
        self.assertTrue((inputs / "revoked.yaml").is_file())
        with patch.object(t, "verify_attestation"):
            result = t.package(inputs, self.base / "dist", RELEASE)
            self.assertEqual(result["revoked"], [{"id": "old", "sha256": "0" * 64, "reason": "superseded"}])
            t.verify_package(self.base / "dist")
            with self.assertRaisesRegex(t.Error, "legacy catalogs cannot carry revocations"):
                t.catalog(inputs, RELEASE, legacy=True)
            doc = t.load_json((self.base / "dist" / "measurements.json").read_bytes())
            doc["revoked"] = []
            (self.base / "dist" / "measurements.json").write_bytes(t.json_bytes(doc))
            with self.assertRaisesRegex(t.Error, "catalog differs"):
                t.verify_package(self.base / "dist")

    def verifier_result(self, dist, repository_id="12345", timestamp="2026-10-19T10:00:00.123456789Z"):
        subjects = [{"name": name, "digest": {"sha256": t.hash_file(dist / name)}}
                    for name in ("measurements.json", "trustbase-inputs-v1.0.0.tar.gz")]
        return {"attestation": {}, "verificationResult": {
            "statement": {"subject": subjects},
            "signature": {"certificate": {"sourceRepositoryIdentifier": repository_id}},
            "verifiedTimestamps": [{"type": "Tlog", "uri": "https://rekor.sigstore.dev",
                                    "timestamp": timestamp}]}}

    def test_provenance_bundle_binds_subjects_repository_and_signing_time(self):
        inputs = self.snapshot()
        dist = self.base / "dist"
        with patch.object(t, "verify_attestation"):
            t.package(inputs, dist, RELEASE)
        (dist / t.BUNDLE_NAME).write_text("{}")
        good = self.verifier_result(dist)

        def verifier(result, code=0):
            return patch.object(t.subprocess, "run",
                                return_value=subprocess.CompletedProcess([], code, json.dumps([result]), "nope"))
        with verifier(good) as run:
            t.verify_package(dist, require_provenance=True, min_version="v1.0.0", max_age=10 ** 9)
        # The first two verifier runs authenticate the release payloads; later ones re-verify PodVM.
        self.assertGreaterEqual(run.call_count, 2)
        command = run.call_args_list[1].args[0]
        for flag, value in (("--repo", t.TRUSTBASE_REPO), ("--signer-workflow", t.TRUSTBASE_WORKFLOW),
                            ("--source-ref", "refs/tags/v1.0.0"), ("--source-digest", "a" * 40),
                            ("--bundle", str(t.source_file(dist, t.BUNDLE_NAME)))):
            self.assertEqual(command[command.index(flag) + 1], value)
        with verifier(good), patch.object(t, "TRUSTBASE_REPOSITORY_ID", 12345):
            t.verify_package(dist, require_provenance=True)
        with verifier(good), patch.object(t, "TRUSTBASE_REPOSITORY_ID", 999):
            with self.assertRaisesRegex(t.Error, "another repository id"):
                t.verify_package(dist, require_provenance=True)
        with verifier(good), self.assertRaisesRegex(t.Error, "signing event is .* old"):
            t.verify_package(dist, require_provenance=True, max_age=1)
        with verifier(good), self.assertRaisesRegex(t.Error, "below the minimum version"):
            t.verify_package(dist, require_provenance=True, min_version="v1.0.1")
        with self.assertRaisesRegex(t.Error, "invalid minimum version"):
            t.verify_package(dist, min_version="potato")
        with verifier(good, code=1), self.assertRaisesRegex(t.Error, "provenance verification failed"):
            t.verify_package(dist, require_provenance=True)
        for edit, message in (
            (lambda r: r["verificationResult"]["statement"]["subject"][0]["digest"].update(sha256="0" * 64), "subjects differ"),
            (lambda r: r["verificationResult"]["statement"]["subject"].append({"name": "extra", "digest": {"sha256": "1" * 64}}), "subjects differ"),
            (lambda r: r["verificationResult"]["statement"]["subject"].pop(), "subjects differ"),
            (lambda r: r["verificationResult"].update(verifiedTimestamps=[]), "no verified signing timestamp"),
            (lambda r: r["verificationResult"]["verifiedTimestamps"][0].update(timestamp="yesterday"), "invalid verifier timestamp"),
        ):
            bad = copy.deepcopy(good)
            edit(bad)
            with self.subTest(message=message), verifier(bad), self.assertRaisesRegex(t.Error, message):
                t.verify_package(dist, require_provenance=True)
        other = self.base / "other"
        with patch.object(t, "verify_attestation"):
            t.package(inputs, other, t.release_metadata("v1.0.0", "someone/else", "a" * 40))
        (other / t.BUNDLE_NAME).write_text("{}")
        with verifier(good), self.assertRaisesRegex(t.Error, "only verified for prem-research/trustbase"):
            t.verify_package(other, require_provenance=True)

    def test_verifier_timestamps(self):
        for value in ("2026-10-19T10:00:00Z", "2026-10-19T10:00:00.5Z", "2026-10-19T10:00:00.123456789Z",
                      "2026-10-19T12:00:00.1+02:00"):
            self.assertEqual(t.parse_timestamp(value).timestamp() // 1, 1792404000.0)
        for value in ("", None, "2026-10-19 10:00:00Z", "2026-10-19T10:00:00"):
            with self.assertRaises(t.Error):
                t.parse_timestamp(value)

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
