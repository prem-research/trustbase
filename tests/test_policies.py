"""Policy catalog authoring, frozen publication, and public URL contracts."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import threading
import unittest
from unittest.mock import patch
import urllib.request

import trustbase as t
from test_trustbase import RELEASE, Workspace
from test_release import release


class PolicyTests(Workspace):
    def setUp(self):
        super().setUp()
        self.policy_root = self.base / "policy-authoring"
        shutil.copytree(t.ROOT / "policies", self.policy_root / "policies")

    def write_index(self, doc):
        (self.policy_root / "policies/policies.yaml").write_bytes(t.json_bytes(doc))

    def test_yaml_preserves_public_index_and_exact_source_bytes(self):
        expected = {
            "policies": ["/nvidia/policy.rego", "/sev/policy.rego",
                         "/tdx/policy.rego", "/azure/policy.rego"],
            "data": [],
        }
        payloads = t.policy_payloads(self.policy_root)
        self.assertEqual(t.load_json(payloads["policies.json"]), expected)
        for name in expected["policies"]:
            self.assertEqual(payloads[name], (self.policy_root / ("policies" + name)).read_bytes())

    def test_invalid_indexes_and_paths_fail(self):
        good = t.load_json(t.policy_payloads(self.policy_root)["policies.json"])
        for change in (
            {"policies": []},
            {"policies": good["policies"] + [good["policies"][0]]},
            {"policies": ["https://example.com/policy.rego"]},
            {"policies": ["//tdx/policy.rego"]},
            {"policies": ["/../tdx/policy.rego"]},
            {"policies": ["/tdx/../policy.rego"]},
            {"policies": ["/tdx/policy.rego?query=1"]},
            {"policies": ["/tdx/policy.rego\n"]},
            {"policies": ["/tdx\\policy.rego"]},
            {"policies": ["/measurements.json/policy.rego"]},
            {"policies": ["/policies.json/policy.rego"]},
            {"data": ["/measurements.json"]},
            {"unknown": True},
        ):
            with self.subTest(change=change):
                self.write_index({**good, **change})
                with self.assertRaises(t.Error):
                    t.policy_payloads(self.policy_root)
        (self.policy_root / "policies/policies.yaml").write_text(
            "policies: [/tdx/policy.rego]\ndata: []\ndata: []\n")
        with self.assertRaisesRegex(t.Error, "duplicate mapping key"):
            t.policy_payloads(self.policy_root)

    def test_missing_unlisted_and_symlinked_policies_fail(self):
        policy = self.policy_root / "policies/tdx/policy.rego"
        raw = policy.read_bytes()
        policy.unlink()
        with self.assertRaisesRegex(t.Error, "missing or escaping"):
            t.policy_payloads(self.policy_root)
        policy.write_bytes(raw)
        extra = self.policy_root / "policies/unlisted.rego"
        extra.write_bytes(raw)
        with self.assertRaisesRegex(t.Error, "unlisted Rego"):
            t.policy_payloads(self.policy_root)
        extra.unlink()
        policy.unlink()
        policy.symlink_to(self.policy_root / "policies/sev/policy.rego")
        with self.assertRaisesRegex(t.Error, "symlinks are not allowed"):
            t.policy_payloads(self.policy_root)
        policy.unlink()
        directory = policy.parent
        directory.rmdir()
        directory.symlink_to(self.policy_root / "policies/sev", target_is_directory=True)
        with self.assertRaisesRegex(t.Error, "symlinks are not allowed"):
            t.policy_payloads(self.policy_root)

    def test_freeze_and_package_do_not_reread_authoring_policies(self):
        expected = t.policy_payloads(self.policy_root)
        inputs = self.snapshot()
        self.assertEqual(t.policy_payloads(inputs), expected)
        lock = t.load_json((inputs / "resolution.json").read_bytes())
        self.assertIn("policies/policies.yaml", lock["files"])
        for name in expected:
            if name.startswith("/"):
                self.assertEqual(lock["files"]["policies" + name], t.sha256(expected[name]))
        shutil.copytree(t.ROOT / "schemas", self.policy_root / "schemas")
        with patch.object(t, "verify_attestation"), patch.object(t, "ROOT", self.policy_root):
            # Packaging must use frozen policies even when authoring files change.
            (self.policy_root / "policies/tdx/policy.rego").write_text("changed after resolution\n")
            t.package(inputs, self.base / "dist", RELEASE)
            t.verify_package(self.base / "dist")
        self.assertEqual(t.release_payloads(self.base / "dist")["/tdx/policy.rego"],
                         expected["/tdx/policy.rego"])

    def test_index_and_archive_tampering_and_old_format_fail(self):
        inputs = self.snapshot()
        dist = self.base / "dist"
        with patch.object(t, "verify_attestation"):
            t.package(inputs, dist, RELEASE)
            index = (dist / "policies.json").read_bytes()
            changed = t.load_json(index)
            changed["policies"].pop()
            (dist / "policies.json").write_bytes(t.json_bytes(changed))
            for operation in (t.verify_package, t.release_payloads):
                with self.assertRaisesRegex(t.Error, "policy index differs"):
                    operation(dist)
            (dist / "policies.json").unlink()
            with self.assertRaisesRegex(t.Error, "unexpected release assets"):
                t.verify_package(dist)
            (dist / "policies.json").write_bytes(index)
            (inputs / "policies/tdx/policy.rego").write_text("modified\n")
            (dist / t.archive_name(RELEASE)).write_bytes(t.archive_bytes(inputs))
            with self.assertRaisesRegex(t.Error, "inventory/checksum mismatch"):
                t.verify_package(dist)

    def test_subjects_and_pages_export_resolve_every_policy_url(self):
        inputs = self.snapshot()
        dist = self.base / "dist"
        with patch.object(t, "verify_attestation"):
            t.package(inputs, dist, RELEASE)
        (dist / t.BUNDLE_NAME).write_text("{}")
        payloads = t.release_payloads(dist)
        with patch.object(t, "ROOT", self.policy_root):
            # Both utilities must use the downloaded archive, even with different source policies.
            shutil.copytree(Path(__file__).resolve().parents[1] / "schemas", self.policy_root / "schemas")
            (self.policy_root / "policies/tdx/policy.rego").write_text("different checkout\n")
            previous = Path.cwd()
            try:
                os.chdir(self.base)
                release.subjects()
                release.pages()
                with self.assertRaises(t.Error):
                    release.pages()
            finally:
                os.chdir(previous)
        subjects = dict(line.split("  ", 1)[::-1] for line in
                        (self.base / "build/provenance-subjects.txt").read_text().splitlines())
        self.assertEqual(subjects, {name: t.sha256(raw) for name, raw in payloads.items()})
        site = self.base / "_site"
        expected_names = {"measurements.json", "policies.json", t.BUNDLE_NAME} | {
            name.removeprefix("/") for name in payloads if name.startswith("/")}
        self.assertEqual({p.relative_to(site).as_posix() for p in site.rglob("*") if p.is_file()},
                         expected_names)

        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(site)))
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}"
            with urllib.request.urlopen(base_url + "/policies.json", timeout=5) as response:
                index = t.load_json(response.read())
            for name in index["policies"]:
                with urllib.request.urlopen(base_url + name, timeout=5) as response:
                    self.assertEqual(response.read(), payloads[name])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
