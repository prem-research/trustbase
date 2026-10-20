"""Dispatch receiver tests: GitHub calls, the gate, and git are patched; the import logic is real."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import admission
import trustbase as t

spec = importlib.util.spec_from_file_location("receive_script", t.ROOT / ".github/scripts/receive.py")
receive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receive)

QWEN_ID = "qwen38-27b-h100-pcie-1-96g"
QWEN_PATH = "init-data/0932f8125fe9645a3e8d04a3940b79a5f955226e98ef1427a46800b12ccba47f.toml"
CANDIDATE = (t.ROOT / QWEN_PATH).read_bytes() + b"# candidate revision\n"
CONFIG = admission.load_config(t.ROOT)
NEW_ID = "new-model-h100-pcie-1-96g"
NEW_CANDIDATE = CANDIDATE.replace(f'"id" = "{QWEN_ID}"'.encode(),
                                  f'"id" = "{NEW_ID}"'.encode(), 1)


def payload(**overrides):
    base = {"schema_version": 1, "workload": QWEN_ID, "repository": "prem-research/coco-fleet",
            "commit": "c" * 40, "path": f"candidates/{t.sha256(CANDIDATE)}.toml",
            "sha256": t.sha256(CANDIDATE), "podvm": {"profile": "h100-pcie-1-96g", "version": "0.3.18"}}
    base.update(overrides)
    return base


class FakeFleet:
    def __init__(self, status="ahead", content=CANDIDATE):
        self.status = status
        self.content = content
        self.calls = []

    def __call__(self, repository, path, token, accept="application/vnd.github+json"):
        self.calls.append((repository, path, token, accept))
        if path.startswith("compare/"):
            return json.dumps({"status": self.status}).encode()
        if path.startswith("contents/"):
            assert accept == "application/vnd.github.raw+json" and "?ref=" + "c" * 40 in path
            return self.content
        raise AssertionError(path)


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        for name in ("measurements.yaml", "revoked.yaml", "admission.yaml"):
            shutil.copyfile(t.ROOT / name, self.root / name)
        shutil.copytree(t.ROOT / "init-data", self.root / "init-data")

    def event(self, **overrides):
        path = Path(self.temporary.name) / "event.json"
        path.write_bytes(t.json_bytes({"action": "init-data-candidate", "client_payload": payload(**overrides)}))
        return path

    def allow_selection(self, selection):
        config = admission.load_config(self.root)
        config["floor"]["podvm_selections"].append(selection)
        (self.root / "admission.yaml").write_text(yaml.safe_dump(config, sort_keys=False))

    def test_payload_schema_and_event_type(self):
        self.assertEqual(receive.payload_from_event(self.event()), payload())
        path = Path(self.temporary.name) / "event.json"
        path.write_bytes(t.json_bytes({"action": "other", "client_payload": payload()}))
        with self.assertRaisesRegex(t.Error, "event type"):
            receive.payload_from_event(path)
        for change in ({"commit": "abc"}, {"sha256": "0" * 63}, {"path": "../x.toml"}, {"extra": 1},
                       {"workload": "Bad Id"}, {"schema_version": 2}, {"podvm": {"profile": "x"}}):
            path.write_bytes(t.json_bytes({"action": "init-data-candidate", "client_payload": payload(**change)}))
            with self.subTest(change=change), self.assertRaises(t.Error):
                receive.payload_from_event(path)

    def test_payload_must_match_source_and_reviewed_podvm_floor(self):
        manifest = t.validate(t.ROOT)
        self.assertEqual(receive.validate_payload(payload(), CONFIG, manifest)["id"], QWEN_ID)
        self.assertIsNone(receive.validate_payload(payload(workload=NEW_ID), CONFIG, manifest))
        for change, message in (
            ({"repository": "someone/else"}, "not prem-research/coco-fleet"),
            ({"path": "other/" + t.sha256(CANDIDATE) + ".toml"}, "candidates/<sha256>.toml"),
            ({"path": "candidates/" + "0" * 64 + ".toml"}, "candidates/<sha256>.toml"),
            ({"podvm": {"profile": "h100-pcie-1-96g", "version": "0.3.19"}}, "reviewed admission floor"),
            ({"podvm": {"profile": "other", "version": "0.3.18"}}, "reviewed admission floor"),
        ):
            with self.subTest(change=change), self.assertRaisesRegex(t.Error, message):
                receive.validate_payload(payload(**change), CONFIG, manifest)

    def test_fetch_checks_branch_membership_and_digest(self):
        fleet = FakeFleet()
        with patch.object(receive, "api", fleet):
            self.assertEqual(receive.fetch_candidate(payload(), CONFIG, "fleet-token"), CANDIDATE)
        self.assertEqual(fleet.calls[0][:3], ("prem-research/coco-fleet", "compare/" + "c" * 40 + "...main", "fleet-token"))
        for status in ("diverged", "behind", None):
            with patch.object(receive, "api", FakeFleet(status=status)):
                with self.subTest(status=status), self.assertRaisesRegex(t.Error, "is not on main"):
                    receive.fetch_candidate(payload(), CONFIG, "fleet-token")
        with patch.object(receive, "api", FakeFleet(content=CANDIDATE + b"\n")):
            with self.assertRaisesRegex(t.Error, "do not match the dispatched SHA-256"):
                receive.fetch_candidate(payload(), CONFIG, "fleet-token")

    def test_import_replaces_registration_and_is_idempotent(self):
        self.assertTrue(receive.import_candidate(self.root, payload(), CANDIDATE))
        manifest = t.validate(self.root)
        target = f"init-data/{t.sha256(CANDIDATE)}.toml"
        self.assertEqual(manifest["profiles"][0]["initdata"], target)
        self.assertFalse((self.root / QWEN_PATH).exists())
        self.assertEqual((self.root / target).read_bytes(), CANDIDATE)
        text = (self.root / "measurements.yaml").read_text()
        self.assertIn("version: 0.3.18", text)
        self.assertEqual(text.count("initdata:"), 1)
        self.assertFalse(receive.import_candidate(self.root, payload(), CANDIDATE))
        with self.assertRaisesRegex(t.Error, "do not match the dispatched SHA-256"):
            receive.import_candidate(self.root, payload(), CANDIDATE + b"\n")

    def test_import_refuses_revoked_and_wrong_workload_identity(self):
        (self.root / "revoked.yaml").write_text(
            f"schema_version: 1\nentries:\n  - id: {QWEN_ID}\n    sha256: '{t.sha256(CANDIDATE)}'\n    reason: test\n")
        with self.assertRaisesRegex(t.Error, "revoked"):
            receive.import_candidate(self.root, payload(), CANDIDATE)
        (self.root / "revoked.yaml").write_text("schema_version: 1\nentries: []\n")
        with self.assertRaisesRegex(t.Error, "data.id must exactly match"):
            receive.import_candidate(self.root, payload(workload="other"), CANDIDATE)

    def test_import_new_workload_and_update_podvm_selection(self):
        new_payload = payload(workload=NEW_ID, sha256=t.sha256(NEW_CANDIDATE),
                              path=f"candidates/{t.sha256(NEW_CANDIDATE)}.toml")
        before = t.validate(self.root)["profiles"][0].copy()
        self.assertTrue(receive.import_candidate(self.root, new_payload, NEW_CANDIDATE))
        profiles = t.validate(self.root)["profiles"]
        self.assertEqual(profiles[0], before)
        self.assertEqual(profiles[1], {"id": NEW_ID,
            "initdata": f"init-data/{t.sha256(NEW_CANDIDATE)}.toml",
            "podvm": new_payload["podvm"]})
        self.assertFalse(receive.import_candidate(self.root, new_payload, NEW_CANDIDATE))

        updated_selection = {"profile": "h100-pcie-1-96g", "version": "0.3.19"}
        changed = payload(workload=NEW_ID, sha256=t.sha256(NEW_CANDIDATE),
                          path=new_payload["path"], podvm=updated_selection)
        with self.assertRaisesRegex(t.Error, "reviewed admission floor"):
            receive.import_candidate(self.root, changed, NEW_CANDIDATE)
        self.allow_selection(updated_selection)
        self.assertTrue(receive.import_candidate(self.root, changed, NEW_CANDIDATE))
        self.assertEqual(t.validate(self.root)["profiles"][1]["podvm"], updated_selection)
        self.assertFalse(receive.import_candidate(self.root, changed, NEW_CANDIDATE))

    def test_release_admission_rejects_registration_outside_podvm_floor(self):
        manifest = t.validate(self.root)
        manifest["profiles"][0]["podvm"]["version"] = "0.3.19"
        (self.root / "measurements.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
        args = SimpleNamespace(root=self.root, config=None, all=True, ids=[],
                               static_only=True, evaluator=None, report=None)
        with self.assertRaisesRegex(t.Error, "reviewed admission floor"):
            admission.cli(args)

    def test_next_tag(self):
        listing = {"tags?per_page=100&page=1": [{"name": n} for n in ("v1.2.3", "v1.10.0", "v2.0.0-rc.1", "dev", "v1.9.9")]}
        with patch.object(receive, "api", lambda repository, path, token: json.dumps(listing[path]).encode()):
            self.assertEqual(receive.next_tag("prem-research/trustbase", "x"), "v1.10.1")
        with patch.object(receive, "api", lambda repository, path, token: b"[]"):
            self.assertEqual(receive.next_tag("prem-research/trustbase", "x"), "v1.0.0")

    def test_publish_waits_for_previous_release_without_skipping_tags(self):
        output = Path(self.temporary.name) / "out"
        output.mkdir()
        (output / "prepared.json").write_bytes(t.json_bytes({
            "repository": "prem-research/trustbase", "tag": "v1.0.2"}))
        env = {"GITHUB_REPOSITORY": "prem-research/trustbase", "GH_TOKEN": "read-only"}
        with patch.dict(os.environ, env, clear=True), patch.object(receive, "OUTPUT", output), \
                patch.object(receive, "latest_published_tag", side_effect=["v1.0.0", "v1.0.1"]), \
                patch.object(receive, "next_tag", return_value="v1.0.2"), \
                patch.object(receive.time, "sleep") as sleep:
            receive.await_predecessor(timeout=60)
        sleep.assert_called_once_with(15)
        with patch.dict(os.environ, env, clear=True), patch.object(receive, "OUTPUT", output), \
                patch.object(receive, "latest_published_tag", return_value="v1.0.3"):
            with self.assertRaisesRegex(t.Error, "newer release already supersedes"):
                receive.await_predecessor(timeout=0)

    def test_main_prepares_without_pushing(self):
        env = {"GITHUB_REPOSITORY": "prem-research/trustbase", "GITHUB_SHA": "a" * 40,
               "GITHUB_EVENT_PATH": str(self.event()), "FLEET_TOKEN": "fleet", "GH_TOKEN": "read-only"}
        output = Path(self.temporary.name) / "out"
        with patch.dict(os.environ, env, clear=True), patch.object(receive, "api", FakeFleet()), \
                patch.object(receive, "ROOT", self.root), patch.object(receive, "OUTPUT", output), \
                patch.object(admission, "KataPolicyEvaluator", lambda *a: None), \
                patch.object(admission, "admit", return_value={"ok": True}) as gate, \
                patch.object(receive, "next_tag", return_value="v1.0.1") as next_tag, \
                patch.object(receive, "candidate_release") as release, \
                patch.object(receive, "previous_release", return_value="build/previous"), \
                patch.object(receive, "publish") as push, \
                patch.object(receive.subprocess, "run") as run:
            run.side_effect = lambda command, **kwargs: SimpleNamespace(
                stdout=b"candidate patch" if command[:3] == ["git", "diff", "--cached"] else " M measurements.yaml\n")
            receive.main()
        self.assertEqual(gate.call_args.args[:2], (CANDIDATE, QWEN_ID))
        self.assertEqual(next_tag.call_args.args, ("prem-research/trustbase", "read-only"))
        self.assertEqual(release.call_args.args[1:], ("v1.0.1", "a" * 40, "build/previous"))
        self.assertFalse(push.called)
        self.assertIn("would publish v1.0.1", (output / "status.txt").read_text())
        self.assertEqual((output / "changes.patch").read_bytes(), b"candidate patch")
        self.assertEqual(t.load_json((output / "prepared.json").read_bytes())["sha256"], t.sha256(CANDIDATE))
        self.assertTrue((output / "admission-report.json").exists())
        self.assertEqual(t.validate(self.root)["profiles"][0]["initdata"], f"init-data/{t.sha256(CANDIDATE)}.toml")

    def test_denied_candidate_never_prepares_a_publishable_change(self):
        env = {"GITHUB_REPOSITORY": "prem-research/trustbase", "GITHUB_SHA": "a" * 40,
               "GITHUB_EVENT_PATH": str(self.event()), "FLEET_TOKEN": "fleet", "GH_TOKEN": "read-only"}
        output = Path(self.temporary.name) / "out"
        with patch.dict(os.environ, env, clear=True), patch.object(receive, "api", FakeFleet()), \
                patch.object(receive, "ROOT", self.root), patch.object(receive, "OUTPUT", output), \
                patch.object(admission, "KataPolicyEvaluator", lambda *a: None), \
                patch.object(admission, "admit", side_effect=t.Error("denied")), \
                patch.object(receive, "publish") as push:
            with self.assertRaisesRegex(t.Error, "denied"):
                receive.main()
        self.assertFalse(push.called)
        self.assertFalse((output / "prepared.json").exists())

    def test_prepared_patch_applies_to_fresh_checkout_before_write_token(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=test", "-c",
                        "user.email=test@example.com", "commit", "-qm", "base"], check=True)
        checkout = Path(self.temporary.name) / "checkout"
        subprocess.run(["git", "clone", "-q", str(self.root), str(checkout)], check=True)
        output = Path(self.temporary.name) / "out"
        output.mkdir()
        candidate = payload(workload=NEW_ID, sha256=t.sha256(NEW_CANDIDATE),
                            path=f"candidates/{t.sha256(NEW_CANDIDATE)}.toml")
        env = {"GITHUB_REPOSITORY": "prem-research/trustbase", "GITHUB_SHA": "a" * 40,
               "GITHUB_EVENT_PATH": str(self.event(workload=NEW_ID, sha256=candidate["sha256"],
                                                        path=candidate["path"])), "RELEASE_TOKEN": "release"}
        with patch.dict(os.environ, env, clear=True), patch.object(receive, "OUTPUT", output):
            receive.import_candidate(self.root, candidate, NEW_CANDIDATE)
            receive.prepared_change(self.root, candidate, env["GITHUB_REPOSITORY"], "v1.0.1", "import candidate")
            with patch.object(receive, "ROOT", checkout):
                receive.apply_prepared()
                with patch.object(receive, "publish") as publish:
                    receive.publish_prepared()
        self.assertEqual(t.sha256((checkout / "init-data" / (candidate["sha256"] + ".toml")).read_bytes()),
                         candidate["sha256"])
        self.assertEqual(t.validate(checkout)["profiles"][-1]["id"], NEW_ID)
        self.assertEqual(publish.call_args.args[1:4], ("prem-research/trustbase", "release", "v1.0.1"))

    def test_main_already_imported_is_a_noop(self):
        committed = (t.ROOT / QWEN_PATH).read_bytes()
        env = {"GITHUB_REPOSITORY": "prem-research/trustbase", "GITHUB_SHA": "a" * 40,
               "GITHUB_EVENT_PATH": str(self.event(path=f"candidates/{t.sha256(committed)}.toml",
                                                   sha256=t.sha256(committed))),
               "FLEET_TOKEN": "fleet", "RELEASE_TOKEN": "release"}
        output = Path(self.temporary.name) / "out"
        with patch.dict(os.environ, env, clear=True), patch.object(receive, "api", FakeFleet(content=committed)), \
                patch.object(receive, "ROOT", self.root), patch.object(receive, "OUTPUT", output), \
                patch.object(admission, "admit") as gate, patch.object(receive, "publish") as push:
            receive.main()
        self.assertFalse(gate.called)
        self.assertFalse(push.called)
        self.assertEqual((output / "status.txt").read_text(), "already-imported\n")

    def test_publish_uses_an_atomic_push_with_a_header_credential(self):
        with patch.object(receive.subprocess, "run") as run:
            receive.publish(self.root, "prem-research/trustbase", "secret", "v1.0.1", "msg")
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([c[c.index("-c") - 1] if False else c[-3:] for c in commands][-1],
                         ["https://github.com/prem-research/trustbase", "HEAD:refs/heads/main", "refs/tags/v1.0.1"])
        self.assertIn("--atomic", commands[-1])
        self.assertTrue(all("secret" not in part for c in commands for part in c if part.startswith("https://")))
        self.assertTrue(any(part.startswith("http.https://github.com/.extraheader=AUTHORIZATION: basic")
                            for part in commands[-1]))


if __name__ == "__main__":
    unittest.main()
