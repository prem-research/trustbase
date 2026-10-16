"""Publication boundaries: no network mutations are made by these tests."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trustbase as t

spec = importlib.util.spec_from_file_location("release_script", t.ROOT / ".github/scripts/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "tag",
            "GITHUB_REF_NAME": "v1.0.0", "GITHUB_SHA": "a" * 40,
            "GITHUB_REPOSITORY": "prem-research/trustbase", "GH_TOKEN": "test-only",
        }

    def test_only_stable_tag_pushes_can_publish(self):
        with patch.dict(os.environ, self.env, clear=True):
            self.assertEqual(release.tag(), "v1.0.0")
        for change in (
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            {"GITHUB_REF_TYPE": "branch"},
            {"GITHUB_REF_NAME": "v1.0.0-rc.1"},
            {"GITHUB_REF_NAME": "v01.0.0"},
            {"GITHUB_REF_NAME": "vanything"},
        ):
            with patch.dict(os.environ, {**self.env, **change}, clear=True):
                with self.assertRaises(t.Error):
                    release.tag()

    def catalog(self, empty=False, revision="a" * 40):
        return t.json_bytes({
            "release": t.release_metadata("v1.0.0", "prem-research/trustbase", revision),
            "workloads": {} if empty else {"test": {}},
        })

    def test_reject_empty_catalog_and_wrong_source(self):
        with patch.dict(os.environ, self.env, clear=True):
            for data in (self.catalog(empty=True), self.catalog(revision="b" * 40)):
                with patch.object(Path, "read_bytes", return_value=data):
                    with self.assertRaises(t.Error):
                        release.check()

    def test_existing_release_and_api_failures_never_overwrite(self):
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(Path, "read_bytes", return_value=self.catalog()):
            with patch.object(release.urllib.request, "urlopen"):
                with self.assertRaisesRegex(t.Error, "already exists"):
                    release.check()
            for code in (401, 403, 500):
                with patch.object(release.urllib.request, "urlopen",
                                  side_effect=urllib.error.HTTPError("test", code, "", {}, None)):
                    with self.assertRaisesRegex(t.Error, "cannot check"):
                        release.check()
            with patch.object(release.urllib.request, "urlopen",
                              side_effect=urllib.error.HTTPError("test", 404, "", {}, None)):
                self.assertEqual(release.check(), ("v1.0.0", "prem-research/trustbase", "a" * 40))

    def test_publish_verifies_before_creating_draft(self):
        assets = [Path("dist/measurements.json"), Path("dist/SHA256SUMS"),
                  Path("dist/trustbase-inputs-v1.0.0.tar.gz")]
        with patch.object(sys, "argv", ["release.py", "publish"]), \
                patch.object(release, "check", return_value=("v1.0.0", "prem-research/trustbase", "a"*40)), \
                patch.object(Path, "iterdir", return_value=iter(assets)), \
                patch.object(release, "run") as run:
            release.main()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 5)
        self.assertTrue(all(command[:3] == ["gh", "attestation", "verify"] for command in commands[:3]))
        self.assertEqual(commands[3][:3], ["gh", "release", "create"])
        self.assertIn("--draft", commands[3])
        self.assertEqual(commands[4][:3], ["gh", "release", "edit"])
        self.assertIn("--draft=false", commands[4])
        self.assertFalse(any("--clobber" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
