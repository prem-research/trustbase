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
            "GITHUB_REPOSITORY": "prem-research/trustbase", "GITHUB_REPOSITORY_ID": "12345",
            "GH_TOKEN": "test-only",
        }
        lookup = patch.object(t, "github_repository_id", return_value="12345")
        lookup.start()
        self.addCleanup(lookup.stop)

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

    def catalog(self, empty=False, revision="a" * 40, chained=True):
        doc = {
            "release": {**t.release_metadata("v1.0.0", "prem-research/trustbase", revision)},
            "workloads": {} if empty else {"test": {}},
        }
        if chained:
            doc["release"]["previous"] = None
            doc["revoked"] = []
        return t.json_bytes(doc)

    def test_reject_empty_catalog_wrong_source_and_legacy_shape(self):
        with patch.dict(os.environ, self.env, clear=True):
            for data in (self.catalog(empty=True), self.catalog(revision="b" * 40),
                         self.catalog(chained=False)):
                with patch.object(Path, "read_bytes", return_value=data):
                    with self.assertRaises(t.Error):
                        release.check()

    def test_repository_id_is_checked_against_github(self):
        not_found = urllib.error.HTTPError("test", 404, "", {}, None)
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(Path, "read_bytes", return_value=self.catalog()), \
                patch.object(release, "published_releases", return_value=[]), \
                patch.object(release.urllib.request, "urlopen", side_effect=not_found):
            release.check()
            with patch.object(t, "github_repository_id", return_value="999"):
                with self.assertRaisesRegex(t.Error, "unexpected repository"):
                    release.check()

    def test_existing_release_and_api_failures_never_overwrite(self):
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(Path, "read_bytes", return_value=self.catalog()), \
                patch.object(release, "published_releases", return_value=[]):
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

    def test_publish_rechecks_latest_published_predecessor(self):
        catalog = t.load_json(self.catalog())
        catalog["release"]["previous"] = {"version": "v0.9.0", "measurements_sha256": "b" * 64}
        not_found = urllib.error.HTTPError("test", 404, "", {}, None)
        with patch.dict(os.environ, self.env, clear=True), \
                patch.object(Path, "read_bytes", return_value=t.json_bytes(catalog)), \
                patch.object(release.urllib.request, "urlopen", side_effect=not_found):
            with patch.object(release, "published_releases", return_value=["v0.9.0"]):
                release.check()
            with patch.object(release, "published_releases", return_value=["v0.9.0", "v0.9.1"]):
                with self.assertRaisesRegex(t.Error, "latest published release is v0.9.1"):
                    release.check()

    def test_publish_requires_exactly_the_four_assets(self):
        assets = [Path("dist/measurements.json"), Path("dist/provenance.sigstore.json"),
                  Path("dist/policies.json"), Path("dist/trustbase-inputs-v1.0.0.tar.gz")]
        with patch.object(sys, "argv", ["release.py", "publish"]), \
                patch.object(release, "check", return_value=("v1.0.0", "prem-research/trustbase", "a" * 40)), \
                patch.object(release, "run") as run:
            with patch.object(Path, "iterdir", return_value=iter(assets)):
                release.main()
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 2)
            self.assertEqual(commands[0][:3], ["gh", "release", "create"])
            self.assertIn("--draft", commands[0])
            self.assertEqual(commands[1][:3], ["gh", "release", "edit"])
            self.assertIn("--draft=false", commands[1])
            self.assertFalse(any("--clobber" in command for command in commands))
            for wrong in (assets[:2], assets + [Path("dist/SHA256SUMS")]):
                with patch.object(Path, "iterdir", return_value=iter(wrong)):
                    with self.assertRaisesRegex(t.Error, "exactly the three payload assets"):
                        release.main()

    def releases(self, *tags, draft=(), prerelease=()):
        return [{"tag_name": tag, "draft": tag in draft, "prerelease": tag in prerelease} for tag in tags]

    def test_previous_release_selection_and_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            env = {**self.env, "GITHUB_OUTPUT": str(output)}
            previous = Path(temporary) / "previous"
            with patch.dict(os.environ, env, clear=True), patch.object(release, "PREVIOUS", previous):
                with patch.object(release, "api", return_value=[]):
                    release.previous()
                self.assertEqual(output.read_text(), "previous=\n")
                output.write_text("")
                listing = self.releases("v1.0.0", "v1.0.10", "v1.0.9", "v2.0.0", "v1.1.0-rc.1", "dev",
                                        draft=("v2.0.0",), prerelease=("v1.0.9",))
                verified = {"release": {"version": "v1.0.10"}}

                def download(command):
                    if command[:3] == ["gh", "release", "download"]:
                        previous.mkdir()
                        (previous / "measurements.json").write_text("{}")
                        (previous / t.BUNDLE_NAME).write_text("{}")
                with patch.object(release, "api", return_value=listing), \
                        patch.object(release, "run", side_effect=download) as run, \
                        patch.object(t, "verify_package", return_value=verified) as verify:
                    release.previous()
                self.assertEqual(run.call_args_list[0].args[0][:4], ["gh", "release", "download", "v1.0.10"])
                self.assertEqual(verify.call_args.kwargs, {"require_provenance": True})
                self.assertEqual(output.read_text(), f"previous={previous}\n")

    def test_previous_legacy_release_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            previous = Path(temporary) / "previous"
            env = {**self.env, "GITHUB_OUTPUT": str(output)}

            def download(command):
                if command[:3] == ["gh", "release", "download"]:
                    previous.mkdir()
                    for name in ("measurements.json", "SHA256SUMS", "trustbase-inputs-v1.0.0.tar.gz"):
                        (previous / name).write_bytes(b"untrusted")
            with patch.dict(os.environ, env, clear=True), patch.object(release, "PREVIOUS", previous), \
                    patch.object(release, "api", return_value=self.releases("v1.0.0")), \
                    patch.object(release, "run", side_effect=download) as run:
                with self.assertRaisesRegex(t.Error, "legacy Trustbase release format is unsupported"):
                    release.previous()
            self.assertEqual(len(run.call_args_list), 1)
            self.assertEqual(output.read_text(), "")


if __name__ == "__main__":
    unittest.main()
