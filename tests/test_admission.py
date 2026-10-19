"""Admission gate tests: offline with a fake evaluator, plus the real evaluator when it is built."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import admission as a
import trustbase as t

QWEN_ID = "qwen38-27b-h100-pcie-1-96g"
QWEN = t.ROOT / "init-data/575f884446deeca9c042dfa9f69c1574e0272700e373ac2eb908a9d05acb5526.toml"
EXAMPLE = t.ROOT / "examples/init-data/f541d90ef872c2822fe3f73b83b5326782c845d9a13469c18a2d1d3eb8a8ee20.toml"
CONFIG = a.load_config(t.ROOT)
EXAMPLES_CONFIG = a.load_config(t.ROOT / "examples")
RAW = QWEN.read_bytes()
REGO = tomllib.loads(RAW.decode())["data"]["policy.rego"]
POLICY = a.split_policy(REGO)


def evaluator_binary():
    candidate = Path(os.environ.get("KATA_POLICY_EVAL") or a.EVALUATOR_BINARY)
    return candidate if candidate.is_file() else None


def with_rego(rego):
    """The committed TOML with its policy text replaced byte-for-byte."""
    assert "'''" not in rego
    return RAW.replace(REGO.encode(), rego.encode())


def with_policy_data(edit, rules=None):
    pd = copy.deepcopy(POLICY.policy_data)
    edit(pd)
    return with_rego((rules or POLICY.rules) + "policy_data := " + json.dumps(pd, indent=2) + "\n")


def expectations(scenarios):
    table = {}
    for _, steps in scenarios:
        for step in steps:
            table[(step.kind, json.dumps(step.request, sort_keys=True))] = step.expected
    return table


class SplitPolicyTests(unittest.TestCase):
    def test_qwen_sections(self):
        self.assertEqual([a.container_name(c) for c in POLICY.policy_data["containers"]],
                         ["pause", "vllm", "attestation"])
        self.assertIn(POLICY.rules_sha256, CONFIG["rules"]["accepted_sha256"])
        self.assertEqual(POLICY.defaults, CONFIG["defaults"])
        self.assertFalse(POLICY.defaults["ExecProcessRequest"])
        self.assertTrue(POLICY.defaults["StartContainerRequest"])
        self.assertTrue(POLICY.rules.endswith("\n"))

    def test_rejections(self):
        tail = REGO[REGO.index("policy_data := {"):]
        cases = {
            "trailing rule": REGO + "\nExecProcessRequest := true\n",
            "second definition": REGO + "\npolicy_data := {}\n",
            "partial definition": POLICY.rules + "policy_data.containers := []\n" + tail,
            "indented definition": POLICY.rules + "  policy_data := {}\n" + tail,
            "rule body": POLICY.rules + "policy_data if {\n true\n}\n" + tail,
            "not json": POLICY.rules + "policy_data := {\n containers: []\n}\n",
            "duplicate keys": POLICY.rules + 'policy_data := {"a": 1, "a": 2}\n',
            "other package": REGO.replace("package agent_policy", "package other", 1),
            "two packages": REGO.replace("package agent_policy", "package agent_policy\npackage agent_policy", 1),
            "failing policy enabled": REGO.replace("default AllowRequestsFailingPolicy := false",
                                                   "default AllowRequestsFailingPolicy := true"),
            "failing policy rule": REGO.replace("default AllowRequestsFailingPolicy := false",
                                                "default AllowRequestsFailingPolicy := false\n"
                                                "AllowRequestsFailingPolicy if { true }"),
            "unsupported default": REGO.replace("default ReadStreamRequest := false",
                                                "default ReadStreamRequest := maybe"),
            "duplicate default": REGO.replace("default ReadStreamRequest := false",
                                              "default ReadStreamRequest := false\ndefault ReadStreamRequest := true"),
            "empty": "",
        }
        for label, rego in cases.items():
            with self.subTest(label=label), self.assertRaises(t.Error):
                a.split_policy(rego)
        with self.assertRaisesRegex(t.Error, "must not carry policy_data"):
            a.split_policy(REGO, require_policy_data=False)

    def test_comments_do_not_count_as_definitions(self):
        policy = a.split_policy("# policy_data := {}\n# AllowRequestsFailingPolicy := true\n"
                                "package agent_policy\ndefault ExecProcessRequest := false\n"
                                "policy_data := {\"x\": 1}\n")
        self.assertEqual(policy.policy_data, {"x": 1})


class StaticCheckTests(unittest.TestCase):
    def test_committed_qwen_passes_static_checks(self):
        report = a.admit(RAW, QWEN_ID, CONFIG, static_only=True)
        self.assertEqual(report["rules_sha256"], POLICY.rules_sha256)
        self.assertFalse(report["evaluated"])

    def test_mutations_fail_static_checks(self):
        vllm = next(i for i, c in enumerate(POLICY.policy_data["containers"]) if a.container_name(c) == "vllm")
        attestation = next(i for i, c in enumerate(POLICY.policy_data["containers"])
                           if a.container_name(c) == "attestation")
        image = POLICY.policy_data["containers"][vllm]["OCI"]["Annotations"][a.IMAGE_KEY]
        cases = {
            "allowed command": lambda pd: pd["request_defaults"]["ExecProcessRequest"]["allowed_commands"].append(["/bin/sh"]),
            "exec regex": lambda pd: pd["request_defaults"]["ExecProcessRequest"]["regex"].append(".*"),
            "exec_commands": lambda pd: pd["containers"][vllm].update(exec_commands=[["/bin/true"]]),
            "unpinned image": lambda pd: pd["containers"][vllm]["OCI"]["Annotations"].update(
                {a.IMAGE_KEY: image.split("@")[0]}),
            "foreign repository": lambda pd: pd["containers"][vllm]["OCI"]["Annotations"].update(
                {a.IMAGE_KEY: "docker.io/evil/vllm@sha256:" + "0" * 64}),
            "privileged vllm": lambda pd: pd["containers"][vllm]["OCI"]["Process"]["Capabilities"].update(
                Bounding=["$(privileged_caps)"]),
            "literal caps": lambda pd: pd["containers"][vllm]["OCI"]["Process"]["Capabilities"].update(
                Effective=["CAP_SYS_ADMIN"]),
            "read stream": lambda pd: pd["request_defaults"].update(ReadStreamRequest=True),
            "write stream": lambda pd: pd["request_defaults"].update(WriteStreamRequest=True),
            "copy anywhere": lambda pd: pd["request_defaults"].update(CopyFileRequest=["^/.*"]),
            "env regex": lambda pd: pd["request_defaults"]["CreateContainerRequest"]["allow_env_regex"].append("^.*$"),
            "duplicate container": lambda pd: pd["containers"].append(copy.deepcopy(pd["containers"][vllm])),
            "privileged under another name": lambda pd: pd["containers"][attestation]["OCI"]["Annotations"].update(
                {a.NAME_KEY: "debug"}),
            "privileged with another image": lambda pd: pd["containers"][attestation]["OCI"]["Annotations"].update(
                {a.IMAGE_KEY: "docker.io/vllm/vllm-openai@sha256:" + "1" * 64}),
            "second gpu": lambda pd: pd["containers"][vllm]["devices"].append(pd["containers"][vllm]["devices"][0]),
            "gpu on attestation": lambda pd: pd["containers"][attestation].update(
                devices=list(pd["containers"][vllm]["devices"])),
            "kvm bind": lambda pd: pd["containers"][vllm]["OCI"]["Mounts"].append(
                {"destination": "/dev/kvm", "source": "/dev/kvm", "type_": "bind", "options": ["rbind", "rw"]}),
            "extra device bind on attestation": lambda pd: pd["containers"][attestation]["OCI"]["Mounts"].append(
                {"destination": "/dev/kvm", "source": "/dev/kvm", "type_": "bind", "options": ["rbind", "rw"]}),
            "second sandbox": lambda pd: pd["containers"].append(copy.deepcopy(pd["containers"][0])),
            "extra model mount": lambda pd: pd["containers"][vllm]["OCI"]["Mounts"].append(
                {"destination": "/models/other", "source": "^/run/kata-containers/sandbox/storage/[A-Za-z0-9_-]+={0,2}$",
                 "type_": "bind", "options": ["rbind", "rprivate", "ro"]}),
            "linux device": lambda pd: pd["containers"][vllm]["OCI"]["Linux"]["Devices"].append({"Path": "/dev/kvm"}),
            "shared pidns": lambda pd: pd["containers"][vllm].update(sandbox_pidns=True),
            "writable root": lambda pd: pd["containers"][vllm]["OCI"]["Root"].update(Readonly=False),
            "other namespace": lambda pd: [c["OCI"]["Annotations"].update({a.NAMESPACE_KEY: "default"})
                                           for c in pd["containers"]],
            "mixed namespaces": lambda pd: pd["containers"][vllm]["OCI"]["Annotations"].update(
                {a.NAMESPACE_KEY: "default"}),
            "unsynthesizable sandbox name": lambda pd: [c["OCI"]["Annotations"].update(
                {a.SANDBOX_NAME_KEY: "^(a|b)$"}) for c in pd["containers"]],
            "pause tag": lambda pd: pd["cluster_config"].update(pause_container_image="pause:3.9"),
            "guest pull off": lambda pd: pd["cluster_config"].update(guest_pull=False),
            "default caps": lambda pd: pd["common"]["default_caps"].append("CAP_SYS_ADMIN"),
            "privileged caps": lambda pd: pd["common"]["privileged_caps"].append("CAP_FAKE"),
            "sfprefix": lambda pd: pd["common"].update(sfprefix="^/"),
            "vfio path": lambda pd: pd["devices"]["vfio"].update(device_path="/dev/vfio/"),
            "sandbox storage": lambda pd: pd["sandbox"]["storages"].append(pd["sandbox"]["storages"][0]),
            "model mount rw": lambda pd: [m.update(options=["rbind", "rprivate", "rw"])
                                          for m in pd["containers"][vllm]["OCI"]["Mounts"]
                                          if m["destination"] == "/models/model"],
            "model storage shared": lambda pd: [s.update(shared=True) for s in pd["containers"][vllm]["storages"]
                                                if s["fstype"] == "bind"],
        }
        for label, edit in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(t.Error, "static checks failed"):
                a.admit(with_policy_data(edit), QWEN_ID, CONFIG, static_only=True)
        for label, raw in {
            "rules changed": with_policy_data(lambda pd: None, rules=POLICY.rules + "# reviewed?\n"),
            "default flipped": with_rego(REGO.replace("default ReadStreamRequest := false",
                                                      "default ReadStreamRequest := true")),
            "default dropped": with_rego(REGO.replace("default SetPolicyRequest := false\n", "")),
            "model path": RAW.replace(b'"mount_path": "/models/model"', b'"mount_path": "/models/other"'),
        }.items():
            with self.subTest(label=label), self.assertRaisesRegex(t.Error, "static checks failed"):
                a.admit(raw, QWEN_ID, CONFIG, static_only=True)

    def test_sample_pattern(self):
        for pattern in ("^vllm-qwen38-27b-[bcdfghjklmnpqrstvwxz2456789]+-[bcdfghjklmnpqrstvwxz2456789]+$",
                        "^[a-z0-9]{64}$", "^web-[a-z]+$", "^plain$", "^a\\.b$", "^x[0-9]?$"):
            self.assertRegex(a.sample_pattern(pattern), pattern)
        for pattern in ("^(a|b)$", "^a.*$", "^[^a]+$", "^a+$"):
            with self.subTest(pattern=pattern), self.assertRaises(t.Error):
                a.sample_pattern(pattern)

    def test_normalize_repository(self):
        self.assertEqual(a.normalize_repository("busybox"), "docker.io/library/busybox")
        self.assertEqual(a.normalize_repository("vllm/vllm-openai"), "docker.io/vllm/vllm-openai")
        self.assertEqual(a.normalize_repository("ghcr.io/prem-research/reticle"), "ghcr.io/prem-research/reticle")
        self.assertEqual(a.normalize_repository("localhost:5000/x"), "localhost:5000/x")

    def test_deny_all_examples(self):
        manifest = t.validate(t.ROOT / "examples")
        for profile in manifest["profiles"]:
            raw = (t.ROOT / "examples" / profile["initdata"]).read_bytes()
            self.assertEqual(a.admit(raw, profile["id"], EXAMPLES_CONFIG, static_only=True)["policy"], "deny-all")
        example = EXAMPLE.read_bytes()
        rego = tomllib.loads(example.decode())["data"]["policy.rego"]
        with self.assertRaisesRegex(t.Error, "only package and default rules"):
            a.admit(example.replace(rego.encode(), (rego + "ExecProcessRequest if { true }\n").encode()),
                    "example-model", EXAMPLES_CONFIG, static_only=True)
        with self.assertRaisesRegex(t.Error, "differ from the admitted"):
            a.admit(example.replace(b"default ExecProcessRequest := false\n", b""), "example-model",
                    EXAMPLES_CONFIG, static_only=True)
        with self.assertRaisesRegex(t.Error, "policy_data exactly once"):
            a.admit(example.replace(b"example-model", QWEN_ID.encode()), QWEN_ID, CONFIG, static_only=True)
        with self.assertRaisesRegex(t.Error, "must not carry policy_data"):
            a.admit(RAW, QWEN_ID, EXAMPLES_CONFIG, static_only=True)


class ConfigTests(unittest.TestCase):
    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admission.yaml"
            text = (t.ROOT / "admission.yaml").read_text()
            for label, broken, message in (
                ("kata pin", text.replace(t.KATA_REVISION, "0" * 40), "kata_revision"),
                ("regorus pin", text.replace(a.REGORUS_REVISION, "1" * 40), "regorus_revision"),
                ("unknown key", text + "extra: 1\n", "admission.schema.json"),
                ("floor on deny-all", text.replace("policy: genpolicy", "policy: deny-all"), "not allowed for deny-all"),
                ("missing floor", text[:text.index("floor:")], "floor is required"),
                ("privileged repository", text.replace("    attestation: ghcr.io/prem-research/reticle",
                                                       "    attestation: docker.io/other/image"),
                 "not in image_repositories"),
            ):
                path.write_text(broken)
                with self.subTest(label=label), self.assertRaisesRegex(t.Error, message):
                    a.load_config(t.ROOT, path)

    def test_regorus_and_kata_pins_match_the_evaluator_lockfile(self):
        lock = (a.EVALUATOR_SOURCE / "Cargo.lock").read_text()
        blocks = {m.group(1): m.group(2) for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\n(.*?)(?=\n\n|\Z)', lock, re.S)}
        self.assertIn(f"regorus?rev={a.REGORUS_REVISION}#{a.REGORUS_REVISION}", blocks["regorus"])
        for crate in ("kata-agent-policy", "protocols"):
            self.assertIn(f"kata-containers?rev={t.KATA_REVISION}#{t.KATA_REVISION}", blocks[crate])
        toml = (a.EVALUATOR_SOURCE / "Cargo.toml").read_text()
        self.assertEqual(toml.count(f'rev = "{t.KATA_REVISION}"'), 2)


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = a.genpolicy_scenarios(POLICY.policy_data, CONFIG, t.sha256(RAW))

    def test_fake_evaluator_round_trip_and_request_shape(self):
        table = expectations(self.scenarios)
        fake = a.FakeEvaluator(lambda kind, request: table[(kind, json.dumps(request, sort_keys=True))])
        report = a.admit(RAW, QWEN_ID, CONFIG, fake)
        self.assertTrue(report["evaluated"])
        self.assertEqual([s["name"] for s in report["scenarios"]],
                         ["pod-lifecycle-hot-plug", "pod-lifecycle-cold-plug", "fresh-state", "empty-state-denials"])
        kinds = {kind for calls in fake.calls for kind, _ in calls}
        for required in ("CreateSandboxRequest", "CreateContainerRequest", "StartContainerRequest",
                         "ExecProcessRequest", "ReadStreamRequest", "WriteStreamRequest", "SetPolicyRequest",
                         "CopyFileRequest", "GetMetricsRequest", "RemoveContainerRequest"):
            self.assertIn(required, kinds)
        allowed = [step for _, steps in self.scenarios for step in steps
                   if step.kind == "CreateContainerRequest" and step.expected]
        manual = [step for step in allowed if "manual rule" in step.label]
        positives = [step for step in allowed if step not in manual]
        # 3 containers x 2 VFIO modes + the fresh-state sandbox; GPU passthrough to the sandbox and
        # to the reticle is admitted by the fleet's manual VFIO rules.
        self.assertEqual(len(positives), 7)
        self.assertEqual(sorted(step.label for step in manual),
                         sorted(["pause: gpu via manual rule", "attestation: gpu via manual rule"] * 2))
        for step in positives:
            oci = step.request["OCI"]
            annotations = oci["Annotations"]
            index = [a.container_name(c) for c in POLICY.policy_data["containers"]].index(
                "pause" if annotations[a.TYPE_KEY] == "sandbox" else annotations[a.NAME_KEY])
            policy = POLICY.policy_data["containers"][index]
            pull = [s for s in step.request["storages"] if s["driver"] == "image_guest_pull"]
            self.assertEqual(len(pull), 1)
            if annotations[a.TYPE_KEY] == "container":
                self.assertEqual(pull[0]["source"], annotations[a.IMAGE_KEY])
            self.assertEqual(len(oci["Mounts"]), len(policy["OCI"]["Mounts"]))
            self.assertEqual(len(step.request["storages"]), len(policy["storages"]) + 1)
            self.assertNotIn("$(", json.dumps(step.request))
            self.assertTrue(set(oci["Process"]["Capabilities"]["Bounding"]) in (
                set(POLICY.policy_data["common"]["default_caps"]),
                set(POLICY.policy_data["common"]["privileged_caps"])))
            self.assertTrue(oci["Root"]["Path"].startswith("/run/kata-containers/"))
            self.assertRegex(annotations[a.SANDBOX_NAME_KEY], policy["OCI"]["Annotations"][a.SANDBOX_NAME_KEY])
        hot = next(s for s in positives if s.request["devices"])
        self.assertEqual(hot.request["devices"][0]["container_path"], "/dev/vfio/devices/vfio0")
        self.assertIn("cdi.k8s.io/vfio0", hot.request["OCI"]["Annotations"])
        self.assertEqual(len([s for s in positives if s.request["devices"]]), 1)

    def test_unexpected_allow_error_and_failing_flag(self):
        with self.assertRaisesRegex(t.Error, "behavioral checks failed"):
            a.admit(RAW, QWEN_ID, CONFIG, a.FakeEvaluator(lambda kind, request: True))
        table = expectations(self.scenarios)

        def erroring(kind, request):
            expected = table[(kind, json.dumps(request, sort_keys=True))]
            return RuntimeError("undefined rule") if kind == "GetMetricsRequest" else expected
        with self.assertRaisesRegex(t.Error, "metrics .*error=undefined rule"):
            a.admit(RAW, QWEN_ID, CONFIG, a.FakeEvaluator(erroring))
        truthful = a.FakeEvaluator(lambda kind, request: table[(kind, json.dumps(request, sort_keys=True))],
                                   allow_failures=True)
        with self.assertRaisesRegex(t.Error, "AllowRequestsFailingPolicy"):
            a.admit(RAW, QWEN_ID, CONFIG, truthful)

    def test_missing_evaluator_is_an_error(self):
        with patch.dict(os.environ, {"KATA_POLICY_EVAL": "/nonexistent/kata-policy-eval"}), \
                patch.object(a, "EVALUATOR_BINARY", Path("/nonexistent/other")), \
                patch.object(shutil, "which", return_value=None):
            with self.assertRaisesRegex(t.Error, "evaluator not found"):
                a.KataPolicyEvaluator()

    def test_deterministic_requests(self):
        again = a.genpolicy_scenarios(POLICY.policy_data, CONFIG, t.sha256(RAW))
        self.assertEqual(json.dumps(self.scenarios, sort_keys=True), json.dumps(again, sort_keys=True))
        other = a.genpolicy_scenarios(POLICY.policy_data, CONFIG, "other")
        self.assertNotEqual(json.dumps(self.scenarios, sort_keys=True), json.dumps(other, sort_keys=True))

    def test_cli_static_only(self):
        command = [sys.executable, str(t.ROOT / "trustbase.py"), "admit", "--all", "--static-only"]
        output = subprocess.check_output(command, text=True)
        self.assertIn("Admitted qwen38-27b-h100-pcie-1-96g", output)
        with self.assertRaises(subprocess.CalledProcessError):
            subprocess.check_output([sys.executable, str(t.ROOT / "trustbase.py"), "admit", "nope", "--static-only"],
                                    stderr=subprocess.STDOUT, text=True)


@unittest.skipUnless(evaluator_binary(), "kata-policy-eval is not built; run `make evaluator`")
class RealEvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.evaluator = a.KataPolicyEvaluator(evaluator_binary())

    def test_committed_qwen_is_admitted(self):
        report = a.admit(RAW, QWEN_ID, CONFIG, self.evaluator)
        self.assertTrue(report["evaluated"])
        for scenario in report["scenarios"]:
            self.assertTrue(all(step["error"] is None for step in scenario["steps"]), scenario["name"])
        self.assertGreater(sum(len(s["steps"]) for s in report["scenarios"]), 200)

    def test_examples_are_admitted(self):
        manifest = t.validate(t.ROOT / "examples")
        for profile in manifest["profiles"]:
            raw = (t.ROOT / "examples" / profile["initdata"]).read_bytes()
            a.admit(raw, profile["id"], EXAMPLES_CONFIG, self.evaluator)

    def test_behavioral_checks_catch_policy_data_flips(self):
        # Static checks would already refuse these; the replay must refuse them on its own too.
        flipped = tomllib.loads(with_policy_data(
            lambda pd: pd["request_defaults"].update(ReadStreamRequest=True)).decode())["data"]["policy.rego"]
        _, verdicts = self.evaluator.run(flipped, [("ReadStreamRequest", {"container_id": "x", "exec_id": "x", "len": 1})])
        self.assertTrue(verdicts[0].allowed)
        header, _ = self.evaluator.run(REGO.replace("default AllowRequestsFailingPolicy := false",
                                                    "default AllowRequestsFailingPolicy := true"), [])
        self.assertTrue(header["allow_requests_failing_policy"])
        with patch.object(a, "static_checks", return_value=[]):
            with self.assertRaisesRegex(t.Error, "read stdout"):
                a.admit(with_policy_data(lambda pd: pd["request_defaults"].update(ReadStreamRequest=True)),
                        QWEN_ID, CONFIG, self.evaluator)

    def test_engine_rejects_policies_without_a_package(self):
        with self.assertRaisesRegex(t.Error, "rejected the policy"):
            self.evaluator.run("", [])
        with self.assertRaisesRegex(t.Error, "rejected the policy"):
            self.evaluator.run("default X := false\n", [])


if __name__ == "__main__":
    unittest.main()
