#!/usr/bin/env python3
"""Automated acceptance gate for Init-Data candidates.

The gate has two halves. Static checks read the genpolicy ``policy_data`` embedded in the
candidate's ``policy.rego`` and compare it with the committed ``admission.yaml``: pinned
images from allowed repositories, no exec or stream surface, privileged capabilities only
where declared, the expected model mounts, and the exact rules text that was reviewed.
Behavioral checks replay agent requests through ``tools/kata-policy-eval``, a thin wrapper
around the kata-agent's own policy crate at the PodVM's Kata revision, and require that the
pod's own containers are admitted while every mutation and every host-side probe is denied.

Everything workload-specific (containers, images, model, namespace, sandbox name pattern) is
taken from the candidate itself; Trustbase keeps no second description of the pod, only a
global floor in ``admission.yaml``. Nothing here proves that the real runtime emits exactly the synthesized requests; the SNP
acceptance run on hardware remains the authority for that. The report records every request
so it can be compared with the guest's policy log.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
from typing import NamedTuple
import uuid

import yaml

import trustbase as t

REGORUS_REVISION = "898643129e3652efd43e596f978d99f85e770235"
EVALUATOR_SOURCE = t.ROOT / "tools" / "kata-policy-eval"
EVALUATOR_BINARY = EVALUATOR_SOURCE / "target" / "release" / "kata-policy-eval"
SHARED_DIR = "/run/kata-containers/shared/containers"
NAME_KEY = "io.kubernetes.cri.container-name"
TYPE_KEY = "io.kubernetes.cri.container-type"
IMAGE_KEY = "io.kubernetes.cri.image-name"
SANDBOX_NAME_KEY = "io.kubernetes.cri.sandbox-name"
NAMESPACE_KEY = "io.kubernetes.cri.sandbox-namespace"
IMAGE_PATTERN = re.compile(
    r"^(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?@sha256:(?P<digest>[0-9a-f]{64})$")
DEFAULT_RULE = re.compile(r"default\s+([A-Za-z][A-Za-z0-9_]*)\s*:=\s*(true|false)\s*")
REGEX_METACHARACTERS = re.compile(r"[\[\]()*+?{}|\\]")


class Policy(NamedTuple):
    text: str
    rules: str
    rules_sha256: str
    policy_data: dict | None
    defaults: dict


class Step(NamedTuple):
    label: str
    kind: str
    request: dict
    expected: bool


class Verdict(NamedTuple):
    kind: str | None
    allowed: bool | None
    error: str | None
    prints: str
    input: str | None


class PodIdentity(NamedTuple):
    namespace: str
    sandbox_name: str
    names: list


def error(message):
    raise t.Error(message)


# --- configuration -----------------------------------------------------------------------

def load_config(root, path=None):
    root = Path(root)
    if path is None:
        raw = t.source_file(root, "admission.yaml").read_bytes()
    else:
        path = Path(path)
        t.require(path.is_file() and not path.is_symlink(), f"admission config missing: {path}")
        raw = path.read_bytes()
    config = yaml.load(raw, Loader=t.UniqueLoader)
    t.check_schema(config, "admission.schema.json")
    t.require(config["evaluator"]["kata_revision"] == t.KATA_REVISION,
              "admission.yaml evaluator.kata_revision differs from trustbase.KATA_REVISION")
    t.require(config["evaluator"]["regorus_revision"] == REGORUS_REVISION,
              "admission.yaml evaluator.regorus_revision differs from admission.REGORUS_REVISION")
    genpolicy = config["policy"] == "genpolicy"
    for key in ("rules", "policy_data", "floor"):
        t.require((key in config) == genpolicy,
                  f"admission.yaml {key} is {'required' if genpolicy else 'not allowed'} for {config['policy']} policies")
    if genpolicy:
        floor = config["floor"]
        for name, repository in floor["privileged_containers"].items():
            t.require(repository in floor["image_repositories"],
                      f"privileged container {name}: repository is not in image_repositories")
    return config


# --- policy text -------------------------------------------------------------------------

def split_policy(rego, require_policy_data=True):
    """Separate the reviewed rules from the generated policy_data object, failing closed."""
    t.require(isinstance(rego, str) and rego.strip(), "policy.rego is empty")
    statements = [line for line in rego.split("\n") if line.strip() and not line.lstrip().startswith("#")]
    t.require(statements and statements[0].strip() == "package agent_policy",
              "policy must start with 'package agent_policy'")
    t.require(len(re.findall(r"^\s*package\b", rego, re.M)) == 1, "policy must declare exactly one package")
    # Any statement that (re)defines policy_data: assignment, unification, partial rule, or body.
    matches = [m for m in re.finditer(r"^[ \t]*policy_data\b.*$", rego, re.M)
               if re.search(r":=|(?<![=!<>])=(?!=)|\bif\b|\bcontains\b", m.group())]
    policy_data = None
    rules = rego
    if require_policy_data:
        t.require(len(matches) == 1, "policy must define policy_data exactly once")
        match = matches[0]
        t.require(match.group().startswith("policy_data := {"), "policy_data must be one JSON object assignment")
        rules = rego[:match.start()]
        tail = rego[match.start() + len("policy_data := "):]
        try:
            policy_data, end = json.JSONDecoder(object_pairs_hook=t.unique_pairs).raw_decode(tail)
        except (json.JSONDecodeError, t.Error) as exc:
            error(f"policy_data is not a JSON object: {exc}")
        t.require(tail[end:].strip() == "", "unexpected Rego after policy_data")
    else:
        t.require(not matches, "this policy kind must not carry policy_data")
    code = "\n".join(line.split("#", 1)[0] for line in rules.split("\n"))
    t.require(not re.search(r"^[ \t]*(default[ \t]+)?AllowRequestsFailingPolicy\b(?![ \t]*:=[ \t]*false)", code, re.M),
              "policy defines AllowRequestsFailingPolicy other than 'default ... := false'")
    defaults = {}
    for line in rules.split("\n"):
        if not re.match(r"[ \t]*default\b", line):
            continue
        match = DEFAULT_RULE.fullmatch(line)
        t.require(match is not None and not line[0].isspace(), f"unsupported default rule: {line.strip()!r}")
        t.require(match.group(1) not in defaults, f"duplicate default rule: {match.group(1)}")
        defaults[match.group(1)] = match.group(2) == "true"
    return Policy(rego, rules, t.sha256(rules.encode()), policy_data, defaults)


def sample_pattern(pattern):
    """A concrete string matching a genpolicy-style anchored pattern (literals and classes)."""
    text = pattern[1:] if pattern.startswith("^") else pattern
    text = text[:-1] if text.endswith("$") else text
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
        elif char == "[":
            end = text.find("]", i + 1)
            t.require(end > i + 1 and text[i + 1] != "^", f"cannot synthesize a value for {pattern!r}")
            member = text[i + 2] if text[i + 1] == "\\" else text[i + 1]
            i = end + 1
            count = 1
            if i < len(text) and text[i] in "+*":
                count = 5
                i += 1
            elif i < len(text) and text[i] == "?":
                i += 1
            elif i < len(text) and text[i] == "{":
                close = text.find("}", i)
                t.require(close > 0, f"cannot synthesize a value for {pattern!r}")
                count = max(int(text[i + 1:close].split(",")[0] or "1"), 1)
                i = close + 1
            out.append(member * count)
        elif char in "()|.*+?{}":
            error(f"cannot synthesize a value for {pattern!r}")
        else:
            out.append(char)
            i += 1
    sample = "".join(out)
    t.require(re.fullmatch(pattern, sample) is not None, f"cannot synthesize a value for {pattern!r}")
    return sample


def pod_identity(pd):
    """Namespace, a concrete sandbox name, and container names, all read from the candidate."""
    containers = pd.get("containers", [])
    names = [container_name(c) for c in containers]
    t.require(all(names) and len(set(names)) == len(names), f"containers must have unique names: {names}")
    sandboxes = [c for c in containers if c["OCI"]["Annotations"].get(TYPE_KEY) == "sandbox"]
    t.require(len(sandboxes) == 1, "policy must describe exactly one sandbox container")
    namespaces = {c["OCI"]["Annotations"].get(NAMESPACE_KEY) for c in containers}
    t.require(len(namespaces) == 1 and None not in namespaces, f"containers disagree on the namespace: {namespaces}")
    patterns = {c["OCI"]["Annotations"].get(SANDBOX_NAME_KEY) for c in containers}
    t.require(len(patterns) == 1 and None not in patterns, f"containers disagree on the sandbox name: {patterns}")
    return PodIdentity(namespaces.pop(), sample_pattern(patterns.pop()), names)


# --- static checks -----------------------------------------------------------------------

def normalize_repository(repository):
    parts = repository.split("/")
    if len(parts) == 1:
        return "docker.io/library/" + repository
    if "." not in parts[0] and ":" not in parts[0] and parts[0] != "localhost":
        return "docker.io/" + repository
    return repository


def container_name(container):
    annotations = container["OCI"]["Annotations"]
    return "pause" if annotations.get(TYPE_KEY) == "sandbox" else annotations.get(NAME_KEY)


def static_checks(doc, policy, config):
    """Collect every static finding instead of stopping at the first one."""
    findings = []
    note = findings.append
    pd = policy.policy_data
    expected = config["policy_data"]
    floor = config["floor"]
    if policy.rules_sha256 not in config["rules"]["accepted_sha256"]:
        note(f"rules text sha256 {policy.rules_sha256} is not an accepted rules revision")
    if policy.defaults != config["defaults"]:
        diff = sorted(set(policy.defaults.items()) ^ set(config["defaults"].items()))
        note(f"default request rules differ from admission.yaml: {diff}")
    rd = pd.get("request_defaults", {})
    if rd.get("ExecProcessRequest") != {"allowed_commands": [], "regex": []}:
        note("request_defaults.ExecProcessRequest must allow no commands")
    if rd.get("CopyFileRequest") != expected["copy_file"]:
        note("request_defaults.CopyFileRequest differs from the accepted path patterns")
    for name in ("ReadStreamRequest", "WriteStreamRequest", "CloseStdinRequest",
                 "UpdateEphemeralMountsRequest", "GetDiagnosticDataRequest"):
        if rd.get(name) is not False:
            note(f"request_defaults.{name} must be false")
    if rd.get("CreateContainerRequest", {}).get("allow_env_regex") != expected["allow_env_regex"]:
        note("request_defaults.CreateContainerRequest.allow_env_regex differs from admission.yaml")
    common = pd.get("common", {})
    for key, value in expected["common"].items():
        if common.get(key) != value:
            note(f"common.{key} differs from admission.yaml")
    for key in ("default_caps", "privileged_caps"):
        if common.get(key) != expected[key]:
            note(f"common.{key} differs from admission.yaml")
    if pd.get("devices", {}).get("vfio", {}).get("device_path") != expected["vfio_device_path"]:
        note("devices.vfio.device_path differs from admission.yaml")
    cluster = pd.get("cluster_config", {})
    if cluster.get("pause_container_image") != floor["pause_image"]:
        note(f"cluster_config.pause_container_image is {cluster.get('pause_container_image')!r}")
    if cluster.get("guest_pull") is not True:
        note("cluster_config.guest_pull must be true")
    if pd.get("sandbox", {}).get("storages") != expected["sandbox_storages"]:
        note("sandbox.storages differ from the accepted sandbox storage records")
    try:
        identity = pod_identity(pd)
    except t.Error as exc:
        note(str(exc))
        identity = None
    if identity and identity.namespace not in floor["namespaces"]:
        note(f"namespace {identity.namespace!r} is not allowed")
    mounts_doc = doc["data"].get("model-mounts.json")
    model_paths = {entry["mount_path"] for entry in t.load_json(mounts_doc)} if mounts_doc else set()
    mounted_models = set()
    gpu_total = 0
    for container in pd.get("containers", []):
        name = container_name(container) or "<unnamed>"
        prefix = f"container {name}:"
        oci = container["OCI"]
        annotations = oci["Annotations"]
        is_sandbox = annotations.get(TYPE_KEY) == "sandbox"
        if container.get("exec_commands") != []:
            note(f"{prefix} exec_commands must be empty")
        if container.get("sandbox_pidns") is not False:
            note(f"{prefix} sandbox_pidns must be false")
        if oci["Root"].get("Readonly") is not True:
            note(f"{prefix} root filesystem must be read-only")
        repository = None
        if not is_sandbox:
            match = IMAGE_PATTERN.match(annotations.get(IMAGE_KEY, ""))
            if match is None:
                note(f"{prefix} image is not digest-pinned: {annotations.get(IMAGE_KEY)!r}")
            else:
                repository = normalize_repository(match.group("repository"))
                if repository not in floor["image_repositories"]:
                    note(f"{prefix} image repository {repository} is not allowed")
        caps = oci["Process"].get("Capabilities") or {}
        privileged = False
        for field in ("Ambient", "Bounding", "Effective", "Inheritable", "Permitted"):
            value = caps.get(field)
            if value not in ([], ["$(default_caps)"], ["$(privileged_caps)"]):
                note(f"{prefix} capability set {field} must be empty, default, or privileged: {value}")
            privileged = privileged or value == ["$(privileged_caps)"]
        if privileged and floor["privileged_containers"].get(name) != repository:
            note(f"{prefix} requests privileged capabilities but is not the declared "
                 f"privileged container for repository {repository}")
        if oci["Linux"].get("Devices") != []:
            note(f"{prefix} Linux.Devices must be empty")
        vfio = [d for d in container.get("devices", []) if d.get("container_path") == expected["vfio_device_path"]]
        gpu_total += len(vfio)
        if len(vfio) != len(container.get("devices", [])):
            note(f"{prefix} declares non-VFIO devices")
        binds = sorted(m["source"] for m in oci["Mounts"]
                       if m["type_"] == "bind" and m["source"].startswith("/dev/"))
        if binds and (not privileged or not set(binds) <= set(floor["device_binds"])):
            note(f"{prefix} /dev bind mounts {binds} are not allowed")
        for mount in oci["Mounts"]:
            if mount["source"].startswith("^" + expected["common"]["spath"] + "/"):
                if mount["destination"] not in model_paths:
                    note(f"{prefix} sandbox-storage mount {mount['destination']} is not in model-mounts.json")
                if mount["options"] != ["rbind", "rprivate", "ro"]:
                    note(f"{prefix} model mount {mount['destination']} must be a read-only private bind")
                mounted_models.add(mount["destination"])
        model_storages = [s for s in container.get("storages", []) if s["fstype"] == "bind"]
        if any(s["shared"] is not False or s["options"] != ["rbind", "rprivate", "ro"] for s in model_storages):
            note(f"{prefix} model storage records must be read-only and unshared")
    if mounted_models != model_paths:
        note(f"model-mounts.json paths {sorted(model_paths)} differ from the mounted model paths "
             f"{sorted(mounted_models)}")
    if gpu_total > floor["max_gpu_devices"]:
        note(f"pod declares {gpu_total} VFIO device(s); the floor allows {floor['max_gpu_devices']}")
    return findings


def static_checks_deny_all(policy, config):
    findings = []
    if policy.defaults != config["defaults"]:
        findings.append(f"default rules {policy.defaults} differ from the admitted {config['defaults']}")
    body = [line for line in policy.rules.split("\n")
            if line.strip() and not line.lstrip().startswith("#")
            and not line.startswith("package ") and not line.startswith("default ")]
    if body:
        findings.append("deny-all policies may contain only package and default rules")
    return findings


# --- request synthesis -------------------------------------------------------------------

class RuntimeIds(NamedTuple):
    sandbox_id: str
    sandbox_name: str
    namespace: str
    pod_uid: str
    netns: str
    share_suffix: str
    container_ids: dict


def runtime_ids(seed, identity):
    def hexdigest(label, length):
        return hashlib.sha256(f"{seed}:{label}".encode()).hexdigest()[:length]
    return RuntimeIds(
        sandbox_id=hexdigest("sandbox", 64),
        sandbox_name=identity.sandbox_name,
        namespace=identity.namespace,
        pod_uid=str(uuid.uuid5(uuid.NAMESPACE_URL, seed + ":pod")),
        netns=str(uuid.uuid5(uuid.NAMESPACE_URL, seed + ":netns")),
        share_suffix=hexdigest("share", 16),
        container_ids={name: hexdigest("container:" + name, 64) for name in identity.names},
    )


def b64url(value):
    return base64.urlsafe_b64encode(value.encode()).decode()


def substitute(value, ids):
    replacements = {
        "$(host-name)": ids.sandbox_name, "$(sandbox-name)": ids.sandbox_name,
        "$(sandbox-namespace)": ids.namespace, "$(pod-uid)": ids.pod_uid, "$(node-name)": "node-1",
        "$(pod-ip)": "10.244.3.17", "$(host-ip)": "10.0.0.17", "$(resource-field)": "1",
        "$(todo-annotation)": "1",
    }
    for key, replacement in replacements.items():
        value = value.replace(key, replacement)
    return value


def expand_caps(values, common):
    if values == ["$(default_caps)"]:
        return list(common["default_caps"])
    if values == ["$(privileged_caps)"]:
        return list(common["privileged_caps"])
    return list(values)


def container_request(pd, index, ids, config, vfio_mode="hot"):
    """A CreateContainerRequest the policy should admit for its container at ``index``."""
    container = pd["containers"][index]
    oci = container["OCI"]
    annotations = oci["Annotations"]
    common = pd["common"]
    spath = common["spath"]
    name = container_name(container)
    is_sandbox = annotations.get(TYPE_KEY) == "sandbox"
    cid = ids.sandbox_id if is_sandbox else ids.container_ids[name]
    vfio_path = config["policy_data"]["vfio_device_path"]

    synthesized = {}
    for key, value in annotations.items():
        if key == "io.kubernetes.cri.sandbox-id":
            synthesized[key] = ids.sandbox_id
        elif key == SANDBOX_NAME_KEY:
            synthesized[key] = ids.sandbox_name
        elif key == "io.kubernetes.cri.sandbox-log-directory":
            synthesized[key] = f"/var/log/pods/{ids.namespace}_{ids.sandbox_name}_{ids.pod_uid}"
        elif key == "nerdctl/network-namespace":
            synthesized[key] = f"/var/run/netns/cni-{ids.netns}"
        elif key == "io.katacontainers.pkg.oci.bundle_path":
            synthesized[key] = value.replace("$(bundle-id)", cid)
        else:
            t.require(not value.startswith("^"), f"{name}: cannot synthesize annotation {key}={value!r}")
            synthesized[key] = value
    if not is_sandbox:
        synthesized["io.kubernetes.container.terminationMessagePath"] = "/dev/termination-log"
        synthesized["io.kubernetes.container.terminationMessagePolicy"] = "File"

    devices = []
    for number, device in enumerate(d for d in container.get("devices", []) if d["container_path"] == vfio_path):
        synthesized[f"cdi.k8s.io/vfio{number}"] = "nvidia.com/pgpu=0"
        if vfio_mode == "hot":
            devices.append({"id": f"vfio{number}", "type_": device["type_"], "vm_path": device["vm_path"],
                            "container_path": f"{vfio_path}{number}",
                            "options": [f"0000:{number + 1:02x}:00.0=0{number + 3}/02"]})

    image = pd["cluster_config"]["pause_container_image"] if is_sandbox else annotations[IMAGE_KEY]
    storages = [{"driver": "image_guest_pull", "driver_options": [], "source": image, "fstype": "overlay",
                 "options": [], "mount_point": f"/run/kata-containers/{cid}/rootfs", "fs_group": None,
                 "shared": False}]
    ext4_points, bind_points = [], []
    device_number = 0
    for storage in container.get("storages", []):
        record = dict(storage)
        if storage["source"] == "" and storage["fstype"] in ("ext4", "bind"):
            device_number += 1
            source = f"{device_number:02x}"
            record.update(driver="blk", source=source, mount_point=f"{spath}/{b64url(source)}")
            (ext4_points if storage["fstype"] == "ext4" else bind_points).append(record["mount_point"])
        elif storage["mount_point"].startswith("^"):
            literal = storage["mount_point"][1:-1]
            t.require(not REGEX_METACHARACTERS.search(literal), f"{name}: cannot synthesize storage {storage}")
            record["mount_point"] = literal
        storages.append(record)

    mounts = []
    for mount in oci["Mounts"]:
        source = mount["source"]
        if source == "":
            t.require(ext4_points, f"{name}: mount {mount['destination']} has no backing block storage")
            source = ext4_points.pop(0)
        elif source.startswith("$(sfprefix)"):
            leaf = re.sub(r"\\(.)", r"\1", source[len("$(sfprefix)"):].rstrip("$"))
            source = f"{SHARED_DIR}/{cid}-{ids.share_suffix}-{leaf}"
        elif source.startswith("^"):
            literal = source[1:-1]
            if literal.startswith(spath + "/"):
                t.require(bind_points, f"{name}: mount {mount['destination']} has no backing bind storage")
                source = bind_points.pop(0)
            else:
                t.require(not REGEX_METACHARACTERS.search(literal), f"{name}: cannot synthesize mount {mount}")
                source = literal
        mounts.append({"destination": mount["destination"], "source": source,
                       "type_": mount["type_"], "options": list(mount["options"])})
    t.require(not ext4_points and not bind_points, f"{name}: unused block storages in policy")

    process = oci["Process"]
    caps = process["Capabilities"]
    spec = {
        "Version": oci["Version"],
        "Hostname": ids.sandbox_name if is_sandbox else "",
        "Process": {
            "Terminal": process["Terminal"],
            "User": dict(process["User"]),
            "Args": [arg.replace("$$", "$") for arg in process["Args"]],
            "Env": [substitute(var, ids) for var in process["Env"]],
            "Cwd": process["Cwd"],
            "Capabilities": {field: expand_caps(caps.get(field, []), common)
                             for field in ("Ambient", "Bounding", "Effective", "Inheritable", "Permitted")},
            "NoNewPrivileges": process["NoNewPrivileges"],
        },
        "Root": {"Path": f"/run/kata-containers/{cid}/rootfs", "Readonly": oci["Root"]["Readonly"]},
        "Mounts": mounts,
        "Annotations": synthesized,
        "Linux": {
            "Namespaces": copy.deepcopy(oci["Linux"]["Namespaces"]),
            "MaskedPaths": list(oci["Linux"].get("MaskedPaths", [])),
            "ReadonlyPaths": list(oci["Linux"].get("ReadonlyPaths", [])),
            "Devices": [],
            "Sysctl": dict(oci["Linux"].get("Sysctl", {})),
            "Resources": {},
        },
    }
    return {"container_id": cid, "exec_id": cid, "devices": devices, "storages": storages,
            "OCI": spec, "sandbox_pidns": container["sandbox_pidns"]}


def exec_request(cid, args, cwd, terminal=False):
    return {"container_id": cid, "exec_id": "exec-" + cid[:12],
            "process": {"Terminal": terminal, "User": {"UID": 0, "GID": 0, "AdditionalGids": [0], "Username": ""},
                        "Args": args, "Env": [], "Cwd": cwd, "NoNewPrivileges": False}}


def copy_request(path, kind="regular", target=""):
    modes = {"regular": 0o100644, "directory": 0o040755, "symlink": 0o120777}
    request = {"path": path, "file_size": 0, "file_mode": modes[kind], "dir_mode": 0o755, "uid": 0, "gid": 0}
    if kind == "symlink":
        request["data"] = list(target.encode())
    return request


def probes(cid, cwd, ids, with_copy=True):
    """Host-side requests every admitted policy must refuse."""
    deny = [
        Step("exec shell", "ExecProcessRequest", exec_request(cid, ["/bin/sh"], cwd), False),
        Step("exec tty", "ExecProcessRequest", exec_request(cid, ["/bin/sh"], cwd, terminal=True), False),
        Step("read stdout", "ReadStreamRequest", {"container_id": cid, "exec_id": cid, "len": 4096}, False),
        Step("write stdin", "WriteStreamRequest", {"container_id": cid, "exec_id": cid, "data": [104, 105]}, False),
        Step("close stdin", "CloseStdinRequest", {"container_id": cid, "exec_id": cid}, False),
        Step("replace policy", "SetPolicyRequest",
             {"policy": "package agent_policy\ndefault CreateContainerRequest := true\n"}, False),
        Step("metrics", "GetMetricsRequest", {}, False),
        Step("diagnostics", "GetDiagnosticDataRequest", {}, False),
        Step("set guest time", "SetGuestDateTimeRequest", {"Sec": 0, "Usec": 0}, False),
        Step("ephemeral mounts", "UpdateEphemeralMountsRequest", {"storages": []}, False),
        Step("pause container", "PauseContainerRequest", {"container_id": cid}, False),
        Step("update container", "UpdateContainerRequest", {"container_id": cid}, False),
        Step("reseed random", "ReseedRandomDevRequest", {"data": [1, 2, 3]}, False),
        Step("add swap", "AddSwapRequest", {"PCIPath": [1]}, False),
        Step("iptables", "SetIPTablesRequest", {"is_ipv6": False, "data": []}, False),
    ]
    if with_copy:
        shared = f"{SHARED_DIR}/{ids.sandbox_id}-{ids.share_suffix}-"
        deny += [
            Step("copy outside shared dir", "CopyFileRequest", copy_request("/etc/ssl/cert.pem"), False),
            Step("copy into rootfs", "CopyFileRequest", copy_request(f"/run/kata-containers/{cid}/rootfs/bin/sh"), False),
            Step("copy traversal", "CopyFileRequest", copy_request(shared + "x/../../../../etc/passwd"), False),
            Step("copy absolute symlink", "CopyFileRequest",
                 copy_request(shared + "dir/link", "symlink", "/etc/passwd"), False),
        ]
    return deny


def mutations(request, policy_container, pd, config):
    """Single-change variants of an admitted container request with the verdict each must get."""
    common = pd["common"]
    vfio_path = config["policy_data"]["vfio_device_path"]
    annotations = request["OCI"]["Annotations"]
    is_sandbox = annotations.get(TYPE_KEY) == "sandbox"
    privileged = request["OCI"]["Process"]["Capabilities"]["Bounding"] == list(common["privileged_caps"])
    has_gpu = any(d["container_path"] == vfio_path for d in policy_container.get("devices", []))
    result = []

    def variant(label, edit, expected=False):
        changed = copy.deepcopy(request)
        edit(changed)
        result.append(Step(label, "CreateContainerRequest", changed, expected))

    def set_image(r):
        image = "docker.io/library/busybox@sha256:" + "0" * 64
        r["OCI"]["Annotations"][IMAGE_KEY] = image
        for storage in r["storages"]:
            if storage["driver"] == "image_guest_pull":
                storage["source"] = image

    def vfio_device(number):
        return {"id": f"vfio{number}", "type_": "vfio-pci-gk", "vm_path": "",
                "container_path": f"{vfio_path}{number}", "options": [f"0000:0{number + 1}:00.0=03/02"]}

    if not is_sandbox:
        # The sandbox image is not policy-enforced: any io.kubernetes.cri.* annotation is accepted
        # and image_pull_source_allowed ignores the sandbox source (see README).
        variant("unlisted image", set_image)
    variant("extra mount", lambda r: r["OCI"]["Mounts"].append(
        {"destination": "/host", "source": f"{SHARED_DIR}/{r['container_id']}-0123456789abcdef-host",
         "type_": "bind", "options": ["rbind", "rprivate", "rw"]}))
    if not privileged:
        variant("extra capability", lambda r: [r["OCI"]["Process"]["Capabilities"][f].append("CAP_SYS_ADMIN")
                                               for f in ("Bounding", "Effective", "Permitted")])
    variant("extra env", lambda r: r["OCI"]["Process"]["Env"].append("TRUSTBASE_PROBE=1"))
    if privileged:
        variant("ambient privileged caps", lambda r: r["OCI"]["Process"]["Capabilities"].update(
            Ambient=list(common["privileged_caps"])))
    else:
        variant("privileged caps", lambda r: r["OCI"]["Process"].update(Capabilities={
            f: list(common["privileged_caps"]) for f in ("Bounding", "Effective", "Permitted")} | {
            "Ambient": [], "Inheritable": []}))
    variant("writable root", lambda r: r["OCI"]["Root"].update(Readonly=False))
    variant("other uid", lambda r: r["OCI"]["Process"]["User"].update(UID=1000))
    variant("changed args", lambda r: r["OCI"]["Process"].update(Args=["/bin/sh", "-c", "id"]))
    variant("other namespace", lambda r: r["OCI"]["Annotations"].update({NAMESPACE_KEY: "default"}))
    variant("other sandbox name", lambda r: r["OCI"]["Annotations"].update({SANDBOX_NAME_KEY: "evil-pod"}))
    if not is_sandbox:
        variant("other container name", lambda r: r["OCI"]["Annotations"].update({NAME_KEY: "debug"}))
    variant("shared pid namespace", lambda r: r.update(sandbox_pidns=True))
    variant("extra linux device", lambda r: r["OCI"]["Linux"]["Devices"].append(
        {"Path": "/dev/kvm", "Type": "c", "Major": 10, "Minor": 232}))
    variant("hook", lambda r: r["OCI"].update(Hooks={"Prestart": [{"Path": "/bin/true"}]}))
    variant("extra storage", lambda r: r["storages"].append(
        {"driver": "blk", "driver_options": [], "source": "7f", "fstype": "ext4", "options": [],
         "mount_point": f"{common['spath']}/{b64url('7f')}", "fs_group": None, "shared": True}))
    variant("extra shared mount", lambda r: r.update(shared_mounts=[{"name": "x", "src_ctr": "a", "src_path": "/",
                                                                    "dst_ctr": "b", "dst_path": "/"}]))
    if has_gpu:
        variant("second gpu", lambda r: (r["devices"].append(vfio_device(9)),
                                         r["OCI"]["Annotations"].update({"cdi.k8s.io/vfio9": "nvidia.com/pgpu=0"})))
        variant("gpu without cdi annotation", lambda r: [r["OCI"]["Annotations"].pop(k)
                                                          for k in list(r["OCI"]["Annotations"])
                                                          if k.startswith("cdi.k8s.io/vfio")])
        variant("gpu with other device type", lambda r: (r["devices"].clear(),
                                                         r["devices"].append(dict(vfio_device(0), type_="vfio-pci"))))
    else:
        # The fleet rules let the sandbox and containers advertising VISIBLE_CDI_DEVICES receive a GPU
        # without a policy device entry; everything else must be refused.
        manual = is_sandbox or any(re.match(r"^VISIBLE_CDI_DEVICES=(.*:)?nvidia\.com/gpu=", var)
                                   for var in request["OCI"]["Process"]["Env"])
        variant("gpu via manual rule" if manual else "unexpected gpu",
                lambda r: r["devices"].append(vfio_device(0)), expected=manual)
        if manual and not is_sandbox:
            variant("gpu without VISIBLE_CDI_DEVICES", lambda r: (
                r["devices"].append(vfio_device(0)),
                r["OCI"]["Process"].update(Env=[v for v in r["OCI"]["Process"]["Env"]
                                                if not v.startswith("VISIBLE_CDI_DEVICES=")])))
        variant("more gpus than the pod declares", lambda r: r["devices"].extend([vfio_device(0), vfio_device(1)]))
    return result


def genpolicy_scenarios(pd, config, seed):
    identity = pod_identity(pd)
    ids = runtime_ids(seed, identity)
    names = identity.names
    by_name = {name: index for index, name in enumerate(names)}
    sandbox_index = next(i for i, c in enumerate(pd["containers"]) if c["OCI"]["Annotations"].get(TYPE_KEY) == "sandbox")
    gpu_index = next((i for i, c in enumerate(pd["containers"]) if c.get("devices")), None)
    scenarios = []
    for vfio_mode in ("hot", "cold"):
        requests = {name: container_request(pd, index, ids, config, vfio_mode) for name, index in by_name.items()}
        steps = [
            Step("failing policy flag", "AllowRequestsFailingPolicy", {}, False),
            Step("create sandbox", "CreateSandboxRequest", {
                "hostname": ids.sandbox_name, "dns": [], "storages": copy.deepcopy(pd["sandbox"]["storages"]),
                "sandbox_pidns": False, "sandbox_id": ids.sandbox_id, "guest_hook_path": "", "kernel_modules": []},
                 True),
            Step("sandbox with hooks", "CreateSandboxRequest", {
                "hostname": ids.sandbox_name, "storages": [], "sandbox_pidns": False, "sandbox_id": ids.sandbox_id,
                "guest_hook_path": "/usr/share/oci/hooks"}, False),
            Step("sandbox with shared pidns", "CreateSandboxRequest", {
                "hostname": ids.sandbox_name, "storages": [], "sandbox_pidns": True, "sandbox_id": ids.sandbox_id},
                 False),
        ]
        order = [names[sandbox_index]] + [n for n in names if n != names[sandbox_index]]
        for name in order:
            steps.append(Step(f"create {name}", "CreateContainerRequest", requests[name], True))
        for name in order:
            steps.append(Step(f"start {name}", "StartContainerRequest",
                              {"container_id": requests[name]["container_id"]}, True))
        for name in order:
            request = requests[name]
            cwd = request["OCI"]["Process"]["Cwd"]
            steps += probes(request["container_id"], cwd, ids, with_copy=(name == order[0]))
            steps.append(Step(f"exec entrypoint in {name}", "ExecProcessRequest",
                              exec_request(request["container_id"], request["OCI"]["Process"]["Args"], cwd), False))
        shared = f"{SHARED_DIR}/{ids.sandbox_id}-{ids.share_suffix}-"
        steps += [
            Step("copy resolv.conf", "CopyFileRequest", copy_request(shared + "resolv.conf"), True),
            Step("copy directory", "CopyFileRequest", copy_request(shared + "serviceaccount", "directory"), True),
            Step("copy relative symlink", "CopyFileRequest",
                 copy_request(shared + "serviceaccount/token", "symlink", "..data/token"), True),
        ]
        for name in order:
            steps += [Step(f"{name}: {step.label}", step.kind, step.request, step.expected)
                      for step in mutations(requests[name], pd["containers"][by_name[name]], pd, config)]
        probe_name = names[gpu_index] if gpu_index is not None else order[-1]
        steps += [
            Step(f"remove {probe_name}", "RemoveContainerRequest",
                 {"container_id": requests[probe_name]["container_id"]}, True),
            Step("exec after removal", "ExecProcessRequest",
                 exec_request(requests[probe_name]["container_id"], ["/bin/sh"], "/"), False),
        ]
        scenarios.append((f"pod-lifecycle-{vfio_mode}-plug", steps))
    fresh = [Step("failing policy flag", "AllowRequestsFailingPolicy", {}, False)]
    fresh += probes("c" * 64, "/", ids)
    fresh.append(Step("container before sandbox state", "CreateContainerRequest",
                      dict(container_request(pd, sandbox_index, ids, config), container_id="d" * 64), True))
    scenarios.append(("fresh-state", fresh))
    scenarios.append(("empty-state-denials", [
        Step("mutation without state", "CreateContainerRequest", {"container_id": "e" * 64}, False),
        Step("exec without state", "ExecProcessRequest", exec_request("e" * 64, ["/bin/sh"], "/"), False),
    ]))
    return scenarios


def deny_all_scenarios(config):
    steps = []
    for name, value in sorted(config["defaults"].items()):
        request = {"container_id": "a" * 64}
        if name == "ExecProcessRequest":
            request = exec_request("a" * 64, ["/bin/sh"], "/")
        steps.append(Step(f"{name} default", name, request, value))
    return [("deny-all", steps)]


# --- evaluator ---------------------------------------------------------------------------

class KataPolicyEvaluator:
    """Drive tools/kata-policy-eval: one process per scenario, one agent lifetime of state."""

    def __init__(self, binary=None):
        candidates = [binary, os.environ.get("KATA_POLICY_EVAL"), shutil.which("kata-policy-eval"), EVALUATOR_BINARY]
        found = next((Path(c) for c in candidates if c and Path(c).is_file()), None)
        t.require(found is not None,
                  "admission evaluator not found; run `make evaluator` or set KATA_POLICY_EVAL")
        self.binary = found

    def run(self, policy_text, cases):
        payload = "".join(json.dumps({"kind": kind, "request": request}) + "\n" for kind, request in cases)
        with tempfile.TemporaryDirectory(prefix="trustbase-admit-") as temporary:
            policy_file = Path(temporary) / "policy.rego"
            policy_file.write_text(policy_text)
            try:
                completed = subprocess.run([str(self.binary), str(policy_file)], input=payload,
                                           capture_output=True, text=True, timeout=600)
            except (OSError, subprocess.TimeoutExpired) as exc:
                error(f"cannot run the admission evaluator: {exc}")
        lines = [t.load_json(line) for line in completed.stdout.splitlines() if line.strip()]
        t.require(lines and "self" in lines[0], f"evaluator produced no verdicts: {completed.stderr.strip()}")
        header = lines[0]["self"]
        t.require(header.get("loaded") is True,
                  f"the agent policy engine rejected the policy: {header.get('error')}")
        t.require(completed.returncode == 0, f"evaluator failed: {completed.stderr.strip()}")
        verdicts = [Verdict(v.get("kind"), v.get("allowed"), v.get("error"), v.get("prints", ""), v.get("input"))
                    for v in lines[1:]]
        t.require(len(verdicts) == len(cases), "evaluator answered a different number of cases")
        return header, verdicts


class FakeEvaluator:
    """Offline stand-in: answers from a callable and records what it was asked."""

    def __init__(self, decide, allow_failures=False):
        self.decide = decide
        self.allow_failures = allow_failures
        self.calls = []

    def run(self, _policy_text, cases):
        self.calls.append(list(cases))
        header = {"loaded": True, "allow_requests_failing_policy": self.allow_failures}
        verdicts = []
        for kind, request in cases:
            answer = self.decide(kind, request)
            if isinstance(answer, Exception):
                verdicts.append(Verdict(kind, None, str(answer), "", None))
            else:
                verdicts.append(Verdict(kind, answer, None, "", json.dumps(request)))
        return header, verdicts


# --- gate --------------------------------------------------------------------------------

def admit(raw, workload_id, config, evaluator=None, static_only=False):
    """Run the gate on exact TOML bytes; raise trustbase.Error on any finding."""
    values = t.initdata(raw, workload_id)
    doc = tomllib.loads(raw.decode("utf-8"))
    rego = doc["data"].get("policy.rego", "")
    report = {"workload": workload_id, "initdata_sha256": values["sha256"], "policy": config["policy"],
              "evaluated": False, "scenarios": []}
    if config["policy"] == "deny-all":
        policy = split_policy(rego, require_policy_data=False)
        findings = static_checks_deny_all(policy, config)
        scenarios = deny_all_scenarios(config)
    else:
        policy = split_policy(rego)
        findings = static_checks(doc, policy, config)
        scenarios = genpolicy_scenarios(policy.policy_data, config, values["sha256"]) if not findings else []
    report["rules_sha256"] = policy.rules_sha256
    t.require(not findings, f"{workload_id}: admission static checks failed:\n  - " + "\n  - ".join(findings))
    if static_only:
        return report
    evaluator = evaluator or KataPolicyEvaluator()
    failures = []
    for name, steps in scenarios:
        header, verdicts = evaluator.run(policy.text, [(step.kind, step.request) for step in steps])
        t.require(header.get("allow_requests_failing_policy") is False,
                  f"{workload_id}: policy enables AllowRequestsFailingPolicy")
        recorded = []
        for step, verdict in zip(steps, verdicts):
            passed = verdict.error is None and verdict.allowed is step.expected
            if not passed:
                failures.append(f"{name}: {step.label} ({step.kind}) expected {step.expected}, "
                                f"got {verdict.allowed}; error={verdict.error}; prints={verdict.prints[-1500:]}")
            recorded.append({"label": step.label, "kind": step.kind, "expected": step.expected,
                             "allowed": verdict.allowed, "error": verdict.error, "request": step.request})
        report["scenarios"].append({"name": name, "steps": recorded})
    report["evaluated"] = True
    t.require(not failures, f"{workload_id}: admission behavioral checks failed:\n  - " + "\n  - ".join(failures))
    return report


def cli(args):
    root = Path(args.root)
    config = load_config(root, args.config)
    manifest = t.validate(root)
    selected = [p for p in manifest["profiles"] if args.all or p["id"] in args.ids]
    t.require(args.all or len(selected) == len(set(args.ids)),
              f"unknown workload(s): {sorted(set(args.ids) - {p['id'] for p in selected})}")
    t.require(selected, "no workloads selected")
    evaluator = None if args.static_only else KataPolicyEvaluator(args.evaluator)
    reports = []
    for profile in selected:
        raw = t.source_file(root, profile["initdata"]).read_bytes()
        reports.append(admit(raw, profile["id"], config, evaluator, args.static_only))
        print(f"Admitted {profile['id']} ({profile['initdata']})"
              + (" [static checks only]" if args.static_only else ""))
    if args.report:
        t.require(not Path(args.report).exists(), f"output already exists: {args.report}")
        Path(args.report).write_bytes(t.json_bytes(reports))
    return reports
