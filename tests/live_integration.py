"""Read-only CPU/NVIDIA integration against published stable PodVM releases.

Without --podvm-version, it checks the newest release each registered workload in
measurements.yaml resolves to, so the test tracks the PodVMs Trustbase actually ships.
"""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trustbase as t


def registered_versions():
    manifest = t.validate(t.ROOT)
    t.require(manifest["profiles"], "measurements.yaml registers no workloads; pass --podvm-version")
    selections, _ = t.select_releases(manifest, t.GitHub().releases())
    return sorted({t.stable_version(tags[-1]) for tags in selections.values()})


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--podvm-version", help="exact stable PodVM version (default: registered workloads)")
    args = cli.parse_args()
    if args.podvm_version:
        version = t.stable_version(args.podvm_version)
        t.require(version is not None, "integration requires an exact stable PodVM version")
        versions = [version]
    else:
        versions = registered_versions()
    for version in versions:
        check(version)


def check(version):
    with tempfile.TemporaryDirectory(prefix="trustbase-live-") as temporary:
        base = Path(temporary)
        authoring = base / "authoring"
        shutil.copytree(t.ROOT / "examples", authoring)
        manifest = t.validate(authoring)
        for profile in manifest["profiles"]:
            profile["podvm"]["version"] = str(version)
        (authoring / "measurements.yaml").write_bytes(t.json_bytes(manifest))
        inputs, dist = base / "inputs", base / "dist"
        lock = t.resolve(authoring, inputs)
        assert len(lock["releases"]) == 1
        tag = next(iter(lock["releases"]))
        assert t.stable_version(tag) == version
        upstream = t.load_json((inputs / "podvm" / tag / "measurements.json").read_bytes())
        release = t.release_metadata("v0.0.0-integration", "prem-research/trustbase", "0" * 40)
        t.package(inputs, dist, release, None, require_workloads=True)
        result = t.verify_package(dist, require_workloads=True)
        assert {p.name for p in dist.iterdir()} == set(t.release_assets(release))
        assert t.policy_payloads(t.ROOT) == t.policy_payloads(inputs)
        assert len(result["workloads"]) == 2
        profiles = {p["id"]: p["podvm"]["profile"] for p in manifest["profiles"]}
        variants = set()
        count = 0
        for ident, workload in result["workloads"].items():
            selected = upstream["profiles"][profiles[ident]]
            variants.add(t.podvm_variant(selected))
            entry = workload["releases"][tag]
            assert set(entry["snp"]) == set(selected["sev"])
            for cpu, measurement in entry["snp"].items():
                assert measurement == selected["sev"][cpu]["measurement"]
            if "tdx" in selected:
                assert entry["tdx"] == {key: selected["tdx"]["measurement"][key]
                                        for key in entry["tdx"]}
            else:
                assert "tdx" not in entry
            path = authoring / next(p["initdata"] for p in manifest["profiles"] if p["id"] == ident)
            assert workload["initdata"]["host_data"] == t.initdata(path.read_bytes(), ident)["host_data"]
            count += len(entry["snp"]) + ("tdx" in entry)
        assert variants == {"cpu", "nvidia"}
        print(f"Live integration passed: PodVM {tag}, CPU + NVIDIA, "
              f"{count} reference measurements, verified attestations, reproducible package.")


if __name__ == "__main__":
    main()
