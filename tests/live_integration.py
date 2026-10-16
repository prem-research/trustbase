"""Read-only integration against the published PodVM v0.1.6 release."""
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trustbase as t


def main():
    with tempfile.TemporaryDirectory(prefix="trustbase-live-") as temporary:
        base = Path(temporary)
        authoring = base / "authoring"
        shutil.copytree(t.ROOT / "examples", authoring)
        manifest = t.validate(authoring)
        for profile in manifest["profiles"]:
            profile["podvm"]["version"] = "0.1.6"
        (authoring / "measurements.yaml").write_bytes(t.json_bytes(manifest))
        inputs, dist = base / "inputs", base / "dist"
        lock = t.resolve(authoring, inputs)
        assert set(lock["releases"]) == {"v0.1.6"}
        release = t.release_metadata("v0.0.0-integration", "prem-research/trustbase", "0" * 40)
        t.package(inputs, dist, release, require_workloads=True)
        result = t.verify_package(dist, require_workloads=True)
        assert len(result["workloads"]) == 2
        assert all(len(w["references"]) == 5 for w in result["workloads"].values())
        print("Live integration passed: two workloads, one attested PodVM release, "
              "ten complete reference records, reproducible package.")


if __name__ == "__main__":
    main()
