"""Compare Python measurements with unmodified digest/resize code from pinned Kata."""
import base64
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import trustbase as t

SOURCES = {
    "src/runtime/pkg/govmm/qemu/qemu.go": "d32503985c0cb4e1e8cab49e02a5767f2ddcf94eba7a72fee5dc6dda13a3cdac",
    "src/runtime/pkg/oci/utils.go": "fed19ad47071d3839a229a6305fed59990b5b5f42e79ec03647b9787a917580f",
}


def upstream():
    result = {}
    for path, digest in SOURCES.items():
        url = f"https://raw.githubusercontent.com/kata-containers/kata-containers/{t.KATA_REVISION}/{path}"
        raw = t.GitHub().get(url)
        t.require(t.sha256(raw) == digest, f"Kata source checksum mismatch: {path}")
        result[path] = raw.decode()
    return result


def main():
    sources = upstream()
    qemu = sources["src/runtime/pkg/govmm/qemu/qemu.go"]
    oci = sources["src/runtime/pkg/oci/utils.go"]
    resize = re.search(r"func adjustProperLength\(.*?\n}", qemu, re.S).group()
    digest = re.search(r"\t\tvar initdataDigest \[\]byte.*?initdataDigest = h.Sum\(nil\)", oci, re.S).group()
    assert "hostdataSlice := adjustProperLength(object.InitdataDigest, 32)" in qemu
    assert "mrconfigidSlice := adjustProperLength(object.InitdataDigest, 48)" in qemu
    assert "base64.StdEncoding.EncodeToString(hostdataSlice)" in qemu
    assert "base64.StdEncoding.EncodeToString(mrconfigidSlice)" in qemu
    harness = r'''
package main
import ("crypto/sha256"; "crypto/sha512"; "encoding/base64"; "encoding/json"; "hash"; "os")
type Input struct { Algorithm string; Raw []byte }
func main() {
    var inputs []Input
    if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil { panic(err) }
    outputs := make([]map[string]string, 0, len(inputs))
    for _, input := range inputs {
        initdata := input
        initdataToml := input.Raw
        DIGEST
        outputs = append(outputs, map[string]string{
            "digest": base64.StdEncoding.EncodeToString(initdataDigest),
            "host_data": base64.StdEncoding.EncodeToString(adjustProperLength(initdataDigest, 32)),
            "mr_config_id": base64.StdEncoding.EncodeToString(adjustProperLength(initdataDigest, 48)),
        })
    }
    if err := json.NewEncoder(os.Stdout).Encode(outputs); err != nil { panic(err) }
}
RESIZE
'''.replace("DIGEST", digest).replace("RESIZE", resize)
    vectors = []
    for algorithm in ("sha256", "sha384", "sha512"):
        raw = (f'version = "0.1.0"\nalgorithm = "{algorithm}"\n\n'
               '[data]\nid = "oracle"\nmessage = "caffè ☕"\n').encode()
        for data in (raw, raw + b"# comment\n", raw.replace(b"\n", b"\r\n"), raw.rstrip(b"\n")):
            vectors.append({"Algorithm": algorithm, "Raw": base64.b64encode(data).decode()})
    with tempfile.TemporaryDirectory(prefix="trustbase-kata-") as temporary:
        source = Path(temporary) / "oracle.go"
        source.write_text(harness)
        completed = subprocess.run(["go", "run", str(source)], input=json.dumps(vectors),
                                   text=True, capture_output=True, check=True, timeout=120)
    expected = json.loads(completed.stdout)
    for vector, reference in zip(vectors, expected, strict=True):
        actual = t.initdata(base64.b64decode(vector["Raw"]), "oracle")
        for field in ("digest", "host_data", "mr_config_id"):
            assert bytes.fromhex(actual[field]) == base64.b64decode(reference[field]), (vector, field)
    print(f"Kata {t.KATA_REVISION}: {len(vectors)} exact-byte Go/Python vectors passed.")


if __name__ == "__main__":
    main()
