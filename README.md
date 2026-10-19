# Trustbase

Trustbase publishes reference measurements for confidential workloads.
Each workload combines an exact Init-Data TOML with a named
[prem-research/podvm](https://github.com/prem-research/podvm) launch profile and a
semver constraint. A release freezes every matching published stable PodVM
version and includes the TEE records published for that profile: Intel TDX and
AMD SEV-SNP for CPU guests, and SEV-SNP for NVIDIA guests.

The production catalog registers `model-router` on CPU profile `2vcpu-8g` and
`qwen38-27b-h100-pcie-1-96g` on NVIDIA profile `h100-pcie-1-96g`.
The two definitions under `examples/` demonstrate CPU and NVIDIA selection with
policies that deny container creation. They are tested separately and are never
included in production releases. Trustbase validates and measures the committed
policy bytes; policy review remains part of authoring a workload.

## Define a workload

Create `init-data/<workload-id>/init-data.toml`, then register it in
`measurements.yaml`:

~~~yaml
schema_version: 1
profiles:
  - id: model-router
    initdata: init-data/model-router/init-data.toml
    podvm:
      profile: 2vcpu-8g
      version: ">=0.3.13 <0.4.0"
~~~

The complete TOML uses Kata's existing format, with the identifier in the
measured string-to-string payload map:

~~~toml
version = "0.1.0"
algorithm = "sha384"

[data]
id = "model-router"
"policy.rego" = '''
package agent_policy
# Insert the complete reviewed workload policy here.
'''
~~~

IDs must be unique, match `[data].id` exactly, and use lowercase letters, digits,
dots, underscores, or hyphens (maximum 64 characters). Every TOML beneath
`init-data/` must be registered. Files must be named `init-data.toml`; symlinks and
paths outside that directory are rejected.

Commit complete policies and other payloads, such as `aa.toml`, `cdh.toml`, or
`model-mounts.json`, directly into `[data]` as strings. Trustbase measures these
definitions; it does not run genpolicy or resolve model content.

### Rebuild a model pack referenced by Init-Data

For a workload with `model-mounts.json` in its Init-Data, use its `modelid` as
`M` and the same digest-pinned packer image as the published pack for `IMG`.
[Modelwrap v0.2.1](https://github.com/tinfoilsh/modelwrap/blob/v0.2.1/README.md)
can rebuild the pack either by downloading the pinned Hugging Face revision or
from a local directory containing that exact revision's files:

~~~sh
M='organization/model@full-commit'   # the published modelid
modelwrap --image "$IMG" --verify --output out "$M"
# Or, with local model files:
modelwrap --image "$IMG" --verify --model-dir "$MODEL_DIR" --output out "$M"
~~~

Either route produces an `.mpk` and an `.info` containing the root hash, hash
offset, and UUID recorded in the measured `model-mounts.json`.
Use a fresh output directory for each run.
The exact packer image and model files matter; the UUID alone is derived from
`M` and does not establish the model bytes. Trustbase derives `host_data` from
the committed Init-Data TOML bytes as described below; rebuilding the pack
does not regenerate that TOML or its policy.

`podvm.version` uses npm-style semver, through pinned `semantic-version`
`NpmSpec`:

| Constraint | Meaning |
|---|---|
| `0.3.13` | Exactly 0.3.13 |
| `>=0.3.13 <0.4.0` | All stable versions in this interval |
| `^0.3.13` | Compatible versions below 0.4.0 |
| `~1.2.3` | Versions from 1.2.3 up to, excluding, 1.3.0 |

PodVM tags may have a leading `v`. Drafts, GitHub prereleases, semver prereleases,
and tags without a published release are excluded. Two tags representing the same
version are rejected. Missing profiles, unsupported formats, missing assets, or
invalid provenance on **any** matching release fail the entire resolution.
Narrow the constraint to the versions approved for this workload.

PodVM publishes one unified `measurements.json` and `SHA256SUMS` for its CPU
and NVIDIA bundles. Trustbase supports this unified format and retains support
for older single-bundle CPU catalogs. Separate `measurements-nvidia.json` files
are not consumed. The committed definitions use v0.3.13 as their baseline; the
Qwen workload pins that exact version and `model-router` allows newer 0.3.x releases.

The selected profile determines the bundle; no separate variant field is needed
in `measurements.yaml`. CPU profiles have `tdx` and `sev` records. GPU profiles
have a `gpu` block and `sev` records and select the NVIDIA bundle. For example:

~~~yaml
  - id: example-model
    initdata: init-data/example-model/init-data.toml
    podvm:
      profile: h100-pcie-1-96g
      version: "^0.3.13"
~~~

The published GPU profiles are `h100-pcie-1-96g`, `h200-pcie-1-96g`,
`h100-hgx-8-768g`, `h100-pcie-nvlink-8-768g`, `h200-hgx-8-768g`,
`b200-hgx-8-768g`, and `b300-hgx-8-768g`. GPU profiles publish SNP references
only. Trustbase preserves the declared GPU family, platform, GPU count, and
NVSwitch count; these labels do not constitute GPU hardware attestation. GPU TDX
candidates are not accepted as published references.

New PodVM releases never change an existing Trustbase release. Publish another
Trustbase tag to resolve again. Removing a workload or narrowing its range takes
effect in the next release; relying parties choose which release they trust.

## Exact measurement contract

Trustbase hashes the **original UTF-8 file bytes**, including metadata, comments,
whitespace, and final newline. It validates TOML without serializing it again.
The algorithm is the file's `sha256`, `sha384`, or `sha512`; examples use SHA-384.

For the raw digest `D`:

| Evidence field | Value |
|---|---|
| SNP `HOST_DATA` (`host_data`) | First 32 bytes of `D`, right-padded with zero bytes if needed |
| TDX `MRCONFIGID` (`mr_config_id`) | First 48 bytes of `D`, right-padded with zero bytes if needed |

For SHA-384, SNP receives the first 32 bytes and TDX receives the full digest.
Do not hash again between platforms. Catalog values use lowercase hexadecimal.
QEMU's `host-data` and `mrconfigid` arguments use standard base64 of those same
raw register bytes.

The compatibility baseline is Kata 4.0.0 commit
`cf82bb35c80320178bf7570252fe75d6fb263209`, used by both variants of PodVM v0.3.13.
The revision is checked independently in every variant's provenance.
A different declared Kata revision is rejected until its semantics have been
reviewed and the compatibility pin/conformance tests updated. See Kata's
[Go digest calculation](https://github.com/kata-containers/kata-containers/blob/cf82bb35c80320178bf7570252fe75d6fb263209/src/runtime/pkg/oci/utils.go)
and [QEMU field conversion](https://github.com/kata-containers/kata-containers/blob/cf82bb35c80320178bf7570252fe75d6fb263209/src/runtime/pkg/govmm/qemu/qemu.go).
The conformance test downloads checksum-pinned sources and executes their
unmodified hash and resize code in a temporary Go harness.

Transport the identical TOML bytes to Kata:

~~~sh
python trustbase.py annotation model-router > initdata.b64
base64 --decode initdata.b64 | gzip -dc |
  cmp - init-data/model-router/init-data.toml
~~~

The annotation command emits single-line standard-base64 of deterministic gzip.
Use it as `io.katacontainers.config.hypervisor.cc_init_data`; the runtime must
allow that annotation. Do not put the release input archive into the annotation.
Git attributes disable line-ending conversion for workload TOMLs.

## Local commands

Use Python 3.12+, GitHub CLI 2.102.0, and Go for the conformance test.
CI installs the exact CLI archive with a pinned SHA-256.

~~~sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
make validate test
make conformance
make integration
~~~

`make test` is offline and mocks only the network/signature-verifier boundary.
`make integration` resolves the real PodVM v0.3.13 release, verifies the unified
measurement/checksum attestations and both bundle digests, and round-trips a
temporary release with CPU and NVIDIA workloads. To test a newer published
stable release, override `PODVM_VERSION` when running `make integration`. Public API reads work
without authentication; CI supplies `GH_TOKEN` to avoid anonymous rate limits.

Build an example candidate:

~~~sh
python trustbase.py --root examples resolve --output build/example-inputs
python trustbase.py package \
  --inputs build/example-inputs --output build/example-release \
  --release-version preview \
  --source-revision "$(git rev-parse HEAD)"
python trustbase.py verify --dist build/example-release
~~~

Choose fresh output directories for subsequent runs. Existing snapshots and
release directories are never overwritten. The default authoring root is this
repository; `--root examples` explicitly selects examples.

| Command | Purpose |
|---|---|
| `validate` | Offline manifest and TOML validation |
| `resolve` | Verify selected PodVM releases and freeze all inputs |
| `measure` | Generate only the catalog from frozen inputs |
| `package` | Generate catalog, deterministic archive, and checksums |
| `verify` | Check checksums, upstream provenance, and exact regeneration |
| `annotation` | Encode one workload's original TOML for Kata |

`measure` and `package` take `--inputs`, `--output`, `--release-version`,
`--source-revision`, and optionally `--source-repository`.
`validate`, `package`, and `verify` support `--require-workloads`.

## Release format and relying-party use

Each release contains exactly three uploaded assets:

| Asset | Contents |
|---|---|
| `measurements.json` | Attestation references indexed by workload ID |
| `trustbase-inputs-<tag>.tar.gz` | Exact source definitions, schemas, resolution lock, upstream assets, and attestation bundles |
| `SHA256SUMS` | SHA-256 checksums of the two assets above |

GitHub's automatic source archives are separate. Every uploaded asset receives
a GitHub build-provenance attestation.

The catalog follows `schemas/measurements.schema.json` and carries only the
values a relying party matches against evidence. At `workloads[<id>]`:

- `initdata` records the declared algorithm, full digest, and the derived
  `host_data` and `mr_config_id` registers for the workload.
- `releases` is keyed by the exact PodVM tag. Each entry has an `snp` map from
  CPU model to the expected SNP `measurement`, and/or a `tdx` object with
  `mr_td`, `rtmr_0`, `rtmr_1`, and `rtmr_2`.

Launch configuration, bundle digests, source commits, and upstream catalog
digests are provenance rather than attestation inputs. They remain available in
the attested `trustbase-inputs-<tag>.tar.gz` archive and are not repeated in the
catalog.

A relying party verifies the Trustbase release's provenance, selects the
**intended** workload ID, then selects the release entry and TEE matching the
evidence and matches every register in that entry. `host_data` and
`mr_config_id` come from the workload's `initdata` block. The relying party must
not mix registers from different releases or TEEs, or accept an arbitrary
workload ID supplied by the prover. The ID is a lookup key; workload enforcement
depends on the measured guest consuming and enforcing its Init-Data policy and
model metadata. Evidence signature, freshness, and platform-policy checks remain
part of the relying party.

For a downloaded release, verify published provenance first:

~~~sh
gh attestation verify dist/measurements.json --repo prem-research/trustbase \
  --signer-workflow prem-research/trustbase/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.0
gh attestation verify dist/trustbase-inputs-v1.0.0.tar.gz --repo prem-research/trustbase \
  --signer-workflow prem-research/trustbase/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.0
python trustbase.py verify --dist dist --require-workloads
~~~

`trustbase.py verify` checks internal consistency and upstream provenance; it does
not authenticate the outer Trustbase release. The `gh` checks establish that
trust. Consumers can also pin `--source-digest` to the approved commit.

Upstream attestations are verified against the PodVM repository, the `podvm.yml`
signer workflow, the tag ref, and its dereferenced commit. The resolver downloads
only measurement/checksum assets, not the guest disk bundle; the bundle digest
is taken from those verified assets. Checksums for every declared variant are
checked, including variants not selected by a workload. No measurements are
recomputed or inferred from another profile.

## Reproduce a release

Use the Trustbase source commit recorded in the catalog, the exact packaged
snapshot, and recorded release metadata. `package` never consults GitHub's
release list; it verifies saved attestation bundles and regenerates the outputs.
Tar metadata, file ordering, and gzip headers are normalized.

For fully offline verification, obtain Sigstore roots from a trusted environment
before disconnecting:

~~~sh
gh attestation trusted-root > trusted-root.jsonl
python trustbase.py --trusted-root trusted-root.jsonl verify --dist dist
~~~

`--trusted-root` also applies to `measure` and `package`. Trust roots are an
independent verifier input and are not accepted implicitly from an input archive.

## CI and publication

PRs, pushes to `main`, and manual dispatch run validation, offline tests, Kata
conformance, live CPU/NVIDIA integration, and packaging on ordinary Ubuntu runners.
Actions are pinned to commits, Python to 3.12, Go to 1.25.12, and the integration
release to PodVM v0.3.13.
No confidential hardware or KVM is required. Empty production catalogs produce
empty preview catalogs so bootstrap CI remains usable.

A stable `vX.Y.Z` tag push runs the same checks and requires a nonempty production
catalog. A separate publication job verifies and attests the assets, creates a
draft release with all assets, then publishes it. Existing releases, including
interrupted drafts, are rejected; assets are never clobbered. Publication uses
only `GITHUB_TOKEN` and GitHub OIDC; no PAT or external-service secret is needed
for these public repositories.

After a successful release publication, a separate job deploys the identical
`measurements.json` to GitHub Pages at
<https://trustbase.prem.io/measurements.json>.
Each successful tag deployment replaces that file; use the immutable release
assets when pinning a particular version. The Pages copy can be checked with the
same release provenance attestation.

For initial setup, select **GitHub Actions** under **Settings → Pages → Build and
deployment → Source**. If the `github-pages` environment restricts deployment
branches and tags, allow release tags matching `v*`.

Main pushes and manual runs do not publish. Tag jobs are serialized per tag and
are never cancelled by a newer run of the same tag.
