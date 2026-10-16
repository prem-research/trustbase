# Trustbase

Trustbase publishes complete reference measurements for confidential workloads.
Each workload combines an exact Init-Data TOML with a named
[prem-research/podvm](https://github.com/prem-research/podvm) launch profile and a
semver constraint. A release freezes every matching published stable PodVM
version and includes reference values for Intel TDX and AMD SEV-SNP.

The production catalog starts empty. The two definitions under `examples/` are
non-deployable examples with policies that deny container creation. They are
tested separately and are never included in production releases.

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
      version: ">=0.1.6 <0.2.0"
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

`podvm.version` uses npm-style semver, through pinned `semantic-version`
`NpmSpec`:

| Constraint | Meaning |
|---|---|
| `0.1.6` | Exactly 0.1.6 |
| `>=0.1.6 <0.2.0` | All stable versions in this interval |
| `^0.1.6` | Compatible versions below 0.2.0 |
| `~1.2.3` | Versions from 1.2.3 up to, excluding, 1.3.0 |

PodVM tags may have a leading `v`. Drafts, GitHub prereleases, semver prereleases,
and tags without a published release are excluded. Two tags representing the same
version are rejected. Missing profiles, unsupported formats, missing assets, or
invalid provenance on **any** matching release fail the entire resolution.
Narrow the constraint to the versions approved for this workload.

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
`cf82bb35c80320178bf7570252fe75d6fb263209`, used by PodVM v0.1.6.
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
`make integration` resolves the real PodVM v0.1.6 release, verifies both upstream
assets' attestations, and round-trips a temporary release. Public API reads work
without authentication; CI supplies `GH_TOKEN` to avoid anonymous rate limits.

After the first repository commit, build an example candidate:

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
| `measurements.json` | Complete references indexed by workload ID |
| `trustbase-inputs-<tag>.tar.gz` | Exact source definitions, schemas, resolution lock, upstream assets, and attestation bundles |
| `SHA256SUMS` | SHA-256 checksums of the two assets above |

GitHub's automatic source archives are separate. Every uploaded asset receives
a GitHub build-provenance attestation.

The catalog follows `schemas/measurements.schema.json`. At `workloads[<id>]`:

- `initdata` records the path, declared algorithm, full digest, and file SHA-256.
- `podvm` records the repository, selected profile, and original constraint.
- `references` contains complete records for each selected version and TEE/CPU.

Each reference identifies the exact PodVM tag, source commit, measurement-asset
digest, PodVM bundle digest, launch profile, and launch configuration. TDX records
carry `mr_td`, `rtmr_0`, `rtmr_1`, `rtmr_2`, and `mr_config_id` together. SNP records
carry the CPU model, `measurement`, and `host_data` together.

A relying party verifies the Trustbase release's provenance, selects the
**intended** workload ID, and matches all measurement fields of one complete
record. It must not mix registers from different records or accept an arbitrary
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
is taken from those verified assets.

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
conformance, live integration, and packaging on ordinary Ubuntu runners.
No confidential hardware or KVM is required. Empty production catalogs produce
empty preview catalogs so bootstrap CI remains usable.

A stable `vX.Y.Z` tag push runs the same checks and requires a nonempty production
catalog. A separate publication job verifies and attests the assets, creates a
draft release with all assets, then publishes it. Existing releases, including
interrupted drafts, are rejected; assets are never clobbered. Publication uses
only `GITHUB_TOKEN` and GitHub OIDC; no PAT or external-service secret is needed
for these public repositories.

Main pushes and manual runs do not publish. Tag jobs are serialized per tag and
are never cancelled by a newer run of the same tag.
