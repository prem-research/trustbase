# Trustbase

Trustbase publishes reference measurements for confidential workloads.
Each workload combines an exact Init-Data TOML with a named
[prem-research/podvm](https://github.com/prem-research/podvm) launch profile and a
semver constraint. A release freezes every matching published stable PodVM
version and includes the TEE records published for that profile: Intel TDX and
AMD SEV-SNP for CPU guests, and SEV-SNP for NVIDIA guests.

Production Init-Data is not authored here. Candidates are submitted by the fleet
repository, fetched byte-exactly, checked by the automated admission gate in
`admission.py` against the committed `admission.yaml`, and published only when
every check passes (see [Candidate submission and admission](#candidate-submission-and-admission)).
The definitions under `examples/` demonstrate CPU and NVIDIA selection with
policies that deny container creation. They are tested separately and are never
included in production releases.

## Define a workload

Create `init-data/<sha256-of-exact-file-bytes>.toml`, then register it in
`measurements.yaml`:

~~~yaml
schema_version: 1
profiles:
  - id: my-workload
    initdata: init-data/<sha256>.toml
    podvm:
      profile: 2vcpu-8g
      version: ">=0.3.13 <0.4.0"
~~~

The TOML uses Kata's existing format, with the identifier in the measured
string-to-string payload map:

~~~toml
version = "0.1.0"
algorithm = "sha384"

[data]
id = "my-workload"
"policy.rego" = '''
package agent_policy
# Insert the complete reviewed workload policy here.
'''
~~~

IDs must be unique, match `[data].id` exactly, and use lowercase letters, digits,
dots, underscores, or hyphens (maximum 64 characters). Every TOML beneath
`init-data/` must be registered. The filename must equal the SHA-256 of the exact
TOML bytes; symlinks and paths outside that directory are rejected. No registered
digest may appear in `revoked.yaml`.

During a rollout a profile may also carry the definition it replaced:

~~~yaml
    previous:
      initdata: init-data/<sha256-of-the-replaced-file>.toml
      not_after: "2026-10-22T12:00:00Z"
~~~

The previous TOML is validated exactly like the current one, must carry the same
`[data].id`, and stays acceptable to relying parties only until `not_after`, an
absolute UTC timestamp committed here so that releases remain reproducible.

Commit complete policies and other payloads, such as `aa.toml`, `cdh.toml`, or
`model-mounts.json`, directly into `[data]` as strings. Trustbase measures these
definitions; it does not run genpolicy or resolve model content.

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
for older single-bundle CPU catalogs. The selected profile determines the bundle;
no separate variant field is needed. CPU profiles have `tdx` and `sev` records.
GPU profiles have a `gpu` block and `sev` records and select the NVIDIA bundle.
GPU profiles publish SNP references only. Trustbase preserves the declared GPU
family, platform, GPU count, and NVSwitch count; these labels do not constitute
GPU hardware attestation.

New PodVM releases never change an existing Trustbase release. Publish another
Trustbase tag to resolve again. Removing a workload or narrowing its range takes
effect in the next release; relying parties choose which release they trust.

## Candidate submission and admission

The fleet repository commits each generated Init-Data candidate and sends a
`repository_dispatch` to this repository naming the source commit, path, digest,
workload, and intended PodVM profile and version. The dispatch is one-way and
proves only delivery. The receiver (`.github/workflows/admit.yml`,
`.github/scripts/receive.py`) always runs from this repository's default branch,
validates the payload against `schemas/dispatch.schema.json`, requires the selected
PodVM profile and exact version to be listed in the reviewed `admission.yaml`
floor, confirms the commit belongs to the fleet default branch, fetches the file
at exactly that commit, and requires the
bytes to hash to the dispatched SHA-256. It checks that `[data].id` matches the
dispatched workload, then imports the TOML and creates or updates its
`measurements.yaml` registration. An update may also change the workload's PodVM
selection within the reviewed floor. The receiver keeps a superseded TOML as the
workload's `previous` with `not_after` set to the import time plus the reviewed
`floor.rollout_overlap_seconds`, deletes the definition that `previous` displaces,
and runs the admission gate. Revoked digests are refused before import; a candidate
whose digest and PodVM selection are already registered is acknowledged without
a second import. A PodVM version change can reuse the same Init-Data bytes; the
registration and resolved PodVM measurements still change. A new PodVM profile
or version needs a reviewed floor change.
New model IDs and model-specific arguments can flow automatically when the
resulting candidate satisfies the floor and policy checks.

Rolling out a replacement therefore needs no second release: the next catalog
lists the new definition as `initdata` and the replaced one as
`previous_initdata` with its deadline. Fleet should merge the candidate, wait
until the published catalog lists the new digest for the workload, then roll
the deployment within the window. New pods verify from the start and old pods
keep verifying until `not_after`. Revoking the previous digest ends the overlap
early.

The pipeline is the dry run: the prepare job resolves, packages, and verifies the
would-be release and uploads it with the admission report as a workflow
artifact. Only when every check passed, and only for events sent by the
configured fleet dispatcher, does a separate publish job commit the import and
push it together with the next `vX.Y.Z` tag in one atomic push, after the
preceding tag has a published release. The tag push starts the ordinary release
workflow, which reruns every check before signing. A failed check publishes
nothing.

### What the gate checks

`admission.py` runs on the exact TOML bytes. `admission.yaml` holds only global
rules and allowed PodVM selections; everything specific to the pod is read from
the candidate itself, so a fleet change that stays within the floor flows through
without a Trustbase edit. Release preparation still resolves the selected PodVM
to authenticated measurements and verifies the packaged result before publishing.

The static half splits `policy.rego` into the reviewed rules text and the
generated `policy_data` object. The rules text must hash to an accepted digest,
so a change to Rego logic needs a reviewed Trustbase pull request while
`policy_data`-only changes stay automatic. It then checks the default request
headers, the request defaults, and a floor over the sandbox, containers, images,
capabilities, devices, mounts, and storage records against the accepted values.

The behavioral half replays agent requests through `tools/kata-policy-eval`, a
small Rust binary that links the kata-agent's own policy and protocol crates at
the PodVM's Kata revision, so policies are evaluated by the same regorus build
and request serialization as the guest. It synthesizes the pod's own sandbox and
container creation requests and requires them to be admitted, then requires
denial of every host-side probe and of single-change mutations of each admitted
container. Every synthesized request is recorded in the report so a hardware run
can compare them with the guest's policy log.

The gate does not prove that the real runtime emits exactly these requests. An
acceptance run on hardware remains the authority for the deployed path.

For each changed fleet candidate that passes the gate, the receiver writes
`build/admission/admission-report.json`. It records the workload and exact TOML
digest, approved rules digest, and each replayed request with its expected and
observed verdict. The admission workflow uploads it as a 30-day Actions artifact.

Run the gate locally with a Rust toolchain (rustup installs the pinned channel from
`tools/kata-policy-eval/rust-toolchain.toml`):

~~~sh
make evaluator   # builds tools/kata-policy-eval from the pinned Kata crates
make admit       # gates every registered workload and the examples
python trustbase.py admit <workload-id> --report build/admission.json
~~~

`--static-only` skips the replay for local iteration; CI never passes it.

### Revocation

`revoked.yaml` is a cumulative list of Init-Data digests that relying parties must
reject even if an earlier release referenced them. Entries are never removed, a
revoked digest cannot remain registered as either a current or a `previous`
definition, and the receiver refuses to import one.
Quote digests: an all-digit hexadecimal string is otherwise a YAML integer.

## Exact measurement contract

Trustbase hashes the **original UTF-8 file bytes**, including metadata, comments,
whitespace, and final newline. It validates TOML without serializing it again.
The algorithm is the file's `sha256`, `sha384`, or `sha512`.

For the raw digest `D`:

| Evidence field | Value |
|---|---|
| SNP `HOST_DATA` (`host_data`) | First 32 bytes of `D`, right-padded with zero bytes if needed |
| TDX `MRCONFIGID` (`mr_config_id`) | First 48 bytes of `D`, right-padded with zero bytes if needed |

For SHA-384, SNP receives the first 32 bytes and TDX receives the full digest.
Do not hash again between platforms. Catalog values use lowercase hexadecimal.
QEMU's `host-data` and `mrconfigid` arguments use standard base64 of those same
raw register bytes.

The Kata revision is pinned in `trustbase.py` and checked independently in every
variant's provenance. A different declared revision is rejected until its
semantics have been reviewed and the pin and conformance tests updated. The
conformance test downloads checksum-pinned Kata sources and executes their
unmodified hash and resize code in a temporary Go harness.

Transport the identical TOML bytes to Kata:

~~~sh
python trustbase.py annotation <workload-id> > initdata.b64
base64 --decode initdata.b64 | gzip -dc | cmp - init-data/<sha256>.toml
~~~

The annotation command emits single-line standard-base64 of deterministic gzip.
Use it as `io.katacontainers.config.hypervisor.cc_init_data`; the runtime must
allow that annotation. Do not put the release input archive into the annotation.
Git attributes disable line-ending conversion for workload TOMLs.

## Local commands

Use Python 3.12+, GitHub CLI, Go for the conformance test, and rustup for the
admission evaluator. CI installs pinned versions of each.

~~~sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
make validate test
make evaluator admit
make conformance
make integration
~~~

`make test` is offline and mocks only the network/signature-verifier boundary.
`make integration` resolves a real PodVM release, verifies the unified
measurement/checksum attestations and both bundle digests, and round-trips a
temporary release with CPU and NVIDIA workloads. By default it tests the newest
PodVM release each workload in `measurements.yaml` resolves to; set `PODVM_VERSION`
to test one specific published stable release instead. Public API reads work without
authentication; set `GH_TOKEN` to avoid anonymous rate limits.

Build an example candidate:

~~~sh
python trustbase.py --root examples resolve --output build/example-inputs
python trustbase.py package \
  --inputs build/example-inputs --output build/example-release \
  --release-version preview --no-previous \
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
| `package` | Generate catalog and deterministic input archive |
| `verify` | Check payloads, Sigstore provenance, release chain, and exact regeneration |
| `annotation` | Encode one workload's original TOML for Kata |
| `admit` | Run the admission gate on registered workloads |

`measure` and `package` take `--inputs`, `--output`, `--release-version`,
`--source-revision`, optionally `--source-repository`, and exactly one of
`--previous-dist <downloaded release>` or `--no-previous`.
`validate`, `package`, and `verify` support `--require-workloads`. `verify` also
takes `--require-provenance`, `--min-version`, `--max-age`, and `--previous-dist`.

## Release format and relying-party use

Each release contains exactly three uploaded assets:

| Asset | Contents |
|---|---|
| `measurements.json` | Attestation references indexed by workload ID, the chain link to the previous release, and the cumulative revocation list |
| `trustbase-inputs-<tag>.tar.gz` | Exact Init-Data TOMLs, manifest, `revoked.yaml`, schemas, resolution lock, and the upstream PodVM assets with their attestation bundles |
| `provenance.sigstore.json` | One Sigstore bundle: the signed in-toto statement naming both payloads as subjects, the signing certificate, and verification material (a public transparency-log entry for public repositories or a signed timestamp for internal repositories) |

GitHub's automatic source archives are separate. The bundle is the output of the
release workflow's `attest-build-provenance` step, so the same attestation is also
discoverable through GitHub's API; publishing it with the release lets verifiers
work from the three files alone. Releases published before this format carried a
`SHA256SUMS` file and per-asset attestations instead. The current `verify` command
rejects those legacy Trustbase releases. Historical verification requires checking
each old asset against its per-asset attestation and the expected tag, source
commit, repository, and signer workflow. The current release chain can be checked
back to `v0.0.10`; walking its older `v0.0.7` link requires that separate procedure.

The catalog follows `schemas/measurements.schema.json` and carries only the
values a relying party matches against evidence. At `workloads[<id>]`:

- `initdata` records the declared algorithm, full digest, and the derived
  `host_data` and `mr_config_id` registers for the workload.
- `previous_initdata`, when present, records the same fields for the definition
  this one replaced, plus `not_after`. A relying party accepts it only while
  `not_after` is in the future; after that it ignores the block entirely.
- `releases` is keyed by the exact PodVM tag. Each entry has an `snp` map from
  CPU model to the expected SNP `measurement`, and/or a `tdx` object with
  `mr_td`, `rtmr_0`, `rtmr_1`, and `rtmr_2`.

Launch configuration, bundle digests, source commits, and upstream catalog
digests are provenance rather than attestation inputs. They remain available in
the attested `trustbase-inputs-<tag>.tar.gz` archive and are not repeated in the
catalog.

`release.previous` names the release this one supersedes (`version` and the
SHA-256 of its `measurements.json`), or is `null` for the first chained release.
The publisher downloads and verifies the latest published release before building,
requires the new version to be higher, and requires every earlier revocation to be
carried forward. `revoked` lists Init-Data digests that must be rejected even if an
older release referenced them. Relying parties therefore pick the highest published
release, verify it, reject anything in its `revoked` list, and may walk `previous`
links to confirm the chain.

A relying party verifies the Trustbase release's provenance, selects the
**intended** workload ID, then selects the release entry and TEE matching the
evidence and matches every register in that entry. `host_data` and
`mr_config_id` come from the workload's `initdata` block, or from its
`previous_initdata` block while that block's `not_after` has not passed. The
relying party must not mix registers from different releases or TEEs, or accept
an arbitrary workload ID supplied by the prover. The ID is a lookup key; workload enforcement
depends on the measured guest consuming and enforcing its Init-Data policy and
model metadata. Evidence signature, freshness, and platform-policy checks remain
part of the relying party.

For a downloaded release, verify it with its bundle:

~~~sh
gh release download <tag> --repo <owner>/trustbase --dir dist
python trustbase.py verify --dist dist --require-provenance --require-workloads \
  --min-version <tag> --max-age 7776000
~~~

With `--require-provenance`, `verify` runs `gh attestation verify --bundle` for
both payloads against this repository, its `release.yml` signer workflow, the
release tag, and the source commit recorded in the catalog; it then requires the
statement's subjects to be exactly the two payloads with their digests, requires a
verified signing timestamp, and compares the certificate's repository ID with
the current ID fetched from GitHub. `--require-provenance` needs GitHub API access.
`--max-age` bounds the age of that signing event (the Rekor integration time on a public
repository), `--min-version` rejects older releases, and `--previous-dist` checks
that the catalog chains to a given predecessor. Without `--require-provenance` the
command checks only internal consistency and upstream PodVM provenance.

Upstream attestations are verified against the PodVM repository, its signer
workflow, the tag ref, and its dereferenced commit. The resolver downloads only
measurement/checksum assets, not the guest disk bundle; the bundle digest is
taken from those verified assets. Checksums for every declared variant are
checked, including variants not selected by a workload. No measurements are
recomputed or inferred from another profile.

## Reproduce a release

Use the Trustbase source commit recorded in the catalog, the exact packaged
snapshot, and recorded release metadata. `package` never consults GitHub's
release list; it verifies saved attestation bundles and regenerates the outputs.
Tar metadata, file ordering, and gzip headers are normalized.

For offline checks of the packaged inputs and upstream attestations, obtain
Sigstore roots from a trusted environment before disconnecting:

~~~sh
gh attestation trusted-root > trusted-root.jsonl
python trustbase.py --trusted-root trusted-root.jsonl verify --dist dist
~~~

`--trusted-root` also applies to `measure` and `package`. Trust roots are an
independent verifier input and are not accepted implicitly from an input archive.
Rekor only records signing events on public repositories; the transparency
property of the bundle therefore requires this repository to be public when a
release is signed.

## CI and publication

PRs, pushes to `main`, and manual dispatch run validation, offline tests, the
admission gate with the pinned evaluator, Kata conformance (including a check that
the evaluator's regorus revision equals the one in Kata's lockfile), live
CPU/NVIDIA integration, a download and verification of the latest published
release, and packaging on the `arc-runners` runner group. Actions and toolchains are
pinned. No confidential hardware or KVM is required. Empty production catalogs
produce empty preview catalogs so bootstrap CI remains usable.

A stable `vX.Y.Z` tag push runs the same checks and requires a nonempty production
catalog. A separate publication job verifies the candidate, attests the two
payloads, attaches the resulting bundle as `provenance.sigstore.json`, verifies the
signed three-file set with `--require-provenance`, creates a draft release, then
publishes it. Existing releases, including interrupted drafts, are rejected; assets
are never clobbered. Publication uses only `GITHUB_TOKEN` and GitHub OIDC.
Tag workflows queue behind one another, and publication checks that its
predecessor is still the latest published release. If another release wins the
race, the stale tag run fails and must be rerun to rebuild its chain link.

The admission workflow is the only path that writes to `main` without a pull
request, and only after every check in its prepare job has passed for an event
from the configured fleet dispatcher. It relies on three GitHub Apps (a read-only
reader on the fleet repository, a release App with write access here, and the
fleet's dispatcher) and rulesets that make the release App the only bypass actor
for `main` and `v*` tags.

### Setup checklist

1. Create three GitHub Apps in the organization (Settings → Developer settings →
   GitHub Apps). Disable their webhooks and limit installation to this organization.
   Install each with **Only select repositories**:

   | App | Contents permission | Install on | Store private key in |
   |---|---|---|---|
   | `trustbase-fleet-reader` | Read | `coco-fleet` | trustbase repository secrets |
   | `trustbase-release-bot` | Read and write | `trustbase` | trustbase `release` environment secrets |
   | `trustbase-dispatcher` | Read and write | `trustbase` | coco-fleet repository secrets |

   In Trustbase, set `TRUSTBASE_READER_APP_CLIENT_ID` and `TRUSTBASE_RELEASE_APP_CLIENT_ID` to
   their Apps' **Client IDs**.
   In coco-fleet, set `FLEET_DISPATCH_APP_CLIENT_ID` to the dispatcher's **Client ID**.

   The dispatcher needs write access to send `repository_dispatch`; only the
   release bot may bypass branch and tag rulesets.

2. In trustbase, set repository variables `TRUSTBASE_READER_APP_CLIENT_ID` and
   `TRUSTBASE_RELEASE_APP_CLIENT_ID`, and repository secret
   `TRUSTBASE_READER_APP_PRIVATE_KEY`. Create a `release` environment with secret
   `TRUSTBASE_RELEASE_APP_PRIVATE_KEY`, deployment access limited to `main`, a
   zero wait timer, and self-review prevention. Require one or two reviewers
   while the flow is new.

3. Set repository variable `TRUSTBASE_FLEET_DISPATCH_ACTOR` to
   `trustbase-dispatcher[bot]`. Events from any other sender cannot publish.
   Remove the environment reviewers when publication is ready to run unattended.

4. Add two rulesets: on `main`, block deletion and force pushes and require a PR
   with one approval and the "Build and verify release candidate" check; on `v*`
   tags, restrict creation, updates, and deletion. Give only the
   `trustbase-release-bot` App an **always** bypass on both.

5. Allow this repository in the `arc-runners` runner group. Enable **Allow public
   repositories** before making it public. Set Pages source to **GitHub Actions**
   and allow `v*` tags in the `github-pages` environment's deployment rules.

6. Make the repository public before the first chained release so signing uses
   public Rekor.

In coco-fleet, `check.yml` already uses `FLEET_DISPATCH_APP_CLIENT_ID` and
`FLEET_DISPATCH_APP_PRIVATE_KEY` to mint a token scoped to `trustbase` with
`contents: write` and send the dispatch on pushes to `main`. Its README has the
App creation steps under "Submit to Trustbase, Setup".

After a successful release publication, a separate job deploys the identical
`measurements.json` and `provenance.sigstore.json` to GitHub Pages. Each
successful tag deployment replaces those files; use the immutable release assets
when pinning a particular version.

Main pushes and manual runs do not publish. All tag runs are serialized and
queued; none is cancelled by a later tag.
