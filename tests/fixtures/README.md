# Public upstream fixtures

`podvm-v0.3.13.json` is the unmodified public unified release asset:
https://github.com/prem-research/podvm/releases/download/v0.3.13/measurements.json

Source revision: `98fb81edf7284bc44f503ce21347f440acb0e3a6`
SHA-256: `2dc23f10f9a31367cffd804d7655effc1e5bdc256301bd7b42c4d73d3d4de481`

It contains the CPU profile and seven NVIDIA GPU profiles, both bundle digests,
and per-variant provenance. Tests exercise every profile, preserve GPU metadata,
and ensure GPU TDX candidates cannot become reference records.

`podvm-v0.1.6.json` preserves the unmodified legacy single CPU bundle asset:
https://github.com/prem-research/podvm/releases/download/v0.1.6/measurements.json

SHA-256: `3cd0e61ea7efc251a051743ca6e8adf31783d185925827ee78344e5e65908d94`

Unit tests replace the network and signature verifier explicitly. Production code
has no switch to bypass verification. Live integration uses real attestations.
