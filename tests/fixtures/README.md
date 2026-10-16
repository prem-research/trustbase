# Public upstream fixture

`podvm-v0.1.6.json` is the unmodified public release asset:
https://github.com/prem-research/podvm/releases/download/v0.1.6/measurements.json

SHA-256: 3cd0e61ea7efc251a051743ca6e8adf31783d185925827ee78344e5e65908d94

Unit tests replace the network and signature verifier explicitly. Production code
has no switch to bypass verification. Live integration uses real attestations.
