# PodVM schemas

`podvm-measurements.schema.json` retains the legacy single CPU bundle contract
from prem-research/podvm commit `b57d5e92583388169743bc0084673f0249d64a34`
(release v0.1.6), reformatted with sorted keys:
https://github.com/prem-research/podvm/blob/b57d5e92583388169743bc0084673f0249d64a34/schemas/measurements.schema.json

`podvm-measurements-variants.schema.json` is copied byte-for-byte from commit
`98fb81edf7284bc44f503ce21347f440acb0e3a6` (release v0.3.13):
https://github.com/prem-research/podvm/blob/98fb81edf7284bc44f503ce21347f440acb0e3a6/schemas/measurements.schema.json

`podvm-model-mounts.schema.json` is copied byte-for-byte from commit
`98fb81edf7284bc44f503ce21347f440acb0e3a6` (release v0.3.13):
https://github.com/prem-research/podvm/blob/98fb81edf7284bc44f503ce21347f440acb0e3a6/schemas/model-mounts.schema.json

The unified format has variant-keyed `artifacts` and `inputs`, a shared
`profiles` map, CPU TDX/SNP records, and GPU SNP-only records.
Schemas are vendored so remote schemas cannot redefine the supported input
contract. Update them together with compatibility tests when PodVM changes.
