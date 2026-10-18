# PodVM schemas

`podvm-measurements.schema.json` is the single CPU bundle format, copied from
prem-research/podvm commit `b57d5e92583388169743bc0084673f0249d64a34` (release v0.1.6):
https://github.com/prem-research/podvm/blob/b57d5e92583388169743bc0084673f0249d64a34/schemas/measurements.schema.json

`podvm-measurements-variants.schema.json` is the per-variant (`cpu`, `nvidia`) format
used since v0.3.9, copied from commit `98fb81edf7284bc44f503ce21347f440acb0e3a6`
(release v0.3.13):
https://github.com/prem-research/podvm/blob/98fb81edf7284bc44f503ce21347f440acb0e3a6/schemas/measurements.schema.json

Both are reformatted with sorted keys. They are vendored so remote schemas cannot
redefine the supported input contract. Update them together with compatibility
tests when the PodVM format changes.
