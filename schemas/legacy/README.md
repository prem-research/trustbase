# Verifier-only historical schemas

`measurements-v1.schema.json` is the exact pre-processor-keyed public catalog
schema from Trustbase revision
`9d2af26c66859e4126bd17facccc202df7234aef` (SHA-256
`b40943529fcc6869fe4496bba4b56412b33e5879cbf92acd6e6c7dbad50e10a4`).
It was also frozen into the published v1.1.1 and v1.1.2 input archives.

This schema is never copied into newly resolved snapshots. Only an archived
measurements schema byte-identical to this trusted file selects the historical
reader, including its flat TDX references and legacy-only PodVM catalog rules.
All other archived schema files must continue matching current trusted bytes.
The subsequently introduced processor catalog schema must be absent; mixing
legacy and processor-keyed snapshot profiles is rejected.

Do not relax these checks to accept arbitrary archive-supplied schemas. Preserve
signature, frozen-inventory, schema, and exact regenerated-catalog verification
when adding another historical format.
