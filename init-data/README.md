# Production Init-Data

Each file is an exact TOML named `<sha256-of-file-bytes>.toml` and registered in
`measurements.yaml`; its `[data].id` must match the manifest's `id`. Production
definitions arrive through the
coco-fleet `repository_dispatch` flow and the admission gate (see the README section
"Candidate submission and admission"); a manual change here still has to pass
`make admit` and a reviewed pull request. See `../examples/` for fixtures.
