# Declarative command extension contributions

Command extensions are authored as bounded JSON and compiled by the reviewed Rust source compiler. The canonical guide is
[Declarative extension contributions](../extension-contributions.md).

For a new command extension, submit only these contributor-authored inputs:

1. `contributions/command-sources/command.<name>.json`;
2. `tests/fixtures/command-source-<slug>.v1.json`, bound to that exact source document; and
3. the external trust-class entry in `contracts/extensions/trust-class-map.v1.json`.

Do not add Python detector modules or edit generated descriptors, native programs, package resources, or public catalogs.
Maintainers prepare those deterministic projections after review:

```sh
uv run --no-sync python scripts/prepare_extension_contribution.py \
  --source contributions/command-sources/command.<name>.json \
  --fixture tests/fixtures/command-source-<slug>.v1.json
```

The command validates the fixture through native evaluation with zero target-command execution, recompiles the complete
catalog, and synchronizes the checked-in projections. Use `--check` in CI or before a follow-up review. Optional public
credit, upstream, and claim-readiness metadata belongs in
`contributions/extension-listings/command.<name>.json`; it is documented in
[publisher metadata](publisher-metadata.md). Contributor credit never grants claim authority.
