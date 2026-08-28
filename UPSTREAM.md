# Upstream provenance

`legal-cn-anonymizer` is bootstrapped from **fishonbike/vault-engine** at commit
`24afa4d84dc1ad39945404b5d3f05b63056adba5` (Apache-2.0). The full Git history of the
upstream skeleton is preserved in this repository; `upstream` is the renamed origin
remote.

Structure mapping performed at S0 (via `git mv`, history preserved):

| Upstream | Here |
|---|---|
| `vaultengine/` | `src/legal_anonymizer/` |
| `tests/` | `tests/upstream/` |
| `examples/` | `examples/upstream/` |

The upstream package was renamed `vaultengine` -> `legal_anonymizer`. The upstream
serialized map data key `vaultengine_map_version` is intentionally kept unchanged so
upstream mapping files remain comparable during the S2 rewrite.

Do not silently follow the upstream remote's HEAD. The authoritative snapshot is
`upstream.lock.json`.
