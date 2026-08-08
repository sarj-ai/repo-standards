# sarj-repo-lint

`sarj-repo-lint` is a deterministic, read-only repository architecture linter. It validates
declared component ownership, physical layout, typed dependency direction, migration mappings,
and exact legacy-debt baselines without importing or executing repository code.

The repository intentionally separates:

- `repo-lint-core`: organization-neutral models, parsing, fingerprints, modes, and rendering;
- `repo-lint-policy-sarj`: Sarj products, topology, dependency rules, and remediation guidance;
- `sarj-repo-lint`: the CLI assembly.

This is a private Stage 0/V1 prototype. It does not move files, rewrite imports, generate source,
run package managers, call cloud APIs, deploy, or prove live operational state.

## Quick start

Requires Python 3.12+ and uv.

```bash
uv sync --frozen
uv run repo-lint check /path/to/repository --policy sarj --mode report
uv run repo-lint list-rules --policy sarj
uv run repo-lint explain sarj/graph/cross-product-import --policy sarj
uv run repo-lint schema
```

Machine consumers should use canonical JSON:

```bash
uv run repo-lint check /path/to/repository \
  --policy sarj \
  --mode report \
  --format json
```

JSON is the authoritative interface. Standard output contains exactly one JSON value; operational
errors are represented as `completion: "incomplete"`, `conclusion: "inconclusive"`, and exit 2.

## Modes

| Mode | Exit 0 | Exit 1 | Exit 2 |
|---|---|---|---|
| `report` | Complete analysis, even with findings | Never | Invalid or incomplete analysis |
| `ratchet` | No new or stale blocking debt | New/stale blocking debt | Invalid baseline or incomplete analysis |
| `strict` | No blocking findings | Blocking findings | Invalid or incomplete analysis |

Warnings remain non-blocking in every mode. New judgment-heavy rules ship as warnings and are
promoted only after labeled fixtures and representative corpus inspection show zero known false
positives.

## Repository manifest

The default manifest is `.repo-lint/repository.toml`:

```toml
schema_version = 1
repository_id = "example-repository"
policy = "sarj"
policy_version = 1

[[components]]
id = "platform.agent"
kind = "application"
product = "platform"
path = "products/platform/components/agent"
owner = "@example/platform"

[[components.dependencies]]
target = "platform.request-signing"
type = "package-dependency"

[[components]]
id = "platform.request-signing"
kind = "product-library"
product = "platform"
capability = "request-signing"
path = "products/platform/libraries/python/request-signing"
owner = "@example/platform"
```

The manifest is strict: unknown keys, unknown component/edge kinds, duplicate IDs, unsafe paths,
missing targets, and mismatched policy versions make analysis incomplete. Legacy paths are allowed
only through `legacy = true`; intentional moves use an explicit `[[migration_paths]]` record.

Exceptions are exact `(rule_id, component_id)` pairs with owner, issue, reason, creation date, and
a maximum 90-day ISO expiry.
When exceptions exist, callers must pass `--as-of YYYY-MM-DD` so results never depend silently on
the machine clock.

Ratchet mode reads `.repo-lint/baseline.json`. Baselines are reviewed debt records, not suppression
counts:

```json
{
  "schema_version": 1,
  "repository_id": "example-repository",
  "source_sha": "0000000000000000000000000000000000000000",
  "policy": "sarj",
  "policy_version": 1,
  "scope_digest": "<digest from a report>",
  "fingerprints": ["<exact blocking diagnostic fingerprint>"]
}
```

Normal ratchet operation may only remove resolved fingerprints. New findings and stale baseline
entries both fail, preventing one fixed component from financing new debt elsewhere.

## Evidence boundary

Every diagnostic states its evidence level:

- `verified`: deterministically proven from parsed bytes;
- `declared`: asserted by a valid repository manifest;
- `external`: requires CI, registry, GitHub, cloud, or human evidence;
- `unknown`: required evidence is missing.

V1 blocks only deterministic structural violations and invalid declarations. It never equates a
workflow file with proof that a deployment, approval, artifact promotion, rollback, or cloud IAM
policy actually worked.

See [architecture.md](docs/architecture.md), [diagnostics.md](docs/diagnostics.md), and
[rule-evaluation.md](docs/rule-evaluation.md).

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run basedpyright
```

No license is granted while this remains a private evaluation prototype.
