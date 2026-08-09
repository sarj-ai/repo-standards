# sarj-repo-lint

`sarj-repo-lint` is a deterministic, read-only repository architecture linter. It validates
declared component ownership and target topology, typed dependency direction, migration mappings,
and exact legacy-debt baselines without importing or executing repository code. `inspect` verifies
tracked Git-tree inventory; manifest `check` does not yet prove every declared component path exists.

The repository intentionally separates:

- `repo-lint-core`: organization-neutral models, parsing, fingerprints, modes, and rendering;
- `repo-lint-policy-sarj`: Sarj products, topology, dependency rules, and remediation guidance;
- `sarj-repo-lint`: the CLI assembly.

This is a private prototype. It does not move files, rewrite imports, generate source,
run package managers, call cloud APIs, deploy, or prove live operational state.

## Quick start

Requires Python 3.12+ and uv.

```bash
uv sync --frozen
uv run repo-lint inspect /path/to/repository
uv run repo-lint report /path/to/repository --policy sarj
uv run repo-lint rules --policy sarj
uv run repo-lint explain sarj/graph/cross-product-import --policy sarj
uv run repo-lint schema
```

Machine consumers should use canonical JSON:

```bash
uv run repo-lint report /path/to/repository \
  --policy sarj \
  --format json
```

JSON is the authoritative `report`/`check` interface. Standard output contains exactly one JSON value;
operational errors are represented as `completion: "incomplete"`,
`conclusion: "inconclusive"`, and exit 2. `inspect` has its own versioned inventory envelope.

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
policy_version = 2

[[components]]
id = "platform.agent"
kind = "application"
product = "platform"
path = "applications/platform/agent"
owner = "@example/platform"

[[components.dependencies]]
target = "platform.request-signing"
type = "package-dependency"

[[components]]
id = "platform.request-signing"
kind = "product-library"
product = "platform"
capability = "request-signing"
path = "libraries/python/platform/request-signing"
owner = "@example/platform"
```

The manifest is strict: unknown keys, unknown component/edge kinds, duplicate IDs, unsafe paths,
invalid kind-specific product/capability fields, missing targets, and mismatched policy versions
make analysis incomplete or produce a precise structural finding. `legacy = true` is
inventory metadata only and never suppresses a rule; reviewed legacy debt lives in the exact
baseline. Intentional moves use an explicit `[[migration_paths]]` record.

Exceptions are exact `(rule_id, component_id, manifest_anchor, fingerprint)` occurrences with
owner, issue, reason, creation date, and a maximum 90-day ISO expiry.
When exceptions exist, callers must pass `--as-of YYYY-MM-DD` so results never depend silently on
the machine clock.

Ratchet mode reads `.repo-lint/baseline.json`. Baselines are reviewed debt records, not suppression
counts:

```json
{
  "schema_version": 1,
  "repository_id": "example-repository",
  "policy": "sarj",
  "policy_version": 2,
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

The current Sarj policy blocks only deterministic structural violations and invalid declarations. It evaluates
owner-declared manifest facts; it does not prove that declared paths exist, that every tracked
package or component is represented, or that an old path moved safely. Operational target paths
for Terraform, Cloud Build, Kubernetes, and Cloudflare remain non-blocking guidance until typed
evidence adapters can validate state boundaries, build contexts, and runtime configuration.

The linter never equates a
workflow file with proof that a deployment, approval, artifact promotion, rollback, or cloud IAM
policy actually worked.

See [architecture.md](docs/architecture.md), [diagnostics.md](docs/diagnostics.md), and
[rule-evaluation.md](docs/rule-evaluation.md).
The proposed reusable-code, repository-layout, Actions, Cloud Build, and deployment conventions are
in [repository-policy.md](docs/repository-policy.md).

## Development

```bash
uv sync
uv run pytest
uvx --isolated --python 3.14 --from sarj-standards==5.2.0 \
  sarj-standards check --trust-repository-code
```

No license is granted while this remains a private evaluation prototype.
