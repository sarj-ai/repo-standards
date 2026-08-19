# sarj-repo-lint

`sarj-repo-lint` performs deterministic, read-only analysis of repository architecture,
API contracts, delivery policy, and pull-request size. It inspects committed data without
executing or modifying the repository under review.

## Run it

Use the current release without installing it:

```bash
uvx sarj-repo-lint github . --format text
uvx sarj-repo-lint pull-request size . --base origin/main
```

For a reproducible repository dependency, let uv record the resolved version:

```bash
uv add --dev sarj-repo-lint
uv run --frozen repo-lint github . --format text
```

The installed package provides both `repo-lint` and `sarj-repo-lint`. Run
`repo-lint capabilities` for the machine-readable feature contract, `repo-lint rules` for
the installed rule catalog, and `repo-lint --version` for the resolved release.

## GitHub Action

Organization repositories can run the exact source pinned by a full commit SHA. Private
consumers must first be granted access under the action repository settings.

```yaml
name: Repository policy

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  repository-policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: sarj-ai/sarj-repo-lint@<full-commit-sha>
        with:
          root: .
          policy: sarj
          mode: ratchet
```

Pull-request sizing uses the same action and emits counted, excluded, and total line counts
plus the canonical JSON report:

```yaml
- name: Calculate review size
  id: size
  uses: sarj-ai/sarj-repo-lint@<full-commit-sha>
  with:
    operation: pull-request-size
    root: .
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
- run: echo '${{ steps.size.outputs.counted-lines }} review lines'
```

Tests are recognized by conventional Python and JavaScript/TypeScript paths. Mark exact
generated or machine-owned artifacts in the trusted base revision:

```gitattributes
path/to/generated/** pr-size-excluded
```

The size report classifies all changed lines and lists the largest counted files. Thresholds,
labels, comments, and approval requirements remain consumer policy.

## Live GitHub evidence

Live governance checks are explicit and read-only. Supply a repository whose token can read
metadata, branch protection, rulesets, and Actions settings:

```bash
export SARJ_REPO_LINT_GITHUB_TOKEN=...
repo-lint check . \
  --github-repository owner/repository \
  --require-github-evidence \
  --policy sarj \
  --format json
```

Without `SARJ_REPO_LINT_GITHUB_TOKEN`, the CLI can reuse an authenticated `gh` session. Live
delivery checks require the selected revision to match the default-branch head.

## Safety model

- Repository contents come from one exact Git tree.
- Workflow YAML and API descriptions are parsed as inert data.
- GitHub access is read-only and credentials never come from inspected configuration.
- Missing required evidence produces an inconclusive result rather than a false pass.
- The linter has no autofix or repository mutation mode.

Repositories with production, preview, and development branches can declare and verify
continuous hotfix propagation. See [Delivery and CI/CD policy](docs/delivery-policy.md) for
the complete evidence model.

## Development

```bash
uv sync --locked
uv run pytest
uv run ruff check .
uv run basedpyright
uvx --no-config --isolated --python 3.14 \
  --from sarj-standards-bootstrap==1.0.3 \
  sarj-standards check --trust-repository-code
```

Build the same wheel and source distribution used by publishing:

```bash
uv build --no-sources
```

Releases are atomic. Update the root manifest with `uv version`, merge the reviewed change to
`main`, and the protected publish workflow builds and verifies both artifacts, publishes them
through PyPI Trusted Publishing, then creates the matching GitHub Release.
