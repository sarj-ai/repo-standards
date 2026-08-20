# repo-standards

`repo-standards` measures pull-request review size without executing repository code. Its
repository rules are available for review but remain disabled until individually approved
and explicitly activated by a consumer.

After a rule is approved, opt in per run with `--enable-rule <rule-id>`. Approval alone
never enables a rule, and the option may be repeated for multiple approved rules.

## Run it

Use the current release without installing it:

```bash
uvx --from repo-standards repo-standards pull-request size . --base origin/main
```

For a persistent user installation:

```bash
uv tool install repo-standards
repo-standards pull-request size . --base origin/main
```

Upgrade with `uv tool upgrade repo-standards`. Automation should pin the package version or
the GitHub Action's full commit SHA.

## GitHub Action

The Action measures size only. It enables no repository lint rules and needs no inputs on a
`pull_request` event.

```yaml
name: Pull-request size

on:
  pull_request:

permissions:
  contents: read

jobs:
  size:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: sarj-ai/repo-standards@<full-commit-sha> # v1.0.0
```

The Action emits counted, excluded, and total line counts plus canonical JSON. Tests are
recognized across Python, JavaScript/TypeScript, Go, JVM, Android, Xcode/Swift, .NET, Ruby,
and Bats conventions. Mark generated or machine-owned artifacts in the trusted base revision:

```gitattributes
path/to/generated/** pr-size-excluded
```

Thresholds, labels, comments, and approval requirements remain consumer policy. Use
`pull_request`, never `pull_request_target`; this metric is not a security gate.

## Live GitHub evidence

Live governance checks are explicit and read-only. Supply a repository whose token can read
metadata, branch protection, rulesets, and Actions settings:

```bash
export SARJ_REPO_LINT_GITHUB_TOKEN=...
repo-standards check . \
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
  --from sarj-standards-bootstrap==2.0.0 \
  code-standards check --trust-repository-code
```

Build the same wheel and source distribution used by publishing:

```bash
uv build --no-sources
```

Releases are reconcilable. The protected workflow independently repairs a missing PyPI
publication or GitHub Release from the same verified source revision.
