# repo-standards

`repo-standards` measures pull-request review size without executing repository code. Its
repository rules are available for review but remain disabled until individually approved
and explicitly activated by a consumer.

## Where rules belong

- Exact tracked-tree facts—filenames, placement, topology, migrations, pull-request size,
  ownership, delivery/GitHub state, and repository-wide API/document sets—belong here.
- Source and configuration semantics for Python, TypeScript, SQL, Terraform/HCL, Markdown,
  YAML, JSON, and shell belong in `sarj-ai/code-standards`.
- If a path alone is sufficient to produce the finding, use Repo Standards. If source content
  is necessary, use Code Standards.

After a rule is approved, activate its stable ID in `.repo-standards/repository.toml`:

```toml
enabled_rules = ["repository/artifacts/bespoke-iac-verifiers"]
```

The locked Repo Standards release supplies the current reviewed implementation. Manifests never
select historical rule versions; `--enable-rule <rule-id>@<version>` remains available only for
legacy manifests and calibration runs.

## Run it

Use the current release without installing it:

```bash
uvx --from repo-standards repo-standards pull-request size . --base origin/main
uvx --from repo-standards repo-standards pull-request schema-provenance . --base origin/main
```

For a persistent user installation:

```bash
uv tool install repo-standards
repo-standards pull-request size . --base origin/main
repo-standards pull-request schema-provenance . --base origin/main
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
      - uses: sarj-ai/repo-standards@89ed271aedaba854879d7b890f1a429b71460452 # v5.0.0
```

The Action emits counted, excluded, and total line counts plus canonical JSON. Tests are
recognized across Python, JavaScript/TypeScript, Go, JVM, Android, Xcode/Swift, .NET, Ruby,
and Bats conventions. Mark generated or machine-owned artifacts in the trusted base revision:

```gitattributes
path/to/generated/** pr-size-excluded
```

Thresholds, labels, comments, and approval requirements remain consumer policy. Use
`pull_request`, never `pull_request_target`; this metric is not a security gate.

## Safety model

- Repository contents come from one exact Git tree.
- Workflow YAML and API descriptions are parsed as inert data.
- Missing required evidence produces an inconclusive result rather than a false pass.
- The linter has no autofix or repository mutation mode.

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
