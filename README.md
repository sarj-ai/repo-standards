# repo-standards

`repo-standards` enforces deterministic repository, pull-request, commit, and API contract
policy without executing repository code.

## Run it

Sarj repositories adopt it through [Code Standards setup](https://github.com/sarj-ai/code-standards#readme)
rather than installing it separately.

Use the current release without installing it:

```bash
uvx --from repo-standards repo-standards pull-request size . --base origin/main
```

For a persistent user installation:

```bash
uv tool install repo-standards
repo-standards pull-request size . --base origin/main
```

Automation should pin the package version or the GitHub Action's full commit SHA.

## Safety model

- Repository contents come from one exact Git tree.
- Workflow YAML and API descriptions are parsed as inert data.
- Missing required evidence produces an inconclusive result rather than a false pass.
- Advisory commit-history analysis reports incomplete evidence without blocking local commits.

## Development

```bash
uv sync --locked
uv run pytest
uv run ruff check .
uv run basedpyright
```

Build the same wheel and source distribution used by publishing:

```bash
uv build --no-sources
```

Releases are reconcilable. The protected workflow independently repairs a missing PyPI
publication or GitHub Release from the same verified source revision.
