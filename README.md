# repo-standards

`repo-standards` measures pull-request review size without executing repository code.

## Where rules belong

- Exact tracked-tree facts—filenames, placement, topology, migrations, pull-request size,
  ownership, delivery/GitHub state, and repository-wide API/document sets—belong here.
- Source and configuration semantics for Python, TypeScript, SQL, Terraform/HCL, Markdown,
  YAML, JSON, and shell belong in `sarj-ai/code-standards`.

## Run it

Sarj repositories should use the single Code Standards setup path. It installs the canonical
staged repository check, managed commit-message check, and authoritative pull-request history
workflow without creating a second Python environment:

```bash
uvx --no-config --isolated --python 3.14 --from code-standards code-standards setup
code-standards doctor
```

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

## Safety model

- Repository contents come from one exact Git tree.
- Workflow YAML and API descriptions are parsed as inert data.
- Missing required evidence produces an inconclusive result rather than a false pass.
- Advisory commit-history analysis reports incomplete evidence without blocking local commits.
- Repository checks remain read-only. `commit-message --fix-safe` changes only the
  supplied message file. The separate POSIX `pull-request prepare` operation
  requires `--trust-repository-code`, rewrites only a clean feature branch before
  its first PR, and runs native commit hooks and signing. Hooks may access the
  network; preparation itself never pushes or creates a PR.

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
