# repo-standards

`repo-standards` checks tracked trees and pull-request delivery policy.

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

Before opening a feature branch's first PR, prepare and push one commit with native hooks:

```bash
repo-standards pull-request push . --base origin/main --message "feat: describe the change" --trust-repository-code
```

This POSIX command requires a clean, complete checkout, a current fetched target and canonical
GitHub origin URLs naming one repository. Fresh metadata protects its default branch and rejects
forks or any prior open or closed PR. The captured destination owns the reads, lease, push and
confirmation; native hooks still run. Existing PRs and forks retain their normal workflow.
Local preparation remains available as `pull-request prepare`.

Upgrade with `uv tool upgrade repo-standards`. Automation should pin the package version or
the GitHub Action's full commit SHA.

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
