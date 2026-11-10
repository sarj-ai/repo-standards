# repo-standards

Check repository structure, pull-request size, commit messages, and Git history from exact
Git evidence. Repository rules are opt-in: review each rule before enabling its stable ID.

[Get started](https://engineering.sarj.ai/projects/repo-standards/getting-started/) ·
[Rules](https://engineering.sarj.ai/projects/repo-standards/rules/) ·
[Git policies](https://engineering.sarj.ai/projects/repo-standards/git-policies/) ·
[CLI](https://engineering.sarj.ai/projects/repo-standards/cli/) ·
[Schemas](https://engineering.sarj.ai/projects/repo-standards/schemas/)

## Run a size check

From a Git repository with [uv](https://docs.astral.sh/uv/getting-started/installation/) installed:

```bash
uvx --from repo-standards repo-standards pull-request size . --base origin/main
```

Replace `origin/main` with your target branch. Output includes counted, excluded, and total
changed lines. The size metric enables no repository rules.

## Set up local checks

Sarj repositories use the shared Code Standards setup for staged checks, commit-message
validation, and the authoritative pull-request history workflow:

```bash
uvx --no-config --isolated --python 3.14 --from code-standards code-standards setup
code-standards doctor
```

For standalone installation, rule activation, and pinned GitHub Actions examples, use the
[setup guide](https://engineering.sarj.ai/projects/repo-standards/getting-started/).
The [Git policy guide](https://engineering.sarj.ai/projects/repo-standards/git-policies/)
covers headers, PR descriptions, merge-risk verdicts, and trusted history checks.

## Where rules belong

| Required evidence | Owner |
| --- | --- |
| Tracked filenames, placement, topology, migrations, ownership, delivery/GitHub state, or repository-wide API/document sets | Repo Standards |
| Source or configuration semantics in Python, TypeScript, SQL, Terraform/HCL, Markdown, YAML, JSON, or shell | [Code Standards](https://github.com/sarj-ai/code-standards) |

If the path alone proves the finding, use Repo Standards. Route source and configuration
semantics to Code Standards.

## Evidence and safety

Repository checks read one exact Git tree or staged index and parse files as inert data.
They execute no repository code and provide no autofix. The commit-message hook separately
supports bounded casing and whitespace normalization with `--fix-safe`.

Missing required evidence produces an inconclusive result. Local history feedback is advisory;
CI checks the exact PR base and head with policy from the trusted base revision.

## Development

```bash
uv sync --locked
uv run ruff check .
uv run basedpyright
uv run pytest
```

For site changes, install locked dependencies and run the documentation checks:

```bash
npm --prefix apps/site ci --ignore-scripts --no-audit --no-fund
npm --prefix apps/site run lint
npm --prefix apps/site run check
npm --prefix apps/site test
npm --prefix apps/site run build
```

Preview with `npm --prefix apps/site run dev`. Build release artifacts with
`uv build --no-sources`. The protected release workflow can repair a missing PyPI publication
or GitHub Release from the same verified source revision.
