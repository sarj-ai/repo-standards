# Standards routing

Before editing a rule, state `Routing: <repository>, because <required evidence>`.

- Use `sarj-ai/repo-standards` when a finding depends on the exact tracked Git tree: a
  filename's existence or placement, repository topology or migrations, pull-request size,
  ownership, delivery/GitHub state, or a repository-wide API/document set.
- Use `sarj-ai/code-standards` when a finding depends on source or configuration semantics in
  Python, TypeScript, SQL, Terraform/HCL, Markdown, YAML, JSON, or shell, or changes lint
  engines, presets, baselines, adoption, release, or fleet rollout.
- A path may select a semantic parser. If the path or basename alone is sufficient to emit the
  finding, the rule belongs here.

Examples: banning a tracked verifier filename belongs here; rejecting a Terraform expression
that derives access from `var.environment` belongs in `code-standards`.

Before review, run `uv run ruff check .`, `uv run basedpyright`, `uv run pytest`, and the docs
lint/check/build commands when catalog or public documentation changes.
