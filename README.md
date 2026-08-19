# sarj-repo-lint

`sarj-repo-lint` is a deterministic, read-only linter for repository architecture,
API contracts, and delivery policy. It inspects committed configuration and an exact Git
tree. When requested, it can also compare those declarations with GitHub state; it never
executes repository code or changes the repository it inspects.

## Delivery policy

Repositories that maintain production, preview, and development branches should continuously
propagate hotfixes in this direction:

```text
main -> preview -> dev
```

The delivery linter checks that both propagation edges have the required guarded workflow
structure. It also reports advisory CI/CD findings for action pinning, explicit permissions,
job timeouts, merge-queue triggers, basic branch protection, ownership metadata, and
dependency-update configuration.

Conventional `main`, `preview`, and `dev` branches are auto-detected when live GitHub evidence
is explicitly requested. A
repository with different branch names, or one that wants explicit offline intent, can add a
`[delivery]` table to `.repo-lint/repository.toml`:

```toml
[delivery]
provider = "github"
repository = "sarj-ai/example"
production_branch = "main"
preview_branch = "preview"
development_branch = "dev"
sync_workflows = [".github/workflows/sync-preview-to-dev.yml"]
```

All fields are optional. The branch defaults are shown above; `repository` defaults to the
repository being inspected and `sync_workflows` defaults to an empty list. Branch names must
be distinct and workflow paths must be repository-relative.

The table is a policy declaration, not an automation switch. Adding it does **not** create
branches, install workflows, merge pull requests, enable auto-merge, or alter branch rules.
See [Delivery and CI/CD policy](docs/delivery-policy.md) for the evidence model and complete
behavior.

## GitHub Action

Organization repositories can consume the linter directly as a private GitHub Action. This
avoids distributing a personal access token or duplicating the checkout and locked-install
sequence in every consumer:

```yaml
- name: Enforce repository architecture
  uses: sarj-ai/sarj-repo-lint@<full-commit-sha>
  with:
    root: .
    policy: sarj
    mode: ratchet
```

The action remains read-only and inspects the caller's committed checkout. Repository
administrators must grant the consuming repository access to this private action. Pin a full
commit SHA; never consume a moving branch.

## Safety model

- Repository contents are read from one exact Git tree.
- Workflow YAML is parsed as inert data and never executed.
- GitHub access is read-only; credentials come from `SARJ_REPO_LINT_GITHUB_TOKEN` or an
existing authenticated `gh` CLI session and are never read from repository configuration.
- Missing required external evidence produces an inconclusive result, never a false pass.
- Remediation is guidance only. The linter has no autofix or repository mutation mode.

Use `repo-lint capabilities` for the installed feature contract and `repo-lint rules` for the
versioned rule catalog.

## Pull-request size analysis

The CLI can calculate review-sized churn between two Git revisions without calling GitHub or
mutating repository state:

```bash
uvx --from sarj-repo-lint==0.6.0 repo-lint pull-request size . \
  --base origin/main --head HEAD --format json
```

Conventional Python and JavaScript/TypeScript test paths are excluded automatically. Repositories
can mark exact generated artifacts and other machine-owned files with the bare
`pr-size-excluded` Git attribute. Attributes are always read from the trusted base revision, so a
pull request cannot change its own size policy. The result includes counted and excluded totals,
category totals, and the largest counted files. Thresholds and GitHub mutations remain consumer
policy; the command only reports deterministic evidence.

The pinned composite action exposes the same analyzer for consumers that have organization access
to the private action:

```yaml
- id: size
  uses: sarj-ai/sarj-repo-lint@<full-commit-sha>
  with:
    operation: pull-request-size
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.event.pull_request.head.sha }}
```

## Quick start

Install the locked development environment and run an offline report against an exact Git tree:

```bash
uv sync --locked
uv run repo-lint report /path/to/repository --policy sarj --format pretty-json
```

Live branch and governance evidence is explicit and read-only. Supply a repository and token
whose scopes can read repository metadata, branch protection, rulesets, and Actions settings:

```bash
export SARJ_REPO_LINT_GITHUB_TOKEN=...
uv run repo-lint check /path/to/repository \
  --github-repository owner/repository \
  --require-github-evidence \
  --policy sarj --format json
```

When `SARJ_REPO_LINT_GITHUB_TOKEN` is unset, the CLI reuses the authenticated `gh` context
without exporting or printing its token. Live delivery checks also require the
selected Git revision to equal the live default-branch head; audit a clean worktree at that
revision when checking branch automation.

Repositories do not need a Sarj architecture manifest to receive workflow checks. Use the
GitHub-specific command for an exact-tree audit, optionally adding live read-only evidence:

```bash
uv run repo-lint github /path/to/repository --format text
uv run repo-lint github /path/to/repository \
  --github-repository owner/repository --format json
```

Exit `0` means the selected mode is satisfied, exit `1` means blocking policy findings, and
exit `2` means analysis was incomplete. Advisory beta warnings are visible but do not block
strict mode. Adding or changing `[delivery]` changes policy applicability and the scope digest;
ratchet baselines must be regenerated and reviewed when changing Sarj policy versions.
