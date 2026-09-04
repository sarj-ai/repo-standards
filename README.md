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
```

For a persistent user installation:

```bash
uv tool install repo-standards
repo-standards pull-request size . --base origin/main
```

Upgrade with `uv tool upgrade repo-standards`. Automation should pin the package version or
the GitHub Action's full commit SHA.

## Pull-request commit policy

`pull-request commits` is strict by default and defaults to five non-merge pull-request commits.
A pull request above that limit passes only when every commit subject begins with the complete,
exact ASCII series `(1/N) ` through `(N/N) `, unless a trusted transition exemption is verified.
Indices must be unique, totals must match the actual commit count, and zero-padded or partial
markers do not pass.

Authoritative GitHub CI must fetch complete history and pass the event payload as a file. Repo
Standards reads the exact direct PR base/head objects, refs, and numeric repository identities;
it never uses the synthetic merge commit in `GITHUB_SHA`. Exit status `1` means the history
violates policy; `2` means required evidence was incomplete.

```bash
repo-standards pull-request commits . --github-event "$GITHUB_EVENT_PATH"
```

Local hooks use checked-in configuration and remain deliberately advisory because history may be
shallow or stale and `pre-commit` runs before the pending commit exists. `--quiet` suppresses only
a completed pass; findings and incomplete analysis remain visible. `pre-push` closes the normal
one-commit feedback lag, while exact CI remains authoritative.

```bash
repo-standards pull-request commits . --advisory --quiet
```

When a series is not intentional, prefer one reviewable commit:

```bash
git rebase -i "$(git merge-base origin/dev HEAD)"
```

Configure local base discovery and narrowly scoped promotion/synchronization transitions in schema
5. Strict CI reads this TOML from the exact PR **base** commit, so a PR cannot raise its own limit
or grant itself an exemption. Each transition also requires the exact destination, a same-repository
PR, an immutable source-SHA branch suffix equal to the PR head, and proof that the head remains in
the configured source ancestry. Protect automation branch namespaces so only the promotion app can
create or update them.

```toml
schema_version = 5

[pull_request.commit_history]
advisory_base_ref = "dev"
# maximum_commits = 5

[[pull_request.commit_history.transitions]]
id = "dev-preview"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-dev-"
# sha_prefix_length = 12
```

Repeat an explicit table for every trusted edge. Repo Standards rejects ambiguous prefixes,
unsafe refs, duplicate IDs, and more than 64 transitions. Missing configuration keeps the strict
five-commit default and grants no transition exemptions. Existing explicit evidence and JSON
transition flags remain supported for non-GitHub providers and migration from 5.9.

Stacked PRs are evaluated against each PR's direct base, never the whole stack base. The composite
Action reports `merge_group` as explicitly not applicable because a merge-queue commit aggregates
already-evaluated PRs; keep the containing required workflow enabled for `merge_group` so GitHub
still receives its required status. The explicit `edited` activity ensures retargeting always
re-evaluates the new exact base.

## Pull-request commits Action and pre-commit hook

After a full-history checkout, use the dedicated Action inside an existing required job. Pin the
release to its complete immutable commit SHA.

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened, edited]
  merge_group:
    types: [checks_requested]

- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
  with:
    fetch-depth: 0
    persist-credentials: false
- uses: sarj-ai/repo-standards/pull-request-commits@FULL_RELEASE_COMMIT_SHA # v5.10.0
```

The published `repo-standards-pull-request-commits` pre-commit hook runs in advisory mode at both
`pre-commit` and `pre-push`. Consumers that already lock Repo Standards may instead invoke the same
quiet advisory command from their existing hook manager to avoid a duplicate environment.

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
- Advisory commit-history analysis reports incomplete evidence without blocking local commits.
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
