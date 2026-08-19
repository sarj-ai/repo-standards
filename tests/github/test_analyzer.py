# ruff: file-ignore[line-too-long]

from __future__ import annotations

from repo_lint.core import DeliveryConfig, SourceLocation
from repo_lint.github import (
    BranchEvidence,
    RepositoryEvidence,
    RulesetEvidence,
    WorkflowDocument,
    analyze,
)


def _config() -> DeliveryConfig:
    return DeliveryConfig(
        provider="github",
        repository="acme/widgets",
        production_branch="main",
        preview_branch="preview",
        development_branch="dev",
        sync_workflows=(".github/workflows/sync.yml",),
    )


def _evidence(*, protected: bool = True) -> RepositoryEvidence:
    branches = tuple(
        BranchEvidence(
            name,
            protected,
            ("gate",) if protected else (),
            "a" * 40 if name == "main" else "b" * 40,
        )
        for name in ("main", "preview", "dev")
    )
    return RepositoryEvidence(
        repository="acme/widgets",
        default_branch="main",
        branches=branches,
        rulesets=(),
        allow_auto_merge=True,
        actions_default_workflow_permissions="read",
        actions_can_approve_pull_requests=False,
    )


def _safe_workflow() -> WorkflowDocument:
    return WorkflowDocument(
        ".github/workflows/sync.yml",
        b"""name: backsync
on:
  push:
    branches: [main, preview]
  schedule:
    - cron: '17 * * * *'
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
concurrency:
  group: backsync
  cancel-in-progress: false
jobs:
  main-to-preview:
    if: github.event_name != 'push' || github.ref == 'refs/heads/main'
    timeout-minutes: 35
    env:
      AUTHOR_TOKEN: ${{ secrets.BACKSYNC_TOKEN }}
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - run: |
          main_sha=$(GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/ref/heads/main --jq .object.sha)
          merged_tree=$(git merge-tree --write-tree origin/preview origin/main)
          preview_tree=$(git rev-parse 'origin/preview^{tree}')
          sync_branch="automation/sync-main-${main_sha:0:12}"
          GH_TOKEN="$AUTHOR_TOKEN" gh api --method POST repos/acme/widgets/git/refs -f ref="refs/heads/$sync_branch" -f sha="$main_sha"
          number=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr list --base preview --head "$sync_branch" --json number)
          if [ -z "$number" ]; then
            GH_TOKEN="$AUTHOR_TOKEN" gh pr create --base preview --head "$sync_branch"
          fi
          pr=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr view "$number" --json headRefOid,mergeable)
          head_oid=$(echo "$pr" | jq -r .headRefOid)
          if [ "$head_oid" != "$main_sha" ]; then exit 1; fi
          if [ "$mergeable" = "CONFLICTING" ]; then exit 1; fi
          GH_TOKEN="$AUTHOR_TOKEN" gh pr merge "$number" --auto --squash --match-head-commit "$main_sha"
  preview-to-dev:
    if: github.event_name != 'push' || github.ref == 'refs/heads/preview'
    timeout-minutes: 35
    env:
      AUTHOR_TOKEN: ${{ secrets.BACKSYNC_TOKEN }}
    steps:
      - run: |
          preview_sha=$(GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/ref/heads/preview --jq .object.sha)
          old_dev=$(GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/ref/heads/dev --jq .object.sha)
          status=$(GH_TOKEN="$AUTHOR_TOKEN" gh api "repos/acme/widgets/compare/$preview_sha...$old_dev" --jq .status)
          sync_branch="automation/sync-preview-${preview_sha:0:12}"
          GH_TOKEN="$AUTHOR_TOKEN" gh api --method POST repos/acme/widgets/git/refs -f ref="refs/heads/$sync_branch" -f sha="$preview_sha"
          number=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr list --base dev --head "$sync_branch" --json number)
          if [ -z "$number" ]; then
            GH_TOKEN="$AUTHOR_TOKEN" gh pr create --base dev --head "$sync_branch"
          fi
          pr=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr view "$number" --json headRefOid,mergeable)
          head_oid=$(echo "$pr" | jq -r .headRefOid)
          if [ "$head_oid" != "$preview_sha" ]; then exit 1; fi
          if [ "$mergeable" = "CONFLICTING" ]; then exit 1; fi
          GH_TOKEN="$AUTHOR_TOKEN" gh pr merge "$number" --auto --merge --match-head-commit "$preview_sha"
""",
    )


def _rule_ids(report: object) -> set[str]:
    return {str(item.rule_id) for item in report.diagnostics}  # type: ignore[attr-defined]


def test_known_good_backsync_passes_all_rules() -> None:
    report = analyze(
        _config(),
        _evidence(),
        (_safe_workflow(),),
        repository_files=(".github/CODEOWNERS", ".github/dependabot.yml"),
        selected_revision="a" * 40,
    )
    assert report.completion == "complete"
    assert report.conclusion == "passed"
    assert not report.diagnostics


def test_missing_edge_and_safety_are_one_blocking_diagnostic() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/sync.yml",
        b"""on: push
jobs:
  sync:
    steps:
      - uses: actions/checkout@v4
      - run: gh pr create --base preview --head main
""",
    )
    report = analyze(_config(), _evidence(), (workflow,), selected_revision="a" * 40)
    errors = [item for item in report.diagnostics if item.severity == "error"]
    assert len(errors) == 1
    assert str(errors[0].rule_id) == "sarj/delivery/hotfix-backsync"
    assert "preview->dev" in errors[0].observed
    assert "automatic PR edge main->preview" in errors[0].observed


def test_branch_trio_auto_detects_without_toml_config() -> None:
    report = analyze(None, _evidence(), (), repository_files=(), selected_revision="a" * 40)
    assert "sarj/delivery/hotfix-backsync" in _rule_ids(report)


def test_selected_non_default_revision_is_inconclusive_for_delivery() -> None:
    evidence = _evidence()
    evidence = RepositoryEvidence(
        repository=evidence.repository,
        default_branch=evidence.default_branch,
        branches=tuple(
            BranchEvidence(
                branch.name,
                branch.protected,
                branch.required_status_checks,
                "a" * 40 if branch.name == "main" else "b" * 40,
            )
            for branch in evidence.branches
        ),
        rulesets=evidence.rulesets,
        allow_auto_merge=evidence.allow_auto_merge,
        actions_default_workflow_permissions=evidence.actions_default_workflow_permissions,
        actions_can_approve_pull_requests=evidence.actions_can_approve_pull_requests,
    )

    report = analyze(None, evidence, (), selected_revision="c" * 40)

    assert report.completion == "incomplete"
    assert "sarj/delivery/hotfix-backsync" not in _rule_ids(report)
    assert "not the live main branch head" in report.execution_issues[0].message
    assert report.execution_issues[0].code == "github.default-branch-revision-mismatch"
    assert report.execution_issues[0].retryable
    assert "Fetch and audit" in report.execution_issues[0].remediation[0]


def test_live_delivery_without_selected_revision_is_inconclusive() -> None:
    report = analyze(_config(), _evidence(), (_safe_workflow(),))

    assert report.completion == "incomplete"
    assert "sarj/delivery/hotfix-backsync" not in _rule_ids(report)
    assert "selected Git revision" in report.execution_issues[0].message


def test_canonical_repository_alias_and_case_match_declared_identity() -> None:
    source = _evidence()
    evidence = RepositoryEvidence(
        repository="sarj-ai/banking",
        requested_repository="SARJ-AI/NOURA-BE",
        default_branch=source.default_branch,
        branches=source.branches,
        rulesets=source.rulesets,
        allow_auto_merge=source.allow_auto_merge,
        actions_default_workflow_permissions=source.actions_default_workflow_permissions,
        actions_can_approve_pull_requests=source.actions_can_approve_pull_requests,
    )
    config = DeliveryConfig(repository="sarj-ai/noura-be")

    report = analyze(config, evidence, (), selected_revision="a" * 40)

    assert report.completion == "complete"
    assert not report.execution_issues
    assert "sarj/delivery/hotfix-backsync" in _rule_ids(report)


def test_no_branch_trio_does_not_infer_delivery_intent() -> None:
    evidence = RepositoryEvidence(
        repository="acme/widgets",
        default_branch="main",
        branches=(BranchEvidence("main", protected=False),),
        rulesets=(),
        allow_auto_merge=False,
        actions_default_workflow_permissions=None,
        actions_can_approve_pull_requests=None,
    )
    report = analyze(None, evidence, ())
    assert "sarj/delivery/hotfix-backsync" not in _rule_ids(report)


def test_missing_external_evidence_is_inconclusive_not_a_false_finding() -> None:
    report = analyze(_config(), None, (_safe_workflow(),))
    assert report.completion == "incomplete"
    assert report.conclusion == "inconclusive"
    assert "sarj/delivery/hotfix-backsync" not in _rule_ids(report)
    assert report.execution_issues[0].code == "github.required-evidence-unavailable"


def test_sha_hardening_and_governance_warnings_are_consolidated() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/ci.yml",
        b"""on: pull_request
jobs:
  test:
    steps:
      - uses: vendor/action@v2
""",
    )
    evidence = RepositoryEvidence(
        repository="acme/widgets",
        default_branch="main",
        branches=(BranchEvidence("main", protected=False),),
        rulesets=(RulesetEvidence("queue", "active", "branch", ("merge_queue",)),),
        allow_auto_merge=False,
        actions_default_workflow_permissions="write",
        actions_can_approve_pull_requests=True,
    )
    report = analyze(None, evidence, (workflow,))
    assert _rule_ids(report) == {
        "sarj/github/actions-sha-pinning",
        "sarj/github/explicit-permissions",
        "sarj/github/job-timeouts",
        "sarj/github/merge-queue-trigger",
        "sarj/github/repository-governance",
    }
    assert all(item.severity == "warning" for item in report.diagnostics)
    queue = next(
        item for item in report.diagnostics if str(item.rule_id).endswith("merge-queue-trigger")
    )
    assert "merge_group" in queue.expected


def test_repeated_mutable_action_is_one_finding_with_related_locations() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/ci.yml",
        b"""on: pull_request
permissions: {}
jobs:
  first:
    timeout-minutes: 5
    steps:
      - uses: vendor/action@v2
  second:
    timeout-minutes: 5
    steps:
      - uses: vendor/action@v2
""",
    )

    report = analyze(None, None, (workflow,))
    findings = [
        item
        for item in report.diagnostics
        if str(item.rule_id) == "sarj/github/actions-sha-pinning"
    ]

    assert len(findings) == 1
    assert findings[0].location == SourceLocation(path=workflow.path, line=7)
    assert findings[0].related_locations[0].location == SourceLocation(path=workflow.path, line=11)


def test_mutable_installs_and_suppressed_vulnerability_gate_are_warnings() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/security.yml",
        b"""on: pull_request
permissions: {}
jobs:
  audit:
    timeout-minutes: 5
    continue-on-error: true
    steps:
      - run: |
          uv sync
          uv run pip-audit || true
  frontend:
    timeout-minutes: 5
    steps:
      - run: pnpm install
""",
    )

    report = analyze(None, None, (workflow,))

    assert _rule_ids(report) == {
        "sarj/github/immutable-installs",
        "sarj/github/vulnerability-gate",
    }
    immutable = next(
        item for item in report.diagnostics if str(item.rule_id).endswith("immutable-installs")
    )
    assert "audit: uv sync" in immutable.observed
    assert "frontend: pnpm install" in immutable.observed


def test_locked_installs_and_blocking_scanners_pass_supply_chain_rules() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/security.yml",
        b"""on: pull_request
permissions: {}
jobs:
  audit:
    timeout-minutes: 5
    steps:
      - run: |
          uv sync --all-packages --locked
          uv sync \
            --frozen
          uvx pip-audit==2.9.0 --no-deps -r requirements.txt
  frontend:
    timeout-minutes: 5
    steps:
      - run: yarn install --immutable
""",
    )

    report = analyze(None, None, (workflow,))

    assert "sarj/github/immutable-installs" not in _rule_ids(report)
    assert "sarj/github/vulnerability-gate" not in _rule_ids(report)


def test_global_tool_installs_are_outside_lockfile_rule_scope() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/tools.yml",
        b"""on: pull_request
permissions: {}
jobs:
  tools:
    timeout-minutes: 5
    steps:
      - run: |
          npm install -g squawk-cli@2.57.0
          npm install --global playwright@1.0.0
""",
    )

    report = analyze(None, None, (workflow,))

    assert "sarj/github/immutable-installs" not in _rule_ids(report)


def test_distinct_workflow_findings_have_distinct_finding_keys() -> None:
    workflow = WorkflowDocument(
        ".github/workflows/ci.yml",
        b"""on: pull_request
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: uv sync
""",
    )

    report = analyze(None, None, (workflow,))
    keys = [item.finding_key for item in report.diagnostics]

    assert len(keys) == len(set(keys))


def test_decoy_text_and_one_real_edge_cannot_prove_backsync() -> None:
    content = _safe_workflow().content.replace(
        b"  preview-to-dev:\n",
        b"decoy: |\n  preview dev gh pr create --base dev --head preview\n  gh pr merge --auto --merge --match-head-commit source_sha headRefOid CONFLICTING exit 1\n  ${{ secrets.OTHER_TOKEN }}\n  preview-to-dev:\n  if: false\n",
    )
    report = analyze(
        _config(),
        _evidence(),
        (WorkflowDocument(".github/workflows/sync.yml", content),),
        selected_revision="a" * 40,
    )

    finding = next(
        item for item in report.diagnostics if str(item.rule_id).endswith("hotfix-backsync")
    )
    assert "preview->dev" in finding.observed


def test_wrong_push_branch_and_unrelated_secret_do_not_satisfy_safety() -> None:
    content = (
        _safe_workflow()
        .content.replace(b"branches: [main, preview]", b"branches: [other]")
        .replace(
            b"AUTHOR_TOKEN: ${{ secrets.BACKSYNC_TOKEN }}",
            b"UNUSED_TOKEN: ${{ secrets.BACKSYNC_TOKEN }}",
        )
    )
    report = analyze(
        _config(),
        _evidence(),
        (WorkflowDocument(".github/workflows/sync.yml", content),),
        selected_revision="a" * 40,
    )

    finding = next(
        item for item in report.diagnostics if str(item.rule_id).endswith("hotfix-backsync")
    )
    assert "safety controls for main->preview" in finding.observed
    assert "safety controls for preview->dev" in finding.observed


def test_ignored_source_branch_and_negative_condition_do_not_satisfy_safety() -> None:
    content = (
        _safe_workflow()
        .content.replace(b"branches: [main, preview]", b"branches-ignore: [main]")
        .replace(
            b"github.ref == 'refs/heads/main'",
            b"github.ref != 'refs/heads/main'",
        )
    )

    report = analyze(
        _config(),
        _evidence(),
        (WorkflowDocument(".github/workflows/sync.yml", content),),
        selected_revision="a" * 40,
    )

    finding = next(
        item for item in report.diagnostics if str(item.rule_id).endswith("hotfix-backsync")
    )
    assert "safety controls for main->preview" in finding.observed
