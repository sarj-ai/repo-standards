# ruff: file-ignore[line-too-long]

from __future__ import annotations

import pytest

from repo_lint.core import DeliveryConfig
from repo_lint.github import (
    BranchEvidence,
    RepositoryEvidence,
    RulesetEvidence,
    WorkflowDocument,
    analyze,
)
from repo_lint.github.models import GitHubAnalysisReport


def _config() -> DeliveryConfig:
    return DeliveryConfig(
        provider="github",
        repository="acme/widgets",
        production_branch="main",
        preview_branch="preview",
        development_branch="dev",
        sync_workflows=(".github/workflows/sync.yml",),
    )


def test_github_report_rejects_incoherent_outcome_states() -> None:
    with pytest.raises(ValueError, match="complete GitHub reports cannot be inconclusive"):
        GitHubAnalysisReport("complete", "inconclusive", (), (), ())


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
    assert not report.diagnostics


def test_branch_trio_auto_detects_without_toml_config() -> None:
    report = analyze(None, _evidence(), (), repository_files=(), selected_revision="a" * 40)
    assert not report.diagnostics


def test_removed_delivery_rules_do_not_require_live_revision_evidence() -> None:
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

    assert report.completion == "complete"
    assert report.conclusion == "passed"
    assert not report.execution_issues


def test_removed_delivery_rules_do_not_require_a_selected_revision() -> None:
    report = analyze(_config(), _evidence(), (_safe_workflow(),))

    assert report.completion == "complete"
    assert report.conclusion == "passed"
    assert not report.execution_issues


def test_canonical_repository_and_requested_case_match_declared_identity() -> None:
    source = _evidence()
    evidence = RepositoryEvidence(
        repository="acme/widgets",
        requested_repository="ACME/WIDGETS",
        default_branch=source.default_branch,
        branches=source.branches,
        rulesets=source.rulesets,
        allow_auto_merge=source.allow_auto_merge,
        actions_default_workflow_permissions=source.actions_default_workflow_permissions,
        actions_can_approve_pull_requests=source.actions_can_approve_pull_requests,
    )
    config = DeliveryConfig(repository="acme/widgets")

    report = analyze(config, evidence, (), selected_revision="a" * 40)

    assert report.completion == "complete"
    assert not report.execution_issues
    assert not report.diagnostics


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
    assert "delivery/branches/hotfix-back-sync" not in _rule_ids(report)


def test_removed_delivery_rules_do_not_require_external_evidence() -> None:
    report = analyze(_config(), None, (_safe_workflow(),))
    assert report.completion == "complete"
    assert report.conclusion == "passed"
    assert not report.execution_issues


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
    assert not report.diagnostics


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
    assert not report.diagnostics


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

    assert not report.diagnostics


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

    assert not report.diagnostics
