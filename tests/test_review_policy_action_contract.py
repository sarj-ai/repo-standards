from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import re

import pytest

from repo_standards.github_review_policy import (
    CollectedEvidence,
    GitHubClient,
    PullRequestSnapshot,
    ReconciliationError,
    check_conclusion,
    collect_required_checks,
    eligible_reviewer_ids,
    final_policy_decision,
    latest_human_reviews,
    merge_group_pull_request,
    merge_queue_head_sha,
    reconcile_merge_group,
    require_unchanged_evidence,
    required_check_names,
    review_policy_status_passed,
    trusted_manifest,
)


ROOT = Path(__file__).parents[1]
INPUT_KEY = re.compile(r"^  ([a-z][a-z-]+):$", re.MULTILINE)


def test_review_policy_action_contract() -> None:
    source = (ROOT / "pull-request-review-policy" / "action.yml").read_text(encoding="utf-8")
    inputs = source.split("inputs:\n", 1)[1].split("outputs:\n", 1)[0]

    assert set(INPUT_KEY.findall(inputs)) == {
        "root",
        "manifest-path",
        "pr-number",
        "merge-group-head-sha",
        "merge-group-head-ref",
        "github-token",
        "review-optional-enabled",
        "required-check-app-id",
        "policy-workflow-path",
    }
    assert "default: '15368'" in inputs
    assert "repo_standards.github_review_policy" in source
    assert "APPROVAL_TOKEN" not in source
    assert "GITHUB_TOKEN" in source


@pytest.mark.parametrize(
    ("lane_enabled", "same_repository", "author_is_bot", "draft", "expected"),
    [
        (True, True, False, False, (True, None)),
        (False, True, False, False, (False, "review_optional_lane_disabled")),
        (True, False, False, False, (False, "review_optional_fork_blocked")),
        (True, True, True, False, (False, "review_optional_bot_author_blocked")),
        (True, True, False, True, (False, "review_optional_draft_blocked")),
    ],
)
def test_tier_zero_runtime_gate(
    lane_enabled: bool,
    same_repository: bool,
    author_is_bot: bool,
    draft: bool,
    expected: tuple[bool, str | None],
) -> None:
    assert (
        final_policy_decision(
            policy_passed=True,
            tier=0,
            lane_enabled=lane_enabled,
            same_repository=same_repository,
            author_is_bot=author_is_bot,
            draft=draft,
        )
        == expected
    )


def test_non_tier_zero_runtime_gate_ignores_optional_lane() -> None:
    assert final_policy_decision(
        policy_passed=True,
        tier=1,
        lane_enabled=False,
        same_repository=False,
        author_is_bot=True,
        draft=True,
    ) == (True, None)


def test_failed_policy_stays_blocked_when_optional_lane_is_enabled() -> None:
    assert final_policy_decision(
        policy_passed=False,
        tier=0,
        lane_enabled=True,
        same_repository=True,
        author_is_bot=False,
        draft=False,
    ) == (False, None)


@pytest.mark.parametrize("manifest_path", ["", "/absolute.toml", "../escape.toml", "a/../b.toml"])
def test_trusted_manifest_rejects_unsafe_paths(
    tmp_path: Path,
    manifest_path: str,
) -> None:
    with pytest.raises(ReconciliationError, match="manifest-path"):
        trusted_manifest(
            tmp_path, "a" * 40, tmp_path / "manifest.toml", manifest_path=manifest_path
        )


def test_required_checks_come_from_trusted_manifest() -> None:
    manifest = {
        "pull_request": {
            "review_policy": {"required_checks": ["lint", "test"]},
        }
    }

    assert required_check_names(manifest) == ("lint", "test")


def test_rest_pagination_collects_every_page() -> None:
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    calls: list[str] = []

    def request(_method: str, path: str, **_kwargs: object) -> object:
        calls.append(path)
        return list(range(100)) if path.endswith("page=1") else [100]

    client.request = request  # type: ignore[method-assign]

    assert len(client.rest_pages("/items")) == 101
    assert calls == ["/items?per_page=100&page=1", "/items?per_page=100&page=2"]


@pytest.mark.parametrize(
    ("check", "expected"),
    [
        ({"status": "queued", "conclusion": None}, "pending"),
        ({"status": "completed", "conclusion": "success"}, "success"),
        ({"status": "completed", "conclusion": None}, "failure"),
    ],
)
def test_check_conclusions_fail_closed(check: dict[str, object], expected: str) -> None:
    assert check_conclusion(check) == expected


def test_required_check_uses_provider_head_sha() -> None:
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")

    def pages(path: str, **_kwargs: object) -> list[object]:
        if "check-runs" not in path:
            return []
        return [
            {
                "id": 1,
                "name": "lint",
                "status": "completed",
                "conclusion": "success",
                "head_sha": "b" * 40,
                "details_url": "https://github.com/owner/repo/actions/runs/123/job/456",
                "app": {"id": 15368},
            }
        ]

    client.rest_pages = pages

    with pytest.raises(ReconciliationError, match="different head SHA"):
        collect_required_checks(
            client,
            head_sha="a" * 40,
            names=("lint",),
            required_app_id=15368,
        )


def test_latest_reviews_exclude_author_and_bots_and_keep_latest_decisive() -> None:
    head = "a" * 40
    reviews = [
        {
            "id": 1,
            "user": {"id": 20, "login": "reviewer", "type": "User"},
            "state": "APPROVED",
            "submitted_at": "2026-01-01T00:00:00Z",
            "commit_id": head,
        },
        {
            "id": 2,
            "user": {"id": 20, "login": "reviewer", "type": "User"},
            "state": "CHANGES_REQUESTED",
            "submitted_at": "2026-01-02T00:00:00Z",
            "commit_id": head,
        },
        {
            "id": 3,
            "user": {"id": 10, "login": "author", "type": "User"},
            "state": "APPROVED",
            "submitted_at": "2026-01-03T00:00:00Z",
            "commit_id": head,
        },
        {
            "id": 4,
            "user": {"id": 30, "login": "policy[bot]", "type": "Bot"},
            "state": "APPROVED",
            "submitted_at": "2026-01-04T00:00:00Z",
            "commit_id": head,
        },
    ]

    assert latest_human_reviews(reviews, author_id=10, eligible_ids=frozenset({20})) == (
        {
            "reviewer": "20:reviewer",
            "state": "changes_requested",
            "commit_sha": head,
        },
    )


def test_invalid_review_shape_fails_closed() -> None:
    with pytest.raises(ReconciliationError, match="review id"):
        latest_human_reviews(
            [
                {
                    "id": "bad",
                    "user": {"id": 20, "login": "reviewer", "type": "User"},
                    "state": "APPROVED",
                    "submitted_at": "2026-01-01T00:00:00Z",
                    "commit_id": "a" * 40,
                }
            ],
            author_id=10,
            eligible_ids=frozenset({20}),
        )


def test_bot_transition_still_excludes_bot_approval() -> None:
    head = "a" * 40
    reviews = [
        {
            "id": 1,
            "user": {"id": 30, "login": "sdk-reviewer[bot]", "type": "Bot"},
            "state": "APPROVED",
            "submitted_at": "2026-01-01T00:00:00Z",
            "commit_id": head,
        }
    ]

    assert latest_human_reviews(reviews, author_id=10, eligible_ids=frozenset({30})) == ()


def test_reviewer_requires_resolved_write_permission() -> None:
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    reviews = [
        {
            "id": 1,
            "user": {"id": 20, "login": "reviewer", "type": "User"},
            "state": "APPROVED",
        }
    ]

    def request(_method: str, _path: str, **_kwargs: object) -> object:
        return {
            "permission": "write",
            "role_name": "write",
            "user": {"id": 20},
        }

    client.request = request  # type: ignore[method-assign]

    assert eligible_reviewer_ids(client, reviews, author_id=10) == frozenset({20})


def test_complete_evidence_fingerprint_detects_body_drift() -> None:
    snapshot = PullRequestSnapshot(
        number=1,
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_ref="dev",
        head_ref="feature",
        body="original",
        author="author",
        author_id=10,
        author_type="User",
        head_repository="owner/repo",
        base_repository_id=1,
        head_repository_id=1,
        draft=False,
        state="open",
    )
    expected = CollectedEvidence(snapshot, (), (), (), True)
    observed = replace(expected, snapshot=replace(snapshot, body="changed"))

    with pytest.raises(ReconciliationError, match="changed before final success"):
        require_unchanged_evidence(expected, observed, phase="before final success")


def test_merge_group_requires_latest_actions_status_for_exact_head() -> None:
    head = "a" * 40
    statuses = [
        {
            "id": 1,
            "sha": head,
            "context": "Review Policy",
            "state": "success",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        },
        {
            "id": 2,
            "sha": head,
            "context": "Review Policy",
            "state": "failure",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        },
    ]

    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    assert not review_policy_status_passed(
        client,
        statuses,
        head_sha=head,
        workflow_path=".github/workflows/review-policy.yml",
    )


def test_merge_group_rejects_spoofed_success_status() -> None:
    head = "a" * 40
    statuses = [
        {
            "id": 1,
            "sha": head,
            "context": "Review Policy",
            "state": "success",
            "creator": {"login": "person", "type": "User"},
        }
    ]

    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    assert not review_policy_status_passed(
        client,
        statuses,
        head_sha=head,
        workflow_path=".github/workflows/review-policy.yml",
    )


def test_merge_group_accepts_configured_successful_actions_run() -> None:
    head = "a" * 40
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    statuses = [
        {
            "id": 1,
            "sha": head,
            "context": "Review Policy",
            "state": "success",
            "target_url": "https://github.com/owner/repo/actions/runs/123",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        }
    ]

    def request(_method: str, _path: str, **_kwargs: object) -> object:
        return {
            "path": ".github/workflows/review-policy.yml@refs/heads/dev",
            "status": "completed",
            "conclusion": "success",
            "event": "pull_request_target",
        }

    client.request = request  # type: ignore[method-assign]

    assert review_policy_status_passed(
        client,
        statuses,
        head_sha=head,
        workflow_path=".github/workflows/review-policy.yml",
    )


def test_merge_group_resolves_pull_request_from_queue_ref_before_merge() -> None:
    merge_head = "c" * 40
    pull_head = "b" * 40
    queue_parent = "a" * 40
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    calls: list[tuple[str, str]] = []
    posted_statuses: list[dict[str, object]] = []

    def request(method: str, path: str, **kwargs: object) -> object:
        calls.append((method, path))
        if method == "POST" and path == f"/repos/owner/repo/statuses/{merge_head}":
            posted_statuses.append(dict(kwargs["payload"]))  # type: ignore[arg-type]
            return None
        if path == f"/repos/owner/repo/commits/{merge_head}":
            return {"sha": merge_head, "parents": [{"sha": queue_parent}]}
        if path == "/repos/owner/repo/pulls/42":
            return {
                "base": {
                    "sha": queue_parent,
                    "ref": "dev",
                    "repo": {"id": 1},
                },
                "head": {
                    "sha": pull_head,
                    "ref": "feature",
                    "repo": {"id": 1, "full_name": "owner/repo"},
                },
                "user": {"id": 10, "login": "author", "type": "User"},
                "body": "",
                "draft": False,
                "state": "open",
            }
        if path == "/repos/owner/repo/actions/runs/123":
            return {
                "path": ".github/workflows/review-policy.yml@refs/heads/dev",
                "status": "completed",
                "conclusion": "success",
                "event": "pull_request_target",
            }
        message = f"unexpected request: {method} {path}"
        raise AssertionError(message)

    def pages(path: str, **_kwargs: object) -> list[object]:
        calls.append(("PAGES", path))
        assert path == f"/repos/owner/repo/commits/{pull_head}/statuses"
        return [
            {
                "id": 1,
                "sha": pull_head,
                "context": "Review Policy",
                "state": "success",
                "target_url": "https://github.com/owner/repo/actions/runs/123",
                "creator": {"login": "github-actions[bot]", "type": "Bot"},
            }
        ]

    client.request = request
    client.rest_pages = pages

    def graphql(query: str, variables: object) -> dict[str, object]:
        assert "mergeQueueEntry" in query
        assert variables == {"owner": "owner", "repository": "repo", "number": 42}
        return {
            "repository": {
                "pullRequest": {"mergeQueueEntry": {"headCommit": {"oid": merge_head}}}
            }
        }

    client.graphql = graphql

    assert (
        reconcile_merge_group(
            client=client,
            head_sha=merge_head,
            head_ref=f"refs/heads/gh-readonly-queue/dev/pr-42-{queue_parent}",
            workflow_path=".github/workflows/review-policy.yml",
        )
        == 0
    )
    assert [status["state"] for status in posted_statuses] == ["pending", "success"]
    assert not any(path.endswith(f"/commits/{merge_head}/pulls") for _, path in calls)
    assert not any("/compare/" in path for _, path in calls)


@pytest.mark.parametrize(
    "head_ref",
    [
        "gh-readonly-queue/dev/pr-42-" + "a" * 40,
        "refs/heads/gh-readonly-queue/dev/not-pr-42-" + "a" * 40,
        "refs/heads/gh-readonly-queue/dev/pr-0-" + "a" * 40,
        "refs/heads/gh-readonly-queue/dev/pr-42-not-a-sha",
    ],
)
def test_merge_group_rejects_noncanonical_queue_ref(head_ref: str) -> None:
    with pytest.raises(ReconciliationError, match="exact merge-queue ref"):
        merge_group_pull_request(head_ref)


@pytest.mark.parametrize("entry", [None, {"headCommit": {"oid": "d" * 40}}])
def test_merge_group_requires_current_queue_entry(
    entry: dict[str, object] | None,
) -> None:
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")

    def graphql(query: str, variables: object) -> dict[str, object]:
        assert "mergeQueueEntry" in query
        assert variables == {"owner": "owner", "repository": "repo", "number": 42}
        return {"repository": {"pullRequest": {"mergeQueueEntry": entry}}}

    client.graphql = graphql
    if entry is None:
        with pytest.raises(ReconciliationError, match="merge queue entry"):
            merge_queue_head_sha(client, 42)
    else:
        assert merge_queue_head_sha(client, 42) == "d" * 40
