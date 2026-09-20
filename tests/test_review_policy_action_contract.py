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
    latest_human_reviews,
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
        "github-token",
        "approval-token",
        "review-optional-enabled",
        "required-check-app-id",
        "policy-workflow-path",
    }
    assert "default: '15368'" in inputs
    assert "repo_standards.github_review_policy" in source
    assert "APPROVAL_TOKEN" in source
    assert "GITHUB_TOKEN" in source


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
