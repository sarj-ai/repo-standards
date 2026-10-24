from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from pydantic import BaseModel
import pytest

from repo_standards.github_review_policy import (
    CollectedEvidence,
    GitHubClient,
    GitHubRepositoryId,
    GitHubUserId,
    PullRequestSnapshot,
    ReconciliationError,
    check_conclusion,
    collect_required_checks,
    eligible_reviewer_ids,
    fetch_reviewed_commits,
    final_policy_decision,
    latest_human_reviews,
    merge_group_pull_request,
    merge_queue_head_sha,
    pull_request_snapshot,
    reconcile_merge_group,
    render_comment,
    require_unchanged_evidence,
    required_check_names,
    review_policy_status_passed,
    trusted_manifest,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence


ROOT = Path(__file__).parents[1]
INPUT_KEY = re.compile(r"^  ([a-z][a-z-]+):$", re.MULTILINE)


class _PostedStatus(BaseModel):
    state: str


class _RequestFixture(GitHubClient):
    def __init__(self, response: Callable[[str, str], object]) -> None:
        super().__init__(token="token", repository="owner/repo", api_url="https://api.test")
        self._response: Callable[[str, str], object] = response

    def request(
        self, method: str, path: str, *, payload: Mapping[str, object] | None = None
    ) -> object:
        assert payload is None
        return self._response(method, path)


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
    assert 'run: bash "$GITHUB_ACTION_PATH/reconcile.sh"' in source
    script = (ROOT / "pull-request-review-policy/reconcile.sh").read_text(encoding="utf-8")
    assert "repo_standards.github_review_policy" in script
    assert "APPROVAL_TOKEN" not in source
    assert "GITHUB_TOKEN" in source


@pytest.mark.parametrize("injection", ["package", "pythonpath"])
def test_review_policy_action_ignores_candidate_python_code(tmp_path: Path, injection: str) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    marker = tmp_path / "executed"
    payload = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    if injection == "package":
        package = candidate / "repo_standards"
        package.mkdir()
        (package / "__init__.py").write_text(payload, encoding="utf-8")
        (package / "github_review_policy.py").write_text("", encoding="utf-8")
    else:
        (candidate / "sitecustomize.py").write_text(payload, encoding="utf-8")
    script = ROOT / "pull-request-review-policy/reconcile.sh"
    uv = shutil.which("uv")
    assert uv is not None
    completed = subprocess.run(
        ["bash", str(script)],
        cwd=candidate,
        env={
            "PATH": str(Path(uv).parent) + os.pathsep + os.defpath,
            "GITHUB_ACTION_PATH": str(ROOT / "pull-request-review-policy"),
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_TOKEN": "",
            "INPUT_ROOT": ".",
            "INPUT_MANIFEST_PATH": ".repo-standards/repository.toml",
            "INPUT_PR_NUMBER": "42",
            "INPUT_MERGE_GROUP_HEAD_SHA": "",
            "INPUT_REVIEW_OPTIONAL_ENABLED": "false",
            "INPUT_REQUIRED_CHECK_APP_ID": "15368",
            "INPUT_POLICY_WORKFLOW_PATH": ".github/workflows/review-policy.yml",
            "PYTHONPATH": str(candidate),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert not marker.exists(), completed.stderr
    assert completed.returncode == 2
    assert "github-token is required" in completed.stderr


@pytest.mark.parametrize(
    ("state", "merged", "previous_status"),
    [
        pytest.param("closed", True, "success", id="merged-preserves-success"),
        pytest.param("closed", False, "failure", id="closed-preserves-failure"),
        pytest.param("open", False, "failure", id="open-still-publishes-pending"),
    ],
)
def test_closed_pull_request_refusal_does_not_overwrite_status(
    tmp_path: Path, state: str, merged: bool, previous_status: str
) -> None:
    head = "b" * 40
    posted: list[_PostedStatus] = []
    current_status = {"state": previous_status}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == "/repos/owner/repo/pulls/42"
            self._respond(
                {
                    "base": {"sha": "a" * 40, "ref": "dev", "repo": {"id": 1}},
                    "head": {
                        "sha": head,
                        "ref": "feature",
                        "repo": {"id": 1, "full_name": "owner/repo"},
                    },
                    "user": {"id": 10, "login": "author", "type": "User"},
                    "body": "",
                    "draft": False,
                    "state": state,
                    "merged": merged,
                }
            )

        def do_POST(self) -> None:
            assert self.path == f"/repos/owner/repo/statuses/{head}"
            payload = _PostedStatus.model_validate_json(
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
            )
            posted.append(payload)
            current_status["state"] = payload.state
            self._respond({"id": len(posted)})

        def _respond(self, payload: object) -> None:
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_standards.github_review_policy",
                    "--root",
                    str(tmp_path),
                    "--pr-number",
                    "42",
                ],
                env={
                    "GITHUB_REPOSITORY": "owner/repo",
                    "GITHUB_API_URL": f"http://127.0.0.1:{server.server_address[1]}",
                    "GITHUB_TOKEN": "owned-api-token",
                    "GIT_CEILING_DIRECTORIES": str(tmp_path.parent),
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive()

    assert completed.returncode == 2
    if state == "closed":
        assert "review policy only evaluates open pull requests" in completed.stderr
        assert posted == []
        assert current_status["state"] == previous_status
    else:
        # The open snapshot still starts reconciliation; this owned directory has
        # no repository or origin, so the existing Git evidence check refuses it.
        assert "cannot fetch exact pull request revisions" in completed.stderr
        assert [payload.state for payload in posted] == ["pending"]
        assert current_status["state"] == "pending"


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
    decision = final_policy_decision(
        policy_passed=True,
        tier=0,
        lane_enabled=lane_enabled,
        same_repository=same_repository,
        author_is_bot=author_is_bot,
        draft=draft,
    )
    assert (decision.passed, decision.reason) == expected


def test_non_tier_zero_runtime_gate_ignores_optional_lane() -> None:
    decision = final_policy_decision(
        policy_passed=True,
        tier=1,
        lane_enabled=False,
        same_repository=False,
        author_is_bot=True,
        draft=True,
    )
    assert (decision.passed, decision.reason) == (True, None)


@pytest.mark.parametrize(
    ("policy_passed", "same_repository", "draft", "expected"),
    [
        (True, True, False, True),
        (False, True, False, False),
        (True, False, False, False),
        (True, True, True, False),
    ],
)
def test_verified_transition_runtime_gate(
    policy_passed: bool,
    same_repository: bool,
    draft: bool,
    expected: bool,
) -> None:
    decision = final_policy_decision(
        policy_passed=policy_passed,
        tier=0,
        lane_enabled=False,
        same_repository=same_repository,
        author_is_bot=True,
        draft=draft,
        transition_exempt=True,
    )
    assert decision.passed is expected


def test_failed_policy_stays_blocked_when_optional_lane_is_enabled() -> None:
    decision = final_policy_decision(
        policy_passed=False,
        tier=0,
        lane_enabled=True,
        same_repository=True,
        author_is_bot=False,
        draft=False,
    )
    assert (decision.passed, decision.reason) == (False, None)


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
    calls: list[str] = []

    def request(method: str, path: str) -> object:
        assert method == "GET"
        calls.append(path)
        return list(range(100)) if path.endswith("page=1") else [100]

    client = _RequestFixture(request)

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


@pytest.mark.parametrize("conclusion", ["success", "failure", None])
def test_required_checks_read_only_the_configured_app_evidence(conclusion: str | None) -> None:
    head = "a" * 40
    calls: list[str] = []

    def request(method: str, path: str) -> object:
        assert method == "GET"
        calls.append(path)
        assert path == f"/repos/owner/repo/commits/{head}/check-runs?filter=all&per_page=100&page=1"
        check = {
            "name": "lint",
            "status": "completed" if conclusion is not None else "queued",
            "conclusion": conclusion,
            "head_sha": head,
            "details_url": "https://github.com/owner/repo/actions/runs/123/job/456",
        }
        return {
            "check_runs": [
                {**check, "id": 1, "app": {"id": 15368}},
                {**check, "id": 2, "conclusion": "success", "app": {"id": 999}},
            ]
        }

    result = collect_required_checks(
        _RequestFixture(request), head_sha=head, names=("lint", "test"), required_app_id=15368
    )

    assert result == (
        {"name": "lint", "conclusion": conclusion or "pending", "head_sha": head},
        {"name": "test", "conclusion": "missing", "head_sha": head},
    )
    assert len(calls) == 1


def test_single_required_check_filters_by_name_and_preserves_pagination() -> None:
    head = "a" * 40
    name = "lint/python + types"
    calls: list[str] = []
    check = {
        "name": name,
        "status": "completed",
        "head_sha": head,
        "details_url": "https://github.com/owner/repo/actions/runs/123/job/456",
    }

    def request(method: str, path: str) -> object:
        assert method == "GET"
        calls.append(path)
        assert path == (
            f"/repos/owner/repo/commits/{head}/check-runs?filter=all"
            f"&check_name=lint%2Fpython+%2B+types&per_page=100&page={len(calls)}"
        )
        if len(calls) == 1:
            return {
                "check_runs": [
                    *[
                        {**check, "id": 1000 + index, "conclusion": "success", "app": {"id": 999}}
                        for index in range(99)
                    ],
                    {**check, "id": 2, "conclusion": "failure", "app": {"id": 15368}},
                ]
            }
        return {"check_runs": [{**check, "id": 1, "conclusion": "success", "app": {"id": 15368}}]}

    result = collect_required_checks(
        _RequestFixture(request), head_sha=head, names=(name,), required_app_id=15368
    )

    assert result == ({"name": name, "conclusion": "failure", "head_sha": head},)
    assert len(calls) == 2


def test_single_required_check_missing_still_blocks() -> None:
    def request(method: str, path: str) -> object:
        assert method == "GET"
        assert "&check_name=lint&" in path
        return {"check_runs": []}

    assert collect_required_checks(
        _RequestFixture(request), head_sha="a" * 40, names=("lint",), required_app_id=15368
    ) == ({"name": "lint", "conclusion": "missing", "head_sha": "a" * 40},)


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
            "re_requested": False,
        },
    )
    assert latest_human_reviews(
        reviews,
        author_id=10,
        eligible_ids=frozenset({20}),
        requested_ids=frozenset({20}),
    )[0]["re_requested"]


def _snapshot_with_requested(requested: object) -> PullRequestSnapshot:
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")

    def request(method: str, path: str, *, payload: object = None) -> object:
        del method, path, payload
        return {
            "base": {"sha": "a" * 40, "ref": "dev", "repo": {"id": 1}},
            "head": {"sha": "b" * 40, "ref": "feature", "repo": {"id": 1, "full_name": "o/r"}},
            "user": {"id": 10, "login": "author", "type": "User"},
            "body": "",
            "draft": False,
            "state": "open",
            "requested_reviewers": requested,
        }

    client.request = request
    return pull_request_snapshot(client, 42)


def test_snapshot_reads_re_requested_reviewer_ids() -> None:
    snapshot = _snapshot_with_requested([{"id": 20, "login": "reviewer"}])

    assert snapshot.requested_reviewer_ids == frozenset({GitHubUserId(20)})


def test_malformed_requested_reviewers_fail_closed() -> None:
    with pytest.raises(ReconciliationError, match="requested_reviewers"):
        _snapshot_with_requested({"id": 20})


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
    reviews = [
        {
            "id": 1,
            "user": {"id": 20, "login": "reviewer", "type": "User"},
            "state": "APPROVED",
        }
    ]

    def request(method: str, path: str) -> object:
        assert method == "GET"
        assert path.startswith("/repos/owner/repo/")
        return {
            "permission": "write",
            "role_name": "write",
            "user": {"id": 20},
        }

    client = _RequestFixture(request)

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
        author_id=GitHubUserId(10),
        author_type="User",
        head_repository="owner/repo",
        base_repository_id=GitHubRepositoryId(1),
        head_repository_id=GitHubRepositoryId(1),
        draft=False,
        state="open",
    )
    expected = CollectedEvidence(snapshot, (), (), (), True)
    observed = replace(expected, snapshot=replace(snapshot, body="changed"))

    with pytest.raises(ReconciliationError, match="changed before final success"):
        require_unchanged_evidence(expected, observed, phase="before final success")


def test_merge_group_requires_latest_actions_status_for_exact_head() -> None:
    statuses = [
        {
            "id": 1,
            "context": "Review Policy",
            "state": "success",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        },
        {
            "id": 2,
            "context": "Review Policy",
            "state": "failure",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        },
    ]

    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    assert not review_policy_status_passed(
        client,
        statuses,
        workflow_path=".github/workflows/review-policy.yml",
    )


def test_merge_group_rejects_spoofed_success_status() -> None:
    statuses = [
        {
            "id": 1,
            "context": "Review Policy",
            "state": "success",
            "creator": {"login": "person", "type": "User"},
        }
    ]

    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    assert not review_policy_status_passed(
        client,
        statuses,
        workflow_path=".github/workflows/review-policy.yml",
    )


def test_merge_group_accepts_configured_successful_actions_run() -> None:
    statuses = [
        {
            "id": 1,
            "context": "Review Policy",
            "state": "success",
            "target_url": "https://github.com/owner/repo/actions/runs/123",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        }
    ]

    def request(method: str, path: str) -> object:
        assert method == "GET"
        assert path.startswith("/repos/owner/repo/")
        return {
            "path": ".github/workflows/review-policy.yml@refs/heads/dev",
            "status": "completed",
            "conclusion": "success",
            "event": "pull_request_target",
        }

    client = _RequestFixture(request)

    assert review_policy_status_passed(
        client,
        statuses,
        workflow_path=".github/workflows/review-policy.yml",
    )


def _successful_status() -> list[dict[str, object]]:
    return [
        {
            "id": 1,
            "context": "Review Policy",
            "state": "success",
            "target_url": "https://github.com/owner/repo/actions/runs/123",
            "creator": {"login": "github-actions[bot]", "type": "Bot"},
        }
    ]


@pytest.mark.parametrize(
    ("conclusion", "expected"),
    [
        pytest.param("success", True, id="successful-run"),
        pytest.param("failure", False, id="failed-run"),
        pytest.param("cancelled", False, id="cancelled-run"),
    ],
)
def test_merge_group_waits_for_the_status_run_to_complete(conclusion: str, expected: bool) -> None:
    runs = iter(
        [
            {"status": "in_progress", "conclusion": None},
            {"status": "completed", "conclusion": conclusion},
        ]
    )
    sleeps: list[float] = []

    def request(method: str, path: str) -> object:
        assert method == "GET"
        assert path.startswith("/repos/owner/repo/")
        return {
            "path": ".github/workflows/review-policy.yml@refs/heads/dev",
            "event": "workflow_run",
            **next(runs),
        }

    client = _RequestFixture(request)

    assert (
        review_policy_status_passed(
            client,
            _successful_status(),
            workflow_path=".github/workflows/review-policy.yml",
            clock=lambda: 0.0,
            sleep=sleeps.append,
        )
        is expected
    )
    assert sleeps == [5]


def test_merge_group_rejects_a_status_run_that_never_completes() -> None:
    clock = iter([0.0, 100.0, 200.0, 300.0])
    sleeps: list[float] = []

    def request(method: str, path: str) -> object:
        assert method == "GET"
        assert path.startswith("/repos/owner/repo/")
        return {
            "path": ".github/workflows/review-policy.yml@refs/heads/dev",
            "status": "in_progress",
            "conclusion": None,
            "event": "workflow_run",
        }

    client = _RequestFixture(request)

    assert not review_policy_status_passed(
        client,
        _successful_status(),
        workflow_path=".github/workflows/review-policy.yml",
        clock=lambda: next(clock),
        sleep=sleeps.append,
    )
    assert sleeps == [5, 5]


def test_merge_group_resolves_pull_request_from_queue_ref_before_merge() -> None:
    merge_head = "c" * 40
    pull_head = "b" * 40
    queue_parent = "a" * 40
    client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
    calls: list[tuple[str, str]] = []
    posted_statuses: list[dict[str, object]] = []

    def request(method: str, path: str, *, payload: Mapping[str, object] | None = None) -> object:
        calls.append((method, path))
        if method == "POST" and path == f"/repos/owner/repo/statuses/{merge_head}":
            assert payload is not None
            posted_statuses.append(dict(payload))
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
            "repository": {"pullRequest": {"mergeQueueEntry": {"headCommit": {"oid": merge_head}}}}
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


def _receipt(earlier_approvals: list[dict[str, object]]) -> dict[str, object]:
    return {
        "summary": {"tier": 1, "current_human_approvals": 1, "reasons": []},
        "size": {"counted_lines": 300, "excluded_lines": 0},
        "provenance": {"evaluated_head": "a" * 40},
        "earlier_approvals": earlier_approvals,
    }


def test_comment_explains_each_earlier_approval() -> None:
    comment = render_comment(
        _receipt(
            [
                {
                    "reviewer": "20:carried",
                    "commit_sha": "b" * 40,
                    "counted_lines_since_review": 12,
                    "carried_forward": True,
                },
                {
                    "reviewer": "21:stale",
                    "commit_sha": "c" * 40,
                    "counted_lines_since_review": None,
                    "carried_forward": False,
                },
                {
                    "reviewer": "22:gone",
                    "commit_sha": "d" * 40,
                    "counted_lines_since_review": None,
                    "carried_forward": False,
                },
            ]
        ),
        final_passed=True,
        lane_enabled=False,
        operational_reason=None,
        unavailable={"d" * 40: "fatal: remote error: upload-pack: not our ref"},
    )

    assert (
        f"- Earlier approval by @carried on `{'b' * 12}`: 12 counted lines since, "
        "**carried forward**\n"
    ) in comment
    assert (
        f"- Earlier approval by @stale on `{'c' * 12}`: not measurable, **needs re-approval**\n"
    ) in comment
    assert (
        f"- Earlier approval by @gone on `{'d' * 12}`: approved commit unavailable "
        "(`fatal: remote error: upload-pack: not our ref`), **needs re-approval**\n"
    ) in comment


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(repository: Path, name: str) -> str:
    (repository / name).write_text(f"{name}\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        name,
    )
    return _git(repository, "rev-parse", "HEAD")


def test_force_pushed_approved_commit_is_fetched_by_object_id(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "--quiet")
    _git(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
    base = _commit(origin, "base")
    reviewed = _commit(origin, "reviewed")
    _git(origin, "reset", "--quiet", "--hard", base)
    head = _commit(origin, "rewritten")
    clone = tmp_path / "clone"
    _git(tmp_path, "clone", "--quiet", "--no-local", str(origin), str(clone))
    reviews = (
        {"reviewer": "20:reviewer", "state": "approved", "commit_sha": reviewed},
        {"reviewer": "21:missing", "state": "approved", "commit_sha": "f" * 40},
    )

    unavailable = fetch_reviewed_commits(
        clone, reviews, head_sha=head, token="", server_url="https://github.com"
    )

    assert _git(clone, "cat-file", "-t", reviewed) == "commit"
    assert set(unavailable) == {"f" * 40}
    assert unavailable["f" * 40].startswith(("fatal:", "error:"))


@pytest.mark.parametrize("phase", ["cat-file", "fetch"], ids=("local-probe", "remote-fetch"))
@pytest.mark.parametrize("failure", ["timeout", "spawn"], ids=("timeout", "cannot-start"))
def test_unavailable_reviewed_commit_does_not_prevent_checking_other_approvals(
    tmp_path: Path, phase: str, failure: str
) -> None:
    missing, available = "a" * 40, "b" * 40

    def run(
        command: Sequence[str], environment: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        if available in command[-1]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if phase not in command:
            return subprocess.CompletedProcess(command, 1, "", "")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 120)
        raise OSError

    reviews = (
        {"state": "approved", "commit_sha": missing},
        {"state": "approved", "commit_sha": available},
    )

    unavailable = fetch_reviewed_commits(
        tmp_path, reviews, head_sha="c" * 40, token="", server_url="https://github.com", run_git=run
    )

    reason = "git command timed out" if failure == "timeout" else "git command could not start"
    assert unavailable == {missing: reason}


_TOKEN = "test-token"


def _basic(token: str) -> str:
    return "basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode()


@dataclass(frozen=True, slots=True)
class _PrivateOrigin:
    url: str
    reviewed: str
    head: str


def _git_http_handler(project_root: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._serve(b"")

        def do_POST(self) -> None:
            self._serve(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

        def _serve(self, body: bytes) -> None:
            if self.headers.get_all("Authorization") != [_basic(_TOKEN)]:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="private"')
                self.end_headers()
                return
            parsed = urlsplit(self.path)
            backend = subprocess.run(
                ["git", "http-backend"],
                input=body,
                capture_output=True,
                check=True,
                timeout=10,
                env={
                    "GIT_PROJECT_ROOT": str(project_root),
                    "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH_INFO": parsed.path,
                    "QUERY_STRING": parsed.query,
                    "REQUEST_METHOD": self.command,
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
                    "REMOTE_ADDR": "127.0.0.1",
                },
            )
            head, _, payload = backend.stdout.partition(b"\r\n\r\n")
            headers = [line.split(": ", 1) for line in head.decode().split("\r\n")]
            status = next((int(value[:3]) for name, value in headers if name == "Status"), 200)
            self.send_response(status)
            for name, value in headers:
                if name != "Status":
                    self.send_header(name, value)
            self.end_headers()
            self.wfile.write(payload)

    return Handler


@pytest.fixture
def private_origin(tmp_path: Path) -> Iterator[_PrivateOrigin]:
    origin = tmp_path / "srv" / "origin.git"
    origin.mkdir(parents=True)
    _git(origin, "init", "--quiet")
    _git(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
    base = _commit(origin, "base")
    reviewed = _commit(origin, "reviewed")
    _git(origin, "reset", "--quiet", "--hard", base)
    head = _commit(origin, "rewritten")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _git_http_handler(origin.parent))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield _PrivateOrigin(
            f"http://127.0.0.1:{server.server_address[1]}/origin.git", reviewed, head
        )
    finally:
        server.shutdown()
        thread.join()


def _clone_without_credentials(origin: _PrivateOrigin, destination: Path) -> Path:
    _git(
        destination.parent,
        "-c",
        f"http.extraheader=AUTHORIZATION: {_basic(_TOKEN)}",
        "clone",
        "--quiet",
        origin.url,
        str(destination),
    )
    return destination


def _approved(origin: _PrivateOrigin) -> tuple[dict[str, str | None], ...]:
    return ({"reviewer": "20:reviewer", "state": "approved", "commit_sha": origin.reviewed},)


def _server_url(origin: _PrivateOrigin) -> str:
    return origin.url.removesuffix("/origin.git")


def test_force_pushed_approved_commit_is_fetched_from_a_private_origin_with_the_token(
    tmp_path: Path, private_origin: _PrivateOrigin
) -> None:
    clone = _clone_without_credentials(private_origin, tmp_path / "clone")

    unavailable = fetch_reviewed_commits(
        clone,
        _approved(private_origin),
        head_sha=private_origin.head,
        token=_TOKEN,
        server_url=_server_url(private_origin),
    )

    assert unavailable == {}
    assert _git(clone, "cat-file", "-t", private_origin.reviewed) == "commit"
    assert _TOKEN not in (clone / ".git" / "config").read_text(encoding="utf-8")


def test_reviewed_commit_fetch_replaces_a_header_left_by_checkout(
    tmp_path: Path, private_origin: _PrivateOrigin
) -> None:
    clone = _clone_without_credentials(private_origin, tmp_path / "clone")
    _git(
        clone,
        "config",
        f"http.{_server_url(private_origin)}/.extraheader",
        f"AUTHORIZATION: {_basic('expired-token')}",
    )

    unavailable = fetch_reviewed_commits(
        clone,
        _approved(private_origin),
        head_sha=private_origin.head,
        token=_TOKEN,
        server_url=_server_url(private_origin),
    )

    assert unavailable == {}
    assert _git(clone, "cat-file", "-t", private_origin.reviewed) == "commit"


def test_unauthenticated_reviewed_commit_fetch_reports_why_it_failed(
    tmp_path: Path, private_origin: _PrivateOrigin
) -> None:
    clone = _clone_without_credentials(private_origin, tmp_path / "clone")

    unavailable = fetch_reviewed_commits(
        clone,
        _approved(private_origin),
        head_sha=private_origin.head,
        token="",
        server_url=_server_url(private_origin),
    )

    assert set(unavailable) == {private_origin.reviewed}
    assert unavailable[private_origin.reviewed].startswith("fatal:")
