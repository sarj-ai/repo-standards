from __future__ import annotations

import json
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.github_review_policy import (
    GitHubClient,
    allows_reviewed_resolution,
    head_commit_user_logins,
)


if TYPE_CHECKING:
    from pathlib import Path


runner = CliRunner()
_IDENTITY = ("-c", "user.name=Resolver", "-c", "user.email=resolver@example.invalid")
_MANIFEST = """
repository_id = "example"
components = []

[pull_request.commit_history]
advisory_base_ref = "dev"

[[pull_request.commit_history.transitions]]
id = "sync"
source_ref = "preview"
base_ref = "dev"
head_prefix = "automation/sync-preview-"
allow_reviewed_resolution = true

[pull_request.review_policy]
zero_review_below_counted_lines = 200
two_reviews_above_counted_lines = 800
migration_roots = ["db/migrations"]
required_checks = ["ci"]
required_body_sections = ["What & why"]
accepted_check_conclusions = ["success"]
transition_exemptions = ["sync"]
transition_actors = ["release-automation[bot]"]
allowlisted_bot_reviewers = ["review-helper[bot]"]
"""


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(repository), *_IDENTITY, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(repository: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repository / name).write_text(content, encoding="utf-8")
    _git(repository, "add", *files)
    _git(repository, "commit", "--quiet", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _resolution(repository: Path) -> tuple[str, str, str]:
    _git(repository, "init", "--quiet")
    (repository / ".repo-standards").mkdir()
    root = _commit(
        repository,
        {".repo-standards/repository.toml": _MANIFEST.lstrip(), "conflict.txt": "root\n"},
        "root",
    )
    _commit(repository, {"conflict.txt": "preview\n"}, "preview")
    snapshot = _commit(repository, {"preview.txt": "p\n"}, "preview 2")
    _git(repository, "update-ref", "refs/remotes/origin/preview", snapshot)
    _git(repository, "checkout", "--quiet", "--detach", root)
    base = _commit(repository, {"conflict.txt": "dev\n"}, "dev")
    _git(repository, "checkout", "--quiet", "--detach", snapshot)
    _git(repository, "merge", "--quiet", "--no-ff", "--no-commit", base)
    head = _commit(repository, {"conflict.txt": "resolved\n"}, "Merge dev")
    return snapshot, base, head


def _run(
    repository: Path,
    *,
    reviews: list[dict[str, object]],
    resolvers: list[str] | None,
) -> tuple[int, dict[str, object]]:
    snapshot, base, head = _resolution(repository)
    evidence: dict[str, object] = {
        "schema_version": 1,
        "evaluated_head_sha": head,
        "current_head_sha": head,
        "base_ref": "dev",
        "head_ref": f"automation/sync-preview-{snapshot[:12]}",
        "base_repository_id": 123,
        "head_repository_id": 123,
        "is_draft": False,
        "author_login": "release-automation[bot]",
        "author_is_bot": True,
        "required_checks_complete": True,
        "required_checks": [{"name": "ci", "conclusion": "success", "head_sha": head}],
        "reviews_complete": True,
        "latest_human_reviews": [
            {**review, "commit_sha": head if review.get("commit_sha") == "head" else base}
            for review in reviews
        ],
        "threads_complete": True,
        "threads_resolved": True,
        "body": "",
    }
    if resolvers is not None:
        evidence["head_commit_user_logins"] = resolvers
    path = repository.parent / "evidence.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(repository),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(path),
        ],
    )
    payload: object = json.loads(result.stdout)  # pyright: ignore[reportAny] - JSON boundary
    assert isinstance(payload, dict), result.stdout
    assert "summary" in payload, result.stdout
    summary: object = payload["summary"]  # pyright: ignore[reportUnknownVariableType]
    assert isinstance(summary, dict)
    return result.exit_code, {str(key): value for key, value in summary.items()}  # pyright: ignore[reportUnknownVariableType,reportUnknownArgumentType]


def _approval(reviewer: str, *, head: bool = True, bot: bool = False) -> dict[str, object]:
    return {
        "reviewer": reviewer,
        "state": "approved",
        "commit_sha": "head" if head else "older",
        "reviewer_is_bot": bot,
    }


def test_independent_exact_head_approval_admits_a_reviewed_resolution(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    exit_code, summary = _run(
        repository, reviews=[_approval("42:reviewer")], resolvers=["resolver"]
    )

    assert exit_code == 0, summary
    assert summary["transition_exemption"] == "sync"
    assert summary["transition_resolution_paths"] == ["conflict.txt"]
    assert summary["required_human_reviews"] == 1
    reasons = summary["reasons"]
    assert isinstance(reasons, list)
    assert "transition_resolution" in reasons
    assert "transition_resolution_approval_missing" not in reasons


@pytest.mark.parametrize(
    ("reviews", "resolvers"),
    [
        pytest.param([], ["resolver"], id="no-approval"),
        pytest.param([_approval("42:reviewer", head=False)], ["resolver"], id="older-head"),
        pytest.param([_approval("7:Resolver")], ["resolver"], id="resolver-self-approval"),
        pytest.param(
            [_approval("9:release-automation[bot]")], ["resolver"], id="author-self-approval"
        ),
        pytest.param(
            [_approval("5:review-helper[bot]", bot=True)], ["resolver"], id="bot-approval"
        ),
        pytest.param([_approval("42:reviewer")], None, id="resolver-unknown"),
    ],
)
def test_reviewed_resolution_needs_an_independent_exact_head_human_approval(
    tmp_path: Path,
    reviews: list[dict[str, object]],
    resolvers: list[str] | None,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    exit_code, summary = _run(repository, reviews=reviews, resolvers=resolvers)

    assert exit_code == 1
    assert summary["merge_ready"] is False
    reasons = summary["reasons"]
    assert isinstance(reasons, list)
    assert "transition_resolution_approval_missing" in reasons


class _CommitClient(GitHubClient):
    def __init__(self, commit: dict[str, object]) -> None:
        super().__init__(token="token", repository="owner/repo", api_url="https://api.test")
        self.paths: list[str] = []
        self._commit: dict[str, object] = commit

    def request(self, method: str, path: str, *, payload: object | None = None) -> object:
        assert method == "GET"
        assert payload is None
        self.paths.append(path)
        return self._commit


def test_resolver_identity_comes_from_the_exact_head_commit() -> None:
    client = _CommitClient({"author": {"login": "resolver"}, "committer": {"login": "web-flow"}})

    assert head_commit_user_logins(client, "a" * 40) == ["resolver", "web-flow"]
    assert client.paths == [f"/repos/owner/repo/commits/{'a' * 40}"]
    assert head_commit_user_logins(_CommitClient({"author": None, "committer": None}), "a") == []


def test_resolver_evidence_is_collected_only_for_opted_in_transitions() -> None:
    opted_in = {
        "pull_request": {
            "commit_history": {"transitions": [{"id": "sync", "allow_reviewed_resolution": True}]}
        }
    }
    default = {"pull_request": {"commit_history": {"transitions": [{"id": "sync"}]}}}

    assert allows_reviewed_resolution(opted_in)
    assert not allows_reviewed_resolution(default)
    assert not allows_reviewed_resolution({})
