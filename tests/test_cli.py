from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import version
import json
from pathlib import Path
import re
import shutil
import subprocess

from jsonschema import ValidationError as JSONSchemaValidationError, validate
import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.models import RuleId
from repo_standards.github_review_policy import trusted_manifest


runner = CliRunner()


def test_version_matches_installed_distribution() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == version("repo-standards")


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )
    return completed.stdout.decode().strip()


def _commit_fixture(repository: Path) -> None:
    _git(repository, "init", "--quiet")
    _commit_changes(repository)


def _commit_changes(repository: Path) -> None:
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
        "fixture",
    )


def test_pull_request_size_command_returns_stable_json(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".gitattributes").write_text("generated/** pr-size-excluded\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "src" / "app.py").write_text("value = 2\nextra = 3\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("assert True\n" * 20, encoding="utf-8")
    _commit_changes(tmp_path)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "size",
            str(tmp_path),
            "--base",
            base,
            "--head",
            "HEAD",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    assert payload["command"] == "pull-request size"
    summary = _object(payload["summary"])
    assert summary["counted_lines"] == 3
    assert summary["excluded_lines"] == 20
    assert summary["additions"] == 22
    assert summary["deletions"] == 1
    assert summary["counted_files"] == 1
    assert summary["excluded_files"] == 1
    categories = _object_list(payload["categories"])
    assert [(item["category"], item["lines"]) for item in categories] == [
        ("production", 3),
        ("test", 20),
        ("generated", 0),
        ("binary", 0),
    ]
    directories = _object_list(payload["directories"])
    assert [(item["path"], item["total_lines"]) for item in directories] == [
        ("src", 3),
        ("tests", 20),
    ]
    files = _object_list(payload["files"])
    assert [(item["path"], item["category"], item["lines"]) for item in files] == [
        ("src/app.py", "production", 3),
        ("tests/test_app.py", "test", 20),
    ]


def test_pull_request_size_command_writes_full_canonical_report(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "app.py").write_text("value = 2\nextra = 3\n", encoding="utf-8")
    _commit_changes(tmp_path)
    report_path = tmp_path / "artifacts" / "pr-size.json"
    report_path.parent.mkdir()

    result = runner.invoke(
        app,
        [
            "pull-request",
            "size",
            str(tmp_path),
            "--base",
            base,
            "--report-path",
            str(report_path),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert report_path.read_text(encoding="utf-8") == result.stdout
    payload = _json_object(report_path.read_text(encoding="utf-8"))
    assert _object_list(payload["files"])[0]["path"] == "app.py"
    assert _object_list(payload["directories"])[0]["path"] == "."


def test_pull_request_size_report_path_does_not_change_text_stdout(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "app.py").write_text("value = 2\n", encoding="utf-8")
    _commit_changes(tmp_path)
    report_path = tmp_path / "pr-size.json"

    result = runner.invoke(
        app,
        [
            "pull-request",
            "size",
            str(tmp_path),
            "--base",
            base,
            "--report-path",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.startswith("Counted review size:")
    assert _json_object(report_path.read_text(encoding="utf-8"))["command"] == ("pull-request size")


def test_pull_request_size_errors_have_command_specific_remediation(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["pull-request", "size", str(tmp_path), "--format", "json"])
    missing_issue = _object_list(_json_object(missing.stdout)["execution_issues"])[0]
    assert "trusted revision" in str(missing_issue["remediation"])

    _git(tmp_path, "init", "--quiet")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    _commit_changes(tmp_path)
    invalid = runner.invoke(
        app,
        ["pull-request", "size", str(tmp_path), "--base", "missing", "--format", "json"],
    )
    invalid_issue = _object_list(_json_object(invalid.stdout)["execution_issues"])[0]
    assert "Fetch and verify" in str(invalid_issue["remediation"])


def _review_policy_fixture(
    repository: Path,
    *,
    require_resolved_threads: bool = True,
    trusted_bot_authors: tuple[str, ...] = (),
    allowlisted_bot_reviewers: tuple[str, ...] = (),
) -> str:
    _git(repository, "init", "--quiet")
    policy = repository / ".repo-standards"
    policy.mkdir()
    (policy / "repository.toml").write_text(
        """
repository_id = "example"
components = []

[pull_request.commit_history]
advisory_base_ref = "dev"

[[pull_request.commit_history.transitions]]
id = "promote"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-dev-"

[pull_request.review_policy]
zero_review_below_counted_lines = 200
two_reviews_above_counted_lines = 800
migration_roots = ["db/migrations"]
required_checks = ["ci"]
required_body_sections = ["What & why", "QA impact / blast radius"]
accepted_check_conclusions = ["success"]
transition_exemptions = ["promote"]
transition_actors = ["release-automation[bot]"]
""".lstrip()
        + f"require_resolved_threads = {str(require_resolved_threads).lower()}\n"
        + f"trusted_bot_authors = {json.dumps(list(trusted_bot_authors))}\n"
        + f"allowlisted_bot_reviewers = {json.dumps(list(allowlisted_bot_reviewers))}\n",
        encoding="utf-8",
    )
    (repository / "README.md").write_text("base\n", encoding="utf-8")
    _commit_changes(repository)
    return _git(repository, "rev-parse", "HEAD")


def _review_policy_evidence(  # ruff: ignore[too-many-arguments] - focused fixture controls independent evidence
    repository: Path,
    *,
    head: str,
    reviews: list[dict[str, object]] | None = None,
    body: str = "## What & why\nSmall change.\n\n## QA impact / blast radius\nN/A\n",
    checks_complete: bool = True,
    base_ref: str = "dev",
    head_ref: str = "feature/review-policy",
    author_is_bot: bool = False,
    author_login: str = "developer",
    current_head: str | None = None,
    head_repository_id: int = 123,
    check_head: str | None = None,
    threads_resolved: bool = True,
) -> Path:
    evidence = repository / "evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evaluated_head_sha": head,
                "current_head_sha": current_head or head,
                "base_ref": base_ref,
                "head_ref": head_ref,
                "base_repository_id": 123,
                "head_repository_id": head_repository_id,
                "is_draft": False,
                "author_login": author_login,
                "author_is_bot": author_is_bot,
                "required_checks_complete": checks_complete,
                "required_checks": [
                    {
                        "name": "ci",
                        "conclusion": "success",
                        "head_sha": check_head or head,
                    }
                ],
                "reviews_complete": True,
                "latest_human_reviews": reviews or [],
                "threads_complete": True,
                "threads_resolved": threads_resolved,
                "body": body,
            }
        ),
        encoding="utf-8",
    )
    return evidence


def _promotion_evidence(  # ruff: ignore[too-many-arguments] - independent trusted identity and source evidence
    repository: Path,
    *,
    head: str,
    author_login: str = "release-automation[bot]",
    current_head: str | None = None,
    head_repository_id: int = 123,
    source: str | None = None,
) -> Path:
    snapshot = source or head
    _git(repository, "update-ref", "refs/remotes/origin/dev", snapshot)
    return _review_policy_evidence(
        repository,
        head=head,
        reviews=[],
        body="",
        base_ref="preview",
        head_ref=f"automation/promote-dev-{snapshot[:12]}",
        author_is_bot=True,
        author_login=author_login,
        current_head=current_head,
        head_repository_id=head_repository_id,
    )


def test_pull_request_review_policy_emits_ready_tier_zero_receipt(tmp_path: Path) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "README.md").write_text("base\nsmall correction\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_large.py").write_text("assert True\n" * 300, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = _json_object(result.stdout)
    assert payload["command"] == "pull-request review-policy"
    assert payload["conclusion"] == "passed"
    summary = _object(payload["summary"])
    assert summary["tier"] == 0
    assert summary["merge_ready"] is True
    size = _object(payload["size"])
    assert size["counted_lines"] == 1
    assert size["excluded_lines"] == 300
    assert [item["path"] for item in _object_list(payload["files"])] == [
        "README.md",
        "tests/test_large.py",
    ]


@pytest.mark.parametrize(
    ("require_resolved_threads", "merge_ready"),
    [(True, False), (False, True)],
)
def test_pull_request_review_policy_thread_resolution_follows_manifest(
    tmp_path: Path,
    *,
    require_resolved_threads: bool,
    merge_ready: bool,
) -> None:
    base = _review_policy_fixture(tmp_path, require_resolved_threads=require_resolved_threads)
    (tmp_path / "README.md").write_text("base\nsmall correction\n", encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head, threads_resolved=False)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    payload = _json_object(result.stdout)
    assert _object(payload["policy"])["require_resolved_threads"] is require_resolved_threads
    assert _object(payload["summary"])["merge_ready"] is merge_ready


def test_pull_request_review_policy_migration_floor_blocks_without_approval(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(tmp_path)
    migration = tmp_path / "db" / "migrations"
    migration.mkdir(parents=True)
    (migration / "001.sql").write_text("SELECT 1;\n", encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 1
    summary = _object(_json_object(result.stdout)["summary"])
    assert summary["tier"] == 1
    assert summary["touches_migration"] is True
    assert summary["reasons"] == [
        "zero_review_threshold",
        "migration_review_floor",
        "approvals_missing",
    ]


def test_pull_request_review_policy_requires_two_reviews_above_800_lines(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "large.py").write_text("value = 1\n" * 801, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 1
    payload = _json_object(result.stdout)
    summary = _object(payload["summary"])
    assert summary["tier"] == 2
    assert summary["current_human_approvals"] == 0
    assert summary["reasons"] == ["two_review_threshold", "approvals_missing"]


@dataclass(frozen=True, slots=True)
class RebasedReview:
    base: str
    reviewed: str
    head: str


def _rebased_after_review(repository: Path, *, edit_lines: int) -> RebasedReview:
    _review_policy_fixture(repository)
    _git(repository, "branch", "-M", "dev")
    _git(repository, "switch", "--quiet", "-c", "feature")
    (repository / "feature.py").write_text("value = 1\n" * 300, encoding="utf-8")
    _commit_changes(repository)
    reviewed = _git(repository, "rev-parse", "HEAD")
    _git(repository, "switch", "--quiet", "dev")
    (repository / "drift.py").write_text("drift = 1\n" * 900, encoding="utf-8")
    _commit_changes(repository)
    base = _git(repository, "rev-parse", "HEAD")
    _git(repository, "switch", "--quiet", "feature")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "rebase",
        "--quiet",
        "dev",
    )
    if edit_lines:
        (repository / "edit.py").write_text("edit = 1\n" * edit_lines, encoding="utf-8")
        _commit_changes(repository)
    return RebasedReview(base, reviewed, _git(repository, "rev-parse", "HEAD"))


@pytest.mark.parametrize(
    ("edit_lines", "carried_forward", "reasons"),
    [
        (0, True, ["one_review_threshold", "approval_carried_forward"]),
        (500, True, ["one_review_threshold", "approval_carried_forward"]),
        (801, False, ["two_review_threshold", "stale_approval", "approvals_missing"]),
    ],
)
def test_pull_request_review_policy_carries_approval_across_rebase(
    tmp_path: Path,
    *,
    edit_lines: int,
    carried_forward: bool,
    reasons: list[str],
) -> None:
    rebased = _rebased_after_review(tmp_path, edit_lines=edit_lines)
    evidence = _review_policy_evidence(
        tmp_path,
        head=rebased.head,
        reviews=[{"reviewer": "human", "state": "approved", "commit_sha": rebased.reviewed}],
    )

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            rebased.base,
            "--head",
            rebased.head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == (0 if carried_forward else 1), result.stdout
    payload = _json_object(result.stdout)
    assert _object(payload["summary"])["reasons"] == reasons
    assert payload["earlier_approvals"] == [
        {
            "reviewer": "human",
            "commit_sha": rebased.reviewed,
            "counted_lines_since_review": edit_lines,
            "carried_forward": carried_forward,
            "allowlisted_bot": False,
        }
    ]


def test_pull_request_review_policy_verified_transition_skips_size_body_and_review(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "large.py").write_text("value = 1\n" * 900, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _promotion_evidence(tmp_path, head=head)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = _json_object(result.stdout)
    summary = _object(payload["summary"])
    assert summary["tier"] == 0
    assert summary["transition_exemption"] == "promote"
    assert summary["missing_body_sections"] == []
    assert isinstance(summary["reasons"], list)
    assert "transition_exemption" in summary["reasons"]
    assert _object(payload["size"])["classification"] == "transition-exempt"
    assert payload["files"] == []


def test_review_policy_accepts_a_verified_refreshed_promotion(tmp_path: Path) -> None:
    original_base = _review_policy_fixture(tmp_path)
    (tmp_path / "large.py").write_text("value = 1\n" * 900, encoding="utf-8")
    _commit_changes(tmp_path)
    source = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "--quiet", "--detach", original_base)
    (tmp_path / "hotfix.txt").write_text("target hotfix\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "--quiet", "--detach", source)
    _git(
        tmp_path,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "merge",
        "--quiet",
        "--no-ff",
        "-m",
        "Merge target",
        base,
    )
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _promotion_evidence(tmp_path, head=head, source=source)
    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )
    assert result.exit_code == 0, result.stdout
    summary = _object(_json_object(result.stdout)["summary"])
    assert summary["transition_exemption"] == "promote"
    assert summary["tier"] == 0


@pytest.mark.parametrize(
    ("author_login", "current_head", "head_repository_id"),
    [
        ("untrusted-automation[bot]", None, 123),
        ("release-automation[bot]", "b" * 40, 123),
        ("release-automation[bot]", None, 456),
    ],
)
def test_pull_request_review_policy_transition_requires_exact_trusted_identity(
    tmp_path: Path,
    author_login: str,
    current_head: str | None,
    head_repository_id: int,
) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "large.py").write_text("value = 1\n" * 900, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _promotion_evidence(
        tmp_path,
        head=head,
        author_login=author_login,
        current_head=current_head,
        head_repository_id=head_repository_id,
    )

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 1
    payload = _json_object(result.stdout)
    summary = _object(payload["summary"])
    assert summary["transition_exemption"] is None
    assert summary["tier"] == 2
    assert isinstance(summary["reasons"], list)
    assert "bot_authored_pull_request" in summary["reasons"]
    assert _object(payload["size"])["classification"] == "measured"


@dataclass(frozen=True, slots=True)
class ReviewPolicyRun:
    exit_code: int
    summary: dict[str, object]


def _invoke_review_policy(
    repository: Path,
    *,
    base: str,
    head: str,
    evidence: Path,
    manifest: Path | None = None,
) -> ReviewPolicyRun:
    arguments = [
        "pull-request",
        "review-policy",
        str(repository),
        "--base",
        base,
        "--head",
        head,
        "--evidence",
        str(evidence),
    ]
    if manifest is not None:
        arguments.extend(["--manifest", str(manifest)])
    result = runner.invoke(app, arguments)
    return ReviewPolicyRun(result.exit_code, _object(_json_object(result.stdout)["summary"]))


def _approvals(head: str, count: int) -> list[dict[str, object]]:
    return [
        {"reviewer": f"{index}:human-{index}", "state": "approved", "commit_sha": head}
        for index in range(count)
    ]


@pytest.mark.parametrize(
    ("changed_lines", "approvals", "exit_code", "tier", "reasons"),
    [
        pytest.param(
            1,
            0,
            1,
            1,
            ["zero_review_threshold", "author_review_floor", "approvals_missing"],
            id="small-change-without-approval-blocks",
        ),
        pytest.param(
            1,
            1,
            0,
            1,
            ["zero_review_threshold", "author_review_floor"],
            id="small-change-with-one-approval-passes",
        ),
        pytest.param(300, 1, 0, 1, ["one_review_threshold"], id="one-review-tier-passes"),
        pytest.param(
            900,
            1,
            1,
            2,
            ["two_review_threshold", "approvals_missing"],
            id="two-review-tier-needs-two",
        ),
        pytest.param(900, 2, 0, 2, ["two_review_threshold"], id="two-review-tier-passes"),
    ],
)
def test_review_policy_allowlisted_bot_author_always_needs_human_approval(  # ruff: ignore[too-many-arguments] - one decision-table row per tier
    tmp_path: Path,
    *,
    changed_lines: int,
    approvals: int,
    exit_code: int,
    tier: int,
    reasons: list[str],
) -> None:
    base = _review_policy_fixture(tmp_path, trusted_bot_authors=("sarj-bulbul[bot]",))
    (tmp_path / "fix.py").write_text("value = 1\n" * changed_lines, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(
        tmp_path,
        head=head,
        reviews=_approvals(head, approvals),
        author_is_bot=True,
        author_login="Sarj-Bulbul[bot]",
    )

    run = _invoke_review_policy(tmp_path, base=base, head=head, evidence=evidence)

    assert run.exit_code == exit_code
    assert run.summary["merge_ready"] is (exit_code == 0)
    assert run.summary["tier"] == tier
    assert run.summary["current_human_approvals"] == approvals
    assert run.summary["reasons"] == reasons


@pytest.mark.parametrize("author_login", ["other-bot[bot]", "evil-sarj-bulbul[bot]"])
def test_review_policy_unlisted_bot_author_stays_blocked(
    tmp_path: Path,
    author_login: str,
) -> None:
    base = _review_policy_fixture(tmp_path, trusted_bot_authors=("sarj-bulbul[bot]",))
    (tmp_path / "fix.py").write_text("value = 1\n" * 300, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(
        tmp_path,
        head=head,
        reviews=_approvals(head, 1),
        author_is_bot=True,
        author_login=author_login,
    )

    run = _invoke_review_policy(tmp_path, base=base, head=head, evidence=evidence)

    assert run.exit_code == 1
    assert run.summary["merge_ready"] is False
    assert run.summary["reasons"] == ["one_review_threshold", "bot_authored_pull_request"]


def test_review_policy_ignores_trusted_bot_authors_added_by_the_pull_request(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(tmp_path)
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "trusted_bot_authors = []", 'trusted_bot_authors = ["sarj-bulbul[bot]"]'
        ),
        encoding="utf-8",
    )
    (tmp_path / "fix.py").write_text("value = 1\n" * 300, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(
        tmp_path,
        head=head,
        reviews=_approvals(head, 1),
        author_is_bot=True,
        author_login="sarj-bulbul[bot]",
    )
    base_manifest = tmp_path.parent / f"{tmp_path.name}-base-manifest.toml"
    trusted_manifest(tmp_path, base, base_manifest)

    run = _invoke_review_policy(
        tmp_path, base=base, head=head, evidence=evidence, manifest=base_manifest
    )

    assert run.exit_code == 1
    assert run.summary["reasons"] == ["one_review_threshold", "bot_authored_pull_request"]


def test_review_policy_allowlisted_bot_promotion_keeps_its_transition_exemption(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(tmp_path, trusted_bot_authors=("release-automation[bot]",))
    (tmp_path / "large.py").write_text("value = 1\n" * 900, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _promotion_evidence(tmp_path, head=head)

    run = _invoke_review_policy(tmp_path, base=base, head=head, evidence=evidence)

    assert run.exit_code == 0
    assert run.summary["transition_exemption"] == "promote"
    assert run.summary["tier"] == 0


ALLOWLISTED_BOT_REVIEWER = "348999126:bulbul-review[bot]"


def _bot_approval(head: str, reviewer: str = ALLOWLISTED_BOT_REVIEWER) -> dict[str, object]:
    return {"reviewer": reviewer, "state": "approved", "commit_sha": head, "reviewer_is_bot": True}


def test_review_policy_counts_a_listed_bot_approval_apart_from_humans(tmp_path: Path) -> None:
    base = _review_policy_fixture(tmp_path, allowlisted_bot_reviewers=("Bulbul-Review[bot]",))
    (tmp_path / "fix.py").write_text("value = 1\n" * 300, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head, reviews=[_bot_approval(head)])

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = _json_object(result.stdout)
    assert _object(payload["policy"])["allowlisted_bot_reviewers"] == ["Bulbul-Review[bot]"]
    summary = _object(payload["summary"])
    assert summary["current_human_approvals"] == 0
    assert summary["current_allowlisted_bot_approvals"] == 1
    assert summary["allowlisted_bot_approvers"] == [ALLOWLISTED_BOT_REVIEWER]
    counts = _object(payload["counts"])
    assert (counts["human_reviews"], counts["allowlisted_bot_reviews"]) == (0, 1)


def test_review_policy_ignores_a_listed_bot_approval_on_a_bot_authored_pull_request(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(
        tmp_path,
        trusted_bot_authors=("sarj-bulbul[bot]",),
        allowlisted_bot_reviewers=("bulbul-review[bot]",),
    )
    (tmp_path / "fix.py").write_text("value = 1\n" * 300, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(
        tmp_path,
        head=head,
        reviews=[_bot_approval(head)],
        author_is_bot=True,
        author_login="sarj-bulbul[bot]",
    )

    run = _invoke_review_policy(tmp_path, base=base, head=head, evidence=evidence)

    assert run.exit_code == 1
    assert run.summary["current_allowlisted_bot_approvals"] == 0
    assert run.summary["reasons"] == [
        "one_review_threshold",
        "allowlisted_bot_approval_not_counted",
        "approvals_missing",
    ]


@pytest.mark.parametrize(
    "reviewer", ["30:other-bot[bot]", "31:evil-bulbul-review[bot]", "32:bulbul-review"]
)
def test_review_policy_rejects_bot_review_evidence_from_unlisted_reviewers(
    tmp_path: Path,
    reviewer: str,
) -> None:
    base = _review_policy_fixture(tmp_path, allowlisted_bot_reviewers=("bulbul-review[bot]",))
    (tmp_path / "fix.py").write_text("value = 1\n" * 300, encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(
        tmp_path, head=head, reviews=[_bot_approval(head, reviewer=reviewer)]
    )

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 2
    payload = _json_object(result.stdout)
    assert payload["completion"] == "incomplete"
    assert "allowlisted_bot_reviewers" in str(
        _object_list(payload["execution_issues"])[0]["message"]
    )


def test_pull_request_review_policy_reports_missing_body_sections(tmp_path: Path) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "README.md").write_text("changed\n", encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(
        tmp_path,
        head=head,
        body="## What & why\n<!-- not filled -->\n",
    )

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 1
    summary = _object(_json_object(result.stdout)["summary"])
    assert summary["missing_body_sections"] == [
        "What & why",
        "QA impact / blast radius",
    ]
    reasons = summary["reasons"]
    assert isinstance(reasons, list)
    assert "body_sections_incomplete" in reasons


def test_pull_request_review_policy_rejects_incomplete_provider_evidence(
    tmp_path: Path,
) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "README.md").write_text("changed\n", encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head, checks_complete=False)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 2
    payload = _json_object(result.stdout)
    assert payload["completion"] == "incomplete"
    assert "required checks" in str(_object_list(payload["execution_issues"])[0]["message"])


def test_pull_request_review_policy_blocks_check_from_a_stale_head(tmp_path: Path) -> None:
    base = _review_policy_fixture(tmp_path)
    (tmp_path / "README.md").write_text("changed\n", encoding="utf-8")
    _commit_changes(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    evidence = _review_policy_evidence(tmp_path, head=head, check_head="b" * 40)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "review-policy",
            str(tmp_path),
            "--base",
            base,
            "--head",
            head,
            "--evidence",
            str(evidence),
        ],
    )

    assert result.exit_code == 1
    summary = _object(_json_object(result.stdout)["summary"])
    assert isinstance(summary["reasons"], list)
    assert "check_head_mismatch" in summary["reasons"]


def test_pull_request_commits_command_enforces_default_limit(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"change {index}\n", encoding="utf-8")
        _commit_changes(tmp_path)

    result = runner.invoke(
        app,
        [
            "pull-request",
            "commits",
            str(tmp_path),
            "--base",
            base,
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    payload = _json_object(result.stdout)
    assert payload["command"] == "pull-request commits"
    assert payload["conclusion"] == "findings"
    assert _object(payload["summary"])["commit_count"] == 6
    assert _object(payload["policy"])["maximum_commits"] == 5


def test_pull_request_commits_advisory_reports_without_blocking(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    _commit_changes(tmp_path)
    base = _git(tmp_path, "rev-parse", "HEAD")
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"change {index}\n", encoding="utf-8")
        _commit_changes(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--base", base, "--advisory"],
    )

    assert result.exit_code == 0
    assert "Advisory only" in result.stdout


def test_pull_request_commits_advisory_incomplete_does_not_block(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "pull-request",
            "commits",
            str(tmp_path),
            "--base",
            "missing",
            "--advisory",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    assert payload["completion"] == "incomplete"
    assert payload["conclusion"] == "inconclusive"


def test_pull_request_commits_requires_exact_base(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--format", "json"],
    )

    assert result.exit_code == 2
    issue = _object_list(_json_object(result.stdout)["execution_issues"])[0]
    assert issue["code"] == "request.invalid"


def _manifest(root: Path, text: str) -> None:
    policy_directory = root / ".repo-standards"
    policy_directory.mkdir()
    (policy_directory / "repository.toml").write_text(text, encoding="utf-8")
    _commit_fixture(root)


def _json_object(value: str) -> dict[str, object]:
    parsed: object = json.loads(value)  # pyright: ignore[reportAny] -- the JSON decoder returns Any; the object is checked below
    assert isinstance(parsed, dict)
    return {
        key: item
        for key, item in parsed.items()  # pyright: ignore[reportUnknownVariableType] -- runtime checks narrow decoded JSON keys and values
        if isinstance(key, str)
    }


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType] -- runtime checks narrow decoded JSON keys and values
        if isinstance(key, str)
    }


def _object_list(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    return [
        _object(item)  # pyright: ignore[reportUnknownArgumentType] -- each decoded JSON element is narrowed by _object
        for item in value  # pyright: ignore[reportUnknownVariableType] -- runtime checks narrow decoded JSON keys and values
    ]


GOOD_MANIFEST = """
repository_id = "example-repository"
[[components]]
id = "alpha.agent"
kind = "application"
product = "alpha"
path = "applications/alpha/agent"
owner = "@example/alpha"
"""


def test_report_json_is_one_deterministic_value(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    first = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    second = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    report = _json_object(first.stdout)
    assert report["conclusion"] == "passed"
    assert report["command"] == "report"
    assert _object(report["baseline"])["status"] == "not-requested"
    assert _object(report["ratchet"])["status"] == "not-requested"
    assert _object(report["tool"])["version"] != "0.1.0-dev"

    (tmp_path / ".repo-standards" / "repository.toml").write_text(
        GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"),
        encoding="utf-8",
    )
    dirty = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert dirty.exit_code == 0
    assert dirty.stdout == first.stdout


def test_check_staged_reads_index_and_ignores_unstaged_bytes(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.write_text(
        GOOD_MANIFEST.replace("example-repository", "staged-repository"), encoding="utf-8"
    )
    _git(tmp_path, "add", ".repo-standards/repository.toml")
    manifest.write_text(
        GOOD_MANIFEST.replace("example-repository", "unstaged-repository"), encoding="utf-8"
    )

    committed = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    staged = runner.invoke(app, ["check", str(tmp_path), "--staged", "--format", "json"])

    assert committed.exit_code == staged.exit_code == 0
    assert _json_object(committed.stdout)["repository_id"] == "example-repository"
    staged_payload = _json_object(staged.stdout)
    assert staged_payload["repository_id"] == "staged-repository"
    assert _object(staged_payload["provenance"])["kind"] == "git-index"


def test_check_staged_blocks_a_new_forbidden_artifact(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    rule_id = RuleId("repository/artifacts/bespoke-iac-verifiers")
    verifier = tmp_path / "iac" / "verify-plan.mjs"
    verifier.parent.mkdir()
    verifier.write_text("export {};\n", encoding="utf-8")
    _git(tmp_path, "add", "iac/verify-plan.mjs")

    committed = runner.invoke(
        app,
        ["check", str(tmp_path), "--enable-rule", str(rule_id), "--format", "json"],
    )
    staged = runner.invoke(
        app,
        [
            "check",
            str(tmp_path),
            "--staged",
            "--enable-rule",
            str(rule_id),
            "--format",
            "json",
        ],
    )

    assert committed.exit_code == 0
    assert staged.exit_code == 1
    diagnostics = _object_list(_json_object(staged.stdout)["diagnostics"])
    assert [item["path"] for item in diagnostics] == ["iac/verify-plan.mjs"]


def test_pending_report_findings_are_disabled(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"))
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    assert report["conclusion"] == "passed"
    assert _object_list(report["diagnostics"]) == []


def test_unavailable_rule_cannot_be_explicitly_activated(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    result = runner.invoke(
        app,
        [
            "report",
            str(tmp_path),
            "--enable-rule",
            "unknown/rule/id",
            "--format",
            "json",
        ],
    )

    report = _json_object(result.stdout)
    assert result.exit_code == 2
    assert report["conclusion"] == "inconclusive"
    assert "rules are not available" in str(report)


@pytest.mark.parametrize(
    ("selector", "path"),
    [
        (
            "repository/artifacts/terraform-test-files",
            "iac/tests/routing.tftest.hcl",
        ),
    ],
)
def test_approved_artifact_rules_block_only_when_enabled(
    tmp_path: Path, selector: str, path: str
) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    script = tmp_path / path
    script.parent.mkdir(parents=True)
    script.write_text(".\n", encoding="utf-8")
    _commit_changes(tmp_path)

    disabled = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    enabled = runner.invoke(
        app,
        [
            "check",
            str(tmp_path),
            "--enable-rule",
            selector,
            "--format",
            "json",
        ],
    )

    assert disabled.exit_code == 0
    assert enabled.exit_code == 1
    diagnostics = _object_list(_json_object(enabled.stdout)["diagnostics"])
    assert [item["path"] for item in diagnostics] == [path]


def test_manifest_enabled_rules_are_the_single_activation_source(tmp_path: Path) -> None:
    manifest = GOOD_MANIFEST.replace(
        'repository_id = "example-repository"',
        'repository_id = "example-repository"\n'
        'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers"]',
    )
    _manifest(tmp_path, manifest)
    verifier = tmp_path / "verify.mjs"
    verifier.write_text("export {};\n", encoding="utf-8")
    _commit_changes(tmp_path)

    configured = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    conflicting = runner.invoke(
        app,
        [
            "check",
            str(tmp_path),
            "--enable-rule",
            "repository/artifacts/bespoke-iac-verifiers",
            "--format",
            "json",
        ],
    )

    assert configured.exit_code == 1
    paths = [item["path"] for item in _object_list(_json_object(configured.stdout)["diagnostics"])]
    assert paths == ["verify.mjs"]
    assert conflicting.exit_code == 2
    assert "cannot be combined" in conflicting.stdout


def test_manifest_rejects_versioned_rule_selectors(tmp_path: Path) -> None:
    manifest = GOOD_MANIFEST.replace(
        'repository_id = "example-repository"',
        'repository_id = "example-repository"\n'
        'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers@5"]',
    )
    _manifest(tmp_path, manifest)

    result = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])

    assert result.exit_code == 2
    assert "versionless rule IDs" in result.stdout


def test_versioned_rule_selector_cannot_be_enabled(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)

    result = runner.invoke(
        app,
        [
            "check",
            str(tmp_path),
            "--enable-rule",
            "repository/artifacts/bespoke-iac-verifiers@5",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert "versionless rule IDs" in result.stdout


@pytest.mark.parametrize("terminal_width", [80, 160])
@pytest.mark.parametrize("color", [False, True])
def test_enable_rule_help_uses_current_rule_ids(terminal_width: int, *, color: bool) -> None:
    result = runner.invoke(app, ["check", "--help"], terminal_width=terminal_width, color=color)
    uncolored = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    help_text = " ".join(re.sub(r"[│─╭╮╰╯]", " ", uncolored).split())

    assert result.exit_code == 0
    assert "--enable-rule" in help_text
    assert "Activate a current" in help_text
    assert "rule ID for this run." in help_text
    assert "rule-id@version" not in help_text
    assert "[[javascript.artifacts]]" in help_text


def test_text_diagnostics_do_not_invent_source_coordinates(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"))
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "text"])
    assert result.exit_code == 0
    assert ":1:1:" not in result.stdout
    assert result.stdout == "repo-standards: passed; 0 errors, 0 warnings\n"


def test_pending_strict_errors_do_not_block(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"))
    result = runner.invoke(app, ["check", str(tmp_path), "--mode", "strict", "--format", "json"])
    assert result.exit_code == 0


def test_strict_operational_layout_guidance_is_nonblocking(tmp_path: Path) -> None:
    operational_manifest = GOOD_MANIFEST.replace(
        '''id = "alpha.agent"
kind = "application"
product = "alpha"
path = "applications/alpha/agent"''',
        '''id = "alpha.terraform"
kind = "terraform-root"
product = "alpha"
path = "iac/alpha"''',
    )
    _manifest(tmp_path, operational_manifest)
    result = runner.invoke(app, ["check", str(tmp_path), "--mode", "strict", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    assert _object_list(report["diagnostics"]) == []


def test_malformed_manifest_is_incomplete(tmp_path: Path) -> None:
    _manifest(tmp_path, "unknown = true\n")
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 2
    assert report["completion"] == "incomplete"
    assert report["conclusion"] == "inconclusive"


def test_schema_is_machine_discoverable() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    schema = _json_object(result.stdout)
    properties = _object(schema["properties"])
    schema_version = _object(properties["schema_version"])
    assert schema_version["const"] == 3


def test_report_validates_against_published_schema(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert checked.exit_code == 0
    report = _json_object(checked.stdout)
    schema_result = runner.invoke(app, ["schema"])
    assert schema_result.exit_code == 0
    schema = _json_object(schema_result.stdout)
    validate(instance=report, schema=schema)


def test_report_schema_rejects_incoherent_outcome_state(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert checked.exit_code == 0
    report = _json_object(checked.stdout)
    report["completion"] = "complete"
    report["conclusion"] = "inconclusive"
    report["diagnostics"] = []
    report["execution_issues"] = []
    schema_result = runner.invoke(app, ["schema"])
    assert schema_result.exit_code == 0
    with pytest.raises(JSONSchemaValidationError):
        validate(instance=report, schema=_json_object(schema_result.stdout))


def test_incomplete_report_and_anchor_locations_validate_against_schema(tmp_path: Path) -> None:
    _manifest(tmp_path, "unknown = true\n")
    incomplete = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    schema_result = runner.invoke(app, ["schema"])
    validate(instance=_json_object(incomplete.stdout), schema=_json_object(schema_result.stdout))

    policy_directory = tmp_path / ".repo-standards"
    (policy_directory / "repository.toml").write_text(
        GOOD_MANIFEST.replace("applications/alpha/agent", "python/agent"),
        encoding="utf-8",
    )
    _commit_changes(tmp_path)
    findings = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert _object_list(_json_object(findings.stdout)["diagnostics"]) == []


def test_neutral_core_contains_no_sarj_policy_vocabulary() -> None:
    core = Path(__file__).parents[1] / "src" / "repo_standards" / "core"
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(core.glob("*.py"))
    ).casefold()
    assert "sarj" not in source
    assert "foundation-service" not in source
    assert "product-library" not in source


def test_manifest_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text(GOOD_MANIFEST, encoding="utf-8")
    policy_directory = tmp_path / ".repo-standards"
    policy_directory.mkdir()
    Path(policy_directory / "repository.toml").symlink_to(outside)
    _commit_fixture(tmp_path)
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 2
    issues = _object_list(report["execution_issues"])
    assert issues[0]["code"] == "analysis.configuration"
    assert "symlink" in str(issues[0]["message"])


def test_repository_code_is_not_executed(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    marker = tmp_path / "must-not-exist"
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": f"touch {marker}"}}), encoding="utf-8"
    )
    result = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert not marker.exists()


def test_inspect_bootstraps_without_a_repository_manifest() -> None:
    repository = Path(__file__).parents[1]
    result = runner.invoke(app, ["inspect", str(repository)])
    assert result.exit_code == 0
    inspection = _json_object(result.stdout)
    assert inspection["command"] == "inspect"
    assert inspection["completion"] == "complete"
    summary = _object(inspection["summary"])
    assert isinstance(summary["tracked_files"], int)
    assert summary["tracked_files"] > 0
    assert _object(inspection["page"])["limit"] == 100


def test_inspect_supports_bounded_filtered_pages() -> None:
    repository = Path(__file__).parents[1]
    result = runner.invoke(
        app,
        ["inspect", str(repository), "--kind", "project", "--limit", "1"],
    )
    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    page = _object(payload["page"])
    returned = page["returned"]
    assert isinstance(returned, int)
    assert returned <= 1
    assert all(item["kind"] == "project" for item in _object_list(payload["items"]))


def test_invalid_page_is_a_structured_failure() -> None:
    result = runner.invoke(app, ["rules", "--limit", "501"])
    payload = _json_object(result.stdout)
    assert result.exit_code == 2
    assert payload["completion"] == "incomplete"
    issue = _object_list(payload["execution_issues"])[0]
    assert issue["code"] == "request.invalid"


def test_capabilities_are_machine_discoverable() -> None:
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    capabilities = _json_object(result.stdout)
    assert capabilities["schema_version"] == 2
    commands = capabilities["commands"]
    assert isinstance(commands, list)
    assert "catalog" in commands
    assert "pull-request commits" in commands
    safety = _object(capabilities["safety"])
    assert safety["repository_code_execution"] is False
    assert safety["mutation"] == "commit-message --fix-safe only"
    assert safety["network"] is False
    assert safety["network_default"] is False
    assert safety["network_mode"] == "disabled"
    assert _object(capabilities["tool"])["version"]
    assert capabilities["execution_issues"] == []


def test_rules_are_filterable_and_paginated() -> None:
    result = runner.invoke(
        app,
        ["rules", "--rule-prefix", "repository/", "--severity", "error", "--limit", "2"],
    )
    assert result.exit_code == 0
    payload = _json_object(result.stdout)
    rules = _object_list(payload["rules"])
    assert len(rules) == 2
    assert all(str(item["rule_id"]).startswith("repository/") for item in rules)
    assert all(item["default_severity"] == "error" for item in rules)
    assert _object(payload["page"])["next_cursor"] == "2"


def test_ratchet_report_has_explicit_verified_baseline_status(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    initial = runner.invoke(app, ["report", str(tmp_path), "--format", "json"])
    report = _json_object(initial.stdout)
    policy = _object(report["policy"])
    baseline: dict[str, object] = {
        "schema_version": 2,
        "repository_id": report["repository_id"],
        "policy": policy["id"],
        "policy_version": policy["version"],
        "scope_digest": report["scope_digest"],
        "fingerprints": list[str](),
    }
    (tmp_path / ".repo-standards" / "baseline.json").write_text(
        json.dumps(baseline), encoding="utf-8"
    )
    _commit_changes(tmp_path)
    checked = runner.invoke(
        app,
        ["check", str(tmp_path), "--mode", "ratchet", "--format", "json"],
    )
    payload = _json_object(checked.stdout)
    assert checked.exit_code == 0
    assert _object(payload["baseline"])["status"] == "verified"
    assert _object(payload["ratchet"])["status"] == "clean"

    (tmp_path / ".repo-standards" / "baseline.json").write_text("not-json", encoding="utf-8")
    dirty = runner.invoke(
        app,
        ["check", str(tmp_path), "--mode", "ratchet", "--format", "json"],
    )
    assert dirty.exit_code == 0
    assert _object(_json_object(dirty.stdout)["ratchet"])["status"] == "clean"


def test_ratchet_rejects_missing_baseline_explicitly(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(
        app,
        ["check", str(tmp_path), "--mode", "ratchet", "--format", "json"],
    )
    payload = _json_object(checked.stdout)
    assert checked.exit_code == 2
    assert _object(payload["baseline"])["status"] == "rejected"
    assert _object(payload["ratchet"])["status"] == "not-evaluated"


def test_unknown_rule_and_schema_are_structured() -> None:
    for arguments, code in (
        (("explain", "not/a-rule"), "rule.unknown"),
        (("schema", "missing"), "schema.unknown"),
    ):
        result = runner.invoke(app, list(arguments))
        payload = _json_object(result.stdout)
        assert result.exit_code == 2
        assert _object_list(payload["execution_issues"])[0]["code"] == code


def test_public_corpus_is_six_immutable_not_downloaded_sources() -> None:
    manifest_path = Path(__file__).parents[1] / "corpus" / "public-oss-v2.json"
    corpus = _json_object(manifest_path.read_text(encoding="utf-8"))
    sources = _object_list(corpus["sources"])
    assert len(sources) == 6
    assert len({item["profile"] for item in sources}) == 6
    assert all(len(str(item["commit"])) == 40 for item in sources)
    assert all(len(str(item["tree"])) == 40 for item in sources)
    assert all(_object(item["snapshot"])["status"] == "not-downloaded" for item in sources)


def test_rest_discover_requires_explicit_selection_when_ambiguous(tmp_path: Path) -> None:
    for directory in (tmp_path / "a", tmp_path / "b"):
        directory.mkdir()
        (directory / "openapi.json").write_text(
            '{"openapi":"3.1.2","info":{"title":"x","version":"1"},"paths":{}}',
            encoding="utf-8",
        )
    _commit_fixture(tmp_path)
    discovered = runner.invoke(app, ["rest", "discover", str(tmp_path)])
    assert discovered.exit_code == 0
    assert len(_object_list(_json_object(discovered.stdout)["candidates"])) == 2


@pytest.mark.parametrize("count", [100, 101])
def test_rest_discover_reports_its_tracked_input_limit(tmp_path: Path, count: int) -> None:
    for index in range(count):
        directory = tmp_path / f"service-{index}"
        directory.mkdir()
        (directory / "pyproject.toml").write_text(
            f'[project]\nname = "service-{index}"\nversion = "0.1.0"\ndependencies = ["fastapi"]\n',
            encoding="utf-8",
        )
    (tmp_path / "main.py").write_text(
        "raise RuntimeError('application import is forbidden')\n", encoding="utf-8"
    )
    _commit_fixture(tmp_path)

    result = runner.invoke(app, ["rest", "discover", str(tmp_path)])

    assert result.exit_code == (0 if count == 100 else 2)
    payload = _json_object(result.stdout)
    if count == 100:
        assert payload["completion"] == "complete"
        assert payload["application_code_executed"] is False
        assert _object(payload["summary"])["files_scanned"] == count
    else:
        assert payload["completion"] == "incomplete"
        assert payload["conclusion"] == "inconclusive"
        assert _object_list(payload["execution_issues"])[0]["code"] == "rest.discovery-incomplete"


def test_repository_text_is_bounded_without_changing_json_or_failure(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for index in range(120):
        (scripts / f"verify-private-{index:03}.py").write_text("pass\n", encoding="utf-8")
    manifest = GOOD_MANIFEST.replace(
        'repository_id = "example-repository"',
        'repository_id = "example-repository"\n'
        'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers"]',
    )
    _manifest(tmp_path, manifest)
    text = runner.invoke(app, ["check", str(tmp_path)])
    machine = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    assert text.exit_code == machine.exit_code == 1
    payload = _json_object(machine.stdout)
    diagnostics = _object_list(payload["diagnostics"])
    assert len(diagnostics) >= 120
    assert f"{len(diagnostics) - 50} diagnostic(s) omitted" in text.stdout
    assert len(text.stdout.splitlines()) == 52
