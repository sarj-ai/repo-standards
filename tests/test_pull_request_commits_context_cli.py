from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from typing import TYPE_CHECKING

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic schema codecs preserve the tested wire representation without adding a model envelope.
import pytest
from typer.testing import CliRunner

from repo_standards.cli import BaseRepositoryId, HeadRepositoryId, app


if TYPE_CHECKING:
    from pathlib import Path


runner = CliRunner()
OBJECT_MAP = TypeAdapter(dict[str, object])
_BASE_REPOSITORY_ID = BaseRepositoryId(101)
_HEAD_REPOSITORY_ID = HeadRepositoryId(101)


@dataclass(frozen=True, slots=True)
class GitHubMergeCheckout:
    base: str
    head: str
    merge_sha: str


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(root: Path, subject: str) -> str:
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        subject,
    )
    return _git(root, "rev-parse", "HEAD")


def _merge(root: Path, revision: str, subject: str, *options: str) -> None:
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "merge",
        "--quiet",
        "--no-ff",
        *options,
        revision,
        "-m",
        subject,
    )


def _manifest(
    *,
    maximum_commits: int = 5,
    transition: bool = False,
    enforcement: str | None = None,
) -> str:
    transition_table = ""
    if transition:
        transition_table = """
[[pull_request.commit_history.transitions]]
id = "dev-preview"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-dev-"
"""
    commit_message = f'\n[commit_message]\nenforcement = "{enforcement}"\n' if enforcement else ""
    return f"""\
repository_id = "fixture"
components = []

[pull_request.commit_history]
maximum_commits = {maximum_commits}
advisory_base_ref = "dev"
{transition_table}
{commit_message}
"""


def _initialize(root: Path) -> str:
    _git(root, "init", "--quiet", "--initial-branch=dev")
    policy = root / ".repo-standards"
    policy.mkdir()
    (policy / "repository.toml").write_text(_manifest(), encoding="utf-8")
    (root / "change.txt").write_text("base\n", encoding="utf-8")
    return _commit(root, "base")


def _event(  # ruff: ignore[too-many-arguments] - fixture keeps provider evidence explicit
    path: Path,
    *,
    base: str,
    head: str,
    base_ref: str = "dev",
    head_ref: str = "feature",
    base_repository_id: BaseRepositoryId = _BASE_REPOSITORY_ID,
    head_repository_id: HeadRepositoryId = _HEAD_REPOSITORY_ID,
) -> None:
    path.write_text(
        json.dumps(
            {
                "action": "synchronize",
                "pull_request": {
                    "base": {
                        "sha": base,
                        "ref": base_ref,
                        "repo": {"id": base_repository_id},
                    },
                    "head": {
                        "sha": head,
                        "ref": head_ref,
                        "repo": {"id": head_repository_id},
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_github_event_uses_policy_from_exact_base_not_head(tmp_path: Path) -> None:
    base = _initialize(tmp_path)
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"change {index}\n", encoding="utf-8")
        _commit(tmp_path, f"change {index}")
    (tmp_path / ".repo-standards" / "repository.toml").write_text(
        _manifest(maximum_commits=999),
        encoding="utf-8",
    )
    head = _commit(tmp_path, "attempt to weaken policy")
    event = tmp_path.parent / f"{tmp_path.name}-event.json"
    _event(event, base=base, head=head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "pull_request"},
    )

    assert result.exit_code == 1
    assert "limit 5" in result.stdout


def test_github_event_enforces_default_without_manifest(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=dev")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    base = _commit(tmp_path, "base")
    head = base
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"change {index}\n", encoding="utf-8")
        head = _commit(tmp_path, f"change {index}")
    event = tmp_path.parent / f"{tmp_path.name}-default-event.json"
    _event(event, base=base, head=head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "pull_request"},
    )

    assert result.exit_code == 1
    assert "limit 5" in result.stdout


def test_github_event_enforces_commit_messages_from_exact_base(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=dev")
    policy = tmp_path / ".repo-standards"
    policy.mkdir()
    (policy / "repository.toml").write_text(_manifest(), encoding="utf-8")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    base = _commit(tmp_path, "chore: configure policy")
    (tmp_path / "change.txt").write_text("change\n", encoding="utf-8")
    head = _commit(tmp_path, "WIP")
    event = tmp_path.parent / f"{tmp_path.name}-messages-event.json"
    _event(event, base=base, head=head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "pull_request"},
    )

    assert result.exit_code == 1
    assert "commit-message.invalid-header" in result.stdout


def test_github_event_observe_mode_reports_without_blocking(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=dev")
    policy = tmp_path / ".repo-standards"
    policy.mkdir()
    (policy / "repository.toml").write_text(_manifest(enforcement="observe"), encoding="utf-8")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    base = _commit(tmp_path, "chore: configure policy")
    (tmp_path / "change.txt").write_text("change\n", encoding="utf-8")
    head = _commit(tmp_path, "WIP")
    event = tmp_path.parent / f"{tmp_path.name}-observe-event.json"
    _event(event, base=base, head=head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "pull_request"},
    )

    assert result.exit_code == 0
    assert "1 finding(s) (observe)" in result.stdout


@pytest.mark.parametrize("subject", ["fix: feature", "WIP"])
def test_github_merge_checkout_uses_tested_base_policy_and_history(
    tmp_path: Path, subject: str
) -> None:
    old_base = _initialize(tmp_path)
    for index in range(6):
        (tmp_path / "target.txt").write_text(f"target {index}\n", encoding="utf-8")
        (tmp_path / ".repo-standards" / "repository.toml").write_text(
            _manifest(maximum_commits=1), encoding="utf-8"
        )
        _commit(tmp_path, f"chore: target {index}")
    tested_base = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "--quiet", "-b", "feature", old_base)
    (tmp_path / "feature.txt").write_text("feature\n", encoding="utf-8")
    (tmp_path / ".repo-standards" / "repository.toml").write_text(
        _manifest(maximum_commits=999, enforcement="observe"), encoding="utf-8"
    )
    _commit(tmp_path, subject)
    _merge(tmp_path, "dev", "chore: refresh target", "-Xours")
    head = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "checkout", "--quiet", "dev")
    _merge(tmp_path, "feature", "chore: tested merge")
    merge_sha = _git(tmp_path, "rev-parse", "HEAD")
    assert _git(tmp_path, "show", "--no-patch", "--format=%P", merge_sha).split() == [
        tested_base,
        head,
    ]
    event = tmp_path.parent / f"{tmp_path.name}-tested-base-event.json"
    _event(event, base=old_base, head=head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_WORKSPACE": str(tmp_path),
            "GITHUB_SHA": merge_sha,
        },
    )

    assert result.exit_code == (0 if subject == "fix: feature" else 1), result.stdout
    assert "limit 1" in result.stdout
    assert ("commit-message.invalid-header" in result.stdout) == (subject == "WIP")


@pytest.fixture
def github_merge_checkout(tmp_path: Path) -> GitHubMergeCheckout:
    base = _initialize(tmp_path)
    _git(tmp_path, "checkout", "--quiet", "-b", "feature")
    (tmp_path / "feature.txt").write_text("feature\n", encoding="utf-8")
    head = _commit(tmp_path, "fix: feature")
    _git(tmp_path, "checkout", "--quiet", "dev")
    (tmp_path / "target.txt").write_text("target\n", encoding="utf-8")
    _commit(tmp_path, "chore: target")
    _merge(tmp_path, "feature", "chore: tested merge")
    return GitHubMergeCheckout(base=base, head=head, merge_sha=_git(tmp_path, "rev-parse", "HEAD"))


@pytest.mark.parametrize("case", ["different-sha", "missing-sha", "different-head", "linear"])
def test_github_merge_checkout_rejects_inconsistent_runner_evidence(
    tmp_path: Path, github_merge_checkout: GitHubMergeCheckout, case: str
) -> None:
    head = github_merge_checkout.head
    merge_sha = github_merge_checkout.merge_sha
    match case:
        case "different-sha":
            merge_sha = "0" * 40
        case "missing-sha":
            merge_sha = ""
        case "different-head":
            head = github_merge_checkout.base
        case _:
            _git(tmp_path, "checkout", "--quiet", "HEAD^1")
            merge_sha = _git(tmp_path, "rev-parse", "HEAD")
    event = tmp_path.parent / f"{tmp_path.name}-inconsistent-event.json"
    _event(event, base=github_merge_checkout.base, head=head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_WORKSPACE": str(tmp_path),
            "GITHUB_SHA": merge_sha,
        },
    )

    assert result.exit_code == 2, result.stdout
    assert "analysis.incomplete" in result.stdout


@pytest.mark.parametrize(
    "case", ["head-only", "other-workspace", "no-workspace", "replace", "graft"]
)
def test_github_merge_checkout_preserves_explicit_head_and_fixture_boundaries(
    tmp_path: Path, github_merge_checkout: GitHubMergeCheckout, case: str
) -> None:
    workspace = str(tmp_path)
    match case:
        case "head-only":
            _git(tmp_path, "checkout", "--quiet", github_merge_checkout.head)
        case "other-workspace":
            workspace = str(tmp_path.parent)
        case "no-workspace":
            workspace = ""
        case "replace":
            _git(tmp_path, "replace", github_merge_checkout.merge_sha, github_merge_checkout.base)
        case _:
            graft = tmp_path / _git(tmp_path, "rev-parse", "--git-path", "info/grafts")
            graft.parent.mkdir(exist_ok=True)
            graft.write_text(
                f"{github_merge_checkout.merge_sha} {github_merge_checkout.head} "
                f"{github_merge_checkout.base}\n",
                encoding="utf-8",
            )
    event = tmp_path.parent / f"{tmp_path.name}-boundary-event.json"
    _event(event, base=github_merge_checkout.base, head=github_merge_checkout.head)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_WORKSPACE": workspace,
            "GITHUB_SHA": github_merge_checkout.merge_sha,
        },
    )

    assert result.exit_code == 0, result.stdout
    assert "1 non-merge commit(s)" in result.stdout


def test_github_merge_group_is_explicitly_not_applicable(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        '{"action":"checks_requested","merge_group":{}}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "merge_group"},
    )

    assert result.exit_code == 0
    assert "not applicable" in result.stdout


def test_local_advisory_is_quiet_when_satisfied(tmp_path: Path) -> None:
    base = _initialize(tmp_path)
    _git(tmp_path, "remote", "add", "origin", str(tmp_path))
    _git(tmp_path, "fetch", "--quiet", "origin", f"{base}:refs/remotes/origin/dev")
    (tmp_path / "change.txt").write_text("one\n", encoding="utf-8")
    _commit(tmp_path, "chore: one")

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--advisory", "--quiet"],
    )

    assert result.exit_code == 0
    assert not result.stdout


def test_local_advisory_does_not_block_without_manifest(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=dev")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    _commit(tmp_path, "base")

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--advisory", "--quiet"],
    )

    assert result.exit_code == 0
    assert "advisory analysis incomplete" in result.stdout
    assert "No such file" not in result.stdout


def test_local_promotion_candidate_uses_declarative_transition(tmp_path: Path) -> None:
    _initialize(tmp_path)
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.write_text(_manifest(transition=True), encoding="utf-8")
    base = _commit(tmp_path, "configure transition")
    head = base
    _git(tmp_path, "branch", "preview", base)
    _git(tmp_path, "remote", "add", "origin", str(tmp_path))
    _git(tmp_path, "fetch", "--quiet", "origin", "dev:refs/remotes/origin/dev")
    _git(tmp_path, "fetch", "--quiet", "origin", "preview:refs/remotes/origin/preview")
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"promotion {index}\n", encoding="utf-8")
        head = _commit(tmp_path, f"promotion {index}")
    _git(tmp_path, "checkout", "--quiet", "-b", f"automation/promote-dev-{head[:12]}")

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--advisory"],
    )

    assert result.exit_code == 0
    assert "candidate transition dev-preview" in result.stdout
    assert "authoritative CI will verify" in result.stdout


def test_local_promotion_candidate_json_never_claims_provider_proof(
    tmp_path: Path,
) -> None:
    _initialize(tmp_path)
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.write_text(_manifest(transition=True), encoding="utf-8")
    base = _commit(tmp_path, "configure transition")
    head = base
    _git(tmp_path, "branch", "preview", base)
    _git(tmp_path, "remote", "add", "origin", str(tmp_path))
    _git(tmp_path, "fetch", "--quiet", "origin", "dev:refs/remotes/origin/dev")
    _git(tmp_path, "fetch", "--quiet", "origin", "preview:refs/remotes/origin/preview")
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"promotion {index}\n", encoding="utf-8")
        head = _commit(tmp_path, f"promotion {index}")
    _git(tmp_path, "checkout", "--quiet", "-b", f"automation/promote-dev-{head[:12]}")

    result = runner.invoke(
        app,
        [
            "pull-request",
            "commits",
            str(tmp_path),
            "--advisory",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = OBJECT_MAP.validate_json(result.stdout)
    assert payload["conclusion"] == "inconclusive"
    assert payload["provenance"] == {"kind": "local-advisory"}
    summary = OBJECT_MAP.validate_python(payload["summary"])
    assert summary["disposition"] == "not-applicable"


def test_github_event_verifies_declarative_transition(tmp_path: Path) -> None:
    _initialize(tmp_path)
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.write_text(_manifest(transition=True), encoding="utf-8")
    base = _commit(tmp_path, "configure transition")
    head = base
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"promotion {index}\n", encoding="utf-8")
        head = _commit(tmp_path, f"promotion {index}")
    _git(tmp_path, "remote", "add", "origin", str(tmp_path))
    _git(tmp_path, "fetch", "--quiet", "origin", "dev:refs/remotes/origin/dev")
    head_ref = f"automation/promote-dev-{head[:12]}"
    _git(tmp_path, "checkout", "--quiet", "-b", head_ref)
    event = tmp_path.parent / f"{tmp_path.name}-promotion-event.json"
    _event(event, base=base, head=head, base_ref="preview", head_ref=head_ref)

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "pull_request"},
    )

    assert result.exit_code == 0
    assert "Verified transition: dev-preview" in result.stdout


def test_github_event_never_exempts_fork_transition(tmp_path: Path) -> None:
    _initialize(tmp_path)
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.write_text(_manifest(transition=True), encoding="utf-8")
    base = _commit(tmp_path, "configure transition")
    head = base
    for index in range(6):
        (tmp_path / "change.txt").write_text(f"promotion {index}\n", encoding="utf-8")
        head = _commit(tmp_path, f"promotion {index}")
    _git(tmp_path, "remote", "add", "origin", str(tmp_path))
    _git(tmp_path, "fetch", "--quiet", "origin", "dev:refs/remotes/origin/dev")
    head_ref = f"automation/promote-dev-{head[:12]}"
    event = tmp_path.parent / f"{tmp_path.name}-fork-event.json"
    _event(
        event,
        base=base,
        head=head,
        base_ref="preview",
        head_ref=head_ref,
        head_repository_id=HeadRepositoryId(202),
    )

    result = runner.invoke(
        app,
        ["pull-request", "commits", str(tmp_path), "--github-event", str(event)],
        env={"GITHUB_EVENT_NAME": "pull_request"},
    )

    assert result.exit_code == 1
    assert "Disposition: over-limit" in result.stdout


def test_github_event_rejects_manual_policy_overrides(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        '{"action":"checks_requested","merge_group":{}}',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "pull-request",
            "commits",
            str(tmp_path),
            "--github-event",
            str(event),
            "--max-commits",
            "999",
            "--format",
            "json",
        ],
        env={"GITHUB_EVENT_NAME": "merge_group"},
    )

    assert result.exit_code == 2
    assert "policy overrides" in result.stdout
