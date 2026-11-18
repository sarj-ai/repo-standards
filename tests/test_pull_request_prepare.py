from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.errors import ConfigurationError
from repo_standards.pull_request import _prepare as preparation  # ruff: ignore[import-private-name] - exercise the operation's cancellation boundary
from repo_standards.pull_request._prepare import prepare_pull_request  # ruff: ignore[import-private-name] - exercise the operation at its owned boundary


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    return subprocess.run(
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _commit(root: Path, name: str) -> str:
    (root / name).write_text(name, encoding="utf-8")
    _git(root, "add", name)
    _git(root, "commit", "--quiet", "-m", f"feat: add {name}")
    return _git(root, "rev-parse", "HEAD")


def _repository(root: Path) -> str:
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.name", "Preparation fixture")
    _git(root, "config", "user.email", "prepare@example.invalid")
    base = _commit(root, "base.txt")
    _git(root, "switch", "--quiet", "-c", "feature")
    _commit(root, "first.txt")
    _commit(root, "second.txt")
    return base


def _prepare(root: Path) -> None:
    prepare_pull_request(
        root, base="main", message="feat: prepare feature", trust_repository_code=True
    )


def _hook(root: Path, name: str, body: str) -> None:
    path = Path(_git(root, "rev-parse", "--absolute-git-dir")) / "hooks" / name
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o700)


def test_squashes_to_one_commit_preserving_tree_and_native_hooks(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    before = _git(tmp_path, "rev-parse", "HEAD")
    tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")
    _hook(tmp_path, "pre-commit", "echo pre-commit >> .git/ran-hooks")
    _hook(tmp_path, "commit-msg", "echo commit-msg >> .git/ran-hooks")

    result = prepare_pull_request(
        tmp_path, base="main", message="feat: prepare feature", trust_repository_code=True
    )

    assert result.branch == "feature"
    assert result.original_head == before
    assert result.head == _git(tmp_path, "rev-parse", "HEAD")
    assert result.head != before
    assert _git(tmp_path, "rev-parse", "HEAD^{tree}") == tree  # ruff: ignore[missing-f-string-syntax] - literal Git tree syntax
    assert _git(tmp_path, "rev-parse", "HEAD^") == base
    assert _git(tmp_path, "rev-list", "--count", "main..HEAD") == "1"
    assert (tmp_path / ".git/ran-hooks").read_text().splitlines() == ["pre-commit", "commit-msg"]
    assert before in _git(tmp_path, "reflog", "show", "--format=%H", "feature")
    assert not _git(tmp_path, "status", "--porcelain")


def test_single_commit_is_idempotent(tmp_path: Path) -> None:
    _repository(tmp_path)
    _prepare(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _hook(tmp_path, "pre-commit", "exit 1")

    _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == head


def test_target_advanced_uses_common_ancestor_without_deleting_target_work(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    _git(tmp_path, "switch", "--quiet", "main")
    target = _commit(tmp_path, "target.txt")
    _git(tmp_path, "switch", "--quiet", "feature")
    tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")

    _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD^") == base
    assert _git(tmp_path, "rev-parse", "HEAD^{tree}") == tree  # ruff: ignore[missing-f-string-syntax] - literal Git tree syntax
    assert _git(tmp_path, "rev-parse", "main") == target
    assert _git(tmp_path, "diff", "--name-only", "main...HEAD").splitlines() == [
        "first.txt",
        "second.txt",
    ]


@pytest.mark.parametrize("dirty", ["staged", "unstaged", "untracked"])
def test_dirty_checkout_refused_without_mutation(tmp_path: Path, dirty: str) -> None:
    _repository(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    path = "new.txt" if dirty == "untracked" else "base.txt"
    (tmp_path / path).write_text("pending work", encoding="utf-8")
    if dirty == "staged":
        _git(tmp_path, "add", path)
    status = _git(tmp_path, "status", "--porcelain")

    with pytest.raises(ConfigurationError, match="clean"):
        _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert _git(tmp_path, "status", "--porcelain") == status


@pytest.mark.parametrize(
    "state",
    ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply", "sequencer"],
)
def test_in_progress_operation_refused(tmp_path: Path, state: str) -> None:
    _repository(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    path = tmp_path / ".git" / state
    if state in {"rebase-merge", "rebase-apply", "sequencer"}:
        path.mkdir()
    else:
        path.write_text(head, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="in progress"):
        _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == head


def test_requires_trust_before_hook_execution(tmp_path: Path) -> None:
    _repository(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _hook(tmp_path, "pre-commit", "echo executed > .git/unexpected-hook")

    with pytest.raises(ConfigurationError, match="trust-repository-code"):
        prepare_pull_request(
            tmp_path, base="main", message="feat: squash", trust_repository_code=False
        )

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert not (tmp_path / ".git/unexpected-hook").exists()


def test_failed_hook_restores_original_ref_and_preserves_edits(tmp_path: Path) -> None:
    _repository(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")
    _hook(tmp_path, "pre-commit", "echo 'hook edit' >> first.txt\nexit 1")

    with pytest.raises(ConfigurationError, match="commit failed"):
        _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == head
    assert (tmp_path / "first.txt").read_text().endswith("hook edit\n")
    assert _git(tmp_path, "status", "--porcelain").strip() == "M first.txt"


def test_hook_tree_change_blocks_opening_without_discarding_it(tmp_path: Path) -> None:
    _repository(tmp_path)
    _hook(tmp_path, "pre-commit", "echo 'hook edit' >> first.txt\ngit add first.txt")

    with pytest.raises(ConfigurationError, match=r"changed.*content"):
        _prepare(tmp_path)

    assert (tmp_path / "first.txt").read_text().endswith("hook edit\n")


def test_detached_head_refused(tmp_path: Path) -> None:
    _repository(tmp_path)
    _git(tmp_path, "switch", "--quiet", "--detach")
    with pytest.raises(ConfigurationError, match="branch"):
        _prepare(tmp_path)


def test_target_branch_refused_even_if_target_revision_is_old(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    _git(tmp_path, "switch", "--quiet", "main")
    _commit(tmp_path, "target.txt")
    with pytest.raises(ConfigurationError, match="protected"):
        prepare_pull_request(
            tmp_path, base=base, message="feat: squash", trust_repository_code=True
        )


def test_promotion_branch_refused(tmp_path: Path) -> None:
    _repository(tmp_path)
    path = tmp_path / ".repo-standards"
    path.mkdir()
    (path / "repository.toml").write_text(
        """repository_id = "fixture"
components = []
[pull_request.commit_history]
advisory_base_ref = "main"
[[pull_request.commit_history.transitions]]
id = "promote"
source_ref = "dev"
base_ref = "main"
head_prefix = "automation/promote-"
""",
        encoding="utf-8",
    )
    _git(tmp_path, "add", ".repo-standards/repository.toml")
    _git(tmp_path, "commit", "--quiet", "-m", "chore: configure history")
    _git(tmp_path, "branch", "-m", "automation/promote-0123456789ab")

    with pytest.raises(ConfigurationError, match="protected"):
        _prepare(tmp_path)


def test_linked_worktree_supported(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _repository(root)
    worktree = tmp_path / "linked"
    _git(root, "worktree", "add", "--quiet", "-b", "linked-feature", str(worktree), "feature")

    _prepare(worktree)

    assert _git(worktree, "rev-list", "--count", "main..HEAD") == "1"
    assert _git(root, "rev-list", "--count", "main..feature") == "2"


def test_shared_branch_checkout_refused_without_rewriting_either_worktree(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _repository(root)
    original = _git(root, "rev-parse", "HEAD")
    other = tmp_path / "other"
    _git(root, "worktree", "add", "--quiet", "--force", str(other), "feature")

    with pytest.raises(ConfigurationError, match="only one worktree"):
        _prepare(root)

    assert _git(root, "rev-parse", "HEAD") == original
    assert _git(other, "rev-parse", "HEAD") == original


def test_non_origin_target_branch_is_protected(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    _git(tmp_path, "remote", "add", "team/upstream", "https://example.invalid/repository")
    _git(tmp_path, "update-ref", "refs/remotes/team/upstream/dev", base)
    _git(tmp_path, "branch", "-m", "dev")
    original = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(ConfigurationError, match="protected"):
        prepare_pull_request(
            tmp_path,
            base="refs/remotes/team/upstream/dev",
            message="feat: squash",
            trust_repository_code=True,
        )

    assert _git(tmp_path, "rev-parse", "HEAD") == original


def test_empty_single_commit_is_not_publishable(tmp_path: Path) -> None:
    _repository(tmp_path)
    _git(tmp_path, "reset", "--hard", "main")
    _git(tmp_path, "commit", "--allow-empty", "--quiet", "-m", "feat: empty")
    original = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(ConfigurationError, match="no net file changes"):
        _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == original


def test_single_merge_commit_is_reparented_to_one_ordinary_commit(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")
    _git(tmp_path, "switch", "--quiet", "main")
    target = _commit(tmp_path, "target.txt")
    _git(tmp_path, "switch", "--quiet", "feature")
    merge = _git(
        tmp_path, "commit-tree", tree, "-p", target, "-p", base, "-m", "feat: merge changes"
    )
    _git(tmp_path, "reset", "--hard", merge)

    _prepare(tmp_path)

    assert _git(tmp_path, "rev-list", "--parents", "-n", "1", "HEAD").split() == [
        _git(tmp_path, "rev-parse", "HEAD"),
        target,
    ]
    assert _git(tmp_path, "rev-parse", "HEAD^{tree}") == tree  # ruff: ignore[missing-f-string-syntax] - literal Git tree syntax


def test_invalid_hook_header_blocks_publication(tmp_path: Path) -> None:
    _repository(tmp_path)
    _hook(tmp_path, "commit-msg", 'printf "WIP\\n" > "$1"')

    with pytest.raises(ConfigurationError, match="invalid commit header"):
        _prepare(tmp_path)

    assert _git(tmp_path, "log", "-1", "--format=%s") == "WIP"


def test_hook_failure_never_overwrites_a_concurrent_branch_update(tmp_path: Path) -> None:
    _repository(tmp_path)
    original = _git(tmp_path, "rev-parse", "HEAD")
    tree = _git(tmp_path, "rev-parse", "HEAD^{tree}")
    concurrent = _git(tmp_path, "commit-tree", tree, "-p", original, "-m", "feat: another session")
    _hook(tmp_path, "pre-commit", f"git update-ref refs/heads/feature {concurrent}\nexit 1")

    with pytest.raises(ConfigurationError, match="commit failed"):
        _prepare(tmp_path)

    assert _git(tmp_path, "rev-parse", "HEAD") == concurrent


@pytest.mark.skipif(
    not Path("/proc/self/stat").exists(), reason="native Linux process-state evidence"
)
def test_timeout_stops_native_hook_group_and_restores_original_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _repository(tmp_path)
    original = _git(tmp_path, "rev-parse", "HEAD")
    _hook(
        tmp_path,
        "pre-commit",
        "echo $$ > .git/hook-pid\nsleep 30 &\necho $! > .git/child-pid\nwait",
    )
    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- Bound the real Git hook timeout.
        preparation, "_COMMIT_TIMEOUT_SECONDS", 1
    )

    with pytest.raises(ConfigurationError, match="timed out"):
        _prepare(tmp_path)

    for name in ("hook-pid", "child-pid"):
        pid = int((tmp_path / ".git" / name).read_text())
        state = Path(f"/proc/{pid}/stat")
        if state.exists():
            assert state.read_text(encoding="utf-8").rsplit(") ", 1)[1].split()[0] == "Z"
    assert _git(tmp_path, "rev-parse", "HEAD") == original


def test_cli_runs_preparation_and_reports_exact_before_and_after(tmp_path: Path) -> None:
    _repository(tmp_path)
    before = _git(tmp_path, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app,
        [
            "pull-request",
            "prepare",
            str(tmp_path),
            "--base",
            "main",
            "--message",
            "feat: prepared",
            "--trust-repository-code",
        ],
    )

    assert result.exit_code == 0, result.output
    assert before in result.output
    assert _git(tmp_path, "rev-parse", "HEAD") in result.output


def test_cli_does_not_claim_success_without_trust(tmp_path: Path) -> None:
    _repository(tmp_path)
    head = _git(tmp_path, "rev-parse", "HEAD")

    result = CliRunner().invoke(
        app,
        ["pull-request", "prepare", str(tmp_path), "--base", "main", "--message", "feat: prepared"],
    )

    assert result.exit_code == 2, result.output
    assert "trust-repository-code" in result.output
    assert _git(tmp_path, "rev-parse", "HEAD") == head
