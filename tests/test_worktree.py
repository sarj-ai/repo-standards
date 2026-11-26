from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from repo_standards.catalog import build_catalog
from repo_standards.cli import app
from repo_standards.worktree import BRANCH, Row, audit, create, expected_path, guard


def _git(directory: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git")
    assert executable is not None
    return subprocess.run(
        [executable, "-C", str(directory), *arguments],
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
    )


def _commit(directory: Path, message: str) -> str:
    _git(
        directory,
        "-c",
        "user.name=Worktree Test",
        "-c",
        "user.email=worktree@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        message,
    )
    return _git(directory, "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    primary = tmp_path / "code" / "org" / "repo"
    _git(tmp_path, "init", "--bare", "-b", "main", str(origin))
    _git(tmp_path, "init", "-b", "main", str(seed))
    _commit(seed, "initial")
    _git(seed, "push", str(origin), "main")
    primary.parent.mkdir(parents=True)
    _git(tmp_path, "clone", str(origin), str(primary))
    return primary


def _enable_hook(primary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    known = _git(primary, "help", "--config").stdout.splitlines()
    if "hook.<friendly-name>.event" not in known:
        pytest.skip("requires Git with config-defined hooks")
    executable = Path(sys.executable).with_name("repo-standards")
    script = (
        f'case $1 in *[!0]*) ;; *) exec {shlex.quote(str(executable))} worktree guard "$@" ;; esac'
    )
    include = tmp_path / "guard.inc"
    config = tmp_path / "gitconfig"
    command = shlex.join(("sh", "-c", script, "sarj-worktree-guard"))
    _git(
        primary, "config", "--file", str(include), "hook.sarj-worktree-guard.event", "post-checkout"
    )
    _git(primary, "config", "--file", str(include), "hook.sarj-worktree-guard.command", command)
    _git(
        primary,
        "config",
        "--file",
        str(config),
        f"includeIf.gitdir:{primary.parent}/.path",
        str(include),
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))


@pytest.mark.parametrize(
    ("branch", "valid"),
    [
        ("fix/sarj-589-walrus", True),
        ("spike/bold-oak-a3f2", True),
        ("chore/upgrade-logto146", True),
        ("feat/" + "x" * 40, True),
        ("claude/foo", False),
        ("codex/x", False),
        ("fix/Foo", False),
        ("fix/a--b", False),
        ("fix/a/b", False),
        ("fix/x-20261123", False),
        ("fix/x-20261122t005942z", False),
        ("fix/" + "x" * 41, False),
    ],
)
def test_branch_grammar(branch: str, valid: bool) -> None:
    assert bool(BRANCH.fullmatch(branch)) is valid


def test_expected_path_derives_from_primary_and_branch(layout: Path) -> None:
    assert expected_path(layout, "fix/a-b") == layout.parents[1] / "worktrees/repo/fix--a-b"


def test_create_branches_from_fetched_origin_default_without_upstream(
    layout: Path, tmp_path: Path
) -> None:
    seed = tmp_path / "seed"
    head = _commit(seed, "advanced origin default")
    _git(seed, "push", str(tmp_path / "origin.git"), "main")
    target = create(layout, "feat/fresh-base")
    assert _git(target, "rev-parse", "HEAD").stdout.strip() == head
    assert _git(target, "rev-parse", "@{u}", check=False).returncode != 0


def test_create_checks_out_legacy_origin_branch(layout: Path, tmp_path: Path) -> None:
    _git(
        tmp_path / "seed", "push", str(tmp_path / "origin.git"), "HEAD:refs/heads/dependabot/npm/x"
    )
    target = create(layout, "dependabot/npm/x")
    assert target.name == "dependabot--npm--x"
    assert (
        _git(target, "rev-parse", "--abbrev-ref", "@{u}").stdout.strip()
        == "origin/dependabot/npm/x"
    )


def test_create_rejects_ungrammatical_new_branch(layout: Path) -> None:
    with pytest.raises(ValueError, match="fix/sarj-589-walrus"):
        create(layout, "claude/foo")
    assert not expected_path(layout, "claude/foo").exists()
    assert not _git(layout, "branch", "--list", "claude/foo").stdout


def test_new_command_prints_only_the_path(layout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(layout)
    result = CliRunner().invoke(app, ["worktree", "new", "spike/cli-path"])
    assert result.exit_code == 0
    assert result.stdout == f"{expected_path(layout, 'spike/cli-path')}\n"


def test_guard_ignores_primary_checkout(layout: Path) -> None:
    assert guard(layout) == 0


def test_guard_accepts_compliant_worktree(layout: Path) -> None:
    target = create(layout, "fix/compliant")
    assert guard(target) == 0
    assert target.is_dir()


def test_guard_removes_misplaced_worktree_and_its_new_branch(
    layout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not Path("/proc/self/cmdline").is_file():
        pytest.skip("requires Linux Git process evidence")
    _enable_hook(layout, tmp_path, monkeypatch)
    misplaced = tmp_path / "misplaced"
    rejected = _git(layout, "worktree", "add", str(misplaced), "-b", "fix/misplaced", check=False)
    assert rejected.returncode == 1
    assert not misplaced.exists()
    assert not _git(layout, "branch", "--list", "fix/misplaced").stdout
    assert _git(layout, "worktree", "list", "--porcelain").stdout.count("worktree ") == 1


def test_guard_keeps_branch_with_history(layout: Path, tmp_path: Path) -> None:
    target = tmp_path / "history"
    _git(layout, "worktree", "add", "-b", "fix/history", str(target))
    head = _commit(target, "unique worktree commit")
    assert guard(target) == 1
    assert not target.exists()
    assert _git(layout, "rev-parse", "refs/heads/fix/history").stdout.strip() == head


def test_guard_keeps_existing_branch_with_one_reflog_entry(
    layout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(layout, "branch", "fix/existing", "HEAD")
    _enable_hook(layout, tmp_path, monkeypatch)
    target = tmp_path / "existing"
    rejected = _git(layout, "worktree", "add", str(target), "fix/existing", check=False)
    assert rejected.returncode == 1
    assert not target.exists()
    assert _git(layout, "branch", "--list", "fix/existing").stdout.strip() == "fix/existing"


def test_guard_removes_detached_worktree(layout: Path, tmp_path: Path) -> None:
    target = tmp_path / "detached"
    _git(layout, "worktree", "add", "--detach", str(target))
    assert guard(target) == 1
    assert not target.exists()


def test_guard_keeps_worktree_with_untracked_file(layout: Path, tmp_path: Path) -> None:
    target = tmp_path / "dirty"
    _git(layout, "worktree", "add", "--detach", str(target))
    untracked = target / "untracked"
    untracked.touch()
    assert guard(target) == 1
    assert untracked.is_file()


def test_guard_ignores_inherited_git_dir(
    layout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "inherited"
    _git(layout, "worktree", "add", "--detach", str(target))
    git_dir = _git(target, "rev-parse", "--absolute-git-dir").stdout.strip()
    monkeypatch.setenv("GIT_DIR", git_dir)
    assert guard(target) == 1
    assert not target.exists()


def test_config_hook_rejects_native_worktree_add(
    layout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_hook(layout, tmp_path, monkeypatch)
    target = tmp_path / "rejected"
    result = _git(layout, "worktree", "add", "--detach", str(target), check=False)
    assert result.returncode == 1
    assert "Detached worktree" in result.stderr
    assert not target.exists()
    other = tmp_path / "elsewhere"
    _git(tmp_path, "clone", str(tmp_path / "origin.git"), str(other))
    _git(other, "worktree", "add", "--detach", str(target))
    assert target.is_dir()


def test_audit_reports_each_state(layout: Path, tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    detached = tmp_path / "detached"
    misnamed = tmp_path / "misnamed"
    misplaced = tmp_path / "misplaced tree"
    unregistered = expected_path(layout, "fix/unregistered")
    _git(layout, "worktree", "add", "-b", "fix/missing", str(missing))
    missing.rename(tmp_path / "not-registered-here")
    _git(layout, "worktree", "add", "--no-checkout", "--detach", str(detached))
    _git(layout, "worktree", "add", "-b", "invalid/branch", str(misnamed))
    _git(layout, "worktree", "add", "-b", "fix/misplaced", str(misplaced))
    unregistered.mkdir(parents=True)
    prefix = f"git -C {shlex.quote(str(layout))}"
    assert audit(layout.parent) == [
        Row(str(layout), None, "stray-clone", None),
        Row(str(unregistered), None, "unregistered", None),
        Row(str(detached), None, "detached", None),
        Row(
            str(misnamed),
            "invalid/branch",
            "misnamed",
            f"{prefix} branch -m invalid/branch <kind>/<slug>",
        ),
        Row(
            str(misplaced),
            "fix/misplaced",
            "misplaced",
            f"{prefix} worktree move {shlex.quote(str(misplaced))} "
            f"{shlex.quote(str(expected_path(layout, 'fix/misplaced')))}",
        ),
        Row(str(missing), "fix/missing", "prunable", f"{prefix} worktree prune"),
    ]


def test_audit_command_exit_code(layout: Path, tmp_path: Path) -> None:
    origin = tmp_path / "repo.git"
    origin.symlink_to(tmp_path / "origin.git", target_is_directory=True)
    _git(layout, "remote", "set-url", "origin", str(origin))
    arguments = ["worktree", "audit", str(layout.parent)]
    clean = CliRunner().invoke(app, arguments)
    assert (clean.exit_code, clean.stdout) == (0, "[]\n")
    _git(layout, "worktree", "add", "--detach", str(tmp_path / "unplaced"))
    dirty = CliRunner().invoke(app, arguments)
    assert dirty.exit_code == 1
    assert '"state":"detached"' in dirty.stdout


def test_worktree_group_is_absent_from_catalog() -> None:
    catalog = build_catalog(app, package_version="9.8.7")
    assert all(not item.command_id.startswith("worktree") for item in catalog.commands)
