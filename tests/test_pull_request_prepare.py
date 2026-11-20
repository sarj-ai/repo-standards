from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from typing import TYPE_CHECKING, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict, Field
import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.pull_request_commits import analyze_pull_request_commits
from repo_standards.pull_request import _prepare as preparation  # ruff: ignore[import-private-name] - exercise the operation's cancellation boundary
from repo_standards.pull_request._prepare import prepare_pull_request  # ruff: ignore[import-private-name] - exercise the operation at its owned boundary


if TYPE_CHECKING:
    from repo_standards.core.pull_request_commits import PullRequestCommits


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


@dataclass
class _Publication:
    root: Path
    remote: Path
    url: str = "git@github.com:example/project.git"
    mode: str = "ok"
    queries: list[str] = field(default_factory=list)


@pytest.fixture
def publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Publication:
    root = tmp_path / "checkout"
    remote = tmp_path / "remote.git"
    root.mkdir()
    remote.mkdir()
    _repository(root)
    _git(remote, "init", "--bare", "--quiet", "--initial-branch=main")
    _git(root, "remote", "add", "origin", str(remote))
    _git(root, "push", "--quiet", "origin", "main")
    _git(root, "fetch", "--quiet", "origin")
    other = tmp_path / "other.git"
    _git(root, "clone", "--bare", "--quiet", str(remote), str(other))
    state = _Publication(root, remote)
    native_git = shutil.which("git")
    assert native_git is not None
    commands = tmp_path / "commands"
    commands.mkdir()
    state_file = tmp_path / "publication-state.json"
    ssh = commands / "fixture-ssh"
    ssh.write_text(
        f"#!{sys.executable}\n"
        "import os, shlex, sys\n"
        "verb, repository = shlex.split(sys.argv[-1])\n"
        f"destinations = {{'example/project.git': {str(remote)!r},\n"
        f"                'example/other.git': {str(other)!r}}}\n"
        "assert verb in {'git-upload-pack', 'git-receive-pack'}\n"
        f"os.execv({native_git!r}, [{native_git!r},\n"
        "                         verb.removeprefix('git-'), destinations[repository]])\n"
    )
    ssh.chmod(0o700)
    gh = commands / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, subprocess, sys\n"
        f"state = json.loads(pathlib.Path({str(state_file)!r}).read_text())\n"
        "assert sys.argv[1:6] == ['api', '--hostname', 'github.com', '--method', 'GET']\n"
        "path = sys.argv[-1]\n"
        "assert path.startswith('repos/example/project')\n"
        "log = pathlib.Path(state['root']) / '.git/publication-queries.jsonl'\n"
        "with log.open('a') as stream: stream.write(json.dumps(path) + '\\n')\n"
        "mode = state['mode']\n"
        "if mode == 'unavailable': sys.exit(1)\n"
        "if mode == 'malformed': print('invalid json'); sys.exit(0)\n"
        "if '/pulls?' not in path:\n"
        "    print(json.dumps({'fork': mode == 'fork', 'full_name': 'example/project',\n"
        "                      'default_branch': 'trunk' if mode == 'default-branch'\n"
        "                                        else 'main'})); sys.exit(0)\n"
        "requests = sum('/pulls?' in json.loads(line) for line in log.read_text().splitlines())\n"
        f"git = {native_git!r}\n"
        "if requests == 1 and mode == 'local-race':\n"
        "    subprocess.run([git, '-C', state['root'], 'commit', '--quiet', '--allow-empty',\n"
        "                    '-m', 'chore: concurrent edit'], check=True)\n"
        "if requests == 2 and mode == 'remote-race':\n"
        "    base = subprocess.check_output([git, '-C', state['root'], 'rev-parse', 'main'],\n"
        "                                   text=True).strip()\n"
        "    subprocess.run([git, '-C', state['remote'], 'update-ref',\n"
        "                    'refs/heads/feature', base], check=True)\n"
        "print(json.dumps([{'number': 1}] if mode == 'existing-pr' else []))\n"
    )
    gh.chmod(0o700)
    monkeypatch.setenv("PATH", str(commands), prepend=os.pathsep)
    monkeypatch.setenv("GIT_SSH_COMMAND", str(ssh))
    monkeypatch.setenv("GIT_SSH_VARIANT", "ssh")
    return state


class _PublicationResult(Protocol):
    @property
    def exit_code(self) -> int: ...

    @property
    def output(self) -> str: ...


def _publish(state: _Publication) -> _PublicationResult:
    (state.root.parent / "publication-state.json").write_text(
        json.dumps(
            {
                "root": str(state.root),
                "remote": str(state.remote),
                "mode": state.mode,
            }
        )
    )
    _git(state.root, "remote", "set-url", "origin", state.url)
    result = CliRunner().invoke(
        app,
        [
            "pull-request",
            "push",
            str(state.root),
            "--base",
            "origin/main",
            "--message",
            "feat: prepare feature",
            "--trust-repository-code",
        ],
    )
    log = state.root / ".git/publication-queries.jsonl"
    if log.exists():
        state.queries[:] = [json.loads(line) for line in log.read_text().splitlines()]
    return result


def test_first_publication_prepares_one_commit_preserves_tree_and_runs_both_hooks(
    publication: _Publication,
) -> None:
    before = _git(publication.root, "rev-parse", "HEAD")
    tree = _git(publication.root, "log", "-1", "--format=%T")
    _hook(publication.root, "pre-commit", "echo commit >> .git/publication-hooks")
    _hook(publication.root, "pre-push", "echo push >> .git/publication-hooks")
    result = _publish(publication)
    assert result.exit_code == 0, result.output
    head = _git(publication.root, "rev-parse", "HEAD")
    assert head != before
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "1"
    assert _git(publication.root, "log", "-1", "--format=%T") == tree
    assert _git(publication.remote, "rev-parse", "refs/heads/feature") == head
    assert (publication.root / ".git/publication-hooks").read_text().splitlines() == [
        "commit",
        "push",
    ]
    assert all("state=all" in path for path in publication.queries if "/pulls?" in path)


@pytest.mark.parametrize("mode", ["existing-pr", "fork", "unavailable", "malformed"])
def test_publication_evidence_refuses_before_rewriting_history(
    publication: _Publication, mode: str
) -> None:
    publication.mode = mode
    before = _git(publication.root, "rev-parse", "HEAD")
    result = _publish(publication)
    assert result.exit_code != 0
    assert _git(publication.root, "rev-parse", "HEAD") == before
    assert not _git(publication.root, "ls-remote", "origin", "refs/heads/feature")


def test_remote_creation_during_commit_cannot_be_overwritten(publication: _Publication) -> None:
    publication.mode = "remote-race"
    result = _publish(publication)
    assert result.exit_code != 0
    assert _git(publication.remote, "rev-parse", "refs/heads/feature") == _git(
        publication.root, "rev-parse", "main"
    )
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "1"


def test_local_change_during_evidence_read_is_preserved(publication: _Publication) -> None:
    publication.mode = "local-race"
    result = _publish(publication)
    assert result.exit_code != 0
    assert _git(publication.root, "log", "-1", "--format=%s") == "chore: concurrent edit"
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "3"


def test_local_change_between_snapshot_check_and_history_read_is_preserved(
    publication: _Publication, monkeypatch: pytest.MonkeyPatch
) -> None:
    def concurrent_history(root: Path, *, base: str) -> PullRequestCommits:
        _git(root, "commit", "--quiet", "--allow-empty", "-m", "chore: concurrent edit")
        return analyze_pull_request_commits(root, base=base)

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- another injection point misses this race
        preparation, "analyze_pull_request_commits", concurrent_history
    )
    result = _publish(publication)
    assert result.exit_code != 0, result.output
    assert "branch changed after publication preflight" in result.output
    assert _git(publication.root, "log", "-1", "--format=%s") == "chore: concurrent edit"
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "3"
    assert not _git(publication.remote, "for-each-ref", "refs/heads/feature")


def test_failed_native_push_hook_preserves_prepared_commit(publication: _Publication) -> None:
    _hook(publication.root, "pre-push", "echo ran > .git/failed-push-hook\nexit 1")
    result = _publish(publication)
    assert result.exit_code != 0
    assert (publication.root / ".git/failed-push-hook").read_text().strip() == "ran"
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "1"
    assert not _git(publication.root, "ls-remote", "origin", "refs/heads/feature")


def test_publication_does_not_follow_tags_or_mirror_other_refs(publication: _Publication) -> None:
    _git(publication.root, "tag", "-am", "retain local tag", "local-only")
    _git(publication.root, "config", "push.followTags", "true")
    _git(publication.root, "config", "remote.origin.mirror", "true")
    base = _git(publication.remote, "rev-parse", "main")
    result = _publish(publication)
    assert result.exit_code == 0, result.output
    assert not _git(publication.root, "ls-remote", "origin", "refs/tags/local-only")
    assert _git(publication.remote, "rev-parse", "main") == base


def test_unpublished_remote_ancestor_is_replaced_using_its_exact_lease(
    publication: _Publication,
) -> None:
    _git(publication.root, "push", "--quiet", "origin", "HEAD~1:refs/heads/feature")
    tree = _git(publication.root, "log", "-1", "--format=%T")
    result = _publish(publication)
    assert result.exit_code == 0, result.output
    head = _git(publication.root, "rev-parse", "HEAD")
    assert _git(publication.remote, "rev-parse", "feature") == head
    assert _git(publication.root, "log", "-1", "--format=%T") == tree
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "1"


def test_stale_fetched_target_refuses_before_preparation(publication: _Publication) -> None:
    before = _git(publication.root, "rev-parse", "HEAD")
    base = _git(publication.root, "rev-parse", "origin/main")
    _git(publication.root, "push", "--quiet", "origin", "HEAD:refs/heads/main")
    _git(publication.root, "update-ref", "refs/remotes/origin/main", base)
    result = _publish(publication)
    assert result.exit_code != 0
    assert "fetch the current PR target" in result.output
    assert _git(publication.root, "rev-parse", "HEAD") == before
    assert not _git(publication.remote, "for-each-ref", "refs/heads/feature")


def test_split_origin_repositories_refuse_before_rewriting_or_publishing(
    publication: _Publication,
) -> None:
    _git(publication.root, "remote", "set-url", "--push", "origin", publication.url)
    publication.url = "git@github.com:example/other.git"
    before = _git(publication.root, "rev-parse", "HEAD")
    result = _publish(publication)
    assert result.exit_code != 0
    assert "fetch and push URLs must name the same" in result.output
    assert _git(publication.root, "rev-parse", "HEAD") == before
    for remote in (publication.remote, publication.root.parent / "other.git"):
        assert not _git(remote, "for-each-ref", "refs/heads/feature")


def test_commit_hook_cannot_redirect_publication_to_another_repository(
    publication: _Publication,
) -> None:
    _hook(
        publication.root,
        "pre-commit",
        "git remote set-url --push origin git@github.com:example/other.git",
    )
    result = _publish(publication)
    assert result.exit_code != 0
    assert _git(publication.root, "rev-list", "--count", "origin/main..HEAD") == "1"
    for remote in (publication.remote, publication.root.parent / "other.git"):
        assert not _git(remote, "for-each-ref", "refs/heads/feature")


def test_fresh_github_default_is_protected_without_cached_origin_head(
    publication: _Publication,
) -> None:
    _git(publication.root, "branch", "-m", "trunk")
    _git(publication.root, "update-ref", "--no-deref", "-d", "refs/remotes/origin/HEAD")
    publication.mode = "default-branch"
    before = _git(publication.root, "rev-parse", "HEAD")
    result = _publish(publication)
    assert result.exit_code != 0
    assert "current GitHub default branch" in result.output
    assert _git(publication.root, "rev-parse", "HEAD") == before
    assert not _git(publication.remote, "for-each-ref", "refs/heads/trunk")


class _ChildIdentity(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(strict=True, frozen=True)
    pid: int = Field(gt=0)
    birth: int = Field(ge=0)


@dataclass(frozen=True)
class _ForkingRead:
    command: tuple[str, ...]
    receipt: Path


@pytest.fixture
def forking_read(tmp_path: Path) -> _ForkingRead:
    receipt = tmp_path / "owned-child.json"
    script = tmp_path / "forking-read.py"
    script.write_text(
        "import json, os, pathlib, signal\n"
        "child = os.fork()\n"
        "if child == 0: signal.pause(); os._exit(0)\n"
        "stat = pathlib.Path(f'/proc/{child}/stat').read_text().rsplit(')', 1)[1].split()\n"
        f"pathlib.Path({str(receipt)!r}).write_text(json.dumps(\n"
        "    {'pid': child, 'birth': int(stat[19])}))\n"
        "signal.pause()\n"
    )
    return _ForkingRead((sys.executable, str(script)), receipt)


def _original_child_exited(identity: _ChildIdentity) -> bool:
    try:
        fields = (Path("/proc") / str(identity.pid) / "stat").read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return True
    return int(fields[19]) != identity.birth or fields[0] == "Z"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux PID birth and pidfd lifetime witness")
def test_native_read_timeout_terminates_its_owned_descendants(
    forking_read: _ForkingRead,
) -> None:
    with pytest.raises(ConfigurationError, match="command could not complete"):
        preparation.read_native_command(forking_read.command)
    identity = _ChildIdentity.model_validate_json(forking_read.receipt.read_text())
    descriptor = os.pidfd_open(identity.pid) if not _original_child_exited(identity) else None
    try:
        assert _original_child_exited(identity), "Timed-out native read left its child running"
    finally:
        if descriptor is not None:
            try:
                if not _original_child_exited(identity):
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)


@pytest.mark.parametrize(
    "url",
    [
        "https://token@github.com/example/project.git",
        "git@example.invalid:example/project.git",
    ],
)
def test_noncanonical_publication_target_refuses_without_network(
    publication: _Publication, url: str
) -> None:
    publication.url = url
    before = _git(publication.root, "rev-parse", "HEAD")
    result = _publish(publication)
    assert result.exit_code != 0
    assert "canonical github.com" in result.output
    assert _git(publication.root, "rev-parse", "HEAD") == before
    assert not publication.queries


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
