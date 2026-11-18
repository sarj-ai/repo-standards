from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import signal
import subprocess  # ruff: ignore[suspicious-subprocess-import] - trusted native Git and its hooks
from typing import TYPE_CHECKING

from repo_standards.core.commit_message import analyze_commit_header, is_commit_message_satisfied
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.parser import load_manifest
from repo_standards.core.pull_request_commits import analyze_pull_request_commits


if TYPE_CHECKING:
    from collections.abc import Sequence


_READ_TIMEOUT_SECONDS = 30
_COMMIT_TIMEOUT_SECONDS = 1800
_REDIRECTING_ENVIRONMENT = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
)
_OPERATIONS = (
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
    "BISECT_START",
)


@dataclass(frozen=True, slots=True)
class PreparedPullRequest:
    branch: str
    original_head: str
    head: str


class _Git:
    def __init__(self, root: Path) -> None:
        executable = shutil.which("git")
        if executable is None:
            ConfigurationError.fail("git is required to prepare a pull request")
        self.command = (executable, "--no-replace-objects", "-C", str(root))

    def read(self, *arguments: str) -> str:
        try:
            completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed Git executable, argv only
                [*self.command, *arguments],
                check=False,
                capture_output=True,
                text=True,
                timeout=_READ_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            message = "Git preparation command could not complete"
            raise ConfigurationError(message) from error
        if completed.returncode:
            ConfigurationError.fail(f"Git preparation failed: {completed.stderr.strip()}")
        return completed.stdout.strip()

    def commit(self, message: str) -> None:
        # Preserve native identity, signing configuration and every normal hook.
        # A separate process group lets cancellation stop owned hooks before rollback.
        with subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true] - explicit trusted native commit
            [*self.command, "commit", "--message", message],
            start_new_session=True,
        ) as process:
            try:
                returncode = process.wait(timeout=_COMMIT_TIMEOUT_SECONDS)
            except BaseException as error:
                if process.returncode is None:
                    # Stop the owned group before reaping its leader, so its
                    # process-group ID cannot be reused during cancellation.
                    for requested_signal in (signal.SIGTERM, signal.SIGKILL):
                        with suppress(ProcessLookupError):
                            os.killpg(process.pid, requested_signal)
                    process.wait()
                if isinstance(error, subprocess.TimeoutExpired):
                    ConfigurationError.fail("native git commit timed out; preparation stopped")
                raise
        if returncode:
            ConfigurationError.fail("native git commit failed; fix its hook or signing error")


def prepare_pull_request(  # ruff: ignore[too-many-branches,too-many-statements] - transaction guards stay in execution order
    root: Path,
    *,
    base: str,
    message: str,
    trust_repository_code: bool,
) -> PreparedPullRequest:
    # The caller verifies that no PR already exists before this local operation.
    if not trust_repository_code:
        ConfigurationError.fail("pass --trust-repository-code to authorize native commit hooks")
    if os.name != "posix":
        ConfigurationError.fail(
            "local PR preparation currently requires a POSIX process supervisor"
        )
    if any(os.environ.get(key) for key in _REDIRECTING_ENVIRONMENT):  # ruff: ignore[banned-api] - reject Git state redirected outside the explicit repository
        ConfigurationError.fail(
            "unset Git repository, index and object-directory overrides before preparation"
        )
    header = message.splitlines()[0] if message.splitlines() else ""
    if not is_commit_message_satisfied(analyze_commit_header(header)):
        ConfigurationError.fail("provide a valid conventional commit --message before squashing")
    root = root.resolve(strict=True)
    git = _Git(root)
    _require_clean_checkout(root, git)
    branch_ref = git.read("rev-parse", "--symbolic-full-name", "HEAD")
    if not branch_ref.startswith("refs/heads/"):
        ConfigurationError.fail("preparation requires a checked-out feature branch")
    branch = branch_ref.removeprefix("refs/heads/")
    _require_feature_branch(root, git, branch, base)
    _require_exclusive_branch(git, branch_ref)
    history = analyze_pull_request_commits(root, base=base)
    before = str(history.head_object_id)
    base_id = str(history.base_object_id)
    count = int(git.read("rev-list", "--count", f"{base_id}..{before}"))
    if count == 0:
        ConfigurationError.fail("the feature branch has no commits beyond its PR base")
    ancestors = git.read("merge-base", "--all", base_id, before).splitlines()
    if len(ancestors) != 1:
        ConfigurationError.fail("preparation requires one unambiguous merge base")
    parent = ancestors[0]
    tree = git.read("rev-parse", f"{before}^{{tree}}")
    if tree == git.read("rev-parse", f"{parent}^{{tree}}"):
        ConfigurationError.fail("the feature branch has no net file changes to publish")
    parents = git.read("rev-list", "--parents", "-n", "1", before).split()
    original_header = git.read("log", "-1", "--format=%s", before)
    if (
        count == 1
        and parents == [before, parent]
        and is_commit_message_satisfied(analyze_commit_header(original_header))
    ):
        return PreparedPullRequest(branch, before, before)
    _require_clean_checkout(root, git)
    _require_exclusive_branch(git, branch_ref)
    if git.read("symbolic-ref", "--quiet", "HEAD") != branch_ref:
        ConfigurationError.fail("the checked-out branch changed during preparation")
    git.read(
        "update-ref",
        "--create-reflog",
        "-m",
        "repo-standards: prepare PR",
        branch_ref,
        parent,
        before,
    )
    try:
        git.commit(message)
    except BaseException:
        if git.read("rev-parse", branch_ref) == parent:
            git.read(
                "update-ref",
                "-m",
                "repo-standards: restore failed preparation",
                branch_ref,
                before,
                parent,
            )
        raise
    head = git.read("rev-parse", branch_ref)
    if git.read("symbolic-ref", "--quiet", "HEAD") != branch_ref:
        ConfigurationError.fail("the checked-out branch changed; do not open the PR")
    if git.read("rev-parse", f"{head}^{{tree}}") != tree:
        ConfigurationError.fail(
            "native hooks changed committed content; review the edits before opening the PR"
        )
    if git.read("rev-list", "--parents", "-n", "1", head).split() != [head, parent]:
        ConfigurationError.fail("the prepared branch is not one commit; do not open the PR")
    if not is_commit_message_satisfied(
        analyze_commit_header(git.read("log", "-1", "--format=%s", head))
    ):
        ConfigurationError.fail(
            "a native hook produced an invalid commit header; do not open the PR"
        )
    _require_clean_checkout(root, git)
    return PreparedPullRequest(branch, before, head)


def _require_feature_branch(root: Path, git: _Git, branch: str, base: str) -> None:
    protected = {"main", "master"}
    prefixes: Sequence[str] = ()
    manifest_path = root / ".repo-standards/repository.toml"
    if manifest_path.exists():
        manifest = load_manifest(manifest_path)
        if manifest.pull_request is not None:
            history = manifest.pull_request.commit_history
            protected.add(history.advisory_base_ref)
            prefixes = tuple(item.head_prefix for item in history.transitions)
            for item in history.transitions:
                protected.update((item.source_ref, item.base_ref))
    for remote in git.read("remote").splitlines():
        default_ref = git.read("for-each-ref", "--format=%(symref)", f"refs/remotes/{remote}/HEAD")
        if default_ref:
            protected.add(_branch_name(git, default_ref))
    if branch in protected or any(branch.startswith(prefix) for prefix in prefixes):
        ConfigurationError.fail("refusing to squash a protected base, default or promotion branch")
    if branch == _branch_name(git, base):
        ConfigurationError.fail("refusing to squash the protected PR target branch")


def _branch_name(git: _Git, reference: str) -> str:
    full_ref = git.read("rev-parse", "--symbolic-full-name", "--verify", reference)
    if full_ref.startswith("refs/heads/"):
        return full_ref.removeprefix("refs/heads/")
    if full_ref.startswith("refs/remotes/"):
        remote_ref = full_ref.removeprefix("refs/remotes/")
        # Remote names may themselves contain slashes; use the longest match.
        for remote in sorted(git.read("remote").splitlines(), key=len, reverse=True):
            if remote_ref.startswith(f"{remote}/"):
                return remote_ref.removeprefix(f"{remote}/")
    return ConfigurationError.fail("--base must name a fetched local or remote-tracking branch")


def _require_clean_checkout(root: Path, git: _Git) -> None:
    if Path(git.read("rev-parse", "--show-toplevel")).resolve() != root:
        ConfigurationError.fail("prepare must run against the repository root")
    for operation in _OPERATIONS:
        path = Path(git.read("rev-parse", "--path-format=absolute", "--git-path", operation))
        if path.exists():
            ConfigurationError.fail("a Git merge, rebase, cherry-pick or revert is in progress")
    if git.read("status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"):
        ConfigurationError.fail(
            "preparation requires a clean index and working tree, including untracked files"
        )


def _require_exclusive_branch(git: _Git, branch_ref: str) -> None:
    worktrees = git.read("worktree", "list", "--porcelain", "-z").split("\0")
    if worktrees.count(f"branch {branch_ref}") != 1:
        ConfigurationError.fail("the feature branch must be checked out in only one worktree")
