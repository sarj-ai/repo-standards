from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess  # ruff: ignore[suspicious-subprocess-import] - trusted native Git and its hooks
from typing import TYPE_CHECKING, ClassVar
from urllib.parse import urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field, RootModel, ValidationError

from repo_standards.core.commit_message import analyze_commit_header, is_commit_message_satisfied
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.parser import load_manifest
from repo_standards.core.pull_request_commits import analyze_pull_request_commits


if TYPE_CHECKING:
    from collections.abc import Sequence


_REMOTE_REF_FIELDS = 2
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


@dataclass(frozen=True, slots=True)
class _BranchSnapshot:
    branch: str
    head: str


@dataclass(frozen=True, slots=True)
class _GitHubOrigin:
    repository: str
    fetch_url: str
    push_url: str


@dataclass(frozen=True, slots=True)
class _CommandOutput:
    stdout: str
    stderr: str


class _RepositoryMetadata(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", strict=True, frozen=True)
    fork: bool
    full_name: str = Field(min_length=1)
    default_branch: str = Field(min_length=1)


class _PullRequestReference(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", strict=True, frozen=True)
    number: int


class _PullRequestList(RootModel[list[_PullRequestReference]]):
    model_config: ClassVar[ConfigDict] = ConfigDict(strict=True, frozen=True)


class _Git:
    def __init__(self, root: Path) -> None:
        executable = shutil.which("git")
        if executable is None:
            ConfigurationError.fail("git is required to prepare a pull request")
        self.command = (executable, "--no-replace-objects", "-C", str(root))

    def read(self, *arguments: str) -> str:
        return read_native_command((*self.command, *arguments))

    def commit(self, message: str) -> None:
        self.hooked("commit", "--message", message)

    def hooked(self, operation: str, *arguments: str) -> None:
        # Preserve native identity, signing configuration and every normal hook.
        # A separate process group lets cancellation stop owned hooks before rollback.
        with subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true] - explicit trusted native commit
            [*self.command, operation, *arguments],
            start_new_session=True,
        ) as process:
            try:
                returncode = process.wait(timeout=_COMMIT_TIMEOUT_SECONDS)
            except BaseException as error:
                _terminate_owned_process(process)
                if isinstance(error, subprocess.TimeoutExpired):
                    ConfigurationError.fail(
                        f"native git {operation} timed out; preparation stopped"
                    )
                raise
        if returncode:
            ConfigurationError.fail(f"native git {operation} failed; fix its hook or signing error")


def _require_native_environment() -> None:
    if os.name != "posix":
        ConfigurationError.fail(
            "local PR preparation currently requires a POSIX process supervisor"
        )
    if any(os.environ.get(key) for key in _REDIRECTING_ENVIRONMENT):  # ruff: ignore[banned-api] - reject Git state redirected outside the explicit repository
        ConfigurationError.fail(
            "unset Git repository, index and object-directory overrides before preparation"
        )


def _terminate_owned_process(process: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    if process.returncode is None:
        # Stop the owned group while its leader's PID is still unreaped.
        for requested_signal in (signal.SIGTERM, signal.SIGKILL):
            with suppress(ProcessLookupError):
                os.killpg(process.pid, requested_signal)
        process.wait()


def read_native_command(command: Sequence[str], *, root: Path | None = None) -> str:
    try:
        with subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true] - resolved native executable, argv only
            list(command),
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        ) as process:
            output = _read_owned_process(process)
    except (OSError, subprocess.TimeoutExpired) as error:
        message = "Git preparation command could not complete"
        raise ConfigurationError(message) from error
    if process.returncode:
        ConfigurationError.fail(f"Git preparation failed: {output.stderr.strip()}")
    return output.stdout.strip()


def _read_owned_process(process: subprocess.Popen[str]) -> _CommandOutput:
    try:
        stdout, stderr = process.communicate(timeout=_READ_TIMEOUT_SECONDS)
        return _CommandOutput(stdout, stderr)
    except BaseException:
        _terminate_owned_process(process)
        raise


def prepare_pull_request(  # ruff: ignore[too-many-branches,too-many-statements] - transaction guards stay in execution order
    root: Path,
    *,
    base: str,
    message: str,
    trust_repository_code: bool,
    expected: _BranchSnapshot | None = None,
) -> PreparedPullRequest:
    # The caller verifies that no PR already exists before this local operation.
    if not trust_repository_code:
        ConfigurationError.fail("pass --trust-repository-code to authorize native commit hooks")
    _require_native_environment()
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
    if expected is not None and (branch != expected.branch or before != expected.head):
        ConfigurationError.fail(
            "the branch changed after publication preflight; preparation stopped"
        )
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


def push_pull_request(
    root: Path, *, base: str, message: str, trust_repository_code: bool
) -> PreparedPullRequest:
    if not trust_repository_code:
        ConfigurationError.fail(
            "pass --trust-repository-code to authorize native commit and push hooks"
        )
    _require_native_environment()
    root = root.resolve(strict=True)
    git = _Git(root)
    _require_clean_checkout(root, git)
    branch = git.read("symbolic-ref", "--quiet", "--short", "HEAD")
    before = git.read("rev-parse", "HEAD")
    origin = _github_origin(git)
    _require_current_target(git, base, origin.push_url)
    _require_unpublished_feature_branch(root, origin.repository, branch)
    ref = f"refs/heads/{branch}"
    remote_head = _remote_head(git, ref, origin.push_url)
    if remote_head:
        git.read("merge-base", "--is-ancestor", remote_head, before)
    prepared = prepare_pull_request(
        root,
        base=base,
        message=message,
        trust_repository_code=True,
        expected=_BranchSnapshot(branch, before),
    )
    if _github_origin(git) != origin:
        ConfigurationError.fail("origin changed during preparation; publication stopped")
    _require_unpublished_feature_branch(root, origin.repository, branch)
    if (
        git.read("symbolic-ref", "--quiet", "--short", "HEAD") != branch
        or git.read("rev-parse", "HEAD") != prepared.head
    ):
        ConfigurationError.fail("the prepared branch changed; publication stopped")
    git.hooked(
        "push",
        "--porcelain",
        "--no-mirror",
        "--no-follow-tags",
        "--recurse-submodules=no",
        f"--force-with-lease={ref}:{remote_head}",
        "--",
        origin.push_url,
        f"{prepared.head}:{ref}",
    )
    if _remote_head(git, ref, origin.push_url) != prepared.head:
        ConfigurationError.fail(
            "the remote head could not be confirmed; preserve the prepared branch and reconcile"
        )
    if git.read("rev-parse", "HEAD") != prepared.head:
        ConfigurationError.fail(
            "remote published; a push hook changed local HEAD. Reconcile before opening the PR"
        )
    _require_clean_checkout(root, git)
    return prepared


def _github_origin(git: _Git) -> _GitHubOrigin:
    push_url = git.read("remote", "get-url", "--push", "--all", "origin")
    fetch_url = git.read("remote", "get-url", "--all", "origin")
    repository = _push_repository(push_url)
    if _push_repository(fetch_url).casefold() != repository.casefold():
        ConfigurationError.fail("origin fetch and push URLs must name the same GitHub repository")
    return _GitHubOrigin(repository, fetch_url, push_url)


def _push_repository(url: str) -> str:
    if url.startswith("git@github.com:"):
        repository = url.removeprefix("git@github.com:")
    else:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.query
            or parsed.fragment
        ):
            ConfigurationError.fail(
                "first-PR publication requires one canonical github.com origin push URL"
            )
        repository = parsed.path.removeprefix("/")
    repository = repository.removesuffix(".git")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository) is None:
        ConfigurationError.fail("origin must identify one GitHub owner/repository")
    return repository


def _remote_head(git: _Git, ref: str, url: str) -> str:
    lines = git.read("ls-remote", "--refs", "--", url, ref).splitlines()
    if not lines:
        return ""
    if len(lines) != 1:
        ConfigurationError.fail("remote branch evidence is ambiguous")
    fields = lines[0].split()
    if (
        len(fields) != _REMOTE_REF_FIELDS
        or fields[1] != ref
        or re.fullmatch(r"[0-9a-f]{40}", fields[0]) is None
    ):
        ConfigurationError.fail("remote branch evidence is malformed")
    return fields[0]


def _require_current_target(git: _Git, base: str, url: str) -> None:
    ref = git.read("rev-parse", "--symbolic-full-name", base)
    prefix = "refs/remotes/origin/"
    if not ref.startswith(prefix) or ref == f"{prefix}HEAD":
        ConfigurationError.fail("provide an exact fetched origin/<target> branch")
    remote = _remote_head(git, f"refs/heads/{ref.removeprefix(prefix)}", url)
    if not remote or git.read("rev-parse", base) != remote:
        ConfigurationError.fail("fetch the current PR target before first publication")


def _require_unpublished_feature_branch(root: Path, repository: str, branch: str) -> None:
    try:
        metadata = _RepositoryMetadata.model_validate_json(
            _github_read(root, f"repos/{repository}")
        )
        owner = repository.partition("/")[0]
        query = urlencode({"state": "all", "head": f"{owner}:{branch}", "per_page": 1})
        pulls = _PullRequestList.model_validate_json(
            _github_read(root, f"repos/{repository}/pulls?{query}")
        )
    except ValidationError as error:
        message = "GitHub publication evidence is malformed; no branch is published"
        raise ConfigurationError(message) from error
    if metadata.full_name.casefold() != repository.casefold():
        ConfigurationError.fail("origin must name the current canonical GitHub repository")
    if metadata.fork:
        ConfigurationError.fail(
            "first-PR publication supports same-repository branches; preserve fork histories"
        )
    if metadata.default_branch == branch:
        ConfigurationError.fail("refusing to prepare or publish the current GitHub default branch")
    if pulls.root:
        ConfigurationError.fail(
            "an open or closed PR already uses this branch; preserve its history"
        )


def _github_read(root: Path, path: str) -> str:
    executable = shutil.which("gh")
    if executable is None:
        ConfigurationError.fail("authenticated gh is required for first-PR publication")
    try:
        return read_native_command(
            (executable, "api", "--hostname", "github.com", "--method", "GET", path), root=root
        )
    except ConfigurationError:
        ConfigurationError.fail(
            "GitHub publication evidence could not be read with current gh authentication"
        )


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
