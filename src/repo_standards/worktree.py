from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - native Git with explicit argv
import sys
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Iterator


BRANCH: Final = re.compile(
    r"(?:feat|fix|refactor|chore|spike)/(?=.{1,40}\Z)(?!.*20[0-9]{6})[a-z0-9]+(?:-[a-z0-9]+)*"
)
_NAMING = (
    "Use <kind>/<slug>, for example fix/sarj-589-walrus. "
    "Kinds are feat, fix, refactor, chore, and spike. "
    "Use 1 to 40 lowercase kebab characters with no date in the slug."
)
_GIT_LOCATION = (
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
)


@dataclass(frozen=True, slots=True)
class Row:
    path: str
    branch: str | None
    state: str
    fix: str | None


def _git(directory: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("git")
    if executable is None:
        message = "Git is required to manage worktrees."
        raise ValueError(message)
    environment = os.environ.copy()  # ruff: ignore[banned-api] - preserve native Git configuration and identity.
    for key in _GIT_LOCATION:
        environment.pop(key, None)
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - native Git with explicit argv
            [executable, "-C", str(directory), *arguments],
            capture_output=True,
            text=True,
            timeout=120,
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        message = f"Git did not finish {arguments[0]} within 120 seconds."
        raise ValueError(message) from error
    if check and result.returncode:
        message = (result.stderr + result.stdout).strip()
        if not message:
            message = f"Git exited with status {result.returncode}."
        raise ValueError(message)
    return result


def _common_dir(directory: Path) -> Path:
    return Path(
        _git(directory, "rev-parse", "--path-format=absolute", "--git-common-dir").stdout.rstrip(
            "\n"
        )
    ).resolve()


def _has_ref(primary: Path, ref: str) -> bool:
    return _git(primary, "show-ref", "--verify", "--quiet", ref, check=False).returncode == 0


def _allowed(primary: Path, branch: str) -> bool:
    return BRANCH.fullmatch(branch) is not None or _has_ref(
        primary, f"refs/remotes/origin/{branch}"
    )


def expected_path(primary: Path, branch: str) -> Path:
    return primary.parent.parent / "worktrees" / primary.name / branch.replace("/", "--")


def create(checkout: Path, branch: str) -> Path:
    common = _common_dir(checkout)
    if common.name != ".git":
        message = "Create the worktree from a non-bare primary clone or its linked worktree."
        raise ValueError(message)
    primary = common.parent
    fetch = _git(primary, "fetch", "origin")
    sys.stderr.write(fetch.stdout + fetch.stderr)
    target = expected_path(primary, branch)
    if target.exists():
        message = f"Worktree path already exists: {target}"
        raise ValueError(message)
    if _has_ref(primary, f"refs/heads/{branch}") or _has_ref(
        primary, f"refs/remotes/origin/{branch}"
    ):
        arguments = ("--", str(target), branch)
    else:
        if BRANCH.fullmatch(branch) is None:
            message = f"Invalid branch {branch!r}. {_NAMING}"
            raise ValueError(message)
        default = _git(
            primary, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"
        ).stdout.strip()
        arguments = ("--no-track", "-b", branch, str(target), default)
    target.parent.mkdir(parents=True, exist_ok=True)
    added = _git(primary, "worktree", "add", *arguments)
    sys.stderr.write(added.stdout + added.stderr)
    return target


def guard(worktree: Path) -> int:
    common = _common_dir(worktree)
    git_dir = Path(_git(worktree, "rev-parse", "--absolute-git-dir").stdout.rstrip("\n")).resolve()
    if common.name != ".git" or git_dir == common:
        return 0
    primary = common.parent
    branch = _git(worktree, "symbolic-ref", "-q", "--short", "HEAD", check=False).stdout.strip()
    allowed = bool(branch) and _allowed(primary, branch)
    if allowed:
        target = expected_path(primary, branch)
        if worktree.resolve() == target.resolve():
            return 0
        argument = f"-- {shlex.quote(branch)}" if branch.startswith("-") else shlex.quote(branch)
        remedy = f"repo-standards worktree new {argument}"
        message = f"Worktree for {branch} must live at {target}. Run {remedy}."
    else:
        reason = (
            f"Invalid worktree branch {branch!r}." if branch else "Detached worktree is forbidden."
        )
        message = f"{reason} Run repo-standards worktree new <kind>/<slug>. {_NAMING}"
    sys.stderr.write(message + "\n")
    removed = _git(primary, "worktree", "remove", str(worktree.resolve()), check=False)
    if removed.returncode:
        sys.stderr.write(removed.stderr)
    elif branch:
        _discard_created_branch(primary, branch)
    return 1


def _discard_created_branch(primary: Path, branch: str) -> None:
    if not _new_branch_argument(branch):
        return
    ref = f"refs/heads/{branch}"
    if len(_git(primary, "reflog", "show", ref).stdout.splitlines()) != 1:
        return
    containing = _git(
        primary,
        "for-each-ref",
        "--format=%(refname)",
        "--contains",
        ref,
        "refs/heads",
        "refs/remotes",
    ).stdout.splitlines()
    if any(other != ref for other in containing):
        _git(primary, "branch", "-D", "--", branch)


def _new_branch_argument(branch: str) -> bool:
    # post-checkout has the same arguments for new and existing branches. A
    # successful native add with -b proves Git created this branch itself.
    process = Path("/proc") / str(os.getppid())
    try:
        if (process / "exe").readlink().name in {"sh", "dash", "bash"}:
            parent = (process / "stat").read_text(encoding="ascii").rpartition(") ")[2].split()[1]
            process = process.parent / parent
        if (process / "exe").readlink().name != "git":
            return False
        arguments = os.fsdecode((process / "cmdline").read_bytes()).rstrip("\0").split("\0")
    except OSError, IndexError:
        return False
    if "worktree" not in arguments:
        return False
    start = arguments.index("worktree")
    if arguments[start : start + 2] != ["worktree", "add"]:
        return False
    options = arguments[start + 2 :]
    if "--" in options:
        options = options[: options.index("--")]
    return "--reason" not in options and ("-b", branch) in pairwise(options)


def audit(organization: Path) -> list[Row]:
    organization = organization.resolve()
    root = organization.parent / "worktrees"
    primaries = [path for path in organization.iterdir() if (path / ".git").is_dir()]
    registered: set[Path] = set()
    rows: list[Row] = []
    for primary in primaries:
        origin = (
            _git(primary, "remote", "get-url", "origin", check=False).stdout.strip().rstrip("/")
        )
        if origin.rsplit("/", 1)[-1].removesuffix(".git") != primary.name:
            rows.append(Row(str(primary), None, "stray-clone", None))
        for fields in _linked_worktrees(primary):
            registered.add(Path(fields["worktree"]).resolve())
            row = _worktree_row(primary, fields)
            if row is not None:
                rows.append(row)
    rows.extend(_unregistered(root, {primary.name for primary in primaries}, registered))
    return sorted(rows, key=lambda row: row.path)


def _linked_worktrees(primary: Path) -> Iterator[dict[str, str]]:
    records = _git(primary, "worktree", "list", "--porcelain", "-z").stdout.split("\0\0")
    for record in filter(None, records[1:]):
        fields = (field.partition(" ") for field in record.split("\0"))
        yield {key: value for key, _, value in fields}


def _worktree_row(primary: Path, fields: dict[str, str]) -> Row | None:
    path = fields["worktree"]
    branch = fields.get("branch", "").removeprefix("refs/heads/") or None
    git = ("git", "-C", str(primary))
    if "prunable" in fields:
        return Row(path, branch, "prunable", shlex.join((*git, "worktree", "prune")))
    if "detached" in fields or branch is None:
        return Row(path, None, "detached", None)
    if not _allowed(primary, branch):
        rename = shlex.join((*git, "branch", "-m", branch))
        return Row(path, branch, "misnamed", f"{rename} <kind>/<slug>")
    target = expected_path(primary, branch)
    if Path(path).resolve() != target.resolve():
        return Row(
            path, branch, "misplaced", shlex.join((*git, "worktree", "move", path, str(target)))
        )
    return None


def _unregistered(root: Path, names: set[str], registered: set[Path]) -> Iterator[Row]:
    if not root.is_dir():
        return
    for directory in root.iterdir():
        if not directory.is_dir() or directory.resolve() in registered:
            continue
        candidates = directory.iterdir() if directory.name in names else (directory,)
        for path in candidates:
            if path.is_dir() and path.resolve() not in registered:
                yield Row(str(path), None, "unregistered", None)
