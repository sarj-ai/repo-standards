from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import os
import re
import selectors
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
import time
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, NamedTuple, NewType


if TYPE_CHECKING:
    from pathlib import Path
    from typing import NoReturn

from .errors import ConfigurationError
from .models import GitObjectId, RepositoryId


DEFAULT_MAXIMUM_COMMITS = 5
MAXIMUM_ANALYZED_COMMITS = 10_000
_MINIMUM_SHA_PREFIX_LENGTH = 7
_MAXIMUM_SHA_PREFIX_LENGTH = 40
_MAXIMUM_REVISION_BYTES = 1024
_CONTROL_CHARACTER_LIMIT = 32
_REVISION_METADATA_LINES = 3
_MAXIMUM_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
_GIT_TIMEOUT = timedelta(seconds=10)
_READ_CHUNK_BYTES = 64 * 1024
_OBJECT_ID = re.compile(rb"[0-9a-f]{40}\Z")
_NUMBERED_SUBJECT = re.compile(rb"\(([1-9][0-9]*)/([1-9][0-9]*)\) ([^\s].*)\Z")
_GIT_ENVIRONMENT = MappingProxyType(
    {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
)


NumberingIssue = Literal[
    "missing-marker",
    "malformed-marker",
    "wrong-total",
    "duplicate-index",
    "missing-index",
    "out-of-order",
]
Disposition = Literal[
    "within-limit",
    "numbered-series",
    "transition-exemption",
    "over-limit",
]
TransitionExemptionId = NewType("TransitionExemptionId", str)


class _ResolvedRevisions(NamedTuple):
    shallow: bool
    base_object_id: GitObjectId
    head_object_id: GitObjectId


@dataclass(frozen=True, slots=True)
class PullRequestCommit:
    object_id: GitObjectId
    subject: str


@dataclass(frozen=True, slots=True)
class TransitionExemption:
    exemption_id: TransitionExemptionId
    repository_id: RepositoryId
    source_ref: str
    base_ref: str
    head_prefix: str
    sha_prefix_length: int = 12

    def __post_init__(self) -> None:
        values = (
            self.exemption_id,
            self.repository_id,
            self.source_ref,
            self.base_ref,
            self.head_prefix,
        )
        if any(not value or any(char.isspace() for char in value) for value in values):
            ConfigurationError.fail("transition exemption fields must be non-empty single tokens")
        if not (_MINIMUM_SHA_PREFIX_LENGTH <= self.sha_prefix_length <= _MAXIMUM_SHA_PREFIX_LENGTH):
            ConfigurationError.fail(
                "transition exemption SHA prefix length must be between 7 and 40"
            )


@dataclass(frozen=True, slots=True)
class PullRequestCommits:
    base: str
    head: str
    base_object_id: GitObjectId
    head_object_id: GitObjectId
    maximum_commits: int
    commits: tuple[PullRequestCommit, ...]
    disposition: Disposition
    numbering_issue: NumberingIssue | None = None
    exemption_id: TransitionExemptionId | None = None

    @property
    def commit_count(self) -> int:
        return len(self.commits)

    @property
    def satisfied(self) -> bool:
        return self.disposition != "over-limit"


def analyze_pull_request_commits(  # ruff: ignore[too-many-arguments] - evidence stays explicit
    root: Path,
    *,
    base: str,
    head: str = "HEAD",
    maximum_commits: int = DEFAULT_MAXIMUM_COMMITS,
    repository_id: str | None = None,
    base_ref: str | None = None,
    head_ref: str | None = None,
    transition_exemptions: tuple[TransitionExemption, ...] = (),
) -> PullRequestCommits:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    if not 1 <= maximum_commits < MAXIMUM_ANALYZED_COMMITS:
        ConfigurationError.fail("maximum commits must be between 1 and 9999")
    _safe_revision(base, name="base")
    _safe_revision(head, name="head")
    shallow, base_object_id, head_object_id = _resolve_revisions(resolved, base, head)
    if shallow:
        ConfigurationError.fail("Git history is shallow; complete history is required")
    _require_common_history(resolved, base_object_id, head_object_id)

    fast_limit = maximum_commits + 1
    commits = _commits(
        resolved,
        base_object_id,
        head_object_id,
        maximum=fast_limit,
    )
    if len(commits) <= maximum_commits:
        return PullRequestCommits(
            base=base,
            head=head,
            base_object_id=base_object_id,
            head_object_id=head_object_id,
            maximum_commits=maximum_commits,
            commits=commits,
            disposition="within-limit",
        )

    commits = _commits(
        resolved,
        base_object_id,
        head_object_id,
        maximum=MAXIMUM_ANALYZED_COMMITS + 1,
    )
    if len(commits) > MAXIMUM_ANALYZED_COMMITS:
        ConfigurationError.fail("pull-request history exceeds the 10000-commit safety limit")
    exemption_id = _transition_exemption(
        resolved,
        head_object_id=head_object_id,
        repository_id=None if repository_id is None else RepositoryId(repository_id),
        base_ref=base_ref,
        head_ref=head_ref,
        exemptions=transition_exemptions,
    )
    if exemption_id is not None:
        return PullRequestCommits(
            base=base,
            head=head,
            base_object_id=base_object_id,
            head_object_id=head_object_id,
            maximum_commits=maximum_commits,
            commits=commits,
            disposition="transition-exemption",
            exemption_id=exemption_id,
        )

    numbering_issue = _numbering_issue(commits)
    return PullRequestCommits(
        base=base,
        head=head,
        base_object_id=base_object_id,
        head_object_id=head_object_id,
        maximum_commits=maximum_commits,
        commits=commits,
        disposition="numbered-series" if numbering_issue is None else "over-limit",
        numbering_issue=numbering_issue,
    )


def _safe_revision(value: str, *, name: str) -> None:
    if (
        not value
        or value.startswith("-")
        or len(value.encode("utf-8")) > _MAXIMUM_REVISION_BYTES
        or any(ord(char) < _CONTROL_CHARACTER_LIMIT or char.isspace() for char in value)
    ):
        ConfigurationError.fail(f"{name} revision is unsafe")


def _resolve_revisions(root: Path, base: str, head: str) -> _ResolvedRevisions:
    output = _git(
        root,
        "rev-parse",
        "--is-shallow-repository",
        f"{base}^{{commit}}",
        f"{head}^{{commit}}",
        failure="Git could not resolve the requested pull-request revisions",
    )
    lines = output.splitlines()
    if len(lines) != _REVISION_METADATA_LINES or lines[0] not in {b"true", b"false"}:
        ConfigurationError.fail("Git returned malformed revision metadata")
    if _OBJECT_ID.fullmatch(lines[1]) is None or _OBJECT_ID.fullmatch(lines[2]) is None:
        ConfigurationError.fail("Git returned malformed commit object IDs")
    return _ResolvedRevisions(
        shallow=lines[0] == b"true",
        base_object_id=GitObjectId(lines[1].decode("ascii")),
        head_object_id=GitObjectId(lines[2].decode("ascii")),
    )


def _require_common_history(root: Path, base: str, head: str) -> None:
    output = _git(
        root,
        "merge-base",
        base,
        head,
        failure="base and head do not share common history",
    )
    if _OBJECT_ID.fullmatch(output.strip()) is None:
        ConfigurationError.fail("Git returned a malformed merge base")


def _commits(root: Path, base: str, head: str, *, maximum: int) -> tuple[PullRequestCommit, ...]:
    output = _git(
        root,
        "log",
        "-z",
        "--no-color",
        "--no-show-signature",
        "--topo-order",
        "--reverse",
        "--no-merges",
        f"--max-count={maximum}",
        "--format=%H%x00%s",
        f"{base}..{head}",
        "--",
        failure="Git could not enumerate pull-request commits",
    )
    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        ConfigurationError.fail("Git returned malformed commit metadata")
    commits: list[PullRequestCommit] = []
    for index in range(0, len(fields), 2):
        object_id, subject = fields[index : index + 2]
        if _OBJECT_ID.fullmatch(object_id) is None:
            ConfigurationError.fail("Git returned a malformed commit object ID")
        commits.append(
            PullRequestCommit(
                object_id=GitObjectId(object_id.decode("ascii")),
                subject=subject.decode("utf-8", errors="backslashreplace"),
            )
        )
    return tuple(commits)


def _numbering_issue(commits: tuple[PullRequestCommit, ...]) -> NumberingIssue | None:
    expected_total = len(commits)
    indices: set[int] = set()
    ordered_indices: list[int] = []
    for commit in commits:
        raw_subject = commit.subject.encode("utf-8", errors="backslashreplace")
        match = _NUMBERED_SUBJECT.fullmatch(raw_subject)
        if match is None:
            return "malformed-marker" if raw_subject.startswith(b"(") else "missing-marker"
        try:
            index = int(match.group(1))
            total = int(match.group(2))
        except ValueError:
            return "malformed-marker"
        if total != expected_total:
            return "wrong-total"
        if index in indices:
            return "duplicate-index"
        indices.add(index)
        ordered_indices.append(index)
    expected_indices = list(range(1, expected_total + 1))
    issue: NumberingIssue | None = None
    if indices != set(expected_indices):
        issue = "missing-index"
    elif ordered_indices != expected_indices:
        issue = "out-of-order"
    return issue


def _transition_exemption(  # ruff: ignore[too-many-arguments] - identity proof is conjunctive
    root: Path,
    *,
    head_object_id: GitObjectId,
    repository_id: RepositoryId | None,
    base_ref: str | None,
    head_ref: str | None,
    exemptions: tuple[TransitionExemption, ...],
) -> TransitionExemptionId | None:
    if repository_id is None or base_ref is None or head_ref is None:
        return None
    for exemption in exemptions:
        if repository_id != exemption.repository_id or base_ref != exemption.base_ref:
            continue
        if not head_ref.startswith(exemption.head_prefix):
            continue
        snapshot_prefix = head_ref.removeprefix(exemption.head_prefix)
        if (
            len(snapshot_prefix) != exemption.sha_prefix_length
            or re.fullmatch(r"[0-9a-f]+", snapshot_prefix) is None
        ):
            continue
        _safe_revision(exemption.source_ref, name="source")
        source_object_id = _resolve_source(root, exemption.source_ref)
        if not head_object_id.startswith(snapshot_prefix):
            continue
        if _is_ancestor(root, head_object_id, source_object_id):
            return exemption.exemption_id
    return None


def _resolve_source(root: Path, source_ref: str) -> GitObjectId:
    output = _git(
        root,
        "rev-parse",
        f"{source_ref}^{{commit}}",
        failure="Git could not resolve a configured transition source",
    ).strip()
    if _OBJECT_ID.fullmatch(output) is None:
        ConfigurationError.fail("Git returned a malformed transition source object ID")
    return GitObjectId(output.decode("ascii"))


def _is_ancestor(root: Path, ancestor: GitObjectId, descendant: GitObjectId) -> bool:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for pull-request commit analysis")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only Git invocation
            [executable, "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT.total_seconds(),
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        ConfigurationError.fail("Git could not verify transition ancestry")
    if completed.returncode not in {0, 1}:
        ConfigurationError.fail("Git could not verify transition ancestry")
    return completed.returncode == 0


def _git(root: Path, *arguments: str, failure: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for pull-request commit analysis")
    try:
        process = subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only Git invocation
            [executable, "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_GIT_ENVIRONMENT,
        )
    except OSError:
        ConfigurationError.fail(failure)
    return _bounded_git_output(process, failure=failure)


def _bounded_git_output(process: subprocess.Popen[bytes], *, failure: str) -> bytes:
    stdout = process.stdout
    if stdout is None:
        _fail_git_process(process, failure)
    output = bytearray()
    deadline = time.monotonic() + _GIT_TIMEOUT.total_seconds()
    with stdout, selectors.DefaultSelector() as selector:
        selector.register(stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                _fail_git_process(process, failure)
            try:
                chunk = os.read(stdout.fileno(), _READ_CHUNK_BYTES)
            except OSError:
                _fail_git_process(process, failure)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > _MAXIMUM_GIT_OUTPUT_BYTES:
                _fail_git_process(process, "Git output exceeds the 16 MiB safety limit")
    try:
        return_code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _fail_git_process(process, failure)
    if return_code != 0:
        ConfigurationError.fail(failure)
    return bytes(output)


def _fail_git_process(process: subprocess.Popen[bytes], message: str) -> NoReturn:
    process.kill()
    process.wait()
    ConfigurationError.fail(message)
