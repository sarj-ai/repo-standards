from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git query
import tempfile
from typing import Literal, NamedTuple

from conventional_pre_commit.format import ConventionalCommit

from .errors import ConfigurationError


MAXIMUM_MESSAGE_BYTES = 1_048_576
CONVENTIONAL_TYPES = tuple(ConventionalCommit.DEFAULT_TYPES)
_NUMBERING_PREFIX = r"\([1-9][0-9]*/[1-9][0-9]*\)"
_TICKET_PREFIX = r"\[(?:[A-Z][A-Z0-9]*-[0-9]+|NO-TICKET)\]"
_PREFIX = re.compile(rf"^(?:(?P<number>{_NUMBERING_PREFIX}) )?(?:(?P<ticket>{_TICKET_PREFIX}) )?")
_REPAIRABLE = re.compile(
    rf"^(?:(?P<number>{_NUMBERING_PREFIX})\s*)?"
    rf"(?:(?P<ticket>{_TICKET_PREFIX})\s*)?"
    r"(?P<type>[A-Za-z]+)\s*(?P<scope>\([^()\r\n]+\))?\s*"
    r"(?P<breaking>!)?\s*:\s*(?P<description>\S.*)$"
)
_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

FindingCode = Literal[
    "commit-message.empty",
    "commit-message.control-character",
    "commit-message.invalid-header",
    "commit-message.type-case",
]


class _RegularFile(NamedTuple):
    content: bytes
    metadata: os.stat_result


@dataclass(frozen=True, slots=True)
class CommitMessageFinding:
    code: FindingCode
    message: str
    remediation: str


@dataclass(frozen=True, slots=True)
class CommitMessageResult:
    header: str
    findings: tuple[CommitMessageFinding, ...]
    replacement_header: str | None = None
    fix_applied: bool = False

    @property
    def satisfied(self) -> bool:
        return not self.findings


def analyze_commit_header(header: str) -> CommitMessageResult:
    if not header:
        return _finding(
            header,
            "commit-message.empty",
            "The commit message header is empty.",
            "Write `type: description`, optionally preceded by `(i/n)` and a ticket.",
        )
    if _CONTROLS.search(header) is not None:
        return _finding(
            header,
            "commit-message.control-character",
            "The commit header contains a control character.",
            "Remove control characters and retry the commit.",
        )
    prefix = _PREFIX.match(header)
    conventional = header[prefix.end() if prefix is not None else 0 :]
    parsed = ConventionalCommit(commit_msg=conventional).match(conventional)
    groups = parsed.groupdict() if parsed is not None and parsed.end() == len(conventional) else {}
    parsed_type = groups.get("type")
    if parsed_type is not None and parsed_type != parsed_type.lower():
        replacement = _safe_replacement(header)
        return _finding(
            header,
            "commit-message.type-case",
            "The Conventional Commit type must be lowercase.",
            "Use a lowercase type such as `feat`, `fix`, `docs`, or `chore`.",
            replacement=replacement,
        )
    if not _valid_groups(groups, conventional):
        return _finding(
            header,
            "commit-message.invalid-header",
            "The header does not match Managed Conventional Header v1.",
            "Use `[(i/n) ][TICKET] type(scope)!: description`; prefixes and scope are optional.",
            replacement=_safe_replacement(header),
        )
    return CommitMessageResult(header=header, findings=())


def analyze_commit_message_bytes(content: bytes) -> CommitMessageResult:
    if len(content) > MAXIMUM_MESSAGE_BYTES:
        ConfigurationError.fail(f"commit message exceeds {MAXIMUM_MESSAGE_BYTES} bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        ConfigurationError.fail("commit message must be UTF-8")
    header = text.splitlines()[0] if text.splitlines() else ""
    return analyze_commit_header(header)


def check_commit_message_file(
    path: Path,
    *,
    fix_safe: bool = False,
    allow_temporary: bool = False,
) -> CommitMessageResult:
    content, metadata = _read_regular_file(path)
    if allow_temporary:
        temporary = _temporary_commit_result(content)
        if temporary is not None:
            return temporary
    result = analyze_commit_message_bytes(content)
    if not fix_safe or result.replacement_header is None:
        return result
    replacement = _replace_header(content, result.replacement_header)
    verified = analyze_commit_message_bytes(replacement)
    second_pass = _replace_header(replacement, result.replacement_header)
    if not verified.satisfied or second_pass != replacement:
        ConfigurationError.fail("safe commit-message repair could not be verified")
    _atomic_replace(path, replacement, metadata)
    return CommitMessageResult(
        header=result.replacement_header,
        findings=(),
        replacement_header=result.replacement_header,
        fix_applied=True,
    )


def check_local_commit_message_file(
    path: Path,
    *,
    root: Path,
    fix_safe: bool = True,
) -> CommitMessageResult:
    """Validate a local Git message while allowing structurally temporary Git operations."""
    if _merge_in_progress(root):
        return CommitMessageResult(header="", findings=())
    return check_commit_message_file(path, fix_safe=fix_safe, allow_temporary=True)


def _temporary_commit_result(content: bytes) -> CommitMessageResult | None:
    if len(content) > MAXIMUM_MESSAGE_BYTES:
        ConfigurationError.fail(f"commit message exceeds {MAXIMUM_MESSAGE_BYTES} bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        ConfigurationError.fail("commit message must be UTF-8")
    header = text.splitlines()[0] if text.splitlines() else ""
    if any(
        header.startswith(prefix) and header.removeprefix(prefix).strip()
        for prefix in ("fixup! ", "squash! ")
    ):
        return CommitMessageResult(header=header, findings=())
    return None


def _merge_in_progress(root: Path) -> bool:
    executable = shutil.which("git")
    if executable is None:
        return False
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only query
            (executable, "-C", str(root), "rev-parse", "--git-path", "MERGE_HEAD"),
            check=False,
            capture_output=True,
            timeout=5,
            env={"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    raw_path = completed.stdout.decode("utf-8", errors="surrogateescape").strip()
    if not raw_path:
        return False
    marker = Path(raw_path)
    return (marker if marker.is_absolute() else root / marker).is_file()


def _valid_groups(groups: dict[str, str | None], conventional: str) -> bool:
    parsed_type = groups.get("type")
    subject = groups.get("subject")
    return bool(
        parsed_type
        and parsed_type in CONVENTIONAL_TYPES
        and groups.get("delim")
        and subject
        and subject.startswith(" ")
        and subject[1:].strip()
        and "\n" not in conventional
        and "\r" not in conventional
    )


def _safe_replacement(header: str) -> str | None:
    matched = _REPAIRABLE.fullmatch(header)
    if matched is None:
        return None
    commit_type = matched.group("type").lower()
    if commit_type not in CONVENTIONAL_TYPES:
        return None
    pieces = [value for value in (matched.group("number"), matched.group("ticket")) if value]
    conventional = commit_type
    if scope := matched.group("scope"):
        conventional += scope
    if matched.group("breaking"):
        conventional += "!"
    conventional += f": {matched.group('description')}"
    replacement = " ".join((*pieces, conventional))
    if replacement != header and analyze_commit_header(replacement).satisfied:
        return replacement
    return None


def _replace_header(content: bytes, replacement: str) -> bytes:
    boundary = content.find(b"\n")
    suffix = b"" if boundary < 0 else content[boundary:]
    if boundary > 0 and content[boundary - 1 : boundary] == b"\r":
        suffix = b"\r" + suffix
    return replacement.encode("utf-8") + suffix


def _read_regular_file(path: Path) -> _RegularFile:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:  # ruff: ignore[too-many-statements-in-try-clause] - guarded descriptor lifetime
        if path.is_symlink():
            ConfigurationError.fail("commit message path must be a regular file, not a symlink")
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                ConfigurationError.fail("commit message path must be a regular file, not a symlink")
            if metadata.st_size > MAXIMUM_MESSAGE_BYTES:
                ConfigurationError.fail(f"commit message exceeds {MAXIMUM_MESSAGE_BYTES} bytes")
            content = stream.read(MAXIMUM_MESSAGE_BYTES + 1)
    except OSError:
        ConfigurationError.fail("cannot read commit message file")
    if len(content) > MAXIMUM_MESSAGE_BYTES:
        ConfigurationError.fail(f"commit message exceeds {MAXIMUM_MESSAGE_BYTES} bytes")
    return _RegularFile(content, metadata)


def _atomic_replace(path: Path, content: bytes, original: os.stat_result) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:  # ruff: ignore[too-many-statements-in-try-clause] - atomic replacement transaction
        _write_fsync(descriptor, content)
        temporary.chmod(stat.S_IMODE(original.st_mode))
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            ConfigurationError.fail("commit message file changed during safe repair")
        temporary.replace(path)
        _fsync_directory(path.parent)
    except OSError:
        ConfigurationError.fail("cannot safely rewrite commit message file")
    finally:
        temporary.unlink(missing_ok=True)


def _write_fsync(descriptor: int, content: bytes) -> None:
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _finding(
    header: str,
    code: FindingCode,
    message: str,
    remediation: str,
    *,
    replacement: str | None = None,
) -> CommitMessageResult:
    return CommitMessageResult(
        header=header,
        findings=(CommitMessageFinding(code, message, remediation),),
        replacement_header=replacement,
    )
