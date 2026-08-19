from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType

from .errors import ConfigurationError


_GIT_ENVIRONMENT = MappingProxyType(
    {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
)
_TEST_COMPONENTS = frozenset({"test", "tests", "__tests__", "__snapshots__"})
_PYTHON_TEST = re.compile(r"(?:test_.+|.+_test)\.py\Z")
_JAVASCRIPT_TEST = re.compile(r".+\.(?:test|spec)\.(?:[cm]?[jt]sx?)\Z")
_NUMSTAT_FIELDS = 3


@dataclass(frozen=True, slots=True)
class PullRequestFileSize:
    path: str
    additions: int
    deletions: int
    category: str

    @property
    def lines(self) -> int:
        """Return total textual churn for this path."""
        return self.additions + self.deletions


@dataclass(frozen=True, slots=True)
class PullRequestSize:
    base: str
    head: str
    generated_attribute: str
    files: tuple[PullRequestFileSize, ...]

    @property
    def counted_lines(self) -> int:
        """Return lines that contribute to review size."""
        return sum(item.lines for item in self.files if item.category == "production")

    @property
    def excluded_lines(self) -> int:
        """Return textual churn excluded by policy."""
        return sum(item.lines for item in self.files if item.category != "production")

    @property
    def total_lines(self) -> int:
        """Return all textual churn before classification."""
        return sum(item.lines for item in self.files)

    def category_lines(self) -> dict[str, int]:
        categories = {item.category for item in self.files} | {"production"}
        return {
            category: sum(item.lines for item in self.files if item.category == category)
            for category in sorted(categories)
        }


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if any(component.casefold() in _TEST_COMPONENTS for component in pure.parts[:-1]):
        return True
    basename = pure.name.casefold()
    return (
        _PYTHON_TEST.fullmatch(basename) is not None
        or _JAVASCRIPT_TEST.fullmatch(basename) is not None
    )


def analyze_pull_request_size(
    root: Path,
    *,
    base: str,
    head: str,
    generated_attribute: str = "pr-size-excluded",
) -> PullRequestSize:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    if not generated_attribute or any(char.isspace() for char in generated_attribute):
        ConfigurationError.fail("generated attribute must be one non-empty Git attribute name")
    records = _numstat(resolved, base=base, head=head)
    generated = _generated_paths(
        resolved,
        base=base,
        paths=tuple(record[2] for record in records),
        attribute=generated_attribute,
    )
    files = tuple(
        PullRequestFileSize(
            path=path,
            additions=additions,
            deletions=deletions,
            category=(
                "test"
                if is_test_path(path)
                else "generated"
                if path in generated
                else "binary"
                if additions == deletions == 0 and binary
                else "production"
            ),
        )
        for additions, deletions, path, binary in records
    )
    return PullRequestSize(
        base=base,
        head=head,
        generated_attribute=generated_attribute,
        files=files,
    )


def _numstat(root: Path, *, base: str, head: str) -> tuple[tuple[int, int, str, bool], ...]:
    output = _git(root, "diff", "--numstat", "-z", "--no-renames", f"{base}...{head}", "--")
    records: list[tuple[int, int, str, bool]] = []
    for raw_record in output.split(b"\0"):
        if not raw_record:
            continue
        fields = raw_record.split(b"\t", _NUMSTAT_FIELDS - 1)
        if len(fields) != _NUMSTAT_FIELDS:
            ConfigurationError.fail("Git returned malformed numstat output")
        raw_additions, raw_deletions, raw_path = fields
        binary = raw_additions == raw_deletions == b"-"
        if binary:
            additions = deletions = 0
        else:
            try:
                additions = int(raw_additions)
                deletions = int(raw_deletions)
            except ValueError:
                ConfigurationError.fail("Git returned non-numeric numstat output")
        records.append(
            (additions, deletions, raw_path.decode("utf-8", errors="surrogateescape"), binary)
        )
    return tuple(records)


def _generated_paths(
    root: Path,
    *,
    base: str,
    paths: tuple[str, ...],
    attribute: str,
) -> frozenset[str]:
    if not paths:
        return frozenset()
    payload = b"\0".join(path.encode("utf-8", errors="surrogateescape") for path in paths) + b"\0"
    output = _git(
        root,
        "check-attr",
        "-z",
        "--stdin",
        f"--source={base}",
        attribute,
        input_bytes=payload,
    )
    fields = output.split(b"\0")
    generated: set[str] = set()
    for index in range(0, len(fields) - 1, _NUMSTAT_FIELDS):
        path, observed_attribute, value = fields[index : index + _NUMSTAT_FIELDS]
        if observed_attribute.decode() != attribute:
            ConfigurationError.fail("Git returned an unexpected attribute response")
        if value == b"set":
            generated.add(path.decode("utf-8", errors="surrogateescape"))
    return frozenset(generated)


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for pull-request size analysis")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only Git invocation
            [executable, "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            input=input_bytes,
            timeout=30,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        ConfigurationError.fail("Git could not complete pull-request size analysis")
    if completed.returncode != 0:
        ConfigurationError.fail("Git could not resolve the requested pull-request revisions")
    return completed.stdout
