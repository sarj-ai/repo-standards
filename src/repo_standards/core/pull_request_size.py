from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType
from typing import Literal

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
_GO_TEST = re.compile(r".+_test\.go\Z")
_JVM_TEST = re.compile(r".+(?:test|tests)\.(?:java|kt|kts|groovy|scala)\Z")
_DOTNET_TEST = re.compile(r".+(?:test|tests)\.cs\Z")
_RUBY_TEST = re.compile(r".+_(?:spec|test)\.rb\Z")
_XCODE_TEST_COMPONENT = re.compile(r".+(?:ui)?tests\Z")
PullRequestSizeCategory = Literal["production", "test", "generated", "binary"]
_NUMSTAT_FIELDS = 3
_CATEGORIES: tuple[PullRequestSizeCategory, ...] = (
    "production",
    "test",
    "generated",
    "binary",
)


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
class PullRequestCategorySize:
    category: PullRequestSizeCategory
    changed_files: int
    additions: int
    deletions: int

    @property
    def lines(self) -> int:
        """Return total textual churn for this category."""
        return self.additions + self.deletions


@dataclass(frozen=True, slots=True)
class PullRequestDirectorySize:
    path: str
    changed_files: int
    additions: int
    deletions: int
    counted_lines: int
    excluded_lines: int
    categories: tuple[PullRequestCategorySize, ...]

    @property
    def total_lines(self) -> int:
        """Return all textual churn in this directory."""
        return self.additions + self.deletions


@dataclass(frozen=True, slots=True)
class PullRequestSizeSummary:
    changed_files: int
    counted_files: int
    excluded_files: int
    binary_files: int
    additions: int
    deletions: int
    counted_additions: int
    counted_deletions: int
    excluded_additions: int
    excluded_deletions: int

    @property
    def counted_lines(self) -> int:
        """Return lines that contribute to review size."""
        return self.counted_additions + self.counted_deletions

    @property
    def excluded_lines(self) -> int:
        """Return textual churn excluded by policy."""
        return self.excluded_additions + self.excluded_deletions

    @property
    def total_lines(self) -> int:
        """Return all textual churn before classification."""
        return self.additions + self.deletions


@dataclass(frozen=True, slots=True)
class PullRequestSize:
    base: str
    head: str
    generated_attribute: str
    files: tuple[PullRequestFileSize, ...]

    @property
    def summary(self) -> PullRequestSizeSummary:
        """Return aggregate file and churn counts."""
        counted = tuple(item for item in self.files if item.category == "production")
        excluded = tuple(item for item in self.files if item.category != "production")
        return PullRequestSizeSummary(
            changed_files=len(self.files),
            counted_files=len(counted),
            excluded_files=len(excluded),
            binary_files=sum(item.category == "binary" for item in self.files),
            additions=sum(item.additions for item in self.files),
            deletions=sum(item.deletions for item in self.files),
            counted_additions=sum(item.additions for item in counted),
            counted_deletions=sum(item.deletions for item in counted),
            excluded_additions=sum(item.additions for item in excluded),
            excluded_deletions=sum(item.deletions for item in excluded),
        )

    @property
    def counted_lines(self) -> int:
        """Return lines that contribute to review size."""
        return self.summary.counted_lines

    @property
    def excluded_lines(self) -> int:
        """Return textual churn excluded by policy."""
        return self.summary.excluded_lines

    @property
    def total_lines(self) -> int:
        """Return all textual churn before classification."""
        return self.summary.total_lines

    def category_lines(self) -> dict[str, int]:
        categories = {item.category for item in self.files} | {"production"}
        return {
            category: sum(item.lines for item in self.files if item.category == category)
            for category in sorted(categories)
        }

    def category_sizes(self) -> tuple[PullRequestCategorySize, ...]:
        return tuple(_category_size(category, self.files) for category in _CATEGORIES)

    def directory_sizes(self) -> tuple[PullRequestDirectorySize, ...]:
        grouped: dict[str, list[PullRequestFileSize]] = {}
        for item in self.files:
            directory = PurePosixPath(item.path).parent.as_posix()
            grouped.setdefault(directory, []).append(item)
        return tuple(
            _directory_size(directory, tuple(grouped[directory])) for directory in sorted(grouped)
        )


def _category_size(
    category: PullRequestSizeCategory,
    files: tuple[PullRequestFileSize, ...],
) -> PullRequestCategorySize:
    matching = tuple(item for item in files if item.category == category)
    return PullRequestCategorySize(
        category=category,
        changed_files=len(matching),
        additions=sum(item.additions for item in matching),
        deletions=sum(item.deletions for item in matching),
    )


def _directory_size(
    path: str,
    files: tuple[PullRequestFileSize, ...],
) -> PullRequestDirectorySize:
    categories = tuple(_category_size(category, files) for category in _CATEGORIES)
    production = next(item for item in categories if item.category == "production")
    return PullRequestDirectorySize(
        path=path,
        changed_files=len(files),
        additions=sum(item.additions for item in files),
        deletions=sum(item.deletions for item in files),
        counted_lines=production.lines,
        excluded_lines=sum(item.lines for item in categories if item.category != "production"),
        categories=categories,
    )


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    components = tuple(component.casefold() for component in pure.parts[:-1])
    if any(
        component in _TEST_COMPONENTS
        or component == "androidtest"
        or _XCODE_TEST_COMPONENT.fullmatch(component) is not None
        for component in components
    ):
        return True
    basename = pure.name.casefold()
    return (
        _PYTHON_TEST.fullmatch(basename) is not None
        or _JAVASCRIPT_TEST.fullmatch(basename) is not None
        or _GO_TEST.fullmatch(basename) is not None
        or _JVM_TEST.fullmatch(basename) is not None
        or _DOTNET_TEST.fullmatch(basename) is not None
        or _RUBY_TEST.fullmatch(basename) is not None
        or basename.endswith(".bats")
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
        sorted(
            (
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
            ),
            key=lambda item: item.path,
        )
    )
    return PullRequestSize(
        base=base,
        head=head,
        generated_attribute=generated_attribute,
        files=files,
    )


def _numstat(root: Path, *, base: str, head: str) -> tuple[tuple[int, int, str, bool], ...]:
    output = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--numstat",
        "-z",
        "--no-renames",
        f"{base}...{head}",
        "--",
    )
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
