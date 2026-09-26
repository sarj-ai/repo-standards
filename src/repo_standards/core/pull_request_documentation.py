from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType
from typing import TYPE_CHECKING

from repo_standards.pull_request._trusted_manifest import load_trusted_base_manifest

from ._npm_dependency_metadata import lock_dependency_update, package_dependency_update
from .errors import ConfigurationError
from .models import DocumentationConfig, GitObjectId


if TYPE_CHECKING:
    from pathlib import Path


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
_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
_DEFAULT_POLICY = DocumentationConfig(entrypoints=("README.md",))


@dataclass(frozen=True, slots=True)
class PullRequestDocumentation:
    base: GitObjectId
    head: GitObjectId
    maximum_added_pages: int
    added_pages: tuple[str, ...]
    exempt_pages: tuple[str, ...]
    added_content_paths: tuple[str, ...]

    @property
    def satisfied(self) -> bool:
        return not self.added_content_paths and len(self.added_pages) <= self.maximum_added_pages


@dataclass(frozen=True, slots=True)
class _ChangedFile:
    status: str
    old_path: str
    path: str
    old_object: str
    new_object: str
    old_mode: str
    new_mode: str


def analyze_pull_request_documentation(
    root: Path, *, base: str, head: str = "HEAD"
) -> PullRequestDocumentation:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    base_sha = _resolve_revision(resolved, base)
    head_sha = _resolve_revision(resolved, head)
    trusted = load_trusted_base_manifest(resolved, base_sha)
    policy = (
        trusted.manifest.documentation
        if trusted.manifest is not None and trusted.manifest.documentation is not None
        else _DEFAULT_POLICY
    )
    changes = _changed_files(resolved, base=base_sha, head=head_sha)
    additions = tuple(
        sorted(
            change.path
            for change in changes
            if change.status in {"A", "C"} and change.path.casefold().endswith((".md", ".mdx"))
        )
    )
    exemptions = frozenset(policy.addition_exemptions)
    exempt_pages = tuple(path for path in additions if path in exemptions)
    added_pages = tuple(path for path in additions if path not in exemptions)
    return PullRequestDocumentation(
        base=base_sha,
        head=head_sha,
        maximum_added_pages=policy.maximum_added_pages,
        added_pages=added_pages,
        exempt_pages=exempt_pages,
        added_content_paths=_added_content_paths(resolved, changes, base=base_sha, head=head_sha),
    )


def _resolve_revision(root: Path, revision: str) -> GitObjectId:
    if not revision:
        ConfigurationError.fail("an exact pull-request base revision is required")
    output = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    resolved = output.decode().strip()
    if _OBJECT_ID.fullmatch(resolved) is None:
        ConfigurationError.fail("Git returned a malformed revision")
    return GitObjectId(resolved)


def _changed_files(root: Path, *, base: str, head: str) -> tuple[_ChangedFile, ...]:
    output = _git(
        root,
        "diff",
        "--raw",
        "--no-abbrev",
        "-z",
        "--find-renames",
        "--find-copies",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        f"{base}...{head}",
        "--",
    )
    fields = output.split(b"\0")
    changes: list[_ChangedFile] = []
    index = 0
    while index < len(fields) and fields[index]:
        header = re.fullmatch(
            rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([ACDMRT][0-9]*)",
            fields[index],
        )
        if header is None:
            ConfigurationError.fail("Git returned malformed raw diff output")
        status = header[5].decode("ascii")[0]
        index += 1
        path_count = 2 if status in {"R", "C"} else 1
        if index + path_count >= len(fields) or not all(fields[index : index + path_count]):
            ConfigurationError.fail("Git returned malformed raw diff paths")
        paths = fields[index : index + path_count]
        index += path_count
        changes.append(
            _ChangedFile(
                status=status,
                old_path=paths[0].decode("utf-8", errors="surrogateescape"),
                path=paths[-1].decode("utf-8", errors="surrogateescape"),
                old_object=header[3].decode("ascii"),
                new_object=header[4].decode("ascii"),
                old_mode=header[1].decode("ascii"),
                new_mode=header[2].decode("ascii"),
            )
        )
    if fields[index:] != [b""]:
        ConfigurationError.fail("Git returned unterminated raw diff output")
    return tuple(changes)


def _content_scope(path: str, mode: str) -> bool:
    parts = path.casefold().split("/")
    return (
        parts[-1] == "readme.md"
        or "docs" in parts[:-1]
        or (parts[-1] == "docs" and mode in {"120000", "160000"})
    )


def _added_content_paths(
    root: Path, changes: tuple[_ChangedFile, ...], *, base: str, head: str
) -> tuple[str, ...]:
    candidates = tuple(
        change
        for change in changes
        if change.status != "D"
        and _content_scope(change.path, change.new_mode)
        and (
            _prior_content_object(change) != change.new_object or change.old_mode != change.new_mode
        )
    )
    objects = {change.new_object for change in candidates}
    objects.update(
        old for change in candidates if (old := _prior_content_object(change)) is not None
    )
    blobs = _read_blobs(root, tuple(sorted(objects)))
    metadata_updates = _dependency_metadata_updates(root, candidates, blobs, base=base, head=head)
    return tuple(
        sorted(
            change.path
            for change in candidates
            if change.path not in metadata_updates
            and (
                change.new_mode == "120000"
                or _adds_content(
                    blobs.get(_prior_content_object(change) or "", b""), blobs[change.new_object]
                )
            )
        )
    )


def _dependency_metadata_updates(
    root: Path,
    changes: tuple[_ChangedFile, ...],
    blobs: dict[str, bytes],
    *,
    base: str,
    head: str,
) -> frozenset[str]:
    # Permit dependency-only maintenance of existing npm metadata, not added docs content.
    eligible = tuple(
        change
        for change in changes
        if change.status == "M"
        and change.old_path == change.path
        and change.old_mode == change.new_mode == "100644"
    )
    accepted = {
        change.path
        for change in eligible
        if change.path.rsplit("/", 1)[-1] == "package.json"
        and package_dependency_update(blobs[change.old_object], blobs[change.new_object])
    }
    locks = tuple(
        change for change in eligible if change.path.rsplit("/", 1)[-1] == "package-lock.json"
    )
    if not locks:
        return frozenset(accepted)
    merge_base = _git(root, "merge-base", base, head).decode().strip()
    package_paths = tuple(
        change.path.removesuffix("package-lock.json") + "package.json" for change in locks
    )
    old_packages = _tracked_package_blobs(root, merge_base, package_paths)
    new_packages = _tracked_package_blobs(root, head, package_paths)
    for change, package_path in zip(locks, package_paths, strict=True):
        old_package, new_package = old_packages.get(package_path), new_packages.get(package_path)
        if (
            old_package is not None
            and new_package is not None
            and lock_dependency_update(
                blobs[change.old_object], blobs[change.new_object], old_package, new_package
            )
        ):
            accepted.add(change.path)
    return frozenset(accepted)


def _tracked_package_blobs(root: Path, revision: str, paths: tuple[str, ...]) -> dict[str, bytes]:
    output = _git(root, "ls-tree", "-z", revision, "--", *(f":(literal){path}" for path in paths))
    objects: dict[str, str] = {}
    for entry in output.split(b"\0"):
        if not entry:
            continue
        metadata, _, raw_path = entry.partition(b"\t")
        mode, kind, oid = metadata.split()
        if mode == b"100644" and kind == b"blob":
            objects[raw_path.decode("utf-8", errors="surrogateescape")] = oid.decode("ascii")
    blobs = _read_blobs(root, tuple(sorted(set(objects.values()))))
    return {path: blobs[oid] for path, oid in objects.items()}


def _prior_content_object(change: _ChangedFile) -> str | None:
    if change.status in {"A", "C"} or not _content_scope(change.old_path, change.old_mode):
        return None
    return change.old_object


def _read_blobs(root: Path, objects: tuple[str, ...]) -> dict[str, bytes]:
    if not objects:
        return {}
    output = _git(
        root, "cat-file", "--batch", input_bytes="".join(f"{oid}\n" for oid in objects).encode()
    )
    blobs: dict[str, bytes] = {}
    offset = 0
    for oid in objects:
        end = output.find(b"\n", offset)
        header = re.fullmatch(rb"([0-9a-f]{40}) blob ([0-9]+)", output[offset:end])
        if end < 0 or header is None or header[1] != oid.encode():
            ConfigurationError.fail("Git could not provide documentation blob evidence")
        size = int(header[2])
        start = end + 1
        offset = start + size
        if output[offset : offset + 1] != b"\n":
            ConfigurationError.fail("Git returned incomplete documentation blob evidence")
        blobs[oid] = output[start:offset]
        offset += 1
    if offset != len(output):
        ConfigurationError.fail("Git returned unexpected documentation blob evidence")
    return blobs


def _adds_content(before: bytes, after: bytes) -> bool:
    if not after:
        return False
    if b"\0" in before or b"\0" in after:
        return True
    try:
        old_lines = iter(before.decode("utf-8").split("\n"))
        new_lines = after.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        return True
    # An ordered subsequence preserves all existing content while permitting deletions.
    return any(line.strip() and line not in old_lines for line in new_lines)


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for pull-request documentation analysis")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - argv is fixed and bounded
            [executable, "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            input=input_bytes,
            timeout=30,
            env=_GIT_ENVIRONMENT,
        )
    except OSError, subprocess.TimeoutExpired:
        ConfigurationError.fail("Git could not complete pull-request documentation analysis")
    if completed.returncode != 0:
        ConfigurationError.fail("Git could not resolve pull-request documentation evidence")
    return completed.stdout
