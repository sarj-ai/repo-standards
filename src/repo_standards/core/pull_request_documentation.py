from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType
from typing import TYPE_CHECKING

from repo_standards.pull_request._trusted_manifest import load_trusted_base_manifest

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

    @property
    def satisfied(self) -> bool:
        return len(self.added_pages) <= self.maximum_added_pages


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
    additions = _added_markdown_paths(resolved, base=base_sha, head=head_sha)
    exemptions = frozenset(policy.addition_exemptions)
    exempt_pages = tuple(path for path in additions if path in exemptions)
    added_pages = tuple(path for path in additions if path not in exemptions)
    return PullRequestDocumentation(
        base=base_sha,
        head=head_sha,
        maximum_added_pages=policy.maximum_added_pages,
        added_pages=added_pages,
        exempt_pages=exempt_pages,
    )


def _resolve_revision(root: Path, revision: str) -> GitObjectId:
    if not revision:
        ConfigurationError.fail("an exact pull-request base revision is required")
    output = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    resolved = output.decode().strip()
    if _OBJECT_ID.fullmatch(resolved) is None:
        ConfigurationError.fail("Git returned a malformed revision")
    return GitObjectId(resolved)


def _added_markdown_paths(root: Path, *, base: str, head: str) -> tuple[str, ...]:
    output = _git(
        root,
        "diff",
        "--name-status",
        "-z",
        "--find-renames",
        "--find-copies",
        f"{base}...{head}",
        "--",
    )
    fields = output.split(b"\0")
    additions: list[str] = []
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index].decode("ascii", errors="strict")
        index += 1
        path_count = 2 if status[:1] in {"R", "C"} else 1
        if index + path_count > len(fields):
            ConfigurationError.fail("Git returned malformed name-status output")
        paths = fields[index : index + path_count]
        index += path_count
        destination = paths[-1].decode("utf-8", errors="surrogateescape")
        if status[:1] in {"A", "C"} and destination.casefold().endswith((".md", ".mdx")):
            additions.append(destination)
    return tuple(sorted(additions))


def _git(root: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for pull-request documentation analysis")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - argv is fixed and bounded
            [executable, "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=30,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        ConfigurationError.fail("Git could not complete pull-request documentation analysis")
    if completed.returncode != 0:
        ConfigurationError.fail("Git could not resolve pull-request documentation evidence")
    return completed.stdout
