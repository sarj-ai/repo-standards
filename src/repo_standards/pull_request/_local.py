from __future__ import annotations

from datetime import timedelta
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType
from typing import TYPE_CHECKING

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import GitObjectId

from ._context import PullRequestContext


if TYPE_CHECKING:
    from pathlib import Path


_OBJECT_ID = re.compile(rb"[0-9a-f]{40}\Z")
_SAFE_REF = re.compile(r"[^\x00-\x20\x7f]{1,1024}\Z")
_GIT_TIMEOUT = timedelta(seconds=10)
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


def resolve_local_advisory_context(
    root: Path,
    *,
    default_base_ref: str,
    transition_bases: tuple[tuple[str, str, int], ...] = (),
) -> PullRequestContext:
    if _SAFE_REF.fullmatch(default_base_ref) is None or default_base_ref.startswith("-"):
        ConfigurationError.fail("local default base ref is unsafe")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    shallow = _git(resolved, "rev-parse", "--is-shallow-repository").strip()
    if shallow != b"false":
        ConfigurationError.fail("Git history is shallow; local analysis is inconclusive")
    branch = _git(resolved, "branch", "--show-current").decode("utf-8").strip()
    head_ref = branch or "HEAD"
    base_ref = _base_ref_for_branch(
        branch,
        default=default_base_ref,
        transition_bases=transition_bases,
    )
    remote_base = f"origin/{base_ref}"
    head_sha = _object_id(_git(resolved, "rev-parse", "HEAD^{commit}"))
    base_sha = _object_id(_git(resolved, "merge-base", remote_base, head_sha))
    return PullRequestContext(
        base_sha=base_sha,
        head_sha=head_sha,
        base_ref=base_ref,
        head_ref=head_ref,
        base_repository_id=None,
        head_repository_id=None,
        source="local",
    )


def _base_ref_for_branch(
    branch: str,
    *,
    default: str,
    transition_bases: tuple[tuple[str, str, int], ...],
) -> str:
    matches = {
        base_ref
        for prefix, base_ref, sha_prefix_length in transition_bases
        if re.fullmatch(rf"{re.escape(prefix)}[0-9a-f]{{{sha_prefix_length}}}", branch)
        is not None
    }
    if len(matches) > 1:
        ConfigurationError.fail("local branch matches multiple transition destinations")
    if matches:
        return next(iter(matches))
    return default


def _object_id(output: bytes) -> GitObjectId:
    value = output.strip()
    if _OBJECT_ID.fullmatch(value) is None:
        ConfigurationError.fail("Git returned a malformed local object ID")
    return GitObjectId(value.decode("ascii"))


def _git(root: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for local pull-request analysis")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only invocation
            [executable, "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT.total_seconds(),
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        ConfigurationError.fail("Git could not resolve local pull-request context")
    if completed.returncode != 0:
        ConfigurationError.fail("Git could not resolve local pull-request context")
    return completed.stdout
