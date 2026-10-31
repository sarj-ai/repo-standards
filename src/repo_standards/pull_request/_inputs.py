from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git query
from typing import TYPE_CHECKING

from repo_standards._git_environment import GIT_NO_PAGER_ENVIRONMENT
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import GitObjectId, Manifest

from ._context import NotApplicable, PullRequestContext
from ._github import load_github_pull_request_context
from ._local import resolve_local_advisory_context
from ._trusted_manifest import load_trusted_base_manifest


if TYPE_CHECKING:
    from pathlib import Path


_OBJECT_ID = re.compile(rb"[0-9a-f]{40}\Z")
_GIT_TIMEOUT = timedelta(seconds=10)
_MERGE_PARENT_COUNT = 2


@dataclass(frozen=True, slots=True)
class ResolvedPullRequestInputs:
    context: PullRequestContext
    manifest: Manifest | None


def resolve_github_pull_request_inputs(
    root: Path,
    event_path: Path,
    *,
    event_name: str,
    github_sha: str = "",
    github_workspace: Path | None = None,
) -> ResolvedPullRequestInputs | NotApplicable:
    context = load_github_pull_request_context(event_path, event_name=event_name)
    if isinstance(context, NotApplicable):
        return context
    if github_workspace is not None and root.resolve() == github_workspace.resolve():
        context = _tested_merge_context(root, context, github_sha=github_sha)
    trusted = load_trusted_base_manifest(root, context.base_sha)
    return ResolvedPullRequestInputs(context=context, manifest=trusted.manifest)


def _tested_merge_context(
    root: Path, context: PullRequestContext, *, github_sha: str
) -> PullRequestContext:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required to verify the GitHub merge checkout")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only Git query
            [executable, "-C", str(root), "show", "--no-patch", "--format=%H%n%P", "HEAD"],
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT.total_seconds(),
            env={**GIT_NO_PAGER_ENVIRONMENT, "GIT_GRAFT_FILE": os.devnull},
        )
    except OSError, subprocess.TimeoutExpired:
        ConfigurationError.fail("Git could not verify the GitHub merge checkout")
    metadata = completed.stdout.split()
    if completed.returncode != 0 or not metadata:
        ConfigurationError.fail("Git could not verify the GitHub merge checkout")
    checkout, *parents = metadata
    if checkout == context.head_sha.encode("ascii"):
        return context
    if checkout != github_sha.encode("utf-8"):
        ConfigurationError.fail("checkout does not match the GitHub event head or GITHUB_SHA")
    if (
        len(parents) != _MERGE_PARENT_COUNT
        or any(_OBJECT_ID.fullmatch(parent) is None for parent in parents)
        or parents[1] != context.head_sha.encode("ascii")
    ):
        ConfigurationError.fail(
            "GitHub merge checkout must have the event head as its second parent"
        )
    # A PR event can retain an older base SHA after target updates. GitHub's
    # tested merge pins the target; never read policy from the PR's merged tree.
    return replace(context, base_sha=GitObjectId(parents[0].decode("ascii")))


def resolve_local_pull_request_inputs(
    root: Path,
    *,
    default_base_ref: str,
    transition_bases: tuple[tuple[str, str, int], ...] = (),
) -> ResolvedPullRequestInputs:
    return ResolvedPullRequestInputs(
        context=resolve_local_advisory_context(
            root,
            default_base_ref=default_base_ref,
            transition_bases=transition_bases,
        ),
        manifest=None,
    )
