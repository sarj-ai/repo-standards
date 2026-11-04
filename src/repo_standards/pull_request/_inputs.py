from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import GitObjectId, Manifest
from repo_standards.github_checkout import GitHubCheckoutError, resolve_github_checkout

from ._context import NotApplicable, PullRequestContext
from ._github import load_github_pull_request_context
from ._local import resolve_local_advisory_context
from ._trusted_manifest import load_trusted_base_manifest


if TYPE_CHECKING:
    from pathlib import Path


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
    try:
        checkout = resolve_github_checkout(
            root,
            base_sha=str(context.base_sha),
            head_sha=str(context.head_sha),
            github_sha=github_sha,
        )
    except GitHubCheckoutError as error:
        ConfigurationError.fail(str(error))
    if checkout.mode == "head":
        return context
    # A PR event can retain an older base SHA after target updates. GitHub's
    # tested merge pins the target; never read policy from the PR's merged tree.
    return replace(context, base_sha=GitObjectId(checkout.comparison_base))


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
