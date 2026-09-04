from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from repo_standards.core.models import Manifest

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
) -> ResolvedPullRequestInputs | NotApplicable:
    context = load_github_pull_request_context(event_path, event_name=event_name)
    if isinstance(context, NotApplicable):
        return context
    trusted = load_trusted_base_manifest(root, context.base_sha)
    return ResolvedPullRequestInputs(context=context, manifest=trusted.manifest)


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
