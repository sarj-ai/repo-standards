from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Literal

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    GitIdentity,
    git_parent_identity,
    git_revision_identity,
    read_tracked_blob_contents,
    tracked_files_for_identity,
)
from repo_standards.core.models import MakefileComparison, MakefileMetric
from repo_standards.policy_sarj.makefiles import (
    MAKEFILE_GROWTH_RULE_ID,
    is_makefile_path,
    physical_lines,
)


if TYPE_CHECKING:
    from datetime import date
    from pathlib import Path

    from repo_standards.core.models import RepositorySnapshot
    from repo_standards.core.rule_reviews import RuleVersion


def with_makefile_comparison(
    root: Path,
    snapshot: RepositorySnapshot,
    *,
    enabled_rules: frozenset[RuleVersion],
    base_revision: str | None,
    as_of: date | None,
) -> RepositorySnapshot:
    if not any(item.rule_id == MAKEFILE_GROWTH_RULE_ID for item in enabled_rules):
        return snapshot
    provenance = snapshot.provenance
    if provenance.mode == "worktree":
        ConfigurationError.fail("Makefile comparison requires an exact Git tree or index")
    head = GitIdentity(provenance.source_revision, provenance.tree_digest, provenance.mode)
    basis: Literal["explicit", "last-commit", "staged", "empty"]
    if head.mode == "git-index":
        base = (
            None
            if head.source_revision == "0" * 40
            else git_revision_identity(root, head.source_revision)
        )
        basis = "staged"
    elif base_revision is not None:
        base = (
            None if _empty_revision(base_revision) else git_revision_identity(root, base_revision)
        )
        basis = "empty" if base is None else "explicit"
    else:
        base = git_parent_identity(root, head)
        basis = "empty" if base is None else "last-commit"
    head_files = _metrics(root, head)
    comparison = MakefileComparison(
        base_revision=base.source_revision if base else "0" * len(head.source_revision),
        base_tree_digest=base.tree_digest if base else "0" * len(head.source_revision),
        basis=basis,
        base_files=_metrics(root, base, frozenset(item.path for item in head_files))
        if base
        else (),
        head_files=head_files,
        as_of=as_of,
    )
    return replace(
        snapshot,
        makefile_comparison=comparison,
        provenance=replace(
            provenance,
            comparison_base_revision=comparison.base_revision,
            comparison_base_tree_digest=comparison.base_tree_digest,
            comparison_basis=comparison.basis,
        ),
    )


def _empty_revision(revision: str) -> bool:
    return len(revision) in {40, 64} and set(revision) == {"0"}


def _metrics(
    root: Path, identity: GitIdentity, surviving: frozenset[str] | None = None
) -> tuple[MakefileMetric, ...]:
    paths = tuple(
        blob.path
        for blob in tracked_files_for_identity(root, identity)
        if is_makefile_path(blob.path) and (surviving is None or blob.path in surviving)
    )
    return tuple(
        MakefileMetric(blob.path, blob.object_id, physical_lines(blob.content))
        for blob in read_tracked_blob_contents(root, paths, identity=identity)
    )
