from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Literal

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    GitIdentity,
    git_parent_identity,
    git_revision_identity,
    read_tracked_blob_contents,
    tracked_files_for_identity,
)
from repo_standards.core.models import (
    MakefileComparison,
    MakefileMetric,
    MigrationComparison,
    TrackedFileEvidence,
)
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.policy_sarj.makefiles import (
    MAKEFILE_GROWTH_RULE_ID,
    is_makefile_path,
    physical_lines,
)
from repo_standards.policy_sarj.migrations import (
    MIGRATION_CONSOLIDATION_RULE_ID,
    migration_roots,
    protected_roots,
)


if TYPE_CHECKING:
    from datetime import date
    from pathlib import Path

    from repo_standards.core.models import RepositorySnapshot
    from repo_standards.core.rule_reviews import RuleVersion


@dataclass(frozen=True, slots=True)
class _ComparisonBase:
    identity: GitIdentity | None
    basis: Literal["explicit", "last-commit", "staged", "empty"]


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
    comparison_base = _comparison_base(root, head, base_revision)
    base = comparison_base.identity
    head_files = _metrics(root, head)
    comparison = MakefileComparison(
        base_revision=base.source_revision if base else "0" * len(head.source_revision),
        base_tree_digest=base.tree_digest if base else "0" * len(head.source_revision),
        basis=comparison_base.basis,
        base_files=_metrics(root, base, frozenset(item.path for item in head_files), head_files)
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


def with_migration_comparison(
    root: Path,
    snapshot: RepositorySnapshot,
    *,
    enabled_rules: frozenset[RuleVersion],
    base_revision: str | None,
) -> RepositorySnapshot:
    if not any(item.rule_id == MIGRATION_CONSOLIDATION_RULE_ID for item in enabled_rules):
        return snapshot
    provenance = snapshot.provenance
    if provenance.mode == "worktree":
        ConfigurationError.fail("Migration comparison requires an exact Git tree or index")
    head = GitIdentity(provenance.source_revision, provenance.tree_digest, provenance.mode)
    if provenance.comparison_basis is not None:
        base_revision = provenance.comparison_base_revision
    comparison_base = _comparison_base(root, head, base_revision)
    base = comparison_base.identity
    base_files = (
        tuple(
            TrackedFileEvidence(item.path, item.object_id)
            for item in tracked_files_for_identity(root, base)
        )
        if base is not None
        else ()
    )
    head_files = snapshot.inspection.tracked_files
    head_roots = migration_roots(snapshot.manifest, tuple(item.path for item in head_files))
    base_paths = tuple(item.path for item in base_files)
    if base is not None and provenance.manifest_path in base_paths:
        manifest_blob = read_tracked_blob_contents(
            root, (provenance.manifest_path,), identity=base
        )[0]
        base_roots = migration_roots(parse_manifest_bytes(manifest_blob.content), base_paths)
    else:
        base_roots = migration_roots(None, base_paths)
    return replace(
        snapshot,
        migration_comparison=MigrationComparison(
            protected_roots(base_roots, head_roots),
            base_files,
            head_files,
        ),
        provenance=replace(
            provenance,
            comparison_base_revision=(
                base.source_revision if base else "0" * len(head.source_revision)
            ),
            comparison_base_tree_digest=(
                base.tree_digest if base else "0" * len(head.source_revision)
            ),
            comparison_basis=provenance.comparison_basis or comparison_base.basis,
        ),
    )


def _comparison_base(root: Path, head: GitIdentity, base_revision: str | None) -> _ComparisonBase:
    if head.mode == "git-index":
        return _ComparisonBase(
            None
            if _empty_revision(head.source_revision)
            else git_revision_identity(root, head.source_revision),
            "staged",
        )
    if base_revision is not None:
        base = (
            None if _empty_revision(base_revision) else git_revision_identity(root, base_revision)
        )
        return _ComparisonBase(base, "empty" if base is None else "explicit")
    base = git_parent_identity(root, head)
    return _ComparisonBase(base, "empty" if base is None else "last-commit")


def _empty_revision(revision: str) -> bool:
    return len(revision) in {40, 64} and set(revision) == {"0"}


def _metrics(
    root: Path,
    identity: GitIdentity,
    surviving: frozenset[str] | None = None,
    known: tuple[MakefileMetric, ...] = (),
) -> tuple[MakefileMetric, ...]:
    blobs = tuple(
        blob
        for blob in tracked_files_for_identity(root, identity)
        if is_makefile_path(blob.path) and (surviving is None or blob.path in surviving)
    )
    line_counts = {item.object_id: item.lines for item in known}
    missing = tuple(blob.path for blob in blobs if blob.object_id not in line_counts)
    if missing:
        line_counts.update(
            (blob.object_id, physical_lines(blob.content))
            for blob in read_tracked_blob_contents(root, missing, identity=identity)
        )
    return tuple(
        MakefileMetric(blob.path, blob.object_id, line_counts[blob.object_id]) for blob in blobs
    )
