from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, ClassVar, Literal

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    GitIdentity,
    TrackedBlob,
    git_parent_identity,
    git_revision_identity,
    read_tracked_blob_contents,
    tracked_files_for_identity,
)
from repo_standards.core.models import (
    ComparisonProvenance,
    DocumentationComparison,
    DocumentationConfig,
    MakefileComparison,
    MakefileMetric,
    MigrationComparison,
    TrackedFileEvidence,
    TrackedText,
)
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.core.pull_request_documentation import markdown_only_paths_for_revisions
from repo_standards.core.pull_request_size import attribute_paths
from repo_standards.policy_sarj.documentation import (
    ADDED_MARKDOWN_RULE_ID,
    GENERATED_DOCUMENTATION_RULE_ID,
    LOCAL_LINKS_RULE_ID,
    MAKE_TARGETS_RULE_ID,
    MARKDOWN_ONLY_RULE_ID,
    MARKDOWN_WORD_GROWTH_RULE_ID,
    is_make_source,
)
from repo_standards.policy_sarj.makefiles import (
    MAKEFILE_GROWTH_RULE_ID,
    is_makefile_path,
    physical_lines,
)
from repo_standards.policy_sarj.migrations import (
    MIGRATION_CONSOLIDATION_RULE_ID,
    explicit_migration_roots,
    is_non_consolidatable_migration,
    migration_roots,
    protected_roots,
)


if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import date
    from pathlib import Path

    from repo_standards.core.models import RepositorySnapshot
    from repo_standards.core.rule_reviews import RuleVersion


_BLOB_BATCH = 100


@dataclass(frozen=True, slots=True)
class _ExistingComparisonBase:
    kind: ClassVar[Literal["existing"]] = "existing"
    identity: GitIdentity
    basis: Literal["explicit", "last-commit", "staged"]


@dataclass(frozen=True, slots=True)
class _EmptyComparisonBase:
    kind: ClassVar[Literal["empty"]] = "empty"
    basis: Literal["empty", "staged"]
    identity: None = field(init=False, default=None)


type _ComparisonBase = _ExistingComparisonBase | _EmptyComparisonBase


def with_tracked_texts(
    root: Path, snapshot: RepositorySnapshot, *, enabled_rules: frozenset[RuleVersion]
) -> RepositorySnapshot:
    enabled = {item.rule_id for item in enabled_rules}
    if enabled.isdisjoint({LOCAL_LINKS_RULE_ID, MAKE_TARGETS_RULE_ID}):
        return snapshot
    provenance = snapshot.provenance
    if provenance.mode == "worktree":
        ConfigurationError.fail(
            "Markdown link and command checks require an exact Git tree or index"
        )
    identity = GitIdentity(provenance.source_revision, provenance.tree_digest, provenance.mode)
    paths = tuple(
        item.path
        for item in snapshot.inspection.tracked_files
        if item.path.endswith(".md")
        or (MAKE_TARGETS_RULE_ID in enabled and is_make_source(item.path))
    )
    pages = tuple(
        TrackedText(item.path, item.content.decode("utf-8", errors="replace"))
        for start in range(0, len(paths), _BLOB_BATCH)
        for item in read_tracked_blob_contents(
            root, paths[start : start + _BLOB_BATCH], identity=identity
        )
    )
    return replace(snapshot, tracked_texts=pages)


def with_documentation_comparison(
    root: Path,
    snapshot: RepositorySnapshot,
    *,
    enabled_rules: frozenset[RuleVersion],
    base_revision: str | None,
) -> RepositorySnapshot:
    rule_ids = {
        ADDED_MARKDOWN_RULE_ID,
        GENERATED_DOCUMENTATION_RULE_ID,
        LOCAL_LINKS_RULE_ID,
        MARKDOWN_ONLY_RULE_ID,
        MARKDOWN_WORD_GROWTH_RULE_ID,
    }
    if not any(item.rule_id in rule_ids for item in enabled_rules):
        return snapshot
    provenance = snapshot.provenance
    if provenance.mode == "worktree":
        ConfigurationError.fail("Documentation comparison requires an exact Git tree or index")
    head = GitIdentity(provenance.source_revision, provenance.tree_digest, provenance.mode)
    if provenance.comparison_basis is not None:
        base_revision = provenance.comparison_base_revision
    comparison_base = _comparison_base(root, head, base_revision)
    base = comparison_base.identity
    base_files = tracked_files_for_identity(root, base) if base else ()
    base_paths = frozenset(item.path for item in base_files)
    policy = DocumentationConfig(entrypoints=())
    if base is not None and provenance.manifest_path in base_paths:
        blob = read_tracked_blob_contents(root, (provenance.manifest_path,), identity=base)[0]
        policy = parse_manifest_bytes(blob.content).documentation or policy
    generated = tuple(item.path for item in policy.generated)
    head_pages = _markdown_objects(snapshot.inspection.tracked_files, generated)
    base_pages = _markdown_objects(base_files, generated)
    added_pages = tuple(sorted(head_pages.keys() - base_paths - set(policy.addition_exemptions)))
    markdown_only_paths = _markdown_only_paths(root, snapshot, comparison_base, enabled_rules)
    return replace(
        snapshot,
        documentation_comparison=DocumentationComparison(
            maximum_added_pages=policy.maximum_added_pages,
            added_pages=added_pages,
            markdown_only_paths=markdown_only_paths,
            maximum_added_words=policy.maximum_added_words,
            added_words=_added_words(root, head, base, head_pages, base_pages)
            if any(item.rule_id == MARKDOWN_WORD_GROWTH_RULE_ID for item in enabled_rules)
            else 0,
            changed_paths=_changed_paths(snapshot.inspection.tracked_files, base_files),
            linguist_generated=_linguist_generated(root, head, snapshot.inspection.tracked_files)
            if any(item.rule_id == GENERATED_DOCUMENTATION_RULE_ID for item in enabled_rules)
            else (),
        ),
        provenance=replace(
            provenance,
            comparison=ComparisonProvenance(
                revision=base.source_revision if base else "0" * len(head.source_revision),
                tree_digest=base.tree_digest if base else "0" * len(head.source_revision),
                basis=provenance.comparison_basis or comparison_base.basis,
            ),
        ),
    )


def _added_words(
    root: Path,
    head: GitIdentity,
    base: GitIdentity | None,
    head_pages: dict[str, str],
    base_pages: dict[str, str],
) -> int:
    head_objects = Counter(head_pages.values())
    base_objects = Counter(base_pages.values())
    unchanged = head_objects & base_objects
    added = _object_words(root, head, head_pages, head_objects - unchanged)
    removed = _object_words(root, base, base_pages, base_objects - unchanged) if base else 0
    return added - removed


def _changed_paths(
    head: Iterable[TrackedFileEvidence], base: Iterable[TrackedBlob]
) -> tuple[str, ...]:
    objects = {(item.path, item.object_id) for item in head}
    objects ^= {(item.path, item.object_id) for item in base}
    return tuple(sorted({path for path, _ in objects}))


def _linguist_generated(
    root: Path, head: GitIdentity, files: Iterable[TrackedFileEvidence]
) -> tuple[str, ...]:
    generated = attribute_paths(
        root,
        source="--cached" if head.mode == "git-index" else f"--source={head.tree_digest}",
        paths=tuple(item.path for item in files if item.path.casefold().endswith((".md", ".mdx"))),
        attribute="linguist-generated",
        values=frozenset({b"set", b"true"}),
    )
    return tuple(sorted(generated))


def _markdown_objects(
    files: Iterable[TrackedBlob | TrackedFileEvidence], generated: tuple[str, ...]
) -> dict[str, str]:
    return {
        item.path: item.object_id
        for item in files
        if item.path.casefold().endswith((".md", ".mdx"))
        and not any(item.path == path or item.path.startswith(f"{path}/") for path in generated)
    }


def _object_words(
    root: Path, identity: GitIdentity, pages: dict[str, str], objects: Counter[str]
) -> int:
    paths = tuple(sorted({oid: path for path, oid in pages.items() if oid in objects}.values()))
    words: dict[str, int] = {}
    for start in range(0, len(paths), _BLOB_BATCH):
        words.update(
            (item.object_id, len(item.content.split()))
            for item in read_tracked_blob_contents(
                root, paths[start : start + _BLOB_BATCH], identity=identity
            )
        )
    return sum(words[oid] * count for oid, count in objects.items())


def _markdown_only_paths(
    root: Path,
    snapshot: RepositorySnapshot,
    comparison_base: _ComparisonBase,
    enabled_rules: frozenset[RuleVersion],
) -> tuple[str, ...]:
    base = comparison_base.identity
    provenance = snapshot.provenance
    if (
        base is None
        or provenance.mode != "git-tree"
        or (provenance.comparison_basis or comparison_base.basis) != "explicit"
        or not any(item.rule_id == MARKDOWN_ONLY_RULE_ID for item in enabled_rules)
    ):
        return ()
    return markdown_only_paths_for_revisions(
        root, base=base.source_revision, head=provenance.source_revision
    )


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
            comparison=ComparisonProvenance(
                comparison.base_revision, comparison.base_tree_digest, comparison.basis
            ),
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
    head_roots = migration_roots(
        snapshot.manifest, tuple(item.path for item in snapshot.inspection.tracked_files)
    )
    head_files = _flag_lone_concurrent_indexes(
        root, head, snapshot.inspection.tracked_files, base_files, head_roots
    )
    base_paths = tuple(item.path for item in base_files)
    if base is not None and provenance.manifest_path in base_paths:
        manifest_blob = read_tracked_blob_contents(
            root, (provenance.manifest_path,), identity=base
        )[0]
        base_manifest = parse_manifest_bytes(manifest_blob.content)
    else:
        base_manifest = None
    base_roots = migration_roots(base_manifest, base_paths)
    explicit_roots = tuple(
        sorted(
            set(explicit_migration_roots(base_manifest))
            | set(explicit_migration_roots(snapshot.manifest))
        )
    )
    return replace(
        snapshot,
        migration_comparison=MigrationComparison(
            protected_roots(base_roots, head_roots),
            base_files,
            head_files,
            explicit_roots=explicit_roots,
        ),
        provenance=replace(
            provenance,
            comparison=ComparisonProvenance(
                revision=base.source_revision if base else "0" * len(head.source_revision),
                tree_digest=base.tree_digest if base else "0" * len(head.source_revision),
                basis=provenance.comparison_basis or comparison_base.basis,
            ),
        ),
    )


def _flag_lone_concurrent_indexes(
    root: Path,
    head: GitIdentity,
    files: tuple[TrackedFileEvidence, ...],
    base_files: tuple[TrackedFileEvidence, ...],
    roots: tuple[str, ...],
) -> tuple[TrackedFileEvidence, ...]:
    known: set[tuple[str, str]] = (
        {(item.path, item.object_id) for item in base_files} if roots else set()
    )
    paths = tuple(
        item.path
        for item in files
        if item.path.endswith(".sql")
        and (item.path, item.object_id) not in known
        and any(item.path.startswith(f"{prefix}/") for prefix in roots)
    )
    flagged: set[str] = set()
    for start in range(0, len(paths), _BLOB_BATCH):
        blobs = read_tracked_blob_contents(root, paths[start : start + _BLOB_BATCH], identity=head)
        flagged.update(item.path for item in blobs if is_non_consolidatable_migration(item.content))
    return tuple(
        replace(item, non_consolidatable=item.path in flagged)
        if item.non_consolidatable != (item.path in flagged)
        else item
        for item in files
    )


def _comparison_base(root: Path, head: GitIdentity, base_revision: str | None) -> _ComparisonBase:
    if head.mode == "git-index":
        if _empty_revision(head.source_revision):
            return _EmptyComparisonBase("staged")
        return _ExistingComparisonBase(git_revision_identity(root, head.source_revision), "staged")
    if base_revision is not None:
        if _empty_revision(base_revision):
            return _EmptyComparisonBase("empty")
        return _ExistingComparisonBase(git_revision_identity(root, base_revision), "explicit")
    base = git_parent_identity(root, head)
    return (
        _EmptyComparisonBase("empty")
        if base is None
        else _ExistingComparisonBase(base, "last-commit")
    )


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


def with_rule_inputs(
    root: Path,
    snapshot: RepositorySnapshot,
    *,
    enabled_rules: frozenset[RuleVersion],
    base_revision: str | None,
    as_of: date | None,
) -> RepositorySnapshot:
    snapshot = with_makefile_comparison(
        root,
        snapshot,
        enabled_rules=enabled_rules,
        base_revision=base_revision,
        as_of=as_of,
    )
    snapshot = with_migration_comparison(
        root, snapshot, enabled_rules=enabled_rules, base_revision=base_revision
    )
    snapshot = with_documentation_comparison(
        root, snapshot, enabled_rules=enabled_rules, base_revision=base_revision
    )
    return with_tracked_texts(root, snapshot, enabled_rules=enabled_rules)
