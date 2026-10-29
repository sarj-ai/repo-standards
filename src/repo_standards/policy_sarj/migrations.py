from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING

from repo_standards.core.canonical import nearest_component
from repo_standards.core.models import (
    ComponentId,
    Diagnostic,
    RelatedLocation,
    Remediation,
    RuleId,
    SourceLocation,
)


if TYPE_CHECKING:
    from repo_standards.core.models import (
        Manifest,
        RepositorySnapshot,
        RuleDefinition,
        TrackedFileEvidence,
    )


MIGRATION_CONSOLIDATION_RULE_ID = RuleId("repository/artifacts/migration-consolidation")
_FLYWAY_VERSION = re.compile(r"[VU]([0-9]+(?:[._][0-9]+)*)__[^/]+\.sql\Z")
_NESTED_REVISION_PARTS = 2
_AUTO_ROOT_EXCLUDED = frozenset(
    {
        "test",
        "tests",
        "testing",
        "__tests__",
        "fixture",
        "fixtures",
        "__fixtures__",
        "testdata",
        "example",
        "examples",
        "vendor",
        "node_modules",
        "generated",
    }
)


def explicit_migration_roots(manifest: Manifest | None) -> tuple[str, ...]:
    roots = (
        {item.path for item in manifest.components if item.kind == "migration-set"}
        if manifest is not None
        else set[str]()
    )
    if (
        manifest is not None
        and manifest.pull_request is not None
        and manifest.pull_request.review_policy is not None
    ):
        roots.update(manifest.pull_request.review_policy.migration_roots)
    return tuple(sorted(roots))


def migration_roots(manifest: Manifest | None, paths: tuple[str, ...]) -> tuple[str, ...]:
    roots = set(explicit_migration_roots(manifest))
    for path in paths:
        parts = PurePosixPath(path).parts
        if any(part.casefold() in _AUTO_ROOT_EXCLUDED for part in parts[:-1]):
            continue
        for index, part in enumerate(parts[:-1]):
            if part == "migrations":
                roots.add("/".join(parts[: index + 1]))
    return tuple(sorted(roots))


def protected_roots(base: tuple[str, ...], head: tuple[str, ...]) -> tuple[str, ...]:
    trusted = frozenset(base)
    return tuple(
        sorted(
            trusted
            | {
                root
                for root in head
                if not any(parent.as_posix() in trusted for parent in PurePosixPath(root).parents)
            }
        )
    )


def migration_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.migration_comparison
    if comparison is None:
        return ()
    diagnostics: list[Diagnostic] = []
    for root, revisions in _new_revisions(snapshot).items():
        if len(revisions) <= 1:
            continue
        component = nearest_component(root, snapshot.manifest.components)
        diagnostics.append(
            Diagnostic(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=rule.severity,
                evidence_level="verified",
                component_id=component.component_id if component else ComponentId("repository"),
                subject_kind="new-migration-revisions",
                observed=str(len(revisions)),
                expected="one new logical SQL migration per stream",
                observed_value=len(revisions),
                expected_value=1,
                message=(
                    f"{root} adds {len(revisions)} SQL migrations; "
                    "consolidate compatible new revisions."
                ),
                path=revisions[0].path,
                manifest_anchor=f"migration_streams.{root}",
                location=SourceLocation(revisions[0].path, line=1),
                related_locations=tuple(
                    RelatedLocation(SourceLocation(item.path, line=1), "New logical SQL revision")
                    for item in revisions
                ),
                remediation=Remediation(
                    summary="Combine compatible unapplied migrations from this comparison.",
                    steps=(
                        "Preserve statement order and framework rollback and metadata contracts.",
                        "Never squash revisions already applied to a shared database.",
                        "Retain necessary execution boundaries with a reviewed exception.",
                    ),
                    validation=("Rerun with --base set to the exact pull-request base.",),
                ),
            )
        )
    return tuple(diagnostics)


def _new_revisions(snapshot: RepositorySnapshot) -> dict[str, tuple[TrackedFileEvidence, ...]]:
    comparison = snapshot.migration_comparison
    if comparison is None:
        return {}
    base = _revisions(comparison.base_files, comparison.roots, comparison.explicit_roots)
    head = _revisions(comparison.head_files, comparison.roots, comparison.explicit_roots)
    removed = Counter(
        tuple(sorted(item.object_id for item in files))
        for revision, files in base.items()
        if revision not in head
    )
    result: dict[str, list[TrackedFileEvidence]] = defaultdict(list)
    for coordinate in sorted(head.keys() - base.keys()):
        files = head[coordinate]
        signature = tuple(sorted(item.object_id for item in files))
        if removed[signature]:
            removed[signature] -= 1
        else:
            result[coordinate[0]].append(files[0])
    return {root: tuple(files) for root, files in result.items()}


def _revisions(
    files: tuple[TrackedFileEvidence, ...],
    roots: tuple[str, ...],
    explicit_roots: tuple[str, ...] = (),
) -> dict[tuple[str, str], tuple[TrackedFileEvidence, ...]]:
    selected = frozenset(roots)
    explicit = frozenset(explicit_roots)
    grouped: dict[tuple[str, str], list[TrackedFileEvidence]] = defaultdict(list)
    for item in files:
        path = PurePosixPath(item.path)
        ancestors = (parent.as_posix() for parent in path.parents)
        root = next(
            (parent for parent in ancestors if parent in selected),
            None,
        )
        if root is None:
            continue
        if any(part.casefold() in _AUTO_ROOT_EXCLUDED for part in path.parts[:-1]) and not any(
            parent.as_posix() in explicit for parent in path.parents
        ):
            continue
        revision = _revision(item.path, root)
        if revision is not None:
            grouped[root, revision].append(item)
    return {
        revision: tuple(sorted(items, key=lambda item: item.path))
        for revision, items in grouped.items()
    }


def _revision(path: str, root: str) -> str | None:
    relative = path.removeprefix(f"{root}/")
    parts = PurePosixPath(relative).parts
    if len(parts) == _NESTED_REVISION_PARTS and parts[1] == "migration.sql":
        return parts[0]
    if len(parts) == _NESTED_REVISION_PARTS and parts[0] in {"up", "down"}:
        relative = parts[1]
    elif len(parts) != 1:
        return None
    if not relative.endswith(".sql") or relative.startswith("R__"):
        return None
    if (flyway := _FLYWAY_VERSION.fullmatch(relative)) is not None:
        version_parts = [str(int(part)) for part in re.split(r"[._]", flyway[1])]
        while len(version_parts) > 1 and version_parts[-1] == "0":
            version_parts.pop()
        version = ".".join(version_parts)
        return f"flyway:{version}"
    stem = relative.removesuffix(".sql")
    return stem.rpartition(".")[0] if stem.endswith((".up", ".down")) else stem
