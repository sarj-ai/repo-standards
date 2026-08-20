from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from pathlib import PurePosixPath

from .models import (
    Diagnostic,
    MigrationPath,
    PackageEvidence,
    Remediation,
    RepositorySnapshot,
    RuleId,
    WorkspaceEvidence,
)


_PATH_SAMPLE_LIMIT = 20
_MIGRATION_RULE = RuleId("repository/migration/consistency")


@dataclass(frozen=True, slots=True)
class _PathMatch:
    count: int
    sample: tuple[str, ...]


def migration_diagnostics(snapshot: RepositorySnapshot) -> tuple[Diagnostic, ...]:
    tracked = tuple(item.path for item in snapshot.inspection.tracked_files)
    component_by_path = {
        component.path: component.component_id for component in snapshot.manifest.components
    }
    diagnostics: list[Diagnostic] = []
    for migration in snapshot.manifest.migration_paths:
        target_files = _within(tracked, migration.new_path)
        source_files = _within(tracked, migration.old_path)
        if target_files.count == 0:
            diagnostics.append(_missing_target(migration))
        source_owner = component_by_path.get(migration.old_path)
        if source_files.count and source_owner in {None, migration.component_id}:
            diagnostics.append(_retained_source(migration, source_files))
        diagnostics.extend(_workspace_membership_diagnostics(snapshot, migration))
    return tuple(
        sorted(
            diagnostics,
            key=lambda item: (item.path, item.rule_id, item.component_id, item.manifest_anchor),
        )
    )


def _within(paths: tuple[str, ...], root: str) -> _PathMatch:
    selected: list[str] = []
    exact = bisect_left(paths, root)
    exact_count = int(exact < len(paths) and paths[exact] == root)
    if exact_count:
        selected.append(paths[exact])
    prefix = f"{root}/"
    start = bisect_left(paths, prefix)
    end = bisect_left(paths, f"{prefix}\U0010ffff")
    remaining = _PATH_SAMPLE_LIMIT - len(selected)
    selected.extend(paths[start : min(end, start + remaining)])
    return _PathMatch(count=exact_count + end - start, sample=tuple(selected))


def _missing_target(migration: MigrationPath) -> Diagnostic:
    return Diagnostic(
        rule_id=_MIGRATION_RULE,
        rule_version=1,
        severity="warning",
        evidence_level="verified",
        component_id=migration.component_id,
        subject_kind="migration-target",
        observed="no tracked files at the declared target",
        expected=migration.new_path,
        message="declared migration target is absent from the selected Git tree",
        path=migration.new_path,
        manifest_anchor=f"migration_paths.{migration.component_id}.to",
        remediation=Remediation(
            summary="Move the component to its declared target before completing the migration.",
            steps=(
                "Add the component's tracked files at the declared target path.",
                "Update path-sensitive build and workspace configuration in the same change.",
            ),
            validation=("Run repo-standards check against the resulting commit.",),
        ),
    )


def _retained_source(migration: MigrationPath, source_files: _PathMatch) -> Diagnostic:
    return Diagnostic(
        rule_id=_MIGRATION_RULE,
        rule_version=1,
        severity="warning",
        evidence_level="verified",
        component_id=migration.component_id,
        subject_kind="migration-source",
        observed=f"{source_files.count} tracked file(s) remain under {migration.old_path}",
        expected="no tracked files at the old component root",
        message="declared migration source still contains tracked files",
        path=migration.old_path,
        manifest_anchor=f"migration_paths.{migration.component_id}.from",
        remediation=Remediation(
            summary="Finish the relocation or document the compatibility surface separately.",
            steps=(
                "Review every retained file under the old component root.",
                "Move obsolete files and declare intentional compatibility components explicitly.",
            ),
            validation=(
                "Run repo-standards check and confirm the old root is empty or separately owned.",
            ),
        ),
        observed_value={
            "count": source_files.count,
            "paths": list(source_files.sample),
            "truncated": source_files.count > len(source_files.sample),
        },
        expected_value=[],
    )


def _workspace_membership_diagnostics(
    snapshot: RepositorySnapshot, migration: MigrationPath
) -> tuple[Diagnostic, ...]:
    diagnostics: list[Diagnostic] = []
    projects = tuple(
        project
        for project in snapshot.inspection.projects
        if not project.workspace_root and _is_within(project.path, migration.new_path)
    )
    for project in projects:
        old_project_path = _relocated_path(
            path=project.path,
            new_root=migration.new_path,
            old_root=migration.old_path,
        )
        for workspace in snapshot.inspection.workspaces:
            if workspace.ecosystem != project.ecosystem:
                continue
            old_member = _workspace_includes(workspace, old_project_path)
            new_member = _workspace_includes(workspace, project.path)
            if old_member and not new_member:
                diagnostics.append(_workspace_membership_lost(migration, project, workspace))
    return tuple(diagnostics)


def _is_within(path: str, root: str) -> bool:
    return path == root or path.startswith(f"{root}/")


def _relocated_path(*, path: str, new_root: str, old_root: str) -> str:
    suffix = path.removeprefix(new_root)
    return f"{old_root}{suffix}"


def _workspace_includes(workspace: WorkspaceEvidence, project_path: str) -> bool:
    workspace_root = PurePosixPath(workspace.path).parent
    project_directory = PurePosixPath(project_path).parent
    try:
        relative = project_directory.relative_to(workspace_root)
    except ValueError:
        return False
    member = any(relative.match(pattern) for pattern in workspace.member_patterns)
    excluded = any(relative.match(pattern) for pattern in workspace.exclude_patterns)
    return member and not excluded


def _workspace_membership_lost(
    migration: MigrationPath,
    project: PackageEvidence,
    workspace: WorkspaceEvidence,
) -> Diagnostic:
    return Diagnostic(
        rule_id=_MIGRATION_RULE,
        rule_version=1,
        severity="warning",
        evidence_level="verified",
        component_id=migration.component_id,
        subject_kind="workspace-membership",
        observed=f"{project.path} is no longer selected by {workspace.path}",
        expected="the relocated package remains a member of its previous workspace",
        message="path migration drops a package from its native workspace",
        path=workspace.path,
        manifest_anchor=f"migration_paths.{migration.component_id}.to",
        remediation=Remediation(
            summary="Update the native workspace declaration for the relocated package.",
            steps=(
                "Add a member pattern covering the package's new directory.",
                "Keep exclusions at least as narrow as they were before the relocation.",
            ),
            validation=(
                "Run the package manager's immutable workspace install and repo-standards check.",
            ),
        ),
        observed_value={
            "workspace": workspace.path,
            "members": list(workspace.member_patterns),
            "exclude": list(workspace.exclude_patterns),
            "package": project.path,
        },
        expected_value={"package_included": True},
    )
