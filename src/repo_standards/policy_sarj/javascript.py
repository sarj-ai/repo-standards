from __future__ import annotations

from typing import TYPE_CHECKING

from repo_standards.core.canonical import nearest_component
from repo_standards.core.javascript import is_javascript_path, validate_javascript_artifacts
from repo_standards.core.models import (
    ComponentId,
    Diagnostic,
    Remediation,
    RuleId,
    SourceLocation,
)


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


UNTYPED_JAVASCRIPT_RULE_ID = RuleId("repository/artifacts/untyped-javascript")


def javascript_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    tracked_paths = frozenset(item.path for item in snapshot.inspection.tracked_files)
    artifacts = snapshot.manifest.javascript_artifacts
    validate_javascript_artifacts(artifacts, tracked_paths)
    declared_paths = frozenset(item.path for item in artifacts)
    diagnostics: list[Diagnostic] = []
    for path in sorted(
        path for path in tracked_paths if is_javascript_path(path) and path not in declared_paths
    ):
        component = nearest_component(path, snapshot.manifest.components)
        diagnostics.append(
            Diagnostic(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=rule.severity,
                evidence_level="verified",
                component_id=component.component_id if component else ComponentId("repository"),
                subject_kind="tracked-undeclared-javascript",
                observed=path,
                expected="typed source or an exact javascript.artifacts declaration",
                message="Tracked JavaScript has no explicit runtime artifact declaration.",
                path=path,
                manifest_anchor=f"tracked_files.{path}",
                location=SourceLocation(path, line=1),
                remediation=Remediation(
                    summary="Use typed source or declare why this JavaScript artifact is required.",
                    steps=(
                        "Review the file and its runtime, tool, fixture or distribution contract.",
                        (
                            "For authored tooling or application source, migrate to typed "
                            "TypeScript and update callers, module loading and type checks."
                        ),
                        (
                            "For required JavaScript, add an exact javascript.artifacts "
                            "path, kind and reason; generated artifacts also need a tracked "
                            "non-JavaScript source."
                        ),
                    ),
                    validation=(
                        (
                            "Run the owning type, behavior and runtime checks; "
                            "renaming alone is insufficient."
                        ),
                        "Rerun repo-standards on the same selected Git tree or staged index.",
                    ),
                ),
            )
        )
    return tuple(diagnostics)
