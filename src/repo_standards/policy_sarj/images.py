from __future__ import annotations

from typing import TYPE_CHECKING

from repo_standards.core.canonical import ComponentIndex
from repo_standards.core.images import is_image_path, validate_image_artifacts
from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


UNDECLARED_IMAGES_RULE_ID = RuleId("repository/artifacts/undeclared-images")


def image_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    tracked_paths = frozenset(item.path for item in snapshot.inspection.tracked_files)
    artifacts = snapshot.manifest.image_artifacts
    validate_image_artifacts(artifacts, tracked_paths)
    declared_paths = frozenset(item.path for item in artifacts)
    components = ComponentIndex(snapshot.manifest.components)
    diagnostics: list[Diagnostic] = []
    for path in sorted(
        path for path in tracked_paths if is_image_path(path) and path not in declared_paths
    ):
        component = components.nearest(path)
        diagnostics.append(
            Diagnostic(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=rule.severity,
                evidence_level="verified",
                component_id=component.component_id if component else ComponentId("repository"),
                subject_kind="tracked-undeclared-image",
                observed=path,
                expected="an exact images.artifacts declaration with a durable purpose",
                message="Tracked image has no declared application, documentation or fixture use.",
                path=path,
                manifest_anchor=f"tracked_files.{path}",
                location=SourceLocation(path, line=1),
                remediation=Remediation(
                    summary="Keep review evidence out of Git and declare required image assets.",
                    steps=(
                        "Review the image's actual consumer or test contract before changing it.",
                        "Attach review evidence externally, then untrack the review-only file.",
                        "Declare its exact path, purpose and reason in images.artifacts.",
                        "LFS, generated output and directories grant no implicit permissions.",
                    ),
                    validation=(
                        "Preserve real application, documentation and fixture behavior.",
                        "Rerun repo-standards against the same selected Git tree or staged index.",
                    ),
                ),
            )
        )
    return tuple(diagnostics)
