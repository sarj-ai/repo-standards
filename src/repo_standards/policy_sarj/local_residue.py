from __future__ import annotations

from typing import TYPE_CHECKING

from repo_standards.core.canonical import ComponentIndex
from repo_standards.core.models import (
    ComponentId,
    Diagnostic,
    Remediation,
    RuleId,
    SourceLocation,
)


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


LOCAL_RESIDUE_RULE_ID = RuleId("repository/artifacts/local-residue")
_CACHE_SUFFIXES = (".pyc", ".pyo", ".tsbuildinfo")
_STATE_BASENAMES = frozenset({".ds_store", "thumbs.db", ".eslintcache", ".coverage"})


def local_residue_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    components = ComponentIndex(snapshot.manifest.components)
    diagnostics: list[Diagnostic] = []
    paths = {
        item.path for item in snapshot.inspection.tracked_files if _is_local_residue_path(item.path)
    }
    for path in sorted(paths):
        component = components.nearest(path)
        diagnostics.append(
            Diagnostic(
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=rule.severity,
                evidence_level="verified",
                component_id=component.component_id if component else ComponentId("repository"),
                subject_kind="tracked-local-residue-convention",
                observed=path,
                expected="no unreviewed tracked bytecode, cache, coverage data or OS metadata",
                message=(
                    "Tracked filename matches a cache, coverage data or OS metadata convention."
                ),
                path=path,
                manifest_anchor=f"tracked_files.{path}",
                location=SourceLocation(path, line=1),
                remediation=Remediation(
                    summary="Review the file's contract before removing tracked local residue.",
                    steps=(
                        (
                            "Determine whether this exact file is disposable local state or an "
                            "intentional fixture, vendor artifact or sourceless runtime module."
                        ),
                        (
                            "For disposable output, remove it from the Git index and add an "
                            "appropriate ignore pattern; an ignore pattern alone does not "
                            "untrack an existing file."
                        ),
                        (
                            "For required artifacts, retain the file and use the existing exact "
                            "fingerprint exception with owner, reason, issue and review dates."
                        ),
                    ),
                    validation=(
                        "Run the owning behavior or distribution checks after any removal.",
                        "Rerun repo-standards on the same selected Git tree or staged index.",
                    ),
                ),
            )
        )
    return tuple(diagnostics)


def _is_local_residue_path(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1].lower()
    return basename.endswith(_CACHE_SUFFIXES) or basename in _STATE_BASENAMES
