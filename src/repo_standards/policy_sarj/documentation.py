from __future__ import annotations

from typing import TYPE_CHECKING

from repo_standards.core.canonical import nearest_component
from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation


if TYPE_CHECKING:
    from repo_standards.core.models import RepositorySnapshot, RuleDefinition


MARKDOWN_ONLY_RULE_ID = RuleId("repository/documentation/markdown-only-change")
ADDED_MARKDOWN_RULE_ID = RuleId("repository/documentation/added-markdown")
MARKDOWN_WORD_GROWTH_RULE_ID = RuleId("repository/documentation/markdown-word-growth")


def added_markdown_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    if comparison is None or len(comparison.added_pages) <= comparison.maximum_added_pages:
        return ()
    path = comparison.added_pages[0]
    component = nearest_component(path, snapshot.manifest.components)
    return (
        Diagnostic(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            severity=rule.severity,
            evidence_level="verified",
            component_id=component.component_id if component else ComponentId("repository"),
            subject_kind="documentation",
            observed=str(len(comparison.added_pages)),
            expected=str(comparison.maximum_added_pages),
            observed_value=len(comparison.added_pages),
            expected_value=comparison.maximum_added_pages,
            message=(
                f"Added {len(comparison.added_pages)} Markdown paths; the trusted base allows "
                f"{comparison.maximum_added_pages}. Review whether another page is necessary."
            ),
            path=path,
            manifest_anchor=f"tracked_files.{path}",
            location=SourceLocation(path, line=1),
            remediation=Remediation(
                summary="Prefer updating an existing canonical document or native CLI help.",
                steps=(
                    "Keep audit reports, rehearsal notes and task logs outside application source.",
                    "Retain required documentation; do not rename it merely to avoid review.",
                    "Review necessary additions using the existing documentation page budget.",
                ),
                validation=("Rerun the same Git comparison after reviewing the added paths.",),
            ),
            baselineable=False,
        ),
    )


def markdown_only_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    if comparison is None or not comparison.markdown_only_paths:
        return ()
    path = comparison.markdown_only_paths[0]
    component = nearest_component(path, snapshot.manifest.components)
    return (
        Diagnostic(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            severity=rule.severity,
            evidence_level="verified",
            component_id=component.component_id if component else ComponentId("repository"),
            subject_kind="documentation",
            observed="Markdown-only change",
            expected="Review whether this needs a standalone pull request",
            message=(
                "This Git comparison changes only Markdown files. "
                "Review the value of a standalone documentation PR."
            ),
            path=path,
            manifest_anchor=f"tracked_files.{path}",
            location=SourceLocation(path, line=1),
            remediation=Remediation(
                summary="Keep necessary documentation with the change it explains when practical.",
                steps=(
                    "Retain required guides, operational contracts and useful corrections.",
                    "Keep task logs outside source; do not rename files to bypass review.",
                ),
                validation=("Compare the full pull request with its explicit base using --base.",),
            ),
            baselineable=False,
        ),
    )


def markdown_word_growth_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    if comparison is None or comparison.added_words <= comparison.maximum_added_words:
        return ()
    return (
        Diagnostic(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            severity=rule.severity,
            evidence_level="verified",
            component_id=ComponentId("repository"),
            subject_kind="documentation",
            observed=str(comparison.added_words),
            expected=str(comparison.maximum_added_words),
            observed_value=comparison.added_words,
            expected_value=comparison.maximum_added_words,
            message=(
                f"Tracked Markdown grew by {comparison.added_words} net words; the trusted "
                f"base allows {comparison.maximum_added_words}."
            ),
            path=snapshot.provenance.manifest_path,
            manifest_anchor="documentation.maximum_added_words",
            remediation=Remediation(
                summary="Trim or replace existing Markdown so the net growth fits the budget.",
                steps=(
                    "Delete stale, duplicated or history text and link the canonical page.",
                    "Move checkable instructions into rules, tests or native CLI help.",
                    "Keep required contracts; do not rename or reformat text to hide growth.",
                ),
                validation=("Rerun the same Git comparison and require no active findings.",),
            ),
            baselineable=False,
        ),
    )
