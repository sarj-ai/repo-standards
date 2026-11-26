from __future__ import annotations

from functools import partial
from pathlib import PurePosixPath
import posixpath
import re
from typing import TYPE_CHECKING
from urllib.parse import unquote

from repo_standards.core.canonical import nearest_component
from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation


if TYPE_CHECKING:
    from collections.abc import Iterable

    from repo_standards.core.models import GeneratedDocument, RepositorySnapshot, RuleDefinition


MARKDOWN_ONLY_RULE_ID = RuleId("repository/documentation/markdown-only-change")
ADDED_MARKDOWN_RULE_ID = RuleId("repository/documentation/added-markdown")
MARKDOWN_WORD_GROWTH_RULE_ID = RuleId("repository/documentation/markdown-word-growth")
GENERATED_DOCUMENTATION_RULE_ID = RuleId("repository/documentation/generated-sources")
LOCAL_LINKS_RULE_ID = RuleId("repository/documentation/local-links")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_CODE_SPAN = re.compile(r"(`+).+?\1")
_LINK_TARGETS = re.compile(r"(?:\]\(|^ {0,3}\[[^\]^][^\]]*\]:)\s*(?:<([^>]+)>|([^)\s]+))")
_NON_RELATIVE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|[#/])")


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


def generated_documentation_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    policy = snapshot.manifest.documentation
    if comparison is None or policy is None:
        return ()
    tracked = frozenset(item.path for item in snapshot.inspection.tracked_files)
    changed = comparison.changed_paths
    source_changes = frozenset(changed).difference(
        *(_paths_under(changed, item.path) for item in policy.generated)
    )
    diagnostics: list[Diagnostic] = []
    for index, document in enumerate(policy.generated):
        finding = partial(_generated_diagnostic, rule, document, index)
        edited = [path for path in _paths_under(changed, document.path) if path in tracked]
        if not _paths_under(tracked, document.source):
            diagnostics.append(
                finding(document.source, f"Generator source {document.source} is not tracked.")
            )
        elif not _paths_under(tracked, document.path):
            diagnostics.append(
                finding(document.path, f"Generated {document.path} is declared but not tracked.")
            )
        elif edited and not _paths_under(source_changes, document.source):
            diagnostics.append(
                finding(edited[0], f"Generated {edited[0]} changed without {document.source}.")
            )
    return (
        *diagnostics,
        *_undeclared_diagnostics(rule, comparison.linguist_generated, policy.generated),
    )


def _paths_under(paths: Iterable[str], prefix: str) -> list[str]:
    return sorted(path for path in paths if path == prefix or path.startswith(f"{prefix}/"))


def _generated_diagnostic(
    rule: RuleDefinition, document: GeneratedDocument, index: int, path: str, message: str
) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="generated-documentation",
        observed=path,
        expected=f"{document.path} regenerated from {document.source}",
        message=message,
        path=path,
        manifest_anchor=f"documentation.generated[{index}]",
        remediation=Remediation(
            summary=f"Regenerate {document.path} with `{document.command}`.",
            steps=(
                "Change the generator source or its inputs, not the generated output.",
                "Commit the regenerated output together with the source change.",
                "Update or remove the documentation.generated entry when the generator moves.",
            ),
            validation=("Rerun the same Git comparison and require no active findings.",),
        ),
        baselineable=False,
    )


def local_link_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    tracked = {item.path for item in snapshot.inspection.tracked_files}
    targets = tracked | {str(parent) for path in tracked for parent in PurePosixPath(path).parents}
    return tuple(
        _local_link_diagnostic(rule, path=page.path, line=line, target=target)
        for page in snapshot.markdown_pages
        for target, line in _relative_links(page.content).items()
        if _resolve(page.path, target) not in targets
    )


def _relative_links(content: str) -> dict[str, int]:
    links: dict[str, int] = {}
    fence = ""
    for number, line in enumerate(content.splitlines(), start=1):
        if marker := _FENCE.match(line):
            opened = marker.group(1)
            if not fence:
                fence = opened
            elif opened[0] == fence[0] and len(opened) >= len(fence):
                fence = ""
            continue
        if fence:
            continue
        for match in _LINK_TARGETS.finditer(_CODE_SPAN.sub("", line)):
            target = match.group(1) or match.group(2)
            if not _NON_RELATIVE.match(target):
                links.setdefault(target, number)
    return links


def _resolve(page: str, target: str) -> str:
    path = unquote(target.split("#", 1)[0].split("?", 1)[0])
    return posixpath.normpath(posixpath.join(posixpath.dirname(page), path)) if path else "."


def _local_link_diagnostic(
    rule: RuleDefinition, *, path: str, line: int, target: str
) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="documentation-link",
        observed=target,
        expected="a tracked file or directory",
        message=f"Link {target} does not resolve to a tracked path.",
        path=path,
        manifest_anchor=f"tracked_files.{path}.links.{target}",
        location=SourceLocation(path, line=line),
        remediation=Remediation(
            summary="Point the link at the tracked canonical page or remove it.",
            steps=(
                "Update the link when its target moved; remove it when the target was deleted.",
                "Use an absolute URL for content outside this repository.",
            ),
            validation=("Rerun repo-standards and require no active findings.",),
        ),
    )


def _undeclared_diagnostics(
    rule: RuleDefinition, paths: tuple[str, ...], generated: tuple[GeneratedDocument, ...]
) -> tuple[Diagnostic, ...]:
    declared = frozenset(path for item in generated for path in _paths_under(paths, item.path))
    return tuple(_undeclared_diagnostic(rule, path) for path in paths if path not in declared)


def _undeclared_diagnostic(rule: RuleDefinition, path: str) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="generated-documentation",
        observed=path,
        expected=f"a documentation.generated entry covering {path}",
        message=f"{path} is linguist-generated but has no declared generator.",
        path=path,
        manifest_anchor="documentation.generated",
        remediation=Remediation(
            summary=f"Declare the generator of {path} under documentation.generated.",
            steps=(
                "Add a documentation.generated entry whose path covers the output.",
                "Remove linguist-generated from .gitattributes when the page is hand-maintained.",
            ),
            validation=("Rerun the same Git comparison and require no active findings.",),
        ),
        baselineable=False,
    )
