from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import TYPE_CHECKING

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import (
    ComponentId,
    Diagnostic,
    ExceptionUse,
    Remediation,
    RuleId,
    SourceLocation,
)


if TYPE_CHECKING:
    from repo_standards.core.models import (
        MakefileException,
        MakefileMetric,
        RepositorySnapshot,
        RuleDefinition,
    )


MAKEFILE_GROWTH_RULE_ID = RuleId("repository/artifacts/makefile-growth")
_DOCUMENT_SUFFIXES = (".md", ".mdx", ".rst", ".adoc", ".txt")


def is_makefile_path(path: str) -> bool:
    name = path.rpartition("/")[2].casefold()
    return (
        name in {"makefile", "gnumakefile", "makecall"}
        or name.endswith(".mk")
        or (
            name.startswith(("makefile.", "gnumakefile.")) and not name.endswith(_DOCUMENT_SUFFIXES)
        )
    )


def physical_lines(content: bytes) -> int:
    return content.count(b"\n") + int(bool(content) and not content.endswith(b"\n"))


def makefile_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.makefile_comparison
    if comparison is None:
        return ()
    base = {item.path: item.lines for item in comparison.base_files}
    exceptions = {item.path: item for item in snapshot.manifest.makefile_exceptions}
    diagnostics: list[Diagnostic] = []
    for item in comparison.head_files:
        if not is_makefile_path(item.path):
            continue
        previous = base.get(item.path)
        if previous is not None and item.lines <= previous:
            continue
        diagnostic = _growth_diagnostic(item, previous, snapshot=snapshot, rule=rule)
        allowance = exceptions.get(item.path)
        if allowance is not None:
            diagnostic = _apply_allowance(diagnostic, allowance, item.lines, comparison.as_of)
        diagnostics.append(diagnostic)
    return tuple(diagnostics)


def _growth_diagnostic(
    item: MakefileMetric,
    previous: int | None,
    *,
    snapshot: RepositorySnapshot,
    rule: RuleDefinition,
) -> Diagnostic:
    component = max(
        (
            component
            for component in snapshot.manifest.components
            if item.path == component.path or item.path.startswith(f"{component.path}/")
        ),
        key=lambda component: len(component.path),
        default=None,
    )
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=component.component_id if component else ComponentId("repository"),
        subject_kind="makefile",
        observed=str(item.lines),
        expected=str(previous) if previous is not None else "no new Makefile path",
        observed_value=item.lines,
        expected_value=previous,
        message=(
            f"New Makefile path has {item.lines} physical lines; prefer native commands."
            if previous is None
            else f"Makefile grew from {previous} to {item.lines} physical lines."
        ),
        path=item.path,
        manifest_anchor=f"tracked_files.{item.path}",
        location=SourceLocation(item.path, line=1),
        remediation=Remediation(
            summary="Remove new Makefile wrappers or reduce growth to the comparison size.",
            steps=(
                "Use existing native commands and update callers before removing wrappers.",
                "Do not transfer the same aliases into replacement scripts or task files.",
                "If required, add a scoped makefiles.exceptions record with a line cap.",
            ),
            validation=("Rerun the same Git comparison and require no active findings.",),
        ),
        baselineable=False,
    )


def _apply_allowance(
    diagnostic: Diagnostic, allowance: MakefileException, lines: int, as_of: date | None
) -> Diagnostic:
    if lines > allowance.max_lines:
        return replace(
            diagnostic,
            message=f"{diagnostic.message} Exception cap of {allowance.max_lines} lines exceeded.",
        )
    if as_of is None:
        ConfigurationError.fail("using a Makefile exception requires --as-of YYYY-MM-DD")
    if (
        not date.fromisoformat(allowance.created_on)
        <= as_of
        <= date.fromisoformat(allowance.expires_on)
    ):
        return replace(
            diagnostic, message=f"{diagnostic.message} Exception is not valid as of {as_of}."
        )
    return replace(
        diagnostic,
        disposition="excepted",
        exception=ExceptionUse(
            owner=allowance.owner,
            issue=allowance.issue,
            reason=allowance.reason,
            created_on=allowance.created_on,
            expires_on=allowance.expires_on,
        ),
    )
