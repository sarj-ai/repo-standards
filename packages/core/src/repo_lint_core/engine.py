"""Deterministic repository analysis and ratchet semantics."""

from __future__ import annotations

from dataclasses import replace
from datetime import date

from .canonical import scope_digest, with_fingerprint
from .errors import ConfigurationError
from .models import (
    AnalysisReport,
    Baseline,
    Component,
    ComponentId,
    Diagnostic,
    ExceptionUse,
    Manifest,
    Mode,
    Policy,
    RatchetClassification,
    RatchetComparison,
    RatchetEntry,
    Remediation,
    RuleId,
)


def core_diagnostics(manifest: Manifest) -> tuple[Diagnostic, ...]:
    by_id = {item.component_id: item for item in manifest.components}
    diagnostics = list(_overlap_diagnostics(manifest))
    _validate_dependencies(manifest, by_id)
    _validate_migrations(manifest, by_id)
    return tuple(diagnostics)


def _overlap_diagnostics(manifest: Manifest) -> tuple[Diagnostic, ...]:
    diagnostics: list[Diagnostic] = []
    ordered = sorted(
        manifest.components, key=lambda item: (item.path.casefold(), item.path, item.component_id)
    )
    ownership_stack: list[Component] = []
    for component in ordered:
        while ownership_stack and not (
            component.path.casefold() == ownership_stack[-1].path.casefold()
            or component.path.casefold().startswith(f"{ownership_stack[-1].path.casefold()}/")
        ):
            ownership_stack.pop()
        if ownership_stack:
            owner = ownership_stack[-1]
            diagnostics.append(
                Diagnostic(
                    rule_id=RuleId("core/layout/non-overlapping-root"),
                    rule_version=1,
                    severity="error",
                    evidence_level="verified",
                    component_id=component.component_id,
                    subject_kind="component-root",
                    observed=f"{owner.path} contains {component.path}",
                    expected="component roots must be disjoint",
                    message=f"component root overlaps {owner.component_id}",
                    path=component.path,
                    manifest_anchor=f"components.{component.component_id}.path",
                    remediation=Remediation(
                        summary="Give each component one disjoint ownership root.",
                        steps=(
                            "Choose which component owns the overlapping files.",
                            (
                                "Move the other component to a disjoint root or merge "
                                "the declarations."
                            ),
                        ),
                        validation=("Run repo-lint check again.",),
                    ),
                )
            )
        ownership_stack.append(component)
    return tuple(diagnostics)


def _validate_dependencies(manifest: Manifest, by_id: dict[ComponentId, Component]) -> None:
    for component in manifest.components:
        for dependency in component.dependencies:
            if dependency.target not in by_id:
                ConfigurationError.fail(
                    f"component {component.component_id} references unknown target "
                    f"{dependency.target}"
                )


def _validate_migrations(manifest: Manifest, by_id: dict[ComponentId, Component]) -> None:
    migration_components: set[ComponentId] = set()
    migration_sources: set[str] = set()
    migration_targets: dict[str, ComponentId] = {}
    for migration in manifest.migration_paths:
        if migration.component_id not in by_id:
            ConfigurationError.fail(
                f"migration path references unknown component {migration.component_id}"
            )
        if migration.component_id in migration_components:
            ConfigurationError.fail(
                f"component {migration.component_id} has multiple migration path declarations"
            )
        migration_components.add(migration.component_id)
        if migration.old_path == migration.new_path:
            ConfigurationError.fail(
                f"migration path for {migration.component_id} must change the component path"
            )
        if migration.old_path in migration_sources:
            ConfigurationError.fail(
                f"migration source path is declared more than once: {migration.old_path}"
            )
        migration_sources.add(migration.old_path)
        if migration.new_path != by_id[migration.component_id].path:
            ConfigurationError.fail(
                f"migration target for {migration.component_id} must equal its declared "
                "component path"
            )
        migration_targets[migration.new_path] = migration.component_id
    for migration in manifest.migration_paths:
        occupying_component = migration_targets.get(migration.old_path)
        if occupying_component is not None and occupying_component != migration.component_id:
            ConfigurationError.fail(
                f"migration paths form a swap or cycle at {migration.old_path}; "
                "use a disjoint staging path and explicit sequencing"
            )


def apply_exceptions(
    diagnostics: tuple[Diagnostic, ...], manifest: Manifest, as_of: date | None
) -> tuple[Diagnostic, ...]:
    if manifest.exceptions and as_of is None:
        ConfigurationError.fail("--as-of YYYY-MM-DD is required when exceptions are declared")
    exceptions = {
        (item.rule_id, item.component_id, item.manifest_anchor, item.fingerprint): item
        for item in manifest.exceptions
    }
    if len(exceptions) != len(manifest.exceptions):
        ConfigurationError.fail("duplicate exception scope")
    result: list[Diagnostic] = []
    matched: set[tuple[str, str, str, str]] = set()
    for diagnostic in diagnostics:
        key = (
            diagnostic.rule_id,
            diagnostic.component_id,
            diagnostic.manifest_anchor,
            diagnostic.fingerprint,
        )
        exception = exceptions.get(key)
        if exception is None:
            result.append(diagnostic)
            continue
        matched.add(key)
        if as_of is None:
            ConfigurationError.fail("exception analysis date is missing")
        if date.fromisoformat(exception.created_on) > as_of:
            ConfigurationError.fail(
                f"exception for {diagnostic.rule_id}:{diagnostic.component_id} is future-dated"
            )
        if date.fromisoformat(exception.expires_on) < as_of:
            result.extend(
                (
                    diagnostic,
                    Diagnostic(
                        rule_id=RuleId("core/exception/expired"),
                        rule_version=1,
                        severity="error",
                        evidence_level="declared",
                        component_id=diagnostic.component_id,
                        subject_kind="exception",
                        observed=exception.expires_on,
                        expected=f"expiry on or after {as_of.isoformat()}",
                        message=f"exception for {diagnostic.rule_id} has expired",
                        path=diagnostic.path,
                        manifest_anchor=f"exceptions.{diagnostic.rule_id}.{diagnostic.component_id}",
                        remediation=Remediation(
                            summary=(
                                "Resolve the finding or renew the narrow exception through review."
                            ),
                            steps=("Fix the underlying finding or update its reviewed exception.",),
                            validation=("Run repo-lint check with the same --as-of date.",),
                        ),
                        prerequisites=(diagnostic.rule_id,),
                    ),
                )
            )
        else:
            result.append(
                replace(
                    diagnostic,
                    disposition="excepted",
                    exception=ExceptionUse(
                        owner=exception.owner,
                        issue=exception.issue,
                        reason=exception.reason,
                        created_on=exception.created_on,
                        expires_on=exception.expires_on,
                    ),
                )
            )
    unused = sorted(set(exceptions) - matched)
    if unused:
        scopes = ", ".join(
            f"{rule}:{component}:{anchor}:{fingerprint}"
            for rule, component, anchor, fingerprint in unused
        )
        ConfigurationError.fail(f"exceptions do not match current findings: {scopes}")
    return tuple(result)


def analyze(
    manifest: Manifest,
    policy: Policy,
    *,
    mode: Mode,
    as_of: date | None = None,
    additional_diagnostics: tuple[Diagnostic, ...] = (),
) -> AnalysisReport:
    """Evaluate a parsed manifest without repository-code execution."""
    if manifest.policy_id != policy.policy_id or manifest.policy_version != policy.policy_version:
        ConfigurationError.fail(
            f"manifest selects {manifest.policy_id}@{manifest.policy_version}; "
            f"installed policy is {policy.policy_id}@{policy.policy_version}"
        )
    findings = tuple(
        with_fingerprint(item)
        for item in core_diagnostics(manifest) + policy.evaluate(manifest) + additional_diagnostics
    )
    fingerprints = [item.fingerprint for item in findings]
    if len(fingerprints) != len(set(fingerprints)):
        ConfigurationError.fail(
            "analysis emitted duplicate semantic fingerprints; diagnostics must identify "
            "distinct occurrences"
        )
    findings = apply_exceptions(findings, manifest, as_of)
    diagnostics = tuple(
        with_fingerprint(item)
        for item in sorted(
            findings,
            key=lambda item: (item.path, item.rule_id, item.component_id, item.manifest_anchor),
        )
    )
    error_count = sum(
        item.severity == "error" and item.disposition == "active" for item in diagnostics
    )
    warning_count = sum(item.severity == "warning" for item in diagnostics)
    excepted_count = sum(item.disposition == "excepted" for item in diagnostics)
    return AnalysisReport(
        mode=mode,
        repository_id=manifest.repository_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        scope_digest=scope_digest(manifest),
        completion="complete",
        conclusion="findings" if diagnostics else "passed",
        diagnostics=diagnostics,
        summary={
            "diagnostics": len(diagnostics),
            "errors": error_count,
            "warnings": warning_count,
            "excepted": excepted_count,
        },
    )


def check_baseline(report: AnalysisReport, baseline: Baseline) -> tuple[Diagnostic, ...]:
    """Return exact new/stale debt diagnostics for ratchet mode."""
    comparison = classify_baseline(report, baseline)
    new = tuple(
        item.diagnostic
        for item in comparison.entries
        if item.classification is RatchetClassification.NEW and item.diagnostic is not None
    )
    stale = comparison.fingerprints(RatchetClassification.RESOLVED)
    stale_diagnostics = tuple(_stale_baseline_diagnostic(fingerprint) for fingerprint in stale)
    return tuple(sorted(new + stale_diagnostics, key=lambda item: (item.rule_id, item.fingerprint)))


def classify_baseline(report: AnalysisReport, baseline: Baseline) -> RatchetComparison:
    """Classify every active error and baseline entry without losing known debt."""
    if baseline.repository_id != report.repository_id:
        ConfigurationError.fail("baseline repository_id does not match the manifest")
    if baseline.policy_id != report.policy_id or baseline.policy_version != report.policy_version:
        ConfigurationError.fail("baseline policy does not match the selected policy")
    if baseline.scope_digest != report.scope_digest:
        ConfigurationError.fail("baseline scope does not match the current manifest")
    current = {
        item.fingerprint: item
        for item in report.diagnostics
        if item.severity == "error" and item.disposition == "active"
    }
    known = set(baseline.fingerprints)
    entries = [
        RatchetEntry(
            fingerprint=fingerprint,
            classification=(
                RatchetClassification.KNOWN if fingerprint in known else RatchetClassification.NEW
            ),
            diagnostic=current[fingerprint],
        )
        for fingerprint in sorted(current)
    ]
    entries.extend(
        RatchetEntry(
            fingerprint=fingerprint,
            classification=RatchetClassification.RESOLVED,
        )
        for fingerprint in sorted(known - set(current))
    )
    return RatchetComparison(entries=tuple(entries))


def _stale_baseline_diagnostic(fingerprint: str) -> Diagnostic:
    return with_fingerprint(
        Diagnostic(
            rule_id=RuleId("core/baseline/stale-entry"),
            rule_version=1,
            severity="error",
            evidence_level="declared",
            component_id=ComponentId("repository"),
            subject_kind="baseline-entry",
            observed=fingerprint,
            expected="remove resolved debt from the baseline",
            message="baseline retains a finding that no longer exists",
            path=".repo-lint/baseline.json",
            manifest_anchor=f"fingerprints.{fingerprint}",
            remediation=Remediation(
                summary="Delete the resolved fingerprint in the same change.",
                steps=("Remove this exact fingerprint from the reviewed baseline.",),
                validation=("Run repo-lint check --mode ratchet again.",),
            ),
        )
    )


def with_ratchet_diagnostics(
    report: AnalysisReport, baseline_diagnostics: tuple[Diagnostic, ...]
) -> AnalysisReport:
    """Attach ratchet regressions without mutating the original report."""
    if not baseline_diagnostics:
        return report
    return replace(
        report,
        conclusion="findings",
        diagnostics=tuple(
            sorted(report.diagnostics + baseline_diagnostics, key=lambda item: item.fingerprint)
        ),
        summary={
            **report.summary,
            "ratchet_regressions": len(baseline_diagnostics),
        },
    )
