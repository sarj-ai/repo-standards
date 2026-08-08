"""Deterministic repository analysis and ratchet semantics."""

from __future__ import annotations

from dataclasses import replace
from datetime import date

from .canonical import scope_digest, with_fingerprint
from .errors import ConfigurationError
from .models import (
    AnalysisReport,
    Baseline,
    Diagnostic,
    ExceptionUse,
    Manifest,
    Mode,
    Policy,
    Remediation,
)


def _core_diagnostics(manifest: Manifest) -> tuple[Diagnostic, ...]:
    diagnostics: list[Diagnostic] = []
    by_id = {item.component_id: item for item in manifest.components}
    ordered = sorted(manifest.components, key=lambda item: (item.path, item.component_id))
    for index, component in enumerate(ordered):
        for other in ordered[index + 1 :]:
            if other.path.startswith(f"{component.path}/"):
                diagnostics.append(  # noqa: PERF401 - nested pairwise overlap check
                    Diagnostic(
                        rule_id="core/layout/non-overlapping-root",
                        rule_version=1,
                        severity="error",
                        evidence_level="verified",
                        component_id=other.component_id,
                        subject_kind="component-root",
                        observed=f"{component.path} contains {other.path}",
                        expected="component roots must be disjoint",
                        message=f"component root overlaps {component.component_id}",
                        path=other.path,
                        manifest_anchor=f"components.{other.component_id}.path",
                        remediation=Remediation(
                            summary="Give each component one disjoint ownership root.",
                            steps=(
                                "Choose which component owns the overlapping files.",
                                "Move the other component to a disjoint root or merge "
                                "the declarations.",
                            ),
                            validation=("Run repo-lint check again.",),
                        ),
                    )
                )
        for dependency in component.dependencies:
            if dependency.target not in by_id:
                raise ConfigurationError(
                    f"component {component.component_id} references unknown target "
                    f"{dependency.target}"
                )
    migration_components: set[str] = set()
    for migration in manifest.migration_paths:
        if migration.component_id not in by_id:
            raise ConfigurationError(
                f"migration path references unknown component {migration.component_id}"
            )
        if migration.component_id in migration_components:
            raise ConfigurationError(
                f"component {migration.component_id} has multiple migration path declarations"
            )
        migration_components.add(migration.component_id)
        if migration.new_path != by_id[migration.component_id].path:
            raise ConfigurationError(
                f"migration target for {migration.component_id} must equal its declared "
                "component path"
            )
    return tuple(diagnostics)


def _apply_exceptions(
    diagnostics: tuple[Diagnostic, ...], manifest: Manifest, as_of: date | None
) -> tuple[Diagnostic, ...]:
    if manifest.exceptions and as_of is None:
        raise ConfigurationError("--as-of YYYY-MM-DD is required when exceptions are declared")
    exceptions = {(item.rule_id, item.component_id): item for item in manifest.exceptions}
    if len(exceptions) != len(manifest.exceptions):
        raise ConfigurationError("duplicate exception scope")
    result: list[Diagnostic] = []
    matched: set[tuple[str, str]] = set()
    for diagnostic in diagnostics:
        key = (diagnostic.rule_id, diagnostic.component_id)
        exception = exceptions.get(key)
        if exception is None:
            result.append(diagnostic)
            continue
        matched.add(key)
        if as_of is None:
            raise ConfigurationError("exception analysis date is missing")
        if date.fromisoformat(exception.created_on) > as_of:
            raise ConfigurationError(
                f"exception for {diagnostic.rule_id}:{diagnostic.component_id} is future-dated"
            )
        if date.fromisoformat(exception.expires_on) < as_of:
            result.append(diagnostic)
            result.append(
                Diagnostic(
                    rule_id="core/exception/expired",
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
                        summary="Resolve the finding or renew the narrow exception through review.",
                        steps=("Fix the underlying finding or update its reviewed exception.",),
                        validation=("Run repo-lint check with the same --as-of date.",),
                    ),
                    prerequisites=(diagnostic.rule_id,),
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
        scopes = ", ".join(f"{rule}:{component}" for rule, component in unused)
        raise ConfigurationError(f"exceptions do not match current findings: {scopes}")
    return tuple(result)


def analyze(
    manifest: Manifest,
    policy: Policy,
    *,
    mode: Mode,
    as_of: date | None = None,
) -> AnalysisReport:
    """Evaluate a parsed manifest without repository-code execution."""
    if manifest.policy_id != policy.policy_id or manifest.policy_version != policy.policy_version:
        raise ConfigurationError(
            f"manifest selects {manifest.policy_id}@{manifest.policy_version}; "
            f"installed policy is {policy.policy_id}@{policy.policy_version}"
        )
    findings = _core_diagnostics(manifest) + policy.evaluate(manifest)
    findings = _apply_exceptions(findings, manifest, as_of)
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
    if baseline.repository_id != report.repository_id:
        raise ConfigurationError("baseline repository_id does not match the manifest")
    if baseline.policy_id != report.policy_id or baseline.policy_version != report.policy_version:
        raise ConfigurationError("baseline policy does not match the selected policy")
    if baseline.scope_digest != report.scope_digest:
        raise ConfigurationError("baseline scope does not match the current manifest")
    current = {
        item.fingerprint: item
        for item in report.diagnostics
        if item.severity == "error" and item.disposition == "active"
    }
    known = set(baseline.fingerprints)
    new = tuple(current[item] for item in sorted(set(current) - known))
    stale = sorted(known - set(current))
    stale_diagnostics = tuple(
        with_fingerprint(
            Diagnostic(
                rule_id="core/baseline/stale-entry",
                rule_version=1,
                severity="error",
                evidence_level="declared",
                component_id="repository",
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
        for fingerprint in stale
    )
    return tuple(sorted(new + stale_diagnostics, key=lambda item: (item.rule_id, item.fingerprint)))


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
