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
    FindingsReport,
    Manifest,
    Mode,
    PassedReport,
    Policy,
    RatchetClassification,
    RatchetComparison,
    RatchetEntry,
)
from .rule_reviews import RuleVersion


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
            ConfigurationError.fail(
                f"exception for {diagnostic.rule_id}:{diagnostic.component_id} expired on "
                f"{exception.expires_on}"
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


def analyze(  # ruff: ignore[too-many-arguments] - explicit rule activation is a safety boundary
    manifest: Manifest,
    policy: Policy,
    *,
    mode: Mode,
    as_of: date | None = None,
    additional_diagnostics: tuple[Diagnostic, ...] = (),
    enabled_rules: frozenset[RuleVersion] | None = None,
) -> AnalysisReport:
    emitted = _selected_diagnostics(policy, additional_diagnostics, enabled_rules)
    findings = tuple(with_fingerprint(item) for item in emitted)
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
    summary = {
        "diagnostics": len(diagnostics),
        "errors": error_count,
        "warnings": warning_count,
        "excepted": excepted_count,
    }
    if diagnostics:
        return FindingsReport(
            mode=mode,
            repository_id=manifest.repository_id,
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            scope_digest=scope_digest(manifest),
            diagnostics=diagnostics,
            summary=summary,
        )
    return PassedReport(
        mode=mode,
        repository_id=manifest.repository_id,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        scope_digest=scope_digest(manifest),
        summary=summary,
    )


def _selected_diagnostics(
    policy: Policy,
    diagnostics: tuple[Diagnostic, ...],
    enabled_rules: frozenset[RuleVersion] | None,
) -> tuple[Diagnostic, ...]:
    if enabled_rules is not None:
        current_rules = frozenset(
            RuleVersion(rule.rule_id, rule.version) for rule in policy.rules()
        )
        obsolete = sorted(
            f"{item.rule_id}@{item.version}" for item in enabled_rules - current_rules
        )
        if obsolete:
            ConfigurationError.fail(
                "enabled rule selectors are not current for this policy: " + ", ".join(obsolete)
            )
        return tuple(
            item
            for item in diagnostics
            if RuleVersion(item.rule_id, item.rule_version) in enabled_rules
        )
    return diagnostics


def check_baseline(report: AnalysisReport, baseline: Baseline) -> tuple[Diagnostic, ...]:
    comparison = classify_baseline(report, baseline)
    new = tuple(
        item.diagnostic
        for item in comparison.entries
        if item.classification is RatchetClassification.NEW and item.diagnostic is not None
    )
    stale = comparison.fingerprints(RatchetClassification.RESOLVED)
    if stale:
        ConfigurationError.fail("baseline contains resolved fingerprints: " + ", ".join(stale))
    return tuple(sorted(new, key=lambda item: (item.rule_id, item.fingerprint)))


def classify_baseline(report: AnalysisReport, baseline: Baseline) -> RatchetComparison:
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
