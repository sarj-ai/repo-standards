from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

from repo_standards.core.engine import analyze, check_baseline, classify_baseline
from repo_standards.core.errors import BaselineError, ConfigurationError, ManifestAbsentError
from repo_standards.core.inspection import git_index_identity, load_repository_snapshot
from repo_standards.core.models import (
    AnalysisReport,
    Baseline,
    Diagnostic,
    ExecutionIssue,
    IncompleteReport,
    Mode,
    PolicyId,
    RepositoryId,
)
from repo_standards.core.rule_reviews import RuleVersion, activated_rule_ids
from repo_standards.policy_sarj import SarjPolicy

from .comparison import with_makefile_comparison, with_migration_comparison


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryAnalysisRequest:
    root: Path
    manifest_path: str = ".repo-standards/repository.toml"
    baseline_path: str | None = None
    mode: Mode = Mode.STRICT
    as_of: date | None = None
    staged: bool = False
    enabled_rule_ids: tuple[str, ...] = ()
    base_revision: str | None = None
    include_warnings: bool = False


@dataclass(frozen=True, slots=True)
class RepositoryAnalysis:
    report: AnalysisReport
    baseline: Baseline | None
    regressions: tuple[Diagnostic, ...] = ()


def analyze_repository(request: RepositoryAnalysisRequest) -> AnalysisReport:
    policy = SarjPolicy()
    try:
        return complete_repository_analysis(request, policy=policy).report
    except ManifestAbsentError as error:
        return _incomplete(
            policy.policy_id,
            request.mode,
            str(error),
            code="analysis.manifest-absent",
        )
    except (ConfigurationError, OSError) as error:
        return _incomplete(policy.policy_id, request.mode, str(error))


def complete_repository_analysis(
    request: RepositoryAnalysisRequest, *, policy: SarjPolicy
) -> RepositoryAnalysis:
    if request.include_warnings and request.mode is not Mode.RATCHET:
        ConfigurationError.fail("include_warnings requires ratchet analysis mode")
    try:
        root = request.root.resolve(strict=True)
    except OSError:
        ConfigurationError.fail(f"repository root is unavailable: {request.root}")
    if request.mode is Mode.RATCHET and request.baseline_path is None:
        BaselineError.fail("ratchet analysis requires a baseline_path")
    snapshot = load_repository_snapshot(
        root,
        manifest_path=request.manifest_path,
        baseline_path=request.baseline_path if request.mode is Mode.RATCHET else None,
        identity=git_index_identity(root) if request.staged else None,
    )
    if snapshot.manifest.enabled_rules and request.enabled_rule_ids:
        ConfigurationError.fail("manifest enabled_rules cannot be combined with enabled_rule_ids")
    enabled_rules = activated_rule_ids(
        snapshot.manifest.enabled_rules or request.enabled_rule_ids,
        current_rules=frozenset(RuleVersion(rule.rule_id, rule.version) for rule in policy.rules()),
    )
    snapshot = with_makefile_comparison(
        root,
        snapshot,
        enabled_rules=enabled_rules,
        base_revision=request.base_revision,
        as_of=request.as_of,
    )
    snapshot = with_migration_comparison(
        root, snapshot, enabled_rules=enabled_rules, base_revision=request.base_revision
    )
    repository_diagnostics = policy.evaluate_repository(
        snapshot, enabled_rule_ids=frozenset(item.rule_id for item in enabled_rules)
    )
    report = analyze(
        snapshot.manifest,
        policy,
        mode=request.mode,
        as_of=request.as_of,
        additional_diagnostics=repository_diagnostics,
        enabled_rules=enabled_rules,
    )
    report = replace(report, input_provenance=snapshot.provenance)
    regressions: tuple[Diagnostic, ...] = ()
    if request.mode is Mode.RATCHET:
        baseline = snapshot.baseline
        if baseline is None:
            BaselineError.fail("selected ratchet baseline was not loaded")
        try:
            regressions = check_baseline(
                report, baseline, include_warnings=request.include_warnings
            )
        except ConfigurationError as error:
            raise BaselineError(str(error)) from error
        report = replace(
            report,
            ratchet=classify_baseline(report, baseline, include_warnings=request.include_warnings),
        )
    return RepositoryAnalysis(report, snapshot.baseline, regressions)


def _incomplete(
    policy_id: PolicyId,
    mode: Mode,
    issue: str,
    *,
    code: str = "analysis.configuration",
) -> AnalysisReport:
    return IncompleteReport(
        mode=mode,
        repository_id=RepositoryId("unknown"),
        policy_id=policy_id,
        policy_version=0,
        scope_digest="0" * 64,
        execution_issues=(
            ExecutionIssue(
                code=code,
                phase="configuration",
                message=issue,
                retryable=False,
                remediation=(
                    "Correct the declared input or repository manifest.",
                    "Run the same analysis again and require completion=complete.",
                ),
            ),
        ),
        summary={"diagnostics": 0, "errors": 0, "warnings": 0},
    )
