from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import ClassVar, Literal, assert_never

from repo_standards.core.engine import analyze, check_baseline_comparison, classify_baseline
from repo_standards.core.errors import BaselineError, ConfigurationError, ManifestAbsentError
from repo_standards.core.inspection import git_index_identity, load_repository_snapshot
from repo_standards.core.models import (
    AnalysisReport,
    Baseline,
    Diagnostic,
    IncompleteReport,
    Mode,
    PolicyId,
    RepositoryId,
)
from repo_standards.core.outcome import ExecutionIssue
from repo_standards.core.rule_reviews import RuleVersion, activated_rule_ids
from repo_standards.policy_sarj import SarjPolicy

from .comparison import with_makefile_comparison, with_migration_comparison


@dataclass(frozen=True, slots=True)
class UnratchetedAnalysis:
    kind: ClassVar[Literal["unratcheted"]] = "unratcheted"
    mode: Literal[Mode.REPORT, Mode.STRICT] = Mode.STRICT
    baseline_path: ClassVar[None] = None
    include_warnings: ClassVar[Literal[False]] = False

    def __post_init__(self) -> None:
        if self.mode not in {Mode.REPORT, Mode.STRICT}:
            ConfigurationError.fail("unratcheted analysis requires report or strict mode")


@dataclass(frozen=True, slots=True)
class RatchetAnalysis:
    kind: ClassVar[Literal["ratchet"]] = "ratchet"
    baseline_path: str
    include_warnings: bool = False
    mode: ClassVar[Literal[Mode.RATCHET]] = Mode.RATCHET

    def __post_init__(self) -> None:
        if not self.baseline_path.strip():
            BaselineError.fail("ratchet analysis requires a baseline_path")


type AnalysisSelection = UnratchetedAnalysis | RatchetAnalysis


def select_analysis(
    mode: Mode, baseline_path: str | None, *, include_warnings: bool = False
) -> AnalysisSelection:
    match mode:
        case Mode.RATCHET:
            if baseline_path is None:
                BaselineError.fail("ratchet analysis requires a baseline_path")
            return RatchetAnalysis(baseline_path, include_warnings)
        case Mode.REPORT | Mode.STRICT:
            if include_warnings:
                ConfigurationError.fail("include_warnings requires ratchet analysis mode")
            return UnratchetedAnalysis(mode)
        case _:
            assert_never(mode)


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryAnalysisRequest:
    root: Path
    selection: AnalysisSelection = UnratchetedAnalysis()
    manifest_path: str = ".repo-standards/repository.toml"
    as_of: date | None = None
    staged: bool = False
    enabled_rule_ids: tuple[str, ...] = ()
    base_revision: str | None = None

    @property
    def mode(self) -> Mode:
        return self.selection.mode

    @property
    def baseline_path(self) -> str | None:
        return self.selection.baseline_path

    @property
    def include_warnings(self) -> bool:
        return self.selection.include_warnings


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
    try:
        root = request.root.resolve(strict=True)
    except OSError:
        ConfigurationError.fail(f"repository root is unavailable: {request.root}")
    snapshot = load_repository_snapshot(
        root,
        manifest_path=request.manifest_path,
        baseline_path=request.baseline_path if request.mode is Mode.RATCHET else None,
        identity=git_index_identity(root) if request.staged else None,
    )
    if snapshot.manifest.enabled_rules and request.enabled_rule_ids:
        ConfigurationError.fail("manifest enabled_rules cannot be combined with enabled_rule_ids")
    enabled_rules = activated_rule_ids(
        snapshot.manifest.enabled_rules or request.enabled_rule_ids or policy.default_rule_ids,
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
            comparison = classify_baseline(
                report, baseline, include_warnings=request.include_warnings
            )
            regressions = check_baseline_comparison(comparison)
        except ConfigurationError as error:
            raise BaselineError(str(error)) from error
        report = replace(report, ratchet=comparison)
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
