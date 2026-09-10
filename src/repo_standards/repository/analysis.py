from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

from repo_standards.core.catalog import core_rules
from repo_standards.core.engine import analyze
from repo_standards.core.errors import ConfigurationError, ManifestAbsentError
from repo_standards.core.inspection import git_index_identity, load_repository_snapshot
from repo_standards.core.migration import migration_diagnostics
from repo_standards.core.models import (
    AnalysisReport,
    ExecutionIssue,
    IncompleteReport,
    Mode,
    PolicyId,
    RepositoryId,
)
from repo_standards.core.rule_reviews import (
    RuleVersion,
    activated_rule_ids,
    activated_rule_versions,
)
from repo_standards.policy_sarj import SarjPolicy


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryAnalysisRequest:
    root: Path
    manifest_path: str = ".repo-standards/repository.toml"
    mode: Mode = Mode.STRICT
    as_of: date | None = None
    staged: bool = False
    enabled_rule_ids: tuple[str, ...] = ()


def analyze_repository(request: RepositoryAnalysisRequest) -> AnalysisReport:
    policy = SarjPolicy()
    try:
        return _analyze(request, policy)
    except ManifestAbsentError as error:
        return _incomplete(
            policy.policy_id,
            request.mode,
            str(error),
            code="analysis.manifest-absent",
        )
    except (ConfigurationError, OSError) as error:
        return _incomplete(policy.policy_id, request.mode, str(error))


def _analyze(request: RepositoryAnalysisRequest, policy: SarjPolicy) -> AnalysisReport:
    root = request.root.resolve(strict=True)
    snapshot = load_repository_snapshot(
        root,
        manifest_path=request.manifest_path,
        identity=git_index_identity(root) if request.staged else None,
    )
    repository_diagnostics = policy.evaluate_repository(snapshot)
    if snapshot.manifest.enabled_rules and request.enabled_rule_ids:
        ConfigurationError.fail("manifest enabled_rules cannot be combined with enabled_rule_ids")
    report = analyze(
        snapshot.manifest,
        policy,
        mode=request.mode,
        as_of=request.as_of,
        additional_diagnostics=migration_diagnostics(snapshot) + repository_diagnostics,
        enabled_rules=(
            activated_rule_ids if snapshot.manifest.enabled_rules else activated_rule_versions
        )(
            snapshot.manifest.enabled_rules or request.enabled_rule_ids,
            current_rules=frozenset(
                RuleVersion(rule.rule_id, rule.version)
                for rule in core_rules() + policy.rules()
            ),
        ),
    )
    return replace(report, input_provenance=snapshot.provenance)


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
