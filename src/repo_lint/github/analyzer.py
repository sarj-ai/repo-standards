from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple

from repo_lint.core import DeliveryConfig
from repo_lint.core.canonical import with_fingerprint
from repo_lint.core.models import (
    ComponentId,
    Diagnostic,
    ExecutionIssue,
    RelatedLocation,
    Remediation,
    RuleId,
    SourceLocation,
)

from .models import (
    GitHubAnalysisReport,
    RepositoryEvidence,
    WorkflowDocument,
    WorkflowInspection,
    WorkflowJobInspection,
)


if TYPE_CHECKING:
    from collections.abc import Sequence


DeliveryConfiguration = DeliveryConfig


_COMPONENT = ComponentId("repository")
_CRITICAL = "delivery/branches/hotfix-back-sync"


class BranchNames(NamedTuple):
    production: str
    preview: str
    development: str


def analyze(
    config: DeliveryConfig | None,
    evidence: RepositoryEvidence | None,
    workflows: tuple[WorkflowDocument, ...],
    *,
    repository_files: Sequence[str] = (),
    selected_revision: str | None = None,
) -> GitHubAnalysisReport:
    del config, evidence, workflows, repository_files, selected_revision
    return _report([], [], ())


def _branch_names(config: DeliveryConfig | None) -> BranchNames:
    if config is None:
        return BranchNames("main", "preview", "dev")
    return BranchNames(
        config.production_branch,
        config.preview_branch,
        config.development_branch,
    )


def _delivery_evidence_complete(
    config: DeliveryConfig | None,
    evidence: RepositoryEvidence,
    branches: BranchNames,
    issues: list[ExecutionIssue],
    *,
    selected_revision: str | None,
) -> bool:
    missing: list[str] = []
    if config is not None and config.repository:
        accepted_repositories = {
            value.casefold()
            for value in (evidence.repository, evidence.requested_repository)
            if value is not None
        }
        if config.repository.casefold() not in accepted_repositories:
            missing.append("declared and collected repository identities differ")
    if not evidence.repository_metadata_available or evidence.default_branch is None:
        missing.append("repository metadata")
    if not evidence.branches_complete:
        missing.append("complete branch enumeration")
    if evidence.allow_auto_merge is None:
        missing.append("auto-merge setting")
    by_name = {branch.name: branch for branch in evidence.branches}
    default = by_name.get(evidence.default_branch or "")
    if selected_revision is None:
        missing.append("selected Git revision")
    elif default is None or default.head_sha is None:
        missing.append("default-branch head revision")
    elif selected_revision != default.head_sha:
        remediation = f"Fetch and audit the live {evidence.default_branch} branch head."
        issues.append(
            ExecutionIssue(
                code="github.default-branch-revision-mismatch",
                phase="delivery",
                message=(
                    f"selected revision is not the live {evidence.default_branch} branch head"
                ),
                retryable=True,
                remediation=(remediation,),
            )
        )
        return False
    for name in branches:
        branch = by_name.get(name)
        if branch is not None and (
            branch.protected is None or branch.required_status_checks is None
        ):
            missing.append(f"protection details for {name}")
    if not missing:
        return True
    issues.append(
        ExecutionIssue(
            code="github.required-evidence-incomplete",
            phase="delivery",
            message=f"required GitHub delivery evidence is incomplete: {', '.join(missing)}",
            retryable=True,
            remediation=("Collect GitHub evidence with permission to read repository rules.",),
        )
    )
    return False


def _evaluate_backsync(
    config: DeliveryConfig | None,
    evidence: RepositoryEvidence,
    inspections: tuple[WorkflowInspection, ...],
    branches: BranchNames,
    diagnostics: list[Diagnostic],
) -> None:
    production, preview, development = branches
    selected = inspections
    if config is not None and config.sync_workflows:
        wanted = set(config.sync_workflows)
        selected = tuple(item for item in inspections if item.path in wanted)
    observed_branches = {branch.name for branch in evidence.branches}
    missing = [
        f"branch {name!r} is unavailable" for name in branches if name not in observed_branches
    ]
    for source, target in ((production, preview), (preview, development)):
        candidates = tuple(
            (item, job)
            for item in selected
            for job in item.jobs
            if _supports_edge(job, source=source, target=target)
        )
        if not candidates:
            missing.append(f"automatic PR edge {source}->{target}")
            continue
        if not any(
            _safe_backsync(
                item,
                job,
                source=source,
                target=target,
                content_equivalence=source == production,
            )
            for item, job in candidates
        ):
            missing.append(f"safety controls for {source}->{target}")
    protected = {branch.name: branch for branch in evidence.branches}
    for name in branches:
        branch = protected.get(name)
        if branch is not None and (
            branch.protected is not True or not branch.required_status_checks
        ):
            missing.append(f"required protected CI on {name}")
    if evidence.allow_auto_merge is not True:
        missing.append("repository auto-merge")
    if missing:
        diagnostics.append(
            _diagnostic(
                rule=_CRITICAL,
                severity="error",
                message="Hotfix propagation is not proven safe and automatic.",
                observed=", ".join(missing),
                expected=(
                    f"automatic protected PR propagation {production}->{preview}->{development}"
                ),
                path=".repo-lint/repository.toml",
                anchor="delivery",
                summary=(
                    "Add idempotent PR-based backsync workflows and protect every long-lived "
                    "branch."
                ),
            )
        )


def _supports_edge(job: WorkflowJobInspection, *, source: str, target: str) -> bool:
    script = _job_script(job)
    base = re.search(rf"--base(?:=|\s+)[\"']?{re.escape(target)}(?:[\"'\s\\]|$)", script)
    creates = re.search(r"\bgh\s+pr\s+create\b", script) is not None
    reads_source = _branch_reference(script, source)
    return base is not None and creates and reads_source


def _safe_backsync(
    item: WorkflowInspection,
    job: WorkflowJobInspection,
    *,
    source: str,
    target: str,
    content_equivalence: bool,
) -> bool:
    script = _job_script(job).lower()
    trigger_matches = not item.push_uses_branches_ignore and (
        not item.push_branches or source in item.push_branches
    )
    condition_matches = _condition_allows_source(job.condition, source)
    strategy_safe = (
        "merge-tree" in script and "^{tree}" in script
        if content_equivalence
        else "--merge" in script and "/compare/" in script
    )
    return all(
        (
            item.has_push_trigger,
            trigger_matches,
            item.has_schedule_trigger,
            item.has_workflow_dispatch_trigger,
            item.has_concurrency,
            item.cancels_in_progress is False,
            condition_matches,
            _job_uses_non_default_token(job),
            _has_idempotent_pr(job, target),
            "--auto" in script,
            "--match-head-commit" in script,
            "headrefoid" in script,
            re.search(r"\bhead[_-]?oid\b[^\n]*!=", script) is not None,
            "conflicting" in script,
            "exit 1" in script or "exit 2" in script,
            strategy_safe,
        )
    )


def _job_script(job: WorkflowJobInspection) -> str:
    return "\n".join(step.run or "" for step in job.steps)


def _branch_reference(script: str, branch: str) -> bool:
    return (
        re.search(
            rf"(?:refs?/heads/|git/ref/heads/|origin/){re.escape(branch)}(?:[^\w/-]|$)", script
        )
        is not None
    )


def _condition_allows_source(condition: str | None, source: str) -> bool:
    if condition is None:
        return True
    lowered = condition.strip().lower()
    if lowered in {"false", "${{ false }}"}:
        return False
    if "github.ref" not in lowered:
        return True
    return (
        re.search(
            rf"github\.ref\s*==\s*['\"]refs/heads/{re.escape(source)}['\"]",
            lowered,
        )
        is not None
    )


def _job_uses_non_default_token(job: WorkflowJobInspection) -> bool:
    environment = dict(job.environment)
    for step in job.steps:
        environment.update(step.environment)
    direct = environment.get("GH_TOKEN", "")
    if "secrets." in direct and "SECRETS.GITHUB_TOKEN" not in direct.upper():
        return True
    script = _job_script(job)
    for name, value in environment.items():
        if name == "GITHUB_TOKEN" or "secrets." not in value:
            continue
        if re.search(rf"GH_TOKEN\s*=\s*[\"']?\${re.escape(name)}\b", script):
            return True
    return False


def _has_idempotent_pr(job: WorkflowJobInspection, target: str) -> bool:
    script = _job_script(job).lower()
    lists_existing = "gh pr list" in script and re.search(
        rf"--base(?:=|\s+)[\"']?{re.escape(target)}\b", script
    )
    deterministic_branch = "sync_branch=" in script and "refs/heads/$sync_branch" in script
    conditional_create = "if [ -z" in script and "gh pr create" in script
    return lists_existing is not None and deterministic_branch and conditional_create


def _diagnostic(  # ruff: ignore[too-many-arguments]
    *,
    rule: str,
    severity: str,
    message: str,
    observed: str,
    expected: str,
    path: str,
    anchor: str,
    summary: str,
    line: int | None = None,
    related_locations: tuple[RelatedLocation, ...] = (),
) -> Diagnostic:
    return Diagnostic(
        rule_id=RuleId(rule),
        rule_version=1,
        severity="error" if severity == "error" else "warning",
        evidence_level=(
            "external"
            if anchor in {"delivery", "merge-queue", "repository-settings"}
            else "verified"
        ),
        component_id=_COMPONENT,
        subject_kind="github-repository",
        observed=observed,
        expected=expected,
        message=message,
        path=path,
        manifest_anchor=anchor,
        remediation=Remediation(
            summary=summary,
            steps=(summary,),
            validation=(
                "Run repository lint against the same Git tree and refreshed GitHub evidence.",
            ),
        ),
        prerequisites=("github-read-evidence",),
        location=SourceLocation(path=path, line=line),
        related_locations=related_locations,
        observed_value=observed,
        expected_value=expected,
    )


def _report(
    diagnostics: list[Diagnostic],
    issues: list[ExecutionIssue],
    inspections: tuple[WorkflowInspection, ...],
) -> GitHubAnalysisReport:
    ordered_diagnostics = tuple(
        with_fingerprint(item)
        for item in sorted(
            diagnostics,
            key=lambda item: (
                str(item.rule_id),
                item.path,
                item.location.line if item.location and item.location.line is not None else 0,
            ),
        )
    )
    ordered_issues = tuple(sorted(issues, key=lambda item: (item.phase, item.code, item.message)))
    if ordered_issues:
        conclusion = "inconclusive"
        completion = "incomplete"
    elif ordered_diagnostics:
        conclusion = "findings"
        completion = "complete"
    else:
        conclusion = "passed"
        completion = "complete"
    return GitHubAnalysisReport(
        completion=completion,
        conclusion=conclusion,
        diagnostics=ordered_diagnostics,
        execution_issues=ordered_issues,
        workflow_inspections=inspections,
    )
