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
from .workflows import inspect_workflows


if TYPE_CHECKING:
    from collections.abc import Sequence


DeliveryConfiguration = DeliveryConfig


_COMPONENT = ComponentId("repository")
_CRITICAL = "delivery/branches/hotfix-back-sync"
_SHA_PINS = "delivery/actions/safety"
_EXPLICIT_PERMISSIONS = "delivery/actions/safety"
_JOB_TIMEOUTS = "delivery/actions/safety"
_IMMUTABLE_INSTALLS = "delivery/actions/safety"
_VULNERABILITY_GATE = "delivery/actions/safety"
_MERGE_QUEUE_TRIGGER = "delivery/repository/controls"
_GOVERNANCE = "delivery/repository/controls"


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
    issues: list[ExecutionIssue] = list(evidence.issues if evidence else ())
    try:
        inspections = inspect_workflows(workflows)
    except (UnicodeError, ValueError) as error:
        issues.append(
            ExecutionIssue(
                code="github.workflow-input-invalid",
                phase="workflow-inspection",
                message=str(error),
                retryable=False,
                remediation=("Supply unique, bounded workflow bytes from the selected Git tree.",),
            )
        )
        inspections = ()
    invalid = [inspection.path for inspection in inspections if not inspection.valid_utf8]
    if invalid:
        issues.append(
            ExecutionIssue(
                code="github.workflow-encoding",
                phase="workflow-inspection",
                message=f"workflow is not valid UTF-8: {invalid[0]}",
                retryable=False,
                remediation=("Encode GitHub workflow files as UTF-8.",),
            )
        )

    diagnostics: list[Diagnostic] = []
    branches: set[str] = {branch.name for branch in evidence.branches} if evidence else set()
    branch_names = _branch_names(config)
    delivery_active = config is not None or set(branch_names).issubset(branches)
    if delivery_active:
        if evidence is None:
            issues.append(
                ExecutionIssue(
                    code="github.required-evidence-unavailable",
                    phase="delivery",
                    message="live branch and repository settings evidence is required",
                    retryable=True,
                    remediation=(
                        "Collect GitHub evidence with a token that can read repository settings.",
                    ),
                )
            )
        elif not _delivery_evidence_complete(
            config, evidence, branch_names, issues, selected_revision=selected_revision
        ):
            pass
        else:
            _evaluate_backsync(config, evidence, inspections, branch_names, diagnostics)
    _evaluate_sha_pins(inspections, diagnostics)
    _evaluate_hardening(evidence, inspections, diagnostics)
    _evaluate_supply_chain_workflows(inspections, diagnostics)
    if evidence is not None:
        _evaluate_governance(evidence, branch_names, repository_files, diagnostics, issues)
    return _report(diagnostics, issues, inspections)


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


def _evaluate_sha_pins(
    inspections: tuple[WorkflowInspection, ...], diagnostics: list[Diagnostic]
) -> None:
    grouped: dict[tuple[str, str], list[int]] = {}
    for path, line, value in (
        (inspection.path, reference.line, reference.value)
        for inspection in inspections
        for reference in inspection.action_references
        if not reference.pinned_to_full_sha
    ):
        grouped.setdefault((path, value), []).append(line)
    for (path, value), lines in sorted(grouped.items()):
        ordered_lines = sorted(set(lines))
        dependency = value.rsplit("@", maxsplit=1)[0]
        diagnostics.append(
            _diagnostic(
                rule=_SHA_PINS,
                severity="warning",
                message="A non-local workflow reference is mutable.",
                observed=value,
                expected="a full 40-character action SHA or sha256 container digest",
                path=path,
                anchor=f"workflow:{path}:uses:{dependency}",
                summary="Replace the mutable reference with a reviewed immutable digest.",
                line=ordered_lines[0],
                related_locations=tuple(
                    RelatedLocation(
                        location=SourceLocation(path=path, line=related_line),
                        message="The same mutable reference is used here.",
                    )
                    for related_line in ordered_lines[1:]
                ),
            )
        )


def _evaluate_hardening(
    evidence: RepositoryEvidence | None,
    inspections: tuple[WorkflowInspection, ...],
    diagnostics: list[Diagnostic],
) -> None:
    for item in inspections:
        if item.has_permissions:
            continue
        missing_jobs = [job.job_id for job in item.jobs if not job.has_permissions]
        diagnostics.append(
            _diagnostic(
                rule=_EXPLICIT_PERMISSIONS,
                severity="warning",
                message="GitHub Actions permissions are not explicit for every workflow or job.",
                observed=(
                    "workflow or jobs inherit implicit/broad token permissions: "
                    f"{', '.join(missing_jobs) if missing_jobs else 'workflow scope'}"
                ),
                expected="top-level permissions or explicit permissions on every job",
                path=item.path,
                anchor=f"workflow:{item.path}:permissions",
                summary="Declare explicit bounded permissions at workflow or job scope.",
            )
        )
    for item in inspections:
        missing_jobs = [job.job_id for job in item.jobs if not job.has_timeout]
        if not missing_jobs:
            continue
        diagnostics.append(
            _diagnostic(
                rule=_JOB_TIMEOUTS,
                severity="warning",
                message="Executable GitHub Actions jobs do not all have timeouts.",
                observed=f"jobs omit timeout-minutes: {', '.join(missing_jobs)}",
                expected=("timeout-minutes on every executable job; reusable-call jobs are exempt"),
                path=item.path,
                anchor=f"workflow:{item.path}:timeouts",
                summary="Bound every executable job with timeout-minutes.",
            )
        )
    merge_queue = (
        evidence is not None
        and evidence.rulesets_complete
        and any(
            ruleset.enforcement == "active"
            and ruleset.target == "branch"
            and ruleset.details_complete
            and "merge_queue" in ruleset.rule_types
            for ruleset in evidence.rulesets
        )
    )
    if merge_queue and not any(item.has_merge_group_trigger for item in inspections):
        diagnostics.append(
            _diagnostic(
                rule=_MERGE_QUEUE_TRIGGER,
                severity="warning",
                message="Required CI does not declare merge-queue coverage.",
                observed=(
                    "an active branch merge queue exists but no workflow handles merge_group"
                ),
                expected="at least one required CI workflow triggered by merge_group",
                path=".github/workflows",
                anchor="merge-queue",
                summary="Add merge_group to the required CI workflow triggers.",
            )
        )


def _evaluate_supply_chain_workflows(
    inspections: tuple[WorkflowInspection, ...], diagnostics: list[Diagnostic]
) -> None:
    for item in inspections:
        mutable = [finding for job in item.jobs for finding in _mutable_install_findings(job)]
        if mutable:
            diagnostics.append(
                _diagnostic(
                    rule=_IMMUTABLE_INSTALLS,
                    severity="warning",
                    message="A CI dependency install does not enforce its lockfile.",
                    observed=", ".join(mutable),
                    expected="recognized dependency installs use immutable or frozen lock mode",
                    path=item.path,
                    anchor=f"workflow:{item.path}:immutable-installs",
                    summary="Use the package manager's lock-enforcing install mode in CI.",
                )
            )
        suppressed_scanners = [
            job.job_id for job in item.jobs if _vulnerability_failure_is_suppressed(job)
        ]
        if suppressed_scanners:
            diagnostics.append(
                _diagnostic(
                    rule=_VULNERABILITY_GATE,
                    severity="warning",
                    message="A vulnerability scanner cannot fail its workflow job.",
                    observed=f"non-blocking scanner jobs: {', '.join(suppressed_scanners)}",
                    expected="recognized vulnerability scanners propagate a nonzero exit status",
                    path=item.path,
                    anchor=f"workflow:{item.path}:vulnerability-gate",
                    summary="Remove failure suppression from the vulnerability scanning gate.",
                )
            )


def _mutable_install_findings(job: WorkflowJobInspection) -> tuple[str, ...]:
    findings: list[str] = []
    for step in job.steps:
        script = re.sub(r"\\\n\s*", " ", step.run or "")
        for raw_line in script.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if re.search(r"\buv\s+sync\b", line) and not re.search(
                r"\s--(?:locked|frozen)\b", line
            ):
                findings.append(f"{job.job_id}: uv sync")
            if re.search(r"\bpnpm\s+install\b", line) and "--frozen-lockfile" not in line:
                findings.append(f"{job.job_id}: pnpm install")
            if re.search(r"\byarn\s+install\b", line) and "--immutable" not in line:
                findings.append(f"{job.job_id}: yarn install")
            if re.search(r"\bnpm\s+install\b", line) and not re.search(
                r"\bnpm\s+install\s+(?:-[^\s]*g\b|--global\b)", line
            ):
                findings.append(f"{job.job_id}: npm install (use npm ci)")
    return tuple(sorted(set(findings)))


def _vulnerability_failure_is_suppressed(job: WorkflowJobInspection) -> bool:
    scanner_seen = False
    shell_suppressed = False
    for step in job.steps:
        script = step.run or ""
        if not re.search(r"\b(?:pip-audit|osv-scanner|npm\s+audit|pnpm\s+audit)\b", script):
            continue
        scanner_seen = True
        shell_suppressed = (
            shell_suppressed
            or step.continues_on_error
            or re.search(
                r"\b(?:pip-audit|osv-scanner|npm\s+audit|pnpm\s+audit)\b[^\n]*(?:\|\|\s*(?:true|echo))",
                script,
            )
            is not None
        )
    return scanner_seen and (job.continues_on_error or shell_suppressed)


def _evaluate_governance(
    evidence: RepositoryEvidence,
    branches: BranchNames,
    repository_files: Sequence[str],
    diagnostics: list[Diagnostic],
    issues: list[ExecutionIssue],
) -> None:
    files = {path.casefold() for path in repository_files}
    missing: list[str] = []
    if not any(path in files for path in ("codeowners", ".github/codeowners", "docs/codeowners")):
        missing.append("CODEOWNERS")
    if not any(
        path in files
        for path in (
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
            "renovate.json",
            ".renovaterc",
        )
    ):
        missing.append("dependency update automation")
    by_name = {branch.name: branch for branch in evidence.branches}
    existing_long_lived = [by_name[name] for name in branches if name in by_name]
    unknown: list[str] = []
    if not evidence.branches_complete or any(
        branch.protected is None for branch in existing_long_lived
    ):
        unknown.append("long-lived branch protection")
    elif existing_long_lived and any(branch.protected is False for branch in existing_long_lived):
        missing.append("protection on every long-lived branch")
    if (
        not evidence.actions_permissions_available
        or evidence.actions_default_workflow_permissions is None
    ):
        unknown.append("default Actions permissions")
    elif evidence.actions_default_workflow_permissions == "write":
        missing.append("read-only default Actions permissions")
    if unknown and not evidence.issues:
        issues.append(
            ExecutionIssue(
                code="github.governance-evidence-incomplete",
                phase="repository-governance",
                message=f"GitHub governance evidence is incomplete: {', '.join(unknown)}",
                retryable=True,
                remediation=(
                    "Collect GitHub evidence with permission to read branch and Actions settings.",
                ),
            )
        )
    if missing:
        diagnostics.append(
            _diagnostic(
                rule=_GOVERNANCE,
                severity="warning",
                message="Repository governance controls are incomplete.",
                observed=", ".join(missing),
                expected=(
                    "governance-file presence, protected branches, and read-only Actions defaults"
                ),
                path=".github",
                anchor="repository-settings",
                summary="Add the missing ownership, maintenance, and GitHub repository controls.",
            )
        )


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
