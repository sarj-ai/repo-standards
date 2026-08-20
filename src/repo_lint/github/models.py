from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from repo_lint.core import Diagnostic, ExecutionIssue


@dataclass(frozen=True, slots=True)
class BranchEvidence:
    name: str
    protected: bool | None
    required_status_checks: tuple[str, ...] | None = None
    head_sha: str | None = None


@dataclass(frozen=True, slots=True)
class RulesetEvidence:
    name: str
    enforcement: str
    target: str
    rule_types: tuple[str, ...]
    ruleset_id: int | None = None
    details_complete: bool = True


@dataclass(frozen=True, slots=True)
class RepositoryEvidence:
    repository: str
    default_branch: str | None
    branches: tuple[BranchEvidence, ...]
    rulesets: tuple[RulesetEvidence, ...]
    allow_auto_merge: bool | None
    actions_default_workflow_permissions: str | None
    actions_can_approve_pull_requests: bool | None
    repository_metadata_available: bool = True
    branches_complete: bool = True
    rulesets_complete: bool = True
    actions_permissions_available: bool = True
    issues: tuple[ExecutionIssue, ...] = ()
    requested_repository: str | None = None


@dataclass(frozen=True, slots=True)
class WorkflowDocument:
    path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class ActionReference:
    value: str
    line: int
    pinned_to_full_sha: bool


@dataclass(frozen=True, slots=True)
class WorkflowStepInspection:
    uses: str | None
    run: str | None
    environment: tuple[tuple[str, str], ...]
    inputs: tuple[tuple[str, str], ...]
    continues_on_error: bool = False


@dataclass(frozen=True, slots=True)
class WorkflowJobInspection:
    job_id: str
    condition: str | None
    environment: tuple[tuple[str, str], ...]
    has_permissions: bool
    has_timeout: bool
    steps: tuple[WorkflowStepInspection, ...]
    reusable_uses: str | None = None
    permissions_safe: bool = True
    continues_on_error: bool = False


@dataclass(frozen=True, slots=True)
class WorkflowInspection:
    path: str
    valid_utf8: bool
    action_references: tuple[ActionReference, ...]
    has_permissions: bool
    has_timeout: bool
    has_concurrency: bool
    cancels_in_progress: bool | None
    has_pull_request_trigger: bool
    has_merge_group_trigger: bool
    has_push_trigger: bool
    has_schedule_trigger: bool
    has_workflow_dispatch_trigger: bool
    creates_pull_request: bool
    enables_auto_merge: bool
    uses_non_default_token: bool
    pins_source_sha: bool
    guards_stale_head: bool
    refuses_conflicts: bool
    text: str
    push_branches: tuple[str, ...] = ()
    push_uses_branches_ignore: bool = False
    jobs: tuple[WorkflowJobInspection, ...] = ()


@dataclass(frozen=True, slots=True)
class GitHubAnalysisReport:
    completion: Literal["complete", "incomplete"]
    conclusion: Literal["passed", "findings", "inconclusive"]
    diagnostics: tuple[Diagnostic, ...]
    execution_issues: tuple[ExecutionIssue, ...]
    workflow_inspections: tuple[WorkflowInspection, ...]

    def __post_init__(self) -> None:
        if self.completion == "incomplete":
            if self.conclusion != "inconclusive" or not self.execution_issues:
                message = (
                    "incomplete GitHub reports must be inconclusive and contain execution issues"
                )
                raise ValueError(message)
            return
        if self.conclusion == "inconclusive" or self.execution_issues:
            message = "complete GitHub reports cannot be inconclusive or contain execution issues"
            raise ValueError(message)
        if (self.conclusion == "passed") == bool(self.diagnostics):
            message = (
                "passed GitHub reports require no diagnostics; findings reports require diagnostics"
            )
            raise ValueError(message)
