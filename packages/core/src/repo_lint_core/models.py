"""Stable public data model for repository analysis."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import ClassVar, Literal, NewType, Protocol, runtime_checkable


RepositoryId = NewType("RepositoryId", str)
PolicyId = NewType("PolicyId", str)
ComponentId = NewType("ComponentId", str)
RuleId = NewType("RuleId", str)
GitObjectId = NewType("GitObjectId", str)
FixtureId = NewType("FixtureId", str)


Severity = Literal["warning", "error"]
EvidenceLevel = Literal["verified", "declared", "external", "unknown"]
type JSONScalar = str | int | float | bool | None
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]
RuleMaturity = Literal["experimental", "beta", "stable", "deprecated"]
AdapterStatus = Literal["complete", "incomplete", "failed"]


def _empty_json_mapping() -> dict[str, JSONValue]:
    return {}


class Mode(StrEnum):
    """Analysis enforcement modes."""

    REPORT = "report"
    RATCHET = "ratchet"
    STRICT = "strict"


class InventoryKind(StrEnum):
    """Closed inert repository facts discovered from one Git tree."""

    PACKAGE = "package"
    WORKSPACE = "workspace"
    GITHUB_WORKFLOW = "github-workflow"
    CLOUD_BUILD = "cloud-build"
    DOCKERFILE = "dockerfile"
    TERRAFORM_MODULE = "terraform-module"


class RatchetClassification(StrEnum):
    """Stable relationship between one finding and a reviewed baseline."""

    NEW = "new"
    KNOWN = "known"
    RESOLVED = "resolved"


@dataclass(frozen=True, slots=True)
class Dependency:
    """A typed, declared relation between two stable components."""

    target: ComponentId
    kind: str


@dataclass(frozen=True, slots=True)
class Component:
    """A stable repository component declared by the repository owner."""

    component_id: ComponentId
    kind: str
    path: str
    owner: str
    product: str | None = None
    capability: str | None = None
    legacy: bool = False
    dependencies: tuple[Dependency, ...] = ()


@dataclass(frozen=True, slots=True)
class MigrationPath:
    """An explicit path relocation used to preserve diagnostic identity."""

    component_id: ComponentId
    old_path: str
    new_path: str


@dataclass(frozen=True, slots=True)
class ExceptionRecord:
    """A narrow, time-bounded policy exception."""

    rule_id: RuleId
    component_id: ComponentId
    manifest_anchor: str
    fingerprint: str
    owner: str
    reason: str
    issue: str
    created_on: str
    expires_on: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """Strict repository declaration consumed by the engine."""

    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    components: tuple[Component, ...]
    migration_paths: tuple[MigrationPath, ...] = ()
    exceptions: tuple[ExceptionRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class Remediation:
    """Non-executable remediation guidance."""

    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A portable source coordinate; positions are one-based when present."""

    path: str
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    pointer: str | None = None


@dataclass(frozen=True, slots=True)
class RelatedLocation:
    """A second source coordinate that explains a diagnostic relationship."""

    location: SourceLocation
    message: str
    relationship: str = "related"


@dataclass(frozen=True, slots=True)
class ExceptionUse:
    """Visible metadata for an applied, reviewed exception."""

    owner: str
    issue: str
    reason: str
    created_on: str
    expires_on: str


@dataclass(frozen=True, slots=True)
class ExecutionIssue:
    """One stable machine-actionable reason analysis could not complete."""

    code: str
    phase: str
    message: str
    retryable: bool
    remediation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One deterministic policy finding."""

    rule_id: RuleId
    rule_version: int
    severity: Severity
    evidence_level: EvidenceLevel
    component_id: ComponentId
    subject_kind: str
    observed: str
    expected: str
    message: str
    path: str
    manifest_anchor: str
    remediation: Remediation
    prerequisites: tuple[str, ...] = ()
    disposition: Literal["active", "excepted"] = "active"
    exception: ExceptionUse | None = None
    fingerprint: str = ""
    finding_key: str = ""
    location: SourceLocation | None = None
    related_locations: tuple[RelatedLocation, ...] = ()
    observed_value: JSONValue | None = None
    expected_value: JSONValue | None = None


@dataclass(frozen=True, slots=True)
class Rule:
    """Discoverable rule documentation."""

    rule_id: RuleId
    version: int
    severity: Severity
    summary: str
    rationale: str
    bad_example: str
    good_example: str
    problem: str = ""
    harm: str = ""
    non_goals: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    upstream: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    precedence: str = ""
    maturity: RuleMaturity = "stable"
    fixture_ids: tuple[FixtureId, ...] = ()


@runtime_checkable
class Policy(Protocol):
    """Non-executable interface implemented by installed policy packages."""

    policy_id: ClassVar[PolicyId]
    policy_version: ClassVar[int]

    def rules(self) -> tuple[Rule, ...]:
        """Return every immutable rule definition in the policy."""
        ...

    def evaluate(self, manifest: Manifest) -> tuple[Diagnostic, ...]:
        """Evaluate already-parsed repository facts."""
        ...


@dataclass(frozen=True, slots=True)
class Baseline:
    """Exact reviewed legacy debt."""

    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    scope_digest: str
    fingerprints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TrackedFileEvidence:
    """One regular-file blob selected from an immutable Git tree."""

    path: str
    object_id: str


@dataclass(frozen=True, slots=True)
class PackageEvidence:
    """One parser-backed package manifest observed in the selected tree."""

    ecosystem: str
    path: str
    name: str | None
    private: bool | None
    workspace_root: bool
    object_id: str = ""
    content_digest: str = ""


@dataclass(frozen=True, slots=True)
class WorkspaceEvidence:
    """One inert native workspace declaration without glob expansion."""

    ecosystem: str
    path: str
    member_patterns: tuple[str, ...]
    exclude_patterns: tuple[str, ...]
    object_id: str = ""
    content_digest: str = ""


@dataclass(frozen=True, slots=True)
class InventoryUnit:
    """One typed repository unit available for later ownership classification."""

    kind: InventoryKind
    path: str
    object_id: str | None
    content_digest: str | None


@dataclass(frozen=True, slots=True)
class InputProvenance:
    """Content-addressed inputs used to produce a repository analysis."""

    mode: Literal["git-tree", "worktree"]
    source_revision: str
    tree_digest: str
    manifest_path: str
    manifest_object_id: GitObjectId | None
    manifest_digest: str
    baseline_path: str | None = None
    baseline_object_id: GitObjectId | None = None
    baseline_digest: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Typed, inert evidence emitted by one adapter run."""

    evidence_id: str
    kind: str
    values: Mapping[str, JSONValue]
    locations: tuple[SourceLocation, ...] = ()
    content_digest: str | None = None


@dataclass(frozen=True, slots=True)
class AdapterRun:
    """Bounded outcome of collecting evidence through one named adapter."""

    adapter_id: str
    adapter_version: str
    status: AdapterStatus
    evidence: tuple[EvidenceBundle, ...] = ()
    issues: tuple[ExecutionIssue, ...] = ()
    provenance: InputProvenance | None = None


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Framework-neutral inputs supplied to evidence-aware policy rules."""

    repository_id: RepositoryId
    source_revision: str
    tree_digest: str
    evidence: tuple[EvidenceBundle, ...] = ()
    adapter_runs: tuple[AdapterRun, ...] = ()
    parameters: Mapping[str, JSONValue] = field(default_factory=_empty_json_mapping)


@dataclass(frozen=True, slots=True)
class Query:
    """Stable cursor query shared by machine-facing collection APIs."""

    limit: int = 100
    cursor: str | None = None
    filters: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Page[PageItem]:
    """One deterministic cursor page without offset-specific assumptions."""

    items: tuple[PageItem, ...]
    next_cursor: str | None = None
    total_count: int | None = None


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
    """Deterministic bootstrap facts that require no repository manifest."""

    completion: Literal["complete", "incomplete"]
    source_revision: str
    tree_digest: str
    tracked_file_count: int
    projects: tuple[PackageEvidence, ...]
    workflow_paths: tuple[str, ...]
    cloudbuild_paths: tuple[str, ...]
    dockerfile_paths: tuple[str, ...]
    terraform_roots: tuple[str, ...]
    issues: tuple[str, ...]
    tracked_files: tuple[TrackedFileEvidence, ...] = ()
    workspaces: tuple[WorkspaceEvidence, ...] = ()
    inventory_units: tuple[InventoryUnit, ...] = ()

    @property
    def packages(self) -> tuple[PackageEvidence, ...]:
        """Return the preferred package-evidence name for the legacy projects field."""
        return self.projects

    @property
    def terraform_modules(self) -> tuple[str, ...]:
        """Return Terraform directory facts without claiming root-module semantics."""
        return self.terraform_roots


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """One manifest joined to inventory from the exact same immutable Git tree."""

    manifest: Manifest
    baseline: Baseline | None
    inspection: RepositoryInspection
    provenance: InputProvenance


@dataclass(frozen=True, slots=True)
class RatchetEntry:
    """One exact finding fingerprint classified against a baseline."""

    fingerprint: str
    classification: RatchetClassification
    diagnostic: Diagnostic | None = None


@dataclass(frozen=True, slots=True)
class RatchetComparison:
    """Complete deterministic classification of active error debt."""

    entries: tuple[RatchetEntry, ...]

    def fingerprints(self, classification: RatchetClassification) -> tuple[str, ...]:
        """Return sorted fingerprints carrying one classification."""
        return tuple(
            item.fingerprint for item in self.entries if item.classification is classification
        )


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Canonical result with completion separate from policy conclusion."""

    mode: Mode
    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    scope_digest: str
    completion: Literal["complete", "incomplete"]
    conclusion: Literal["passed", "findings", "inconclusive"]
    diagnostics: tuple[Diagnostic, ...] = ()
    execution_issues: tuple[ExecutionIssue, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)
    input_provenance: InputProvenance | None = None
    ratchet: RatchetComparison | None = None
