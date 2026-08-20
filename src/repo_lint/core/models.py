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
RuleCategoryId = NewType("RuleCategoryId", str)
RuleTopicId = NewType("RuleTopicId", str)


Severity = Literal["warning", "error"]
ExampleLanguage = Literal["json", "text", "toml", "yaml"]
EvidenceLevel = Literal["verified", "declared", "external", "unknown"]
type JSONScalar = str | int | float | bool | None
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]
RuleMaturity = Literal["experimental", "beta", "stable", "deprecated"]
AdapterStatus = Literal["complete", "incomplete", "failed"]
DeliveryProvider = Literal["github"]
MAX_RULE_TITLE_LENGTH = 72
MAX_RULE_EXAMPLE_TITLE_LENGTH = 56


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
    target: ComponentId
    kind: str


@dataclass(frozen=True, slots=True)
class Component:
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
    component_id: ComponentId
    old_path: str
    new_path: str


@dataclass(frozen=True, slots=True)
class ExceptionRecord:
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
class DeliveryConfig:
    provider: DeliveryProvider = "github"
    repository: str | None = None
    production_branch: str = "main"
    preview_branch: str = "preview"
    development_branch: str = "dev"
    sync_workflows: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Manifest:
    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    components: tuple[Component, ...]
    migration_paths: tuple[MigrationPath, ...] = ()
    exceptions: tuple[ExceptionRecord, ...] = ()
    delivery: DeliveryConfig | None = None


@dataclass(frozen=True, slots=True)
class Remediation:
    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuleTaxonomy:
    category_id: RuleCategoryId
    topic_id: RuleTopicId
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleExamplePair:
    fixture_id: FixtureId
    language: ExampleLanguage
    flagged: str
    passes: str
    title: str
    severity: Severity

    def __post_init__(self) -> None:
        if (
            any(
                not value
                for value in (
                    self.fixture_id,
                    self.language,
                    self.flagged,
                    self.passes,
                    self.title,
                )
            )
            or "\n" in self.title
            or len(self.title) > MAX_RULE_EXAMPLE_TITLE_LENGTH
        ):
            message = (
                "rule examples require an id, concise title, severity, language, flagged "
                "input, and passing input"
            )
            raise ValueError(message)
        if self.flagged == self.passes:
            message = f"rule example inputs must differ: {self.fixture_id}"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RuleRemediation:
    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.summary or not self.steps or not self.validation:
            message = "rule remediation requires a summary, steps, and validation"
            raise ValueError(message)
        if any(not item for item in (*self.steps, *self.validation)):
            message = "rule remediation entries must be nonempty"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class SourceLocation:
    path: str
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    pointer: str | None = None


@dataclass(frozen=True, slots=True)
class RelatedLocation:
    location: SourceLocation
    message: str
    relationship: str = "related"


@dataclass(frozen=True, slots=True)
class ExceptionUse:
    owner: str
    issue: str
    reason: str
    created_on: str
    expires_on: str


@dataclass(frozen=True, slots=True)
class ExecutionIssue:
    code: str
    phase: str
    message: str
    retryable: bool
    remediation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Diagnostic:
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
class RuleDefinition:
    rule_id: RuleId
    version: int
    default_severity: Severity
    title: str
    summary: str
    detects: str
    impact: str
    taxonomy: RuleTaxonomy
    remediation: RuleRemediation
    examples: tuple[RuleExamplePair, ...]
    evidence_required: tuple[str, ...]
    non_goals: tuple[str, ...] = ()
    false_positive_controls: tuple[str, ...] = ()
    upstream: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    precedence: str = ""
    maturity: RuleMaturity = "stable"

    def __post_init__(self) -> None:
        if self.version < 1:
            message = f"rule version must be positive: {self.rule_id}"
            raise ValueError(message)
        if not self.title or "\n" in self.title or len(self.title) > MAX_RULE_TITLE_LENGTH:
            message = f"rule title must be one concise line: {self.rule_id}"
            raise ValueError(message)
        prose = (self.summary, self.detects, self.impact, self.remediation.summary)
        normalized = tuple(" ".join(value.casefold().split()) for value in prose)
        if any(not value for value in normalized) or len(set(normalized)) != len(normalized):
            message = f"rule clarity fields must be nonempty and distinct: {self.rule_id}"
            raise ValueError(message)
        if not self.evidence_required or any(not item for item in self.evidence_required):
            message = f"rule must describe its evidence: {self.rule_id}"
            raise ValueError(message)
        if not self.examples:
            message = f"rule must provide an example pair: {self.rule_id}"
            raise ValueError(message)
        fixture_ids = tuple(example.fixture_id for example in self.examples)
        if len(fixture_ids) != len(set(fixture_ids)):
            message = f"rule example fixture ids must be unique: {self.rule_id}"
            raise ValueError(message)
        if self.taxonomy.tags != tuple(sorted(set(self.taxonomy.tags))):
            message = f"rule tags must be sorted and unique: {self.rule_id}"
            raise ValueError(message)

    @property
    def severity(self) -> Severity:
        return self.default_severity

    @property
    def fixture_ids(self) -> tuple[FixtureId, ...]:
        return tuple(example.fixture_id for example in self.examples)


Rule = RuleDefinition


@runtime_checkable
class Policy(Protocol):
    policy_id: ClassVar[PolicyId]
    policy_version: ClassVar[int]

    def rules(self) -> tuple[Rule, ...]: ...

    def evaluate(self, manifest: Manifest) -> tuple[Diagnostic, ...]: ...


@dataclass(frozen=True, slots=True)
class Baseline:
    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    scope_digest: str
    fingerprints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TrackedFileEvidence:
    path: str
    object_id: str


@dataclass(frozen=True, slots=True)
class PackageEvidence:
    ecosystem: str
    path: str
    name: str | None
    private: bool | None
    workspace_root: bool
    object_id: str = ""
    content_digest: str = ""


@dataclass(frozen=True, slots=True)
class WorkspaceEvidence:
    ecosystem: str
    path: str
    member_patterns: tuple[str, ...]
    exclude_patterns: tuple[str, ...]
    object_id: str = ""
    content_digest: str = ""


@dataclass(frozen=True, slots=True)
class InventoryUnit:
    kind: InventoryKind
    path: str
    object_id: str | None
    content_digest: str | None


@dataclass(frozen=True, slots=True)
class InputProvenance:
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
    evidence_id: str
    kind: str
    values: Mapping[str, JSONValue]
    locations: tuple[SourceLocation, ...] = ()
    content_digest: str | None = None


@dataclass(frozen=True, slots=True)
class AdapterRun:
    adapter_id: str
    adapter_version: str
    status: AdapterStatus
    evidence: tuple[EvidenceBundle, ...] = ()
    issues: tuple[ExecutionIssue, ...] = ()
    provenance: InputProvenance | None = None


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    repository_id: RepositoryId
    source_revision: str
    tree_digest: str
    evidence: tuple[EvidenceBundle, ...] = ()
    adapter_runs: tuple[AdapterRun, ...] = ()
    parameters: Mapping[str, JSONValue] = field(default_factory=_empty_json_mapping)


@dataclass(frozen=True, slots=True)
class Query:
    limit: int = 100
    cursor: str | None = None
    filters: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Page[PageItem]:
    items: tuple[PageItem, ...]
    next_cursor: str | None = None
    total_count: int | None = None


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
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
    manifest: Manifest
    baseline: Baseline | None
    inspection: RepositoryInspection
    provenance: InputProvenance


@dataclass(frozen=True, slots=True)
class RatchetEntry:
    fingerprint: str
    classification: RatchetClassification
    diagnostic: Diagnostic | None = None


@dataclass(frozen=True, slots=True)
class RatchetComparison:
    entries: tuple[RatchetEntry, ...]

    def fingerprints(self, classification: RatchetClassification) -> tuple[str, ...]:
        return tuple(
            item.fingerprint for item in self.entries if item.classification is classification
        )


@dataclass(frozen=True, slots=True)
class AnalysisReport:
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
