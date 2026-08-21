from __future__ import annotations

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
MAX_RULE_TITLE_LENGTH = 72
MAX_RULE_EXAMPLE_TITLE_LENGTH = 56


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
class Manifest:
    repository_id: RepositoryId
    components: tuple[Component, ...]
    migration_paths: tuple[MigrationPath, ...] = ()
    exceptions: tuple[ExceptionRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class Remediation:
    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuleTaxonomy:
    category_id: RuleCategoryId
    topic_id: RuleTopicId


@dataclass(frozen=True, slots=True)
class RuleExamplePair:
    example_id: FixtureId
    title: str
    language: ExampleLanguage
    before: str
    after: str
    expected_severity: Severity

    def __post_init__(self) -> None:
        if (
            any(
                not value
                for value in (
                    self.example_id,
                    self.language,
                    self.before,
                    self.after,
                    self.title,
                )
            )
            or "\n" in self.title
            or len(self.title) > MAX_RULE_EXAMPLE_TITLE_LENGTH
        ):
            message = (
                "rule examples require an id, concise title, severity, language, before, and after"
            )
            raise ValueError(message)
        if self.before == self.after:
            message = f"rule example inputs must differ: {self.example_id}"
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
    description: str
    why: str
    fix: str
    taxonomy: RuleTaxonomy
    examples: tuple[RuleExamplePair, ...]
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.version < 1:
            message = f"rule version must be positive: {self.rule_id}"
            raise ValueError(message)
        if not self.title or "\n" in self.title or len(self.title) > MAX_RULE_TITLE_LENGTH:
            message = f"rule title must be one concise line: {self.rule_id}"
            raise ValueError(message)
        prose = (self.description, self.why, self.fix)
        normalized = tuple(" ".join(value.casefold().split()) for value in prose)
        if any(not value for value in normalized) or len(set(normalized)) != len(normalized):
            message = f"rule clarity fields must be nonempty and distinct: {self.rule_id}"
            raise ValueError(message)
        if not self.examples:
            message = f"rule must provide an example pair: {self.rule_id}"
            raise ValueError(message)
        fixture_ids = tuple(example.example_id for example in self.examples)
        if len(fixture_ids) != len(set(fixture_ids)):
            message = f"rule example fixture ids must be unique: {self.rule_id}"
            raise ValueError(message)

    @property
    def severity(self) -> Severity:
        return self.default_severity

    @property
    def fixture_ids(self) -> tuple[FixtureId, ...]:
        return tuple(example.example_id for example in self.examples)


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
class RepositoryInspection:
    completion: Literal["complete", "incomplete"]
    source_revision: str
    tree_digest: str
    tracked_file_count: int
    packages: tuple[PackageEvidence, ...]
    workflow_paths: tuple[str, ...]
    cloudbuild_paths: tuple[str, ...]
    dockerfile_paths: tuple[str, ...]
    terraform_modules: tuple[str, ...]
    issues: tuple[str, ...]
    tracked_files: tuple[TrackedFileEvidence, ...] = ()
    workspaces: tuple[WorkspaceEvidence, ...] = ()
    inventory_units: tuple[InventoryUnit, ...] = ()


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


@dataclass(frozen=True, slots=True, kw_only=True)
class _AnalysisReportBase:
    mode: Mode
    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    scope_digest: str
    summary: dict[str, int] = field(default_factory=dict)
    input_provenance: InputProvenance | None = None
    ratchet: RatchetComparison | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PassedReport(_AnalysisReportBase):
    completion: Literal["complete"] = field(init=False, default="complete")
    conclusion: Literal["passed"] = field(init=False, default="passed")
    diagnostics: tuple[Diagnostic, ...] = field(init=False, default=())
    execution_issues: tuple[ExecutionIssue, ...] = field(init=False, default=())


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingsReport(_AnalysisReportBase):
    diagnostics: tuple[Diagnostic, ...]
    completion: Literal["complete"] = field(init=False, default="complete")
    conclusion: Literal["findings"] = field(init=False, default="findings")
    execution_issues: tuple[ExecutionIssue, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        if not self.diagnostics:
            message = "findings reports require at least one diagnostic"
            raise ValueError(message)


@dataclass(frozen=True, slots=True, kw_only=True)
class IncompleteReport(_AnalysisReportBase):
    execution_issues: tuple[ExecutionIssue, ...]
    completion: Literal["incomplete"] = field(init=False, default="incomplete")
    conclusion: Literal["inconclusive"] = field(init=False, default="inconclusive")
    diagnostics: tuple[Diagnostic, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        if not self.execution_issues:
            message = "incomplete reports require at least one execution issue"
            raise ValueError(message)


type AnalysisReport = PassedReport | FindingsReport | IncompleteReport
