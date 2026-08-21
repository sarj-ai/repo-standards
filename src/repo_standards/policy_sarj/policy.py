from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import (
    Component,
    ComponentId,
    Diagnostic,
    ExampleLanguage,
    FixtureId,
    Manifest,
    PolicyId,
    Remediation,
    RepositorySnapshot,
    Rule,
    RuleExamplePair,
    RuleId,
)
from repo_standards.core.taxonomy import (
    ARCHITECTURE,
    COMPONENT_SCHEMA,
    DEPENDENCY_BOUNDARIES,
    REPOSITORY_LAYOUT,
    taxonomy,
)

from .spec import (
    PATH_TEMPLATE_BY_KIND,
    PATH_TEMPLATES,
    PROFILE_ID,
    ChoiceSegment,
    FieldSegment,
    LiteralSegment,
    OptionalTail,
    OwnershipSegment,
    PathTemplate,
    PolicySpec,
    ProfileId,
    RuleClassification,
    RuleGovernance,
    RuleMaturity,
    TokenSegment,
)


if TYPE_CHECKING:
    from collections.abc import Mapping


class _DependencyAnalysis(NamedTuple):
    diagnostics: list[Diagnostic]
    accepted_edges: list[tuple[ComponentId, ComponentId]]


class _CodeBoundary(NamedTuple):
    rule_id: RuleId
    expected: str


class ComponentKind(StrEnum):
    """Closed component kinds understood by the Sarj policy."""

    APPLICATION = "application"
    PRODUCT_LIBRARY = "product-library"
    SHARED_LIBRARY = "shared-library"
    FOUNDATION_SERVICE = "foundation-service"
    CONTRACT = "contract"
    GENERATED_CLIENT = "generated-client"
    MIGRATION_SET = "migration-set"
    TERRAFORM_ROOT = "terraform-root"
    CLOUD_BUILD = "cloud-build"
    KUBERNETES = "kubernetes"
    CLOUDFLARE = "cloudflare"
    TOOL = "tool"


EDGE_KINDS = frozenset(
    {
        "source-import",
        "package-dependency",
        "build-input",
        "generates",
        "implements-contract",
        "runtime-call",
        "deploys",
        "owns-data",
        "applies-migration",
        "terraform-consumes",
        "ci-validates",
    }
)
CODE_EDGES = frozenset({"source-import", "package-dependency"})
_MIN_CYCLE_COMPONENTS = 2
_PATH_TOKEN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"  # ruff: ignore[hardcoded-password-string] - regex, not a secret
_DOCUMENTATION_ROOTS = frozenset({"adr", "architecture", "docs"})
_PACKAGE_DOCUMENT_NAMES = frozenset(
    {
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE.md",
        "README.md",
        "SECURITY.md",
    }
)
_AGENT_CONTRACT_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "SKILL.md"})
_AGENT_CONTRACT_ROOTS = (
    (".agents", "skills"),
    (".claude", "commands"),
    (".claude", "skills"),
    (".codex", "skills"),
)
_NON_OPERATIONAL_COMPONENT_KINDS = frozenset(
    {"application", "contract", "foundation-service", "product-library", "shared-library", "tool"}
)
_COMPONENT_FIELDS: Mapping[ComponentKind, tuple[frozenset[str], frozenset[str]]] = MappingProxyType(
    {
        ComponentKind.APPLICATION: (frozenset({"product"}), frozenset({"capability"})),
        ComponentKind.PRODUCT_LIBRARY: (
            frozenset({"product", "capability"}),
            frozenset(),
        ),
        ComponentKind.SHARED_LIBRARY: (frozenset({"capability"}), frozenset({"product"})),
        ComponentKind.FOUNDATION_SERVICE: (frozenset(), frozenset({"product", "capability"})),
        ComponentKind.CONTRACT: (frozenset(), frozenset({"capability"})),
        ComponentKind.GENERATED_CLIENT: (
            frozenset({"product", "capability"}),
            frozenset(),
        ),
        ComponentKind.MIGRATION_SET: (frozenset({"product"}), frozenset({"capability"})),
        ComponentKind.TERRAFORM_ROOT: (frozenset({"product"}), frozenset({"capability"})),
        ComponentKind.CLOUD_BUILD: (
            frozenset({"product", "capability"}),
            frozenset(),
        ),
        ComponentKind.KUBERNETES: (
            frozenset({"product", "capability"}),
            frozenset(),
        ),
        ComponentKind.CLOUDFLARE: (
            frozenset({"product", "capability"}),
            frozenset(),
        ),
        ComponentKind.TOOL: (frozenset({"capability"}), frozenset({"product"})),
    }
)

_ALLOWED_CODE_TARGETS: Mapping[ComponentKind, frozenset[ComponentKind]] = MappingProxyType(
    {
        ComponentKind.APPLICATION: frozenset(
            {
                ComponentKind.PRODUCT_LIBRARY,
                ComponentKind.SHARED_LIBRARY,
                ComponentKind.CONTRACT,
                ComponentKind.GENERATED_CLIENT,
            }
        ),
        ComponentKind.PRODUCT_LIBRARY: frozenset(
            {
                ComponentKind.PRODUCT_LIBRARY,
                ComponentKind.SHARED_LIBRARY,
                ComponentKind.CONTRACT,
                ComponentKind.GENERATED_CLIENT,
            }
        ),
        ComponentKind.SHARED_LIBRARY: frozenset(
            {ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}
        ),
        ComponentKind.FOUNDATION_SERVICE: frozenset(
            {ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}
        ),
        ComponentKind.CONTRACT: frozenset({ComponentKind.CONTRACT}),
        ComponentKind.GENERATED_CLIENT: frozenset(
            {ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}
        ),
        ComponentKind.MIGRATION_SET: frozenset({ComponentKind.SHARED_LIBRARY}),
        ComponentKind.TERRAFORM_ROOT: frozenset(),
        ComponentKind.CLOUD_BUILD: frozenset(),
        ComponentKind.KUBERNETES: frozenset(),
        ComponentKind.CLOUDFLARE: frozenset(),
        ComponentKind.TOOL: frozenset({ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}),
    }
)


def _example(  # ruff: ignore[too-many-arguments] - keyword-only declarative fixture
    *,
    example_id: str,
    title: str,
    language: ExampleLanguage,
    before: str,
    after: str,
    expected_severity: Literal["warning", "error"] = "error",
) -> RuleExamplePair:
    return RuleExamplePair(
        example_id=FixtureId(example_id),
        title=title,
        language=language,
        before=before,
        after=after,
        expected_severity=expected_severity,
    )


RULES = (
    Rule(
        rule_id=RuleId("architecture/dependencies/policy"),
        version=1,
        default_severity="error",
        title="Enforce dependency boundaries",
        description="Every dependency edge is legal, ownership-safe, and acyclic.",
        why="One dependency policy keeps ownership, release, and build direction explicit.",
        fix="Remove the edge or replace it with an allowed dependency or runtime contract.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        examples=(
            _example(
                example_id="sarj-graph-edge-endpoints",
                title="Edge endpoints",
                language="text",
                before="library --implements-contract--> application",
                after="application --implements-contract--> contract",
            ),
            _example(
                example_id="sarj-graph-application-dependency",
                title="Application dependency",
                language="text",
                before="application A --source-import--> application B",
                after="application A --package-dependency--> product library B",
            ),
            _example(
                example_id="sarj-graph-library-application-dependency",
                title="Library application dependency",
                language="text",
                before="product library --source-import--> application",
                after="application --package-dependency--> product library",
            ),
            _example(
                example_id="sarj-graph-self-dependency",
                title="Self dependency",
                language="text",
                before="component A --source-import--> component A",
                after="component A has no edge to itself",
            ),
            _example(
                example_id="sarj-graph-cross-product-dependency",
                title="Cross-product dependency",
                language="text",
                before="beta library --source-import--> alpha library",
                after="beta application --runtime-call--> alpha API",
            ),
            _example(
                example_id="sarj-graph-shared-product-dependency",
                title="Shared-product dependency",
                language="text",
                before="shared library --package-dependency--> beta library",
                after="beta application --package-dependency--> shared library",
            ),
            _example(
                example_id="sarj-graph-contract-implementation-dependency",
                title="Contract implementation dependency",
                language="text",
                before="contract --source-import--> product library",
                after="product contract --package-dependency--> shared contract",
            ),
            _example(
                example_id="sarj-graph-disallowed-code-dependency",
                title="Disallowed code dependency",
                language="text",
                before="migration set --source-import--> contract",
                after="migration set --package-dependency--> shared library",
            ),
            _example(
                example_id="sarj-graph-code-cycle",
                title="Code cycle",
                language="text",
                before="library A -> library B -> library A",
                after="application -> product library -> shared library",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("architecture/layout/component-paths"),
        version=1,
        default_severity="error",
        title="Use canonical component paths",
        description="Every component has one canonical ownership root.",
        why="Canonical disjoint roots make ownership and impact analysis deterministic.",
        fix="Move the component to its canonical path and keep ownership roots disjoint.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-layout-component-path",
                title="Component path",
                language="toml",
                before="path = 'python/agent'",
                after="path = 'applications/alpha/agent'",
            ),
            _example(
                example_id="sarj-layout-operational-path",
                title="Operational path",
                language="toml",
                before="path = 'iac/alpha'",
                after="path = 'deployments/alpha/terraform'",
            ),
            _example(
                example_id="sarj-layout-overlapping-roots",
                title="Overlapping component roots",
                language="text",
                before="services/payments\nservices/payments/worker",
                after="services/payments\nservices/worker",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("architecture/schema/component"),
        version=1,
        default_severity="error",
        title="Keep component identity consistent",
        description="Component kind, ownership, ID, and capability token agree.",
        why="Trustworthy component identity prevents cascading layout and dependency mistakes.",
        fix="Add required fields, remove forbidden fields, and align IDs and capability tokens.",
        taxonomy=taxonomy(ARCHITECTURE, COMPONENT_SCHEMA),
        examples=(
            _example(
                example_id="sarj-schema-component-fields",
                title="Component fields",
                language="toml",
                before="kind = 'shared-library'\nproduct = 'alpha'",
                after="kind = 'shared-library'\ncapability = 'request-signing'",
            ),
            _example(
                example_id="sarj-naming-capability-token",
                title="Capability token",
                language="toml",
                before="capability = 'request.signing'",
                after="capability = 'request-signing'",
            ),
            _example(
                example_id="sarj-naming-component-id",
                title="Component ID",
                language="toml",
                before="id = 'beta.agent'\nproduct = 'alpha'",
                after="id = 'alpha.agent'\nproduct = 'alpha'",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/terraform-examples"),
        version=1,
        default_severity="error",
        title="Do not commit example tfvars files",
        description="Tracked filenames ending in .tfvars.example are prohibited.",
        why="One typed variable interface prevents copied configuration from drifting.",
        fix="Delete the example file and document validated inputs in variables.tf.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-artifact-no-example-tfvars",
                title="Terraform example variables",
                language="text",
                before="deployments/alpha/terraform/terraform.tfvars.example",
                after="deployments/alpha/terraform/variables.tf",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/documentation/placement"),
        version=1,
        default_severity="error",
        title="Keep Markdown in durable owned locations",
        description="Tracked Markdown must have a durable documentation or tool-contract role.",
        why="Owned documentation stays discoverable instead of becoming repository debris.",
        fix="Move durable guidance into an approved docs root or delete transient notes.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-layout-markdown-placement",
                title="Markdown placement",
                language="text",
                before="deployments/alpha/terraform/README.md",
                after="docs/deployment/alpha-terraform.md",
            ),
        ),
    ),
)

_RULE_CLASSIFICATION: Mapping[RuleId, RuleClassification] = MappingProxyType(
    {
        RuleId("architecture/layout/component-paths"): RuleClassification.OBJECTIVE,
        RuleId("architecture/schema/component"): RuleClassification.SCHEMA,
        RuleId("architecture/dependencies/policy"): RuleClassification.OBJECTIVE,
        RuleId("repository/artifacts/terraform-examples"): RuleClassification.OBJECTIVE,
        RuleId("repository/documentation/placement"): RuleClassification.OBJECTIVE,
    }
)
_RULE_PRECEDENCE: Mapping[RuleId, int] = MappingProxyType(
    {
        RuleId("architecture/schema/component"): 10,
        RuleId("architecture/dependencies/policy"): 20,
        RuleId("architecture/layout/component-paths"): 30,
        RuleId("repository/artifacts/terraform-examples"): 40,
        RuleId("repository/documentation/placement"): 50,
    }
)
_UPSTREAM_BY_CLASSIFICATION: Mapping[RuleClassification, tuple[str, ...]] = MappingProxyType(
    {
        RuleClassification.SCHEMA: ("repository manifest parser",),
        RuleClassification.OBJECTIVE: (
            "Import Linter",
            "dependency-cruiser",
            "native package dependency graphs",
        ),
        RuleClassification.JUDGMENT: ("organization architecture review",),
        RuleClassification.OPERATIONAL: (
            "Terraform plan",
            "deployment control planes",
        ),
    }
)

_RULE_EVIDENCE: Mapping[RuleId, Literal["declared", "verified", "external"]] = MappingProxyType(
    {
        rule.rule_id: ("verified" if str(rule.rule_id).startswith("repository/") else "declared")
        for rule in RULES
    }
)

RULE_GOVERNANCE = tuple(
    RuleGovernance(
        rule_id=rule.rule_id,
        maturity=(
            RuleMaturity.WARNING if rule.severity == "warning" else RuleMaturity.STABLE_ERROR
        ),
        classification=_RULE_CLASSIFICATION[rule.rule_id],
        evidence=_RULE_EVIDENCE[rule.rule_id],
        upstream=_UPSTREAM_BY_CLASSIFICATION[_RULE_CLASSIFICATION[rule.rule_id]],
        precedence=_RULE_PRECEDENCE[rule.rule_id],
    )
    for rule in RULES
)

POLICY_SPEC = PolicySpec(
    schema_version=2,
    policy_id=PolicyId("sarj"),
    policy_version=6,
    profile_id=PROFILE_ID,
    title="Sarj repository standard",
    component_kinds=tuple(kind.value for kind in ComponentKind),
    edge_kinds=tuple(sorted(EDGE_KINDS)),
    path_templates=PATH_TEMPLATES,
    rule_governance=RULE_GOVERNANCE,
)


def _remediation(summary: str, *steps: str) -> Remediation:
    return Remediation(
        summary=summary,
        steps=steps,
        validation=("Run repo-standards check again and inspect the typed dependency graph.",),
    )


def _diagnostic(  # ruff: ignore[too-many-arguments] - wire diagnostic fields remain explicit
    *,
    rule_id: RuleId,
    component_id: ComponentId,
    subject_kind: str,
    observed: str,
    expected: str,
    message: str,
    path: str,
    anchor: str,
    remediation: Remediation,
) -> Diagnostic:
    rule = next(item for item in RULES if item.rule_id == rule_id)
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="declared",
        component_id=component_id,
        subject_kind=subject_kind,
        observed=observed,
        expected=expected,
        message=message,
        path=path,
        manifest_anchor=anchor,
        remediation=remediation,
    )


def _path_matches(template: PathTemplate, component: Component) -> bool:
    actual = component.path.split("/")
    expected = template.segments
    for index, segment in enumerate(expected):
        match segment:
            case OptionalTail():
                return index == len(expected) - 1
            case _:
                if index >= len(actual) or not _segment_matches(segment, actual[index], component):
                    return False
    return len(actual) == len(expected)


def _segment_matches(segment: object, actual: str, component: Component) -> bool:
    match segment:
        case LiteralSegment(value=value):
            return actual == value
        case ChoiceSegment(values=values):
            return actual in values
        case FieldSegment(field=field):
            return actual == _component_field_value(component, field)
        case TokenSegment():
            return re.fullmatch(_PATH_TOKEN, actual) is not None
        case OwnershipSegment():
            return actual == (component.product or "shared")
        case _:
            return False


def _expected_path(template: PathTemplate, component: Component) -> str:
    rendered: list[str] = []
    for segment in template.segments:
        match segment:
            case LiteralSegment(value=value):
                rendered.append(value)
            case ChoiceSegment(values=values):
                rendered.append("{" + ",".join(values) + "}")
            case FieldSegment(field=field):
                rendered.append(_component_field_value(component, field) or f"<{field}>")
            case TokenSegment(label=label):
                rendered.append(f"<{label}>")
            case OwnershipSegment():
                rendered.append(component.product or "shared")
            case OptionalTail():
                rendered.append("...")
    return "/".join(rendered)


def _repository_artifact_diagnostics(
    snapshot: RepositorySnapshot,
) -> tuple[Diagnostic, ...]:
    package_roots = frozenset(
        _parent_path(project.path) for project in snapshot.inspection.packages
    )
    diagnostics: list[Diagnostic] = []
    for tracked in snapshot.inspection.tracked_files:
        path = tracked.path
        component = _nearest_component(path, snapshot.manifest.components)
        if path.casefold().endswith(".tfvars.example"):
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/artifacts/terraform-examples"),
                    component=component,
                    subject_kind="tracked-terraform-example",
                    observed=path,
                    expected="no tracked filename ending in .tfvars.example",
                    message="tracked Terraform example variable file is prohibited",
                    path=path,
                    remediation=Remediation(
                        summary=(
                            "Remove the example file and keep one authoritative input contract."
                        ),
                        steps=(
                            "Delete the tracked .tfvars.example file.",
                            "Describe inputs and validation in variables.tf.",
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
        if path.casefold().endswith(".md") and not _markdown_path_is_owned(
            path,
            package_roots=package_roots,
            component=component,
        ):
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/documentation/placement"),
                    component=component,
                    subject_kind="tracked-markdown",
                    observed=path,
                    expected="a root, durable docs, package, generated, GitHub, or agent path",
                    message="tracked Markdown is outside an approved owned location",
                    path=path,
                    remediation=Remediation(
                        summary=(
                            "Move durable guidance to an owned documentation surface or remove it."
                        ),
                        steps=(
                            "Move durable guidance beneath docs, architecture, or adr.",
                            (
                                "Delete transient plans, handoffs, summaries, and "
                                "implementation notes."
                            ),
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
    return tuple(sorted(diagnostics, key=lambda item: (item.path, item.rule_id)))


def _parent_path(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def _nearest_component(path: str, components: tuple[Component, ...]) -> Component | None:
    owners = tuple(
        component
        for component in components
        if path == component.path or path.startswith(f"{component.path}/")
    )
    return max(owners, key=lambda item: len(item.path), default=None)


def _markdown_path_is_owned(
    path: str,
    *,
    package_roots: frozenset[str],
    component: Component | None,
) -> bool:
    pure_path = PurePosixPath(path)
    parts = pure_path.parts
    is_root_document = len(parts) == 1
    is_durable_tree = parts[0] in _DOCUMENTATION_ROOTS or parts[0] == ".github"
    is_agent_contract = pure_path.name in _AGENT_CONTRACT_NAMES or any(
        parts[: len(root)] == root for root in _AGENT_CONTRACT_ROOTS
    )
    if is_root_document or is_durable_tree or is_agent_contract:
        return True
    parent = _parent_path(path)
    if pure_path.name in _PACKAGE_DOCUMENT_NAMES and parent in package_roots:
        return True
    if component is None:
        return False
    if component.kind == "generated-client":
        return True
    return (
        component.kind in _NON_OPERATIONAL_COMPONENT_KINDS
        and parent == component.path
        and pure_path.name in _PACKAGE_DOCUMENT_NAMES
    )


def _repository_diagnostic(  # ruff: ignore[too-many-arguments] - fields are explicit
    *,
    rule_id: RuleId,
    component: Component | None,
    subject_kind: str,
    observed: str,
    expected: str,
    message: str,
    path: str,
    remediation: Remediation,
) -> Diagnostic:
    rule = next(item for item in RULES if item.rule_id == rule_id)
    component_id = component.component_id if component is not None else ComponentId("repository")
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=component_id,
        subject_kind=subject_kind,
        observed=observed,
        expected=expected,
        message=message,
        path=path,
        manifest_anchor=f"tracked_files.{path}",
        remediation=remediation,
    )


def _component_field_value(
    component: Component, field: Literal["product", "capability"]
) -> str | None:
    if field == "product":
        return component.product
    return component.capability


class SarjPolicy:
    policy_id: ClassVar[PolicyId] = PolicyId("sarj")
    policy_version: ClassVar[int] = POLICY_SPEC.policy_version
    profile_id: ClassVar[ProfileId] = PROFILE_ID

    @staticmethod
    def spec() -> PolicySpec:
        return POLICY_SPEC

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        return RULES

    @staticmethod
    def evaluate_repository(snapshot: RepositorySnapshot) -> tuple[Diagnostic, ...]:
        return _repository_artifact_diagnostics(snapshot)

    @staticmethod
    def evaluate(manifest: Manifest) -> tuple[Diagnostic, ...]:
        diagnostics: list[Diagnostic] = []
        by_id = {item.component_id: item for item in manifest.components}
        kinds: dict[ComponentId, ComponentKind] = {}
        invalid: set[ComponentId] = set()

        # First pass: establish trustworthy kinds and ownership fields for every
        # endpoint. Graph rules never reason from contradictory component facts.
        for component in manifest.components:
            try:
                component_kind = ComponentKind(component.kind)
            except ValueError:
                ConfigurationError.fail(
                    f"component {component.component_id} has unsupported kind {component.kind}"
                )
            kinds[component.component_id] = component_kind
            field_diagnostic = _component_field_diagnostic(component, component_kind)
            if field_diagnostic is not None:
                diagnostics.append(field_diagnostic)
                invalid.add(component.component_id)
                continue
        clean_code_edges: list[tuple[ComponentId, ComponentId]] = []
        for component in manifest.components:
            if component.component_id in invalid:
                continue
            edge_diagnostics, accepted = _dependency_diagnostics(component, by_id, kinds, invalid)
            diagnostics.extend(edge_diagnostics)
            clean_code_edges.extend(accepted)

        # Second pass: naming and layout apply only after the component's
        # identity is valid, preventing regex/path noise from masking schema work.
        for component in manifest.components:
            if component.component_id in invalid:
                continue
            component_kind = kinds[component.component_id]
            diagnostics.extend(_naming_diagnostics(component, component_kind))
            template = PATH_TEMPLATE_BY_KIND[component_kind.value]
            if not _path_matches(template, component):
                diagnostics.append(
                    _diagnostic(
                        rule_id=RuleId("architecture/layout/component-paths"),
                        component_id=component.component_id,
                        subject_kind="component-path",
                        observed=component.path,
                        expected=_expected_path(template, component),
                        message="component path does not match its declared kind",
                        path=component.path,
                        anchor=f"components.{component.component_id}.path",
                        remediation=_remediation(
                            "Move the component through an explicit path-only migration.",
                            "Add an old-to-new migration path declaration.",
                            "Move only this component and update path-sensitive references.",
                            "Preserve package, import, runtime, and deployment identities.",
                        ),
                    )
                )
        diagnostics.extend(_cycle_diagnostics(clean_code_edges, by_id))
        return tuple(diagnostics)


def _naming_diagnostics(component: Component, component_kind: ComponentKind) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if component.capability is not None and re.fullmatch(_PATH_TOKEN, component.capability) is None:
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("architecture/schema/component"),
                component_id=component.component_id,
                subject_kind="capability",
                observed=component.capability,
                expected=_PATH_TOKEN,
                message="component capability is not one kebab-case token",
                path=component.path,
                anchor=f"components.{component.component_id}.capability",
                remediation=_remediation(
                    "Choose one lowercase ASCII kebab-case capability token.",
                    "Keep distribution, import, and runtime aliases separate from this identity.",
                ),
            )
        )
    expected_prefix = _component_id_prefix(component, component_kind)
    if expected_prefix is not None and not component.component_id.startswith(expected_prefix):
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("architecture/schema/component"),
                component_id=component.component_id,
                subject_kind="component-id",
                observed=component.component_id,
                expected=f"{expected_prefix}<component>",
                message="component ID disagrees with its declared ownership namespace",
                path=component.path,
                anchor=f"components.{component.component_id}.id",
                remediation=_remediation(
                    "Use the declared ownership namespace in the stable component ID.",
                    "Update exact manifest references and migration evidence together.",
                ),
            )
        )
    return diagnostics


def _component_field_diagnostic(
    component: Component, component_kind: ComponentKind
) -> Diagnostic | None:
    required, forbidden = _COMPONENT_FIELDS[component_kind]
    values = {"product": component.product, "capability": component.capability}
    missing = sorted(field for field in required if values[field] is None)
    present_forbidden = sorted(field for field in forbidden if values[field] is not None)
    if not missing and not present_forbidden:
        return None
    problems: list[str] = [f"missing {field}" for field in missing]
    problems.extend(f"forbidden {field}" for field in present_forbidden)
    expected_parts: list[str] = []
    if required:
        expected_parts.append(f"required={','.join(sorted(required))}")
    if forbidden:
        expected_parts.append(f"forbidden={','.join(sorted(forbidden))}")
    return _diagnostic(
        rule_id=RuleId("architecture/schema/component"),
        component_id=component.component_id,
        subject_kind="component-fields",
        observed="; ".join(problems),
        expected="; ".join(expected_parts) or "no product/capability constraints",
        message="component identity fields contradict its declared kind",
        path=component.path,
        anchor=f"components.{component.component_id}",
        remediation=_remediation(
            "Make the component fields match the selected component kind.",
            "Add required identity fields and remove fields forbidden for this kind.",
            "Then rerun repo-standards so dependent naming and path rules can evaluate.",
        ),
    )


def _component_id_prefix(component: Component, component_kind: ComponentKind) -> str | None:
    if component_kind is ComponentKind.SHARED_LIBRARY or (
        component_kind is ComponentKind.CONTRACT and component.product is None
    ):
        return "shared."
    if component_kind is ComponentKind.FOUNDATION_SERVICE:
        return "foundation."
    if component_kind is ComponentKind.TOOL:
        return "tool."
    if component.product is not None:
        return f"{component.product}."
    return None


def _dependency_diagnostics(
    component: Component,
    by_id: dict[ComponentId, Component],
    kinds: dict[ComponentId, ComponentKind],
    invalid: set[ComponentId],
) -> _DependencyAnalysis:
    diagnostics: list[Diagnostic] = []
    accepted: list[tuple[ComponentId, ComponentId]] = []
    for dependency in component.dependencies:
        if dependency.kind not in EDGE_KINDS:
            ConfigurationError.fail(
                f"component {component.component_id} has unsupported edge type {dependency.kind}"
            )
        target = by_id[dependency.target]
        if target.component_id in invalid:
            continue
        source_kind = kinds[component.component_id]
        target_kind = kinds[target.component_id]
        if dependency.kind not in CODE_EDGES:
            endpoint_diagnostic = _edge_endpoint_diagnostic(
                component, source_kind, target, target_kind, dependency.kind
            )
            if endpoint_diagnostic is not None:
                diagnostics.append(endpoint_diagnostic)
            continue
        boundary = _code_boundary(component, source_kind, target, target_kind)
        if boundary is None:
            accepted.append((component.component_id, target.component_id))
            continue
        rule_id, expected = boundary
        diagnostics.append(
            _edge_diagnostic(
                rule_id,
                component,
                target,
                dependency.kind,
                expected,
                "declared code dependency violates ownership direction",
            )
        )
    return _DependencyAnalysis(diagnostics, accepted)


def _code_boundary(  # ruff: ignore[too-many-return-statements] - precedence is intentionally linear
    source: Component,
    source_kind: ComponentKind,
    target: Component,
    target_kind: ComponentKind,
) -> _CodeBoundary | None:
    if source.component_id == target.component_id:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"), "remove the self dependency"
        )
    if source_kind is ComponentKind.APPLICATION and target_kind is ComponentKind.APPLICATION:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "depend on a library or use a runtime-call edge",
        )
    if source_kind is ComponentKind.CONTRACT and target_kind is not ComponentKind.CONTRACT:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "contracts may depend only on contracts",
        )
    if source_kind in {ComponentKind.PRODUCT_LIBRARY, ComponentKind.SHARED_LIBRARY} and (
        target_kind is ComponentKind.APPLICATION
    ):
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "applications may import libraries; libraries may not import applications",
        )
    if _is_shared_source(source, source_kind) and target.product is not None:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "shared components import no product implementation",
        )
    if source.product and target.product and source.product != target.product:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "use a shared contract/library or runtime-call edge",
        )
    if target_kind not in _ALLOWED_CODE_TARGETS[source_kind]:
        allowed = ",".join(sorted(kind.value for kind in _ALLOWED_CODE_TARGETS[source_kind]))
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            f"{source_kind.value} code targets one of: {allowed or '<none>'}",
        )
    return None


def _is_shared_source(component: Component, kind: ComponentKind) -> bool:
    return kind in {
        ComponentKind.SHARED_LIBRARY,
        ComponentKind.FOUNDATION_SERVICE,
        ComponentKind.TOOL,
    } or (kind is ComponentKind.CONTRACT and component.product is None)


_EDGE_ENDPOINTS: Mapping[str, tuple[frozenset[ComponentKind] | None, frozenset[ComponentKind]]] = (
    MappingProxyType(
        {
            "implements-contract": (
                frozenset(
                    {
                        ComponentKind.APPLICATION,
                        ComponentKind.PRODUCT_LIBRARY,
                        ComponentKind.SHARED_LIBRARY,
                        ComponentKind.FOUNDATION_SERVICE,
                    }
                ),
                frozenset({ComponentKind.CONTRACT}),
            ),
            "generates": (
                frozenset({ComponentKind.CONTRACT, ComponentKind.TOOL}),
                frozenset({ComponentKind.GENERATED_CLIENT}),
            ),
            "runtime-call": (
                None,
                frozenset({ComponentKind.APPLICATION, ComponentKind.FOUNDATION_SERVICE}),
            ),
            "deploys": (
                frozenset({ComponentKind.CLOUD_BUILD, ComponentKind.TOOL}),
                frozenset({ComponentKind.APPLICATION, ComponentKind.FOUNDATION_SERVICE}),
            ),
            "owns-data": (
                frozenset({ComponentKind.APPLICATION, ComponentKind.FOUNDATION_SERVICE}),
                frozenset({ComponentKind.MIGRATION_SET}),
            ),
            "applies-migration": (
                frozenset(
                    {ComponentKind.APPLICATION, ComponentKind.CLOUD_BUILD, ComponentKind.TOOL}
                ),
                frozenset({ComponentKind.MIGRATION_SET}),
            ),
            "terraform-consumes": (None, frozenset({ComponentKind.TERRAFORM_ROOT})),
        }
    )
)


def _edge_endpoint_diagnostic(
    source: Component,
    source_kind: ComponentKind,
    target: Component,
    target_kind: ComponentKind,
    edge_kind: str,
) -> Diagnostic | None:
    constraint = _EDGE_ENDPOINTS.get(edge_kind)
    if constraint is None:
        return None
    allowed_sources, allowed_targets = constraint
    if (allowed_sources is None or source_kind in allowed_sources) and (
        target_kind in allowed_targets
    ):
        return None
    sources = (
        "*" if allowed_sources is None else ",".join(sorted(kind.value for kind in allowed_sources))
    )
    targets = ",".join(sorted(kind.value for kind in allowed_targets))
    return _edge_diagnostic(
        RuleId("architecture/dependencies/policy"),
        source,
        target,
        edge_kind,
        f"source={sources}; target={targets}",
        "typed dependency has incompatible endpoint kinds",
    )


def _edge_diagnostic(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - edge evidence remains explicit
    rule_id: RuleId,
    source: Component,
    target: Component,
    edge_kind: str,
    expected: str,
    message: str,
) -> Diagnostic:
    return _diagnostic(
        rule_id=rule_id,
        component_id=source.component_id,
        subject_kind=edge_kind,
        observed=f"{source.component_id}->{target.component_id}",
        expected=expected,
        message=message,
        path=source.path,
        anchor=(f"components.{source.component_id}.dependencies.{edge_kind}.{target.component_id}"),
        remediation=_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Classify the shared semantic contract.",
            "Move reusable implementation to the correct product or shared library.",
            "Keep runtime integration represented as runtime-call, not source-import.",
        ),
    )


def _cycle_diagnostics(
    edges: list[tuple[ComponentId, ComponentId]],
    by_id: dict[ComponentId, Component],
) -> list[Diagnostic]:
    adjacency: dict[ComponentId, set[ComponentId]] = {item: set() for item in by_id}
    for source, target in edges:
        adjacency[source].add(target)
    diagnostics: list[Diagnostic] = []
    for members in _strongly_connected_components(adjacency):
        if len(members) < _MIN_CYCLE_COMPONENTS:
            continue
        anchor = members[0]
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("architecture/dependencies/policy"),
                component_id=anchor,
                subject_kind="code-cycle",
                observed=" -> ".join((*members, members[0])),
                expected="an acyclic production code dependency graph",
                message="boundary-clean code dependencies form a cycle",
                path=by_id[anchor].path,
                anchor=f"components.{anchor}.dependencies",
                remediation=_remediation(
                    "Break the cycle at a stable semantic boundary.",
                    "Identify the smallest contract shared by the cycle members.",
                    "Move that contract below the cycle without changing runtime identities.",
                ),
            )
        )
    return diagnostics


def _strongly_connected_components(
    adjacency: dict[ComponentId, set[ComponentId]],
) -> tuple[tuple[ComponentId, ...], ...]:
    visited: set[ComponentId] = set()
    finish_order: list[ComponentId] = []
    for root in sorted(adjacency):
        if root in visited:
            continue
        pending: list[tuple[ComponentId, bool]] = [(root, False)]
        while pending:
            node, expanded = pending.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            pending.append((node, True))
            pending.extend(
                (target, False)
                for target in sorted(adjacency[node], reverse=True)
                if target not in visited
            )

    reverse: dict[ComponentId, set[ComponentId]] = {item: set() for item in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].add(source)

    assigned: set[ComponentId] = set()
    result: list[tuple[ComponentId, ...]] = []
    for root in reversed(finish_order):
        if root in assigned:
            continue
        members: list[ComponentId] = []
        pending = [(root, False)]
        assigned.add(root)
        while pending:
            node, _ = pending.pop()
            members.append(node)
            for source in sorted(reverse[node], reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    pending.append((source, False))
        result.append(tuple(sorted(members)))
    return tuple(sorted(result))
