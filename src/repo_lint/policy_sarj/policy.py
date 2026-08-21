from __future__ import annotations

from enum import StrEnum
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from repo_lint.core.errors import ConfigurationError
from repo_lint.core.models import (
    Component,
    ComponentId,
    Diagnostic,
    ExampleLanguage,
    FixtureId,
    Manifest,
    PolicyId,
    Remediation,
    Rule,
    RuleExamplePair,
    RuleId,
)
from repo_lint.core.taxonomy import (
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
    ProfileDescriptor,
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


def _example(  # ruff: ignore[too-many-arguments, too-many-positional-arguments] - compact data
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
                "sarj-graph-edge-endpoints",
                "Edge endpoints",
                "text",
                "library --implements-contract--> application",
                "application --implements-contract--> contract",
            ),
            _example(
                "sarj-graph-application-dependency",
                "Application dependency",
                "text",
                "application A --source-import--> application B",
                "application A --package-dependency--> product library B",
            ),
            _example(
                "sarj-graph-library-application-dependency",
                "Library application dependency",
                "text",
                "product library --source-import--> application",
                "application --package-dependency--> product library",
            ),
            _example(
                "sarj-graph-self-dependency",
                "Self dependency",
                "text",
                "component A --source-import--> component A",
                "component A has no edge to itself",
            ),
            _example(
                "sarj-graph-cross-product-dependency",
                "Cross-product dependency",
                "text",
                "beta library --source-import--> alpha library",
                "beta application --runtime-call--> alpha API",
            ),
            _example(
                "sarj-graph-shared-product-dependency",
                "Shared-product dependency",
                "text",
                "shared library --package-dependency--> beta library",
                "beta application --package-dependency--> shared library",
            ),
            _example(
                "sarj-graph-contract-implementation-dependency",
                "Contract implementation dependency",
                "text",
                "contract --source-import--> product library",
                "product contract --package-dependency--> shared contract",
            ),
            _example(
                "sarj-graph-disallowed-code-dependency",
                "Disallowed code dependency",
                "text",
                "migration set --source-import--> contract",
                "migration set --package-dependency--> shared library",
            ),
            _example(
                "sarj-graph-code-cycle",
                "Code cycle",
                "text",
                "library A -> library B -> library A",
                "application -> product library -> shared library",
                "warning",
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
                "sarj-layout-component-path",
                "Component path",
                "toml",
                "path = 'python/agent'",
                "path = 'applications/alpha/agent'",
            ),
            _example(
                "sarj-layout-operational-path",
                "Operational path",
                "toml",
                "path = 'iac/alpha'",
                "path = 'deployments/alpha/terraform'",
            ),
            _example(
                "sarj-layout-overlapping-roots",
                "Overlapping component roots",
                "text",
                "services/payments\nservices/payments/worker",
                "services/payments\nservices/worker",
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
                "sarj-schema-component-fields",
                "Component fields",
                "toml",
                "kind = 'shared-library'\nproduct = 'alpha'",
                "kind = 'shared-library'\ncapability = 'request-signing'",
            ),
            _example(
                "sarj-naming-capability-token",
                "Capability token",
                "toml",
                "capability = 'request.signing'",
                "capability = 'request-signing'",
            ),
            _example(
                "sarj-naming-component-id",
                "Component ID",
                "toml",
                "id = 'beta.agent'\nproduct = 'alpha'",
                "id = 'alpha.agent'\nproduct = 'alpha'",
            ),
        ),
    ),
)

_RULE_CLASSIFICATION: Mapping[RuleId, RuleClassification] = MappingProxyType(
    {
        RuleId("architecture/layout/component-paths"): RuleClassification.OBJECTIVE,
        RuleId("architecture/schema/component"): RuleClassification.SCHEMA,
        RuleId("architecture/dependencies/policy"): RuleClassification.OBJECTIVE,
    }
)
_RULE_PRECEDENCE: Mapping[RuleId, int] = MappingProxyType(
    {
        RuleId("architecture/schema/component"): 10,
        RuleId("architecture/dependencies/policy"): 20,
        RuleId("architecture/layout/component-paths"): 30,
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
    {rule.rule_id: "declared" for rule in RULES}
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
    policy_version=5,
    profile=ProfileDescriptor(
        profile_id=PROFILE_ID,
        title="Sarj repository standard",
        product_registry_mode="open",
        repository_overrides=False,
        target_repository_plugins=False,
    ),
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


def _component_field_value(
    component: Component, field: Literal["product", "capability"]
) -> str | None:
    if field == "product":
        return component.product
    return component.capability


class SarjPolicy:
    policy_id: ClassVar[PolicyId] = PolicyId("sarj")
    policy_version: ClassVar[int] = POLICY_SPEC.policy_version
    profile_id: ClassVar[str] = PROFILE_ID

    @staticmethod
    def spec() -> PolicySpec:
        return POLICY_SPEC

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        return RULES

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
