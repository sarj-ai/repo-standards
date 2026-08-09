"""Declarative Sarj repository architecture policy."""

from __future__ import annotations

from enum import StrEnum
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, assert_never

from repo_lint_core.errors import ConfigurationError
from repo_lint_core.models import (
    Component,
    ComponentId,
    Diagnostic,
    Manifest,
    PolicyId,
    Remediation,
    Rule,
    RuleId,
)


if TYPE_CHECKING:
    from collections.abc import Mapping


PRODUCTS = frozenset({"platform", "vb", "najm"})


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
VAGUE_CAPABILITIES = frozenset({"common", "core", "helpers", "shared", "utils"})
_PATH_TOKEN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"  # ruff: ignore[hardcoded-password-string] - regex, not a secret
_APPLICATION_ROLE = rf"(?:api|agent|worker|web|{_PATH_TOKEN}-(?:api|agent|worker|web))"
_OPERATIONAL_KINDS = frozenset(
    {
        ComponentKind.TERRAFORM_ROOT,
        ComponentKind.CLOUD_BUILD,
        ComponentKind.KUBERNETES,
        ComponentKind.CLOUDFLARE,
    }
)
_COMPONENT_FIELDS: Mapping[
    ComponentKind, tuple[frozenset[str], frozenset[str]]
] = MappingProxyType({
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
})


RULES = (
    Rule(
        rule_id=RuleId("sarj/layout/unknown-product"),
        version=1,
        severity="error",
        summary="Product-owned components use a registered product ID.",
        rationale="Ad-hoc product IDs create ambiguous ownership and target coordinates.",
        bad_example="product = 'new-thing'",
        good_example="product = 'platform'",
    ),
    Rule(
        rule_id=RuleId("sarj/layout/component-path"),
        version=1,
        severity="error",
        summary="Component paths match their declared ownership kind.",
        rationale=(
            "Canonical paths make ownership, impact analysis, and merge preflight deterministic."
        ),
        bad_example="path = 'python/agent'",
        good_example="path = 'applications/platform/agent'",
    ),
    Rule(
        rule_id=RuleId("sarj/layout/operational-path"),
        version=1,
        severity="warning",
        summary="Operational configuration has a declared consolidation target.",
        rationale=(
            "Operational configuration moves can affect build context, state, triggers, and "
            "runtime behavior, so target placement remains advisory until verified."
        ),
        bad_example="path = 'iac/platform'",
        good_example="path = 'deployments/platform/terraform'",
    ),
    Rule(
        rule_id=RuleId("sarj/schema/component-fields"),
        version=1,
        severity="error",
        summary="Each component kind has exact required and forbidden identity fields.",
        rationale=(
            "Contradictory ownership fields make path and component-name derivation ambiguous."
        ),
        bad_example="kind = 'shared-library', product = 'platform'",
        good_example="kind = 'shared-library', capability = 'request-signing'",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/application-imports-application"),
        version=1,
        severity="error",
        summary="Applications do not import another application's implementation.",
        rationale="Source coupling prevents independent release and rollback.",
        bad_example="application A --source-import--> application B",
        good_example="application A --package-dependency--> product library B",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/library-imports-application"),
        version=1,
        severity="error",
        summary="Libraries do not import application implementation.",
        rationale=(
            "Reusable code must remain below deployable applications in the dependency graph."
        ),
        bad_example="product library --source-import--> application",
        good_example="application --package-dependency--> product library",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/self-dependency"),
        version=1,
        severity="error",
        summary="Components do not declare dependencies on themselves.",
        rationale="Self edges are invalid graph evidence and can hide resolver mistakes.",
        bad_example="component A --source-import--> component A",
        good_example="omit the redundant self edge",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/cross-product-import"),
        version=1,
        severity="error",
        summary="Product code does not import another product's implementation.",
        rationale="Cross-product implementation coupling hides ownership and release dependencies.",
        bad_example="vb library --source-import--> platform library",
        good_example="vb application --runtime-call--> platform API",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/shared-imports-product"),
        version=1,
        severity="error",
        summary="Organization-shared libraries do not import product code.",
        rationale="A shared dependency on one product reverses the intended dependency direction.",
        bad_example="shared library --package-dependency--> vb library",
        good_example="vb application --package-dependency--> shared library",
    ),
    Rule(
        rule_id=RuleId("sarj/reuse/vague-capability"),
        version=1,
        severity="warning",
        summary="Reusable libraries have narrow capability names.",
        rationale="Generic names become dependency magnets and conceal ownership.",
        bad_example="capability = 'utils'",
        good_example="capability = 'request-signing'",
    ),
    Rule(
        rule_id=RuleId("sarj/naming/application-role"),
        version=1,
        severity="warning",
        summary="Application names end in a controlled deployable role.",
        rationale=(
            "Role-bearing names make deployment ownership and repository navigation explicit."
        ),
        bad_example="applications/platform/integration",
        good_example="applications/platform/integration-api",
    ),
    Rule(
        rule_id=RuleId("sarj/naming/component-id"),
        version=1,
        severity="error",
        summary="Stable component IDs include their declared ownership namespace.",
        rationale=(
            "An ID that disagrees with product ownership makes diagnostics and "
            "migrations ambiguous."
        ),
        bad_example="id = 'vb.agent', product = 'platform'",
        good_example="id = 'platform.agent', product = 'platform'",
    ),
    Rule(
        rule_id=RuleId("sarj/naming/capability-token"),
        version=1,
        severity="error",
        summary="Capabilities use one lowercase ASCII kebab-case token.",
        rationale="One canonical token derives stable paths without ecosystem-specific ambiguity.",
        bad_example="capability = 'request.signing'",
        good_example="capability = 'request-signing'",
    ),
)


def _remediation(summary: str, *steps: str) -> Remediation:
    return Remediation(
        summary=summary,
        steps=steps,
        validation=("Run repo-lint check again and inspect the typed dependency graph.",),
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


def _expected_path(  # ruff: ignore[too-many-return-statements] - direct policy-kind mapping is easier to audit
    kind: ComponentKind, product: str | None, capability: str | None
) -> str:
    product_token = re.escape(product) if product else "<product>"
    capability_token = re.escape(capability) if capability else "<capability>"
    if kind is ComponentKind.APPLICATION:
        return rf"applications/{product_token}/{_PATH_TOKEN}"
    if kind is ComponentKind.PRODUCT_LIBRARY:
        return rf"libraries/(python|typescript)/{product_token}/{capability_token}"
    if kind is ComponentKind.SHARED_LIBRARY:
        return rf"libraries/(python|typescript)/shared/{capability_token}"
    if kind is ComponentKind.FOUNDATION_SERVICE:
        return rf"foundation/components/{_PATH_TOKEN}"
    if kind is ComponentKind.CONTRACT:
        owner_token = product_token if product else "shared"
        return rf"contracts/{owner_token}/{_PATH_TOKEN}"
    if kind is ComponentKind.GENERATED_CLIENT:
        return rf"clients/generated/{product_token}/{capability_token}/(python|typescript)"
    if kind is ComponentKind.MIGRATION_SET:
        return rf"migrations/{product_token}/{_PATH_TOKEN}"
    if kind is ComponentKind.TERRAFORM_ROOT:
        return rf"deployments/{product_token}/terraform(/.*)?"
    if kind is ComponentKind.CLOUD_BUILD:
        return rf"deployments/{product_token}/cloud-build/{capability_token}/cloudbuild\.ya?ml"
    if kind is ComponentKind.KUBERNETES:
        return rf"deployments/{product_token}/kubernetes/{capability_token}(/.*)?"
    if kind is ComponentKind.CLOUDFLARE:
        return rf"deployments/{product_token}/cloudflare/{capability_token}(/.*)?"
    if kind is ComponentKind.TOOL:
        return rf"tools/(ci|mcp|development)/{capability_token}"
    assert_never(kind)


class SarjPolicy:
    """Versioned Sarj conventions implemented only against neutral core types."""

    policy_id: ClassVar[PolicyId] = PolicyId("sarj")
    policy_version: ClassVar[int] = 2

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        """Return immutable rule metadata."""
        return RULES

    @staticmethod
    def evaluate(manifest: Manifest) -> tuple[Diagnostic, ...]:
        """Evaluate Sarj ownership and dependency declarations."""
        diagnostics: list[Diagnostic] = []
        by_id = {item.component_id: item for item in manifest.components}
        for component in manifest.components:
            try:
                component_kind = ComponentKind(component.kind)
            except ValueError:
                ConfigurationError.fail(
                    f"component {component.component_id} has unsupported kind {component.kind}"
                )
            diagnostics.extend(_dependency_diagnostics(component, by_id))
            field_diagnostic = _component_field_diagnostic(component, component_kind)
            if field_diagnostic is not None:
                diagnostics.append(field_diagnostic)
                continue
            diagnostics.extend(_naming_diagnostics(component, component_kind))
            if (
                component_kind
                in {
                    ComponentKind.APPLICATION,
                    ComponentKind.PRODUCT_LIBRARY,
                    ComponentKind.GENERATED_CLIENT,
                    ComponentKind.MIGRATION_SET,
                    ComponentKind.TERRAFORM_ROOT,
                    ComponentKind.CLOUD_BUILD,
                    ComponentKind.KUBERNETES,
                    ComponentKind.CLOUDFLARE,
                }
                or (component_kind is ComponentKind.CONTRACT and component.product is not None)
            ) and component.product not in PRODUCTS:
                diagnostics.append(
                    _diagnostic(
                        rule_id=RuleId("sarj/layout/unknown-product"),
                        component_id=component.component_id,
                        subject_kind="product",
                        observed=component.product or "<missing>",
                        expected="platform|vb|najm",
                        message="component uses an unregistered product",
                        path=component.path,
                        anchor=f"components.{component.component_id}.product",
                        remediation=_remediation(
                            "Use an allocated Sarj product ID.",
                            "Select platform, vb, or najm, or update the reviewed Sarj "
                            "policy first.",
                        ),
                    )
                )
            expected_path = _expected_path(component_kind, component.product, component.capability)
            if re.fullmatch(expected_path, component.path) is None:
                rule_id = (
                    RuleId("sarj/layout/operational-path")
                    if component_kind in _OPERATIONAL_KINDS
                    else RuleId("sarj/layout/component-path")
                )
                diagnostics.append(
                    _diagnostic(
                        rule_id=rule_id,
                        component_id=component.component_id,
                        subject_kind="component-path",
                        observed=component.path,
                        expected=expected_path,
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
            if (
                component_kind in {ComponentKind.PRODUCT_LIBRARY, ComponentKind.SHARED_LIBRARY}
                and component.capability in VAGUE_CAPABILITIES
            ):
                diagnostics.append(
                    _diagnostic(
                        rule_id=RuleId("sarj/reuse/vague-capability"),
                        component_id=component.component_id,
                        subject_kind="capability",
                        observed=component.capability,
                        expected="a narrow capability name",
                        message="reusable asset uses a vague capability name",
                        path=component.path,
                        anchor=f"components.{component.component_id}.capability",
                        remediation=_remediation(
                            "Name the stable capability rather than its generic utility role.",
                            "Identify the cohesive public contract and choose its capability name.",
                        ),
                    )
                )
        return tuple(diagnostics)


def _naming_diagnostics(
    component: Component, component_kind: ComponentKind
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if component.capability is not None and re.fullmatch(_PATH_TOKEN, component.capability) is None:
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("sarj/naming/capability-token"),
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
                rule_id=RuleId("sarj/naming/component-id"),
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
    if component_kind is ComponentKind.APPLICATION:
        application_name = component.path.rsplit("/", maxsplit=1)[-1]
        canonical_application_path = (
            rf"applications/{re.escape(component.product or '')}/{_PATH_TOKEN}"
        )
        if (
            re.fullmatch(canonical_application_path, component.path) is not None
            and re.fullmatch(_APPLICATION_ROLE, application_name) is None
        ):
            diagnostics.append(
                _diagnostic(
                    rule_id=RuleId("sarj/naming/application-role"),
                    component_id=component.component_id,
                    subject_kind="application-role",
                    observed=application_name,
                    expected="api|agent|worker|web|<domain>-(api|agent|worker|web)",
                    message="application name does not end in a controlled deployable role",
                    path=component.path,
                    anchor=f"components.{component.component_id}.path",
                    remediation=_remediation(
                        "Name the deployable by its role or domain and role.",
                        "Use api, agent, worker, or web as the final role token.",
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
        rule_id=RuleId("sarj/schema/component-fields"),
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
            "Then rerun repo-lint so dependent naming and path rules can evaluate.",
        ),
    )


def _component_id_prefix(
    component: Component, component_kind: ComponentKind
) -> str | None:
    if component_kind is ComponentKind.SHARED_LIBRARY or (
        component_kind is ComponentKind.CONTRACT and component.product is None
    ):
        return "shared."
    if component_kind is ComponentKind.FOUNDATION_SERVICE:
        return "foundation."
    if component_kind is ComponentKind.TOOL:
        return "tool."
    if component.product in PRODUCTS:
        return f"{component.product}."
    return None


def _dependency_diagnostics(
    component: Component, by_id: dict[ComponentId, Component]
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for dependency in component.dependencies:
        if dependency.kind not in EDGE_KINDS:
            ConfigurationError.fail(
                f"component {component.component_id} has unsupported edge type {dependency.kind}"
            )
        target = by_id[dependency.target]
        if dependency.kind not in CODE_EDGES:
            continue
        rule_id: RuleId | None = None
        expected = ""
        if component.component_id == target.component_id:
            rule_id = RuleId("sarj/graph/self-dependency")
            expected = "remove the self dependency"
        elif component.kind == "application" and target.kind == "application":
            rule_id = RuleId("sarj/graph/application-imports-application")
            expected = "depend on a library or use a runtime-call edge"
        elif (
            component.kind in {"product-library", "shared-library"} and target.kind == "application"
        ):
            rule_id = RuleId("sarj/graph/library-imports-application")
            expected = "applications may import libraries; libraries may not import applications"
        elif component.product and target.product and component.product != target.product:
            rule_id = RuleId("sarj/graph/cross-product-import")
            expected = "use a shared contract/library or runtime-call edge"
        elif component.kind == "shared-library" and target.product:
            rule_id = RuleId("sarj/graph/shared-imports-product")
            expected = "shared libraries import no product implementation"
        if rule_id is not None:
            diagnostics.append(
                _diagnostic(
                    rule_id=rule_id,
                    component_id=component.component_id,
                    subject_kind=dependency.kind,
                    observed=f"{component.component_id}->{target.component_id}",
                    expected=expected,
                    message="declared code dependency violates ownership direction",
                    path=component.path,
                    anchor=(
                        f"components.{component.component_id}.dependencies."
                        f"{dependency.kind}.{target.component_id}"
                    ),
                    remediation=_remediation(
                        (
                            "Replace implementation coupling with an owned library or "
                            "runtime contract."
                        ),
                        "Classify the shared semantic contract.",
                        "Move reusable implementation to the correct product or shared library.",
                        "Keep runtime integration represented as runtime-call, not source-import.",
                    ),
                )
            )
    return diagnostics
