"""Declarative Sarj repository architecture policy."""

from __future__ import annotations

from enum import StrEnum
import re
from typing import ClassVar, assert_never

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
    product_token = product or "<product>"
    capability_token = capability or "<capability>"
    if kind is ComponentKind.APPLICATION:
        return rf"applications/{product_token}/{_PATH_TOKEN}"
    if kind is ComponentKind.PRODUCT_LIBRARY:
        return rf"libraries/(python|typescript)/{product_token}/{capability_token}"
    if kind is ComponentKind.SHARED_LIBRARY:
        return rf"libraries/(python|typescript)/shared/{capability_token}"
    if kind is ComponentKind.FOUNDATION_SERVICE:
        return rf"foundation/components/{_PATH_TOKEN}"
    if kind is ComponentKind.CONTRACT:
        return rf"contracts/({product_token}|shared)/{_PATH_TOKEN}"
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
    policy_version: ClassVar[int] = 1

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
                diagnostics.append(
                    _diagnostic(
                        rule_id=RuleId("sarj/layout/component-path"),
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
