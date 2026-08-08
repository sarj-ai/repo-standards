"""Declarative Sarj repository architecture policy."""

from __future__ import annotations

import re

from repo_lint_core.errors import ConfigurationError
from repo_lint_core.models import Component, Diagnostic, Manifest, Remediation, Rule

PRODUCTS = frozenset({"platform", "vb", "najm"})
COMPONENT_KINDS = frozenset(
    {
        "application",
        "product-library",
        "shared-library",
        "foundation-service",
        "contract",
        "generated-client",
        "terraform-root",
        "tool",
    }
)
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
_PATH_TOKEN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"  # noqa: S105 - regex, not a secret


RULES = (
    Rule(
        rule_id="sarj/layout/unknown-product",
        version=1,
        severity="error",
        summary="Product-owned components use a registered product ID.",
        rationale="Ad-hoc product IDs create ambiguous ownership and target coordinates.",
        bad_example="product = 'new-thing'",
        good_example="product = 'platform'",
    ),
    Rule(
        rule_id="sarj/layout/component-path",
        version=1,
        severity="error",
        summary="Component paths match their declared ownership kind.",
        rationale=(
            "Canonical paths make ownership, impact analysis, and merge preflight deterministic."
        ),
        bad_example="path = 'python/agent'",
        good_example="path = 'products/platform/components/agent'",
    ),
    Rule(
        rule_id="sarj/graph/application-imports-application",
        version=1,
        severity="error",
        summary="Applications do not import another application's implementation.",
        rationale="Source coupling prevents independent release and rollback.",
        bad_example="application A --source-import--> application B",
        good_example="application A --package-dependency--> product library B",
    ),
    Rule(
        rule_id="sarj/graph/cross-product-import",
        version=1,
        severity="error",
        summary="Product code does not import another product's implementation.",
        rationale="Cross-product implementation coupling hides ownership and release dependencies.",
        bad_example="vb library --source-import--> platform library",
        good_example="vb application --runtime-call--> platform API",
    ),
    Rule(
        rule_id="sarj/graph/shared-imports-product",
        version=1,
        severity="error",
        summary="Organization-shared libraries do not import product code.",
        rationale="A shared dependency on one product reverses the intended dependency direction.",
        bad_example="shared library --package-dependency--> vb library",
        good_example="vb application --package-dependency--> shared library",
    ),
    Rule(
        rule_id="sarj/reuse/vague-capability",
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


def _diagnostic(  # noqa: PLR0913 - wire diagnostic fields remain explicit
    *,
    rule_id: str,
    component_id: str,
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


def _expected_path(  # noqa: PLR0911 - direct policy-kind mapping is easier to audit
    kind: str, product: str | None, capability: str | None
) -> str:
    product_token = product or "<product>"
    capability_token = capability or "<capability>"
    if kind == "application":
        return rf"products/{product_token}/components/{_PATH_TOKEN}"
    if kind == "product-library":
        return rf"products/{product_token}/libraries/(python|typescript)/{capability_token}"
    if kind == "shared-library":
        return rf"shared/libraries/(python|typescript)/{capability_token}"
    if kind == "foundation-service":
        return rf"foundation/components/{_PATH_TOKEN}"
    if kind == "contract":
        return rf"(products/{product_token}|shared)/contracts/{_PATH_TOKEN}"
    if kind == "generated-client":
        return rf"products/{product_token}/components/{_PATH_TOKEN}/clients/generated/{_PATH_TOKEN}"
    if kind == "terraform-root":
        return rf"(products/{product_token}/components/{_PATH_TOKEN}|foundation)/.*terraform/.*"
    return rf"(products/{product_token}|foundation|shared|tools)/.*"


class SarjPolicy:
    """Versioned Sarj conventions implemented only against neutral core types."""

    policy_id = "sarj"
    policy_version = 1

    def rules(self) -> tuple[Rule, ...]:
        """Return immutable rule metadata."""
        return RULES

    def evaluate(self, manifest: Manifest) -> tuple[Diagnostic, ...]:
        """Evaluate Sarj ownership and dependency declarations."""
        diagnostics: list[Diagnostic] = []
        by_id = {item.component_id: item for item in manifest.components}
        for component in manifest.components:
            if component.kind not in COMPONENT_KINDS:
                raise ConfigurationError(
                    f"component {component.component_id} has unsupported kind {component.kind}"
                )
            if component.legacy:
                continue
            if (
                component.kind in {"application", "product-library", "contract", "generated-client"}
                and component.product not in PRODUCTS
            ):
                diagnostics.append(
                    _diagnostic(
                        rule_id="sarj/layout/unknown-product",
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
            expected_path = _expected_path(component.kind, component.product, component.capability)
            if re.fullmatch(expected_path, component.path) is None:
                diagnostics.append(
                    _diagnostic(
                        rule_id="sarj/layout/component-path",
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
            if component.capability in VAGUE_CAPABILITIES:
                diagnostics.append(
                    _diagnostic(
                        rule_id="sarj/reuse/vague-capability",
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
            diagnostics.extend(self._dependency_diagnostics(component, by_id))
        return tuple(diagnostics)

    def _dependency_diagnostics(
        self, component: Component, by_id: dict[str, Component]
    ) -> list[Diagnostic]:
        diagnostics: list[Diagnostic] = []
        for dependency in component.dependencies:
            if dependency.kind not in EDGE_KINDS:
                raise ConfigurationError(
                    f"component {component.component_id} has unsupported edge type "
                    f"{dependency.kind}"
                )
            target = by_id[dependency.target]
            if dependency.kind not in CODE_EDGES:
                continue
            rule_id: str | None = None
            expected = ""
            if component.kind == "application" and target.kind == "application":
                rule_id = "sarj/graph/application-imports-application"
                expected = "depend on a library or use a runtime-call edge"
            elif component.product and target.product and component.product != target.product:
                rule_id = "sarj/graph/cross-product-import"
                expected = "use a shared contract/library or runtime-call edge"
            elif component.kind == "shared-library" and target.product:
                rule_id = "sarj/graph/shared-imports-product"
                expected = "shared libraries import no product implementation"
            if rule_id:
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
                            "Replace implementation coupling with an owned library or "
                            "runtime contract.",
                            "Classify the shared semantic contract.",
                            "Move reusable implementation to the correct product or "
                            "shared library.",
                            "Keep runtime integration represented as runtime-call, "
                            "not source-import.",
                        ),
                    )
                )
        return diagnostics
