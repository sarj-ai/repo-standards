from __future__ import annotations

from typing import NamedTuple

import pytest

from repo_standards.core.engine import analyze
from repo_standards.core.models import (
    AnalysisReport,
    Component,
    ComponentId,
    Dependency,
    Manifest,
    Mode,
    RepositoryId,
)
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.policy_sarj.policy import POLICY_SPEC, RULE_GOVERNANCE
from repo_standards.policy_sarj.spec import RuleClassification, RuleMaturity


def _analyze(*components: Component) -> AnalysisReport:
    return analyze(
        Manifest(
            RepositoryId("example-repository"),
            components,
        ),
        SarjPolicy(),
        mode=Mode("report"),
    )


class EdgeComponents(NamedTuple):
    source: Component
    target: Component


def test_canonical_application_is_clean() -> None:
    report = _analyze(
        Component(
            ComponentId("alpha.agent"),
            "application",
            "applications/alpha/agent",
            "@example/alpha",
            product="alpha",
        )
    )
    assert report.diagnostics == ()


@pytest.mark.parametrize(
    "component_name",
    [
        pytest.param("api", id="role"),
        pytest.param("integration-api", id="domain-api"),
        pytest.param("dashboard-web", id="domain-web"),
    ],
)
def test_canonical_application_roles_are_clean(component_name: str) -> None:
    report = _analyze(
        Component(
            ComponentId(f"alpha.{component_name}"),
            "application",
            f"applications/alpha/{component_name}",
            "@example/alpha",
            product="alpha",
        )
    )
    assert report.diagnostics == ()


@pytest.mark.parametrize(
    "component_name",
    [
        pytest.param("helpers", id="vague-capability"),
        pytest.param("integration", id="missing-role"),
        pytest.param("api-service", id="role-not-final"),
    ],
)
def test_application_roles_are_not_policy_keywords(component_name: str) -> None:
    report = _analyze(
        Component(
            ComponentId(f"alpha.{component_name}"),
            "application",
            f"applications/alpha/{component_name}",
            "@example/alpha",
            product="alpha",
        )
    )
    assert report.diagnostics == ()


def test_invalid_application_path_does_not_cascade_into_role_warning() -> None:
    report = _analyze(
        Component(
            ComponentId("alpha.helpers"),
            "application",
            "python/helpers",
            "@example/alpha",
            product="alpha",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["architecture/layout/component-paths"]


def test_product_component_id_must_match_declared_product() -> None:
    report = _analyze(
        Component(
            ComponentId("beta.agent"),
            "application",
            "applications/alpha/agent",
            "@example/alpha",
            product="alpha",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["architecture/schema/component"]


def test_library_capability_must_be_one_kebab_case_token() -> None:
    report = _analyze(
        Component(
            ComponentId("alpha.request-signing"),
            "product-library",
            "libraries/python/alpha/request.signing",
            "@example/alpha",
            product="alpha",
            capability="request.signing",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["architecture/schema/component"]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("alpha.api"),
                "application",
                "applications/alpha/api",
                "@example/alpha",
                product="alpha",
                capability="api",
            ),
            id="application-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.request-signing"),
                "product-library",
                "libraries/python/alpha/request-signing",
                "@example/alpha",
                product="alpha",
            ),
            id="product-library-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.request-signing"),
                "shared-library",
                "libraries/python/shared/request-signing",
                "@example/alpha",
                product="alpha",
                capability="request-signing",
            ),
            id="shared-library-forbids-product",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.identity"),
                "foundation-service",
                "foundation/components/identity",
                "@example/alpha",
                product="alpha",
            ),
            id="foundation-forbids-product",
        ),
        pytest.param(
            Component(
                ComponentId("shared.events"),
                "contract",
                "contracts/shared/events",
                "@example/alpha",
                capability="events",
            ),
            id="contract-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.billing-client"),
                "generated-client",
                "clients/generated/alpha/billing/python",
                "@example/alpha",
                product="alpha",
            ),
            id="generated-client-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.primary-migrations"),
                "migration-set",
                "migrations/alpha/primary",
                "@example/alpha",
                product="alpha",
                capability="primary",
            ),
            id="migration-set-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.terraform"),
                "terraform-root",
                "deployments/alpha/terraform",
                "@example/alpha",
                product="alpha",
                capability="core",
            ),
            id="terraform-root-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.api-build"),
                "cloud-build",
                "deployments/alpha/cloud-build/api/cloudbuild.yaml",
                "@example/alpha",
                product="alpha",
            ),
            id="cloud-build-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.api-kubernetes"),
                "kubernetes",
                "deployments/alpha/kubernetes/api",
                "@example/alpha",
                product="alpha",
            ),
            id="kubernetes-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.web-cloudflare"),
                "cloudflare",
                "deployments/alpha/cloudflare/web",
                "@example/alpha",
                product="alpha",
            ),
            id="cloudflare-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.release"),
                "tool",
                "tools/ci/release",
                "@example/alpha",
                product="alpha",
                capability="release",
            ),
            id="tool-forbids-product",
        ),
    ],
)
def test_component_kind_fields_are_exact_without_cascades(component: Component) -> None:
    report = _analyze(component)
    assert [item.rule_id for item in report.diagnostics] == ["architecture/schema/component"]
    assert report.diagnostics[0].severity == "error"


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("alpha.request-signing"),
                "product-library",
                "libraries/python/alpha/request-signing",
                "@example/alpha",
                product="alpha",
                capability="request-signing",
            ),
            id="product-library",
        ),
        pytest.param(
            Component(
                ComponentId("shared.request-signing"),
                "shared-library",
                "libraries/typescript/shared/request-signing",
                "@example/alpha",
                capability="request-signing",
            ),
            id="shared-library",
        ),
        pytest.param(
            Component(
                ComponentId("foundation.identity"),
                "foundation-service",
                "foundation/components/identity",
                "@example/alpha",
            ),
            id="foundation-service",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.events"),
                "contract",
                "contracts/alpha/events",
                "@example/alpha",
                product="alpha",
            ),
            id="product-contract",
        ),
        pytest.param(
            Component(
                ComponentId("shared.events"),
                "contract",
                "contracts/shared/events",
                "@example/alpha",
            ),
            id="shared-contract",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.billing-client"),
                "generated-client",
                "clients/generated/alpha/billing/python",
                "@example/alpha",
                product="alpha",
                capability="billing",
            ),
            id="generated-client",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.primary-migrations"),
                "migration-set",
                "migrations/alpha/primary",
                "@example/alpha",
                product="alpha",
            ),
            id="migration-set",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.terraform"),
                "terraform-root",
                "deployments/alpha/terraform",
                "@example/alpha",
                product="alpha",
            ),
            id="terraform-root",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.api-build"),
                "cloud-build",
                "deployments/alpha/cloud-build/api/cloudbuild.yaml",
                "@example/alpha",
                product="alpha",
                capability="api",
            ),
            id="cloud-build",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.api-kubernetes"),
                "kubernetes",
                "deployments/alpha/kubernetes/api",
                "@example/alpha",
                product="alpha",
                capability="api",
            ),
            id="kubernetes",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.web-cloudflare"),
                "cloudflare",
                "deployments/alpha/cloudflare/web",
                "@example/alpha",
                product="alpha",
                capability="web",
            ),
            id="cloudflare",
        ),
        pytest.param(
            Component(
                ComponentId("tool.release"),
                "tool",
                "tools/ci/release",
                "@example/alpha",
                capability="release",
            ),
            id="tool",
        ),
    ],
)
def test_every_canonical_component_kind_is_clean(component: Component) -> None:
    assert _analyze(component).diagnostics == ()


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("alpha.request-signing"),
                "product-library",
                "libraries/go/alpha/request-signing",
                "@example/alpha",
                product="alpha",
                capability="request-signing",
            ),
            id="unsupported-library-language",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.primary-migrations"),
                "migration-set",
                "datastores/alpha/primary/migrations",
                "@example/alpha",
                product="alpha",
            ),
            id="legacy-datastore-path",
        ),
        pytest.param(
            Component(
                ComponentId("tool.release"),
                "tool",
                "tools/random/release",
                "@example/alpha",
                capability="release",
            ),
            id="unknown-tool-category",
        ),
    ],
)
def test_noncanonical_component_layouts_are_rejected(component: Component) -> None:
    assert [item.rule_id for item in _analyze(component).diagnostics] == [
        "architecture/layout/component-paths"
    ]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("alpha.terraform"),
                "terraform-root",
                "iac/alpha",
                "@example/alpha",
                product="alpha",
            ),
            id="terraform",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.api-build"),
                "cloud-build",
                "cloudbuild.yaml",
                "@example/alpha",
                product="alpha",
                capability="api",
            ),
            id="cloud-build",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.api-kubernetes"),
                "kubernetes",
                "k8s/api",
                "@example/alpha",
                product="alpha",
                capability="api",
            ),
            id="kubernetes",
        ),
        pytest.param(
            Component(
                ComponentId("alpha.web-cloudflare"),
                "cloudflare",
                "applications/alpha/web/wrangler.jsonc",
                "@example/alpha",
                product="alpha",
                capability="web",
            ),
            id="cloudflare",
        ),
    ],
)
def test_operational_layout_targets_use_the_component_path_contract(component: Component) -> None:
    report = _analyze(component)
    assert [item.rule_id for item in report.diagnostics] == ["architecture/layout/component-paths"]
    assert report.diagnostics[0].severity == "error"


def test_product_contract_cannot_use_shared_path() -> None:
    report = _analyze(
        Component(
            ComponentId("alpha.events"),
            "contract",
            "contracts/shared/events",
            "@example/alpha",
            product="alpha",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["architecture/layout/component-paths"]


def test_application_source_import_is_rejected_but_runtime_call_is_allowed() -> None:
    source = Component(
        ComponentId("alpha.api"),
        "application",
        "applications/alpha/api",
        "@example/alpha",
        product="alpha",
        dependencies=(Dependency(ComponentId("alpha.worker"), "source-import"),),
    )
    target = Component(
        ComponentId("alpha.worker"),
        "application",
        "applications/alpha/worker",
        "@example/alpha",
        product="alpha",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "architecture/dependencies/policy"
    ]
    runtime = replace_dependency(source, Dependency(ComponentId("alpha.worker"), "runtime-call"))
    assert _analyze(runtime, target).diagnostics == ()


def replace_dependency(component: Component, dependency: Dependency) -> Component:
    return Component(
        component.component_id,
        component.kind,
        component.path,
        component.owner,
        component.product,
        component.capability,
        component.legacy,
        (dependency,),
    )


def test_cross_product_import_is_rejected() -> None:
    source = Component(
        ComponentId("beta.client"),
        "product-library",
        "libraries/python/beta/client",
        "@example/beta",
        product="beta",
        capability="client",
        dependencies=(Dependency(ComponentId("alpha.contract"), "package-dependency"),),
    )
    target = Component(
        ComponentId("alpha.contract"),
        "contract",
        "contracts/alpha/events",
        "@example/alpha",
        product="alpha",
    )
    assert "architecture/dependencies/policy" in {
        item.rule_id for item in _analyze(source, target).diagnostics
    }


def test_generic_but_valid_capability_is_allowed() -> None:
    report = _analyze(
        Component(
            ComponentId("alpha.utils"),
            "product-library",
            "libraries/python/alpha/utils",
            "@example/alpha",
            product="alpha",
            capability="utils",
        )
    )
    assert report.diagnostics == ()


def test_shared_contract_and_migration_paths_are_canonical() -> None:
    shared_contract = Component(
        ComponentId("shared.events"),
        "contract",
        "contracts/shared/events",
        "@example/alpha",
    )
    migrations = Component(
        ComponentId("alpha.primary-migrations"),
        "migration-set",
        "migrations/alpha/primary",
        "@example/alpha",
        product="alpha",
    )
    assert _analyze(shared_contract, migrations).diagnostics == ()


def test_library_importing_application_is_rejected() -> None:
    library = Component(
        ComponentId("alpha.client"),
        "product-library",
        "libraries/python/alpha/client",
        "@example/alpha",
        product="alpha",
        capability="client",
        dependencies=(Dependency(ComponentId("alpha.api"), "source-import"),),
    )
    application = Component(
        ComponentId("alpha.api"),
        "application",
        "applications/alpha/api",
        "@example/alpha",
        product="alpha",
    )
    assert [item.rule_id for item in _analyze(library, application).diagnostics] == [
        "architecture/dependencies/policy"
    ]


def test_policy_spec_governance_covers_every_rule() -> None:
    assert POLICY_SPEC.profile_id == "sarj/public"
    assert POLICY_SPEC.title == "Sarj repository standard"
    assert POLICY_SPEC.policy_version == SarjPolicy.policy_version == 12
    assert {item.rule_id for item in RULE_GOVERNANCE} == {
        item.rule_id for item in SarjPolicy.rules()
    }
    assert {item.evidence for item in RULE_GOVERNANCE} == {"declared", "verified"}
    assert all(item.upstream for item in RULE_GOVERNANCE)


def test_warning_rules_are_explicitly_judgment_or_operational() -> None:
    by_id = {item.rule_id: item for item in RULE_GOVERNANCE}
    for rule in SarjPolicy.rules():
        metadata = by_id[rule.rule_id]
        if rule.severity == "warning":
            assert metadata.maturity is RuleMaturity.WARNING
            assert metadata.classification in {
                RuleClassification.JUDGMENT,
                RuleClassification.OPERATIONAL,
            }
        else:
            assert metadata.maturity is RuleMaturity.STABLE_ERROR


def test_delivery_rules_are_not_public_policy_rules() -> None:
    assert all(not rule.rule_id.startswith("delivery/") for rule in SarjPolicy.rules())


def test_public_expected_path_is_a_template_not_a_regex() -> None:
    report = _analyze(
        Component(
            ComponentId("alpha.signing"),
            "product-library",
            "python/signing",
            "@example/alpha",
            product="alpha",
            capability="signing",
        )
    )
    expected = report.diagnostics[0].expected
    assert expected == "libraries/{kotlin,python,swift,typescript}/alpha/signing"
    assert "(?:" not in expected
    assert "\\" not in expected


def test_invalid_source_fields_precede_and_suppress_graph_rules() -> None:
    source = Component(
        ComponentId("alpha.client"),
        "product-library",
        "libraries/python/alpha/client",
        "@example/alpha",
        product="alpha",
        dependencies=(Dependency(ComponentId("alpha.api"), "source-import"),),
    )
    target = Component(
        ComponentId("alpha.api"),
        "application",
        "applications/alpha/api",
        "@example/alpha",
        product="alpha",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "architecture/schema/component"
    ]


def test_invalid_target_fields_precede_and_suppress_graph_rules() -> None:
    source = Component(
        ComponentId("alpha.client"),
        "product-library",
        "libraries/python/alpha/client",
        "@example/alpha",
        product="alpha",
        capability="client",
        dependencies=(Dependency(ComponentId("alpha.api"), "source-import"),),
    )
    target = Component(
        ComponentId("alpha.api"),
        "application",
        "applications/alpha/api",
        "@example/alpha",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "architecture/schema/component"
    ]


def _edge_components(
    source_kind: str,
    target_kind: str,
    *,
    edge_kind: str = "package-dependency",
) -> EdgeComponents:
    fixtures = {
        "application": ("alpha.app", "applications/alpha/api", "alpha", None),
        "product-library": (
            "alpha.library",
            "libraries/python/alpha/library",
            "alpha",
            "library",
        ),
        "shared-library": (
            "shared.library",
            "libraries/python/shared/library",
            None,
            "library",
        ),
        "foundation-service": (
            "foundation.identity",
            "foundation/components/identity",
            None,
            None,
        ),
        "contract": ("alpha.contract", "contracts/alpha/events", "alpha", None),
        "generated-client": (
            "alpha.generated",
            "clients/generated/alpha/generated/python",
            "alpha",
            "generated",
        ),
        "migration-set": (
            "alpha.migrations",
            "migrations/alpha/primary",
            "alpha",
            None,
        ),
        "tool": ("tool.release", "tools/ci/release", None, "release"),
    }
    source_id, source_path, source_product, source_capability = fixtures[source_kind]
    target_id, target_path, target_product, target_capability = fixtures[target_kind]
    if source_kind == target_kind:
        if target_kind == "application":
            target_id, target_path = "alpha.target-api", "applications/alpha/target-api"
        elif target_kind == "product-library":
            target_id = "alpha.target-library"
            target_path = "libraries/python/alpha/target-library"
            target_capability = "target-library"
        elif target_kind == "contract":
            target_id, target_path = "alpha.target-contract", "contracts/alpha/target-events"
    source = Component(
        ComponentId(source_id),
        source_kind,
        source_path,
        "@example/alpha",
        product=source_product,
        capability=source_capability,
        dependencies=(Dependency(ComponentId(target_id), edge_kind),),
    )
    target = Component(
        ComponentId(target_id),
        target_kind,
        target_path,
        "@example/alpha",
        product=target_product,
        capability=target_capability,
    )
    return EdgeComponents(source, target)


@pytest.mark.parametrize(
    ("source_kind", "target_kind"),
    [
        pytest.param("application", "product-library", id="application-product-library"),
        pytest.param("product-library", "shared-library", id="product-shared"),
        pytest.param("contract", "contract", id="contract-contract"),
        pytest.param("generated-client", "shared-library", id="generated-runtime"),
        pytest.param("tool", "shared-library", id="tool-shared"),
    ],
)
def test_closed_code_matrix_allows_only_reviewed_layers(source_kind: str, target_kind: str) -> None:
    assert _analyze(*_edge_components(source_kind, target_kind)).diagnostics == ()


@pytest.mark.parametrize(
    ("source_kind", "target_kind", "rule_id"),
    [
        pytest.param(
            "application",
            "application",
            "architecture/dependencies/policy",
            id="application-application",
        ),
        pytest.param(
            "contract",
            "product-library",
            "architecture/dependencies/policy",
            id="contract-implementation",
        ),
        pytest.param(
            "product-library",
            "application",
            "architecture/dependencies/policy",
            id="library-application",
        ),
        pytest.param(
            "migration-set",
            "contract",
            "architecture/dependencies/policy",
            id="closed-matrix",
        ),
    ],
)
def test_closed_code_matrix_emits_one_precedence_rule(
    source_kind: str, target_kind: str, rule_id: str
) -> None:
    report = _analyze(*_edge_components(source_kind, target_kind))
    assert [item.rule_id for item in report.diagnostics] == [rule_id]


def test_typed_edge_endpoints_reject_invalid_runtime_call() -> None:
    report = _analyze(*_edge_components("application", "product-library", edge_kind="runtime-call"))
    assert [item.rule_id for item in report.diagnostics] == ["architecture/dependencies/policy"]


def test_typed_edge_endpoints_allow_application_runtime_call() -> None:
    source, target = _edge_components("application", "application", edge_kind="runtime-call")
    target = Component(
        ComponentId("alpha.target-api"),
        target.kind,
        "applications/alpha/target-api",
        target.owner,
        product=target.product,
    )
    source = Component(
        source.component_id,
        source.kind,
        source.path,
        source.owner,
        product=source.product,
        dependencies=(Dependency(target.component_id, "runtime-call"),),
    )
    assert _analyze(source, target).diagnostics == ()


def test_boundary_clean_cycle_is_part_of_dependency_policy() -> None:
    first, second = _edge_components("product-library", "product-library")
    second = Component(
        second.component_id,
        second.kind,
        second.path,
        second.owner,
        product=second.product,
        capability=second.capability,
        dependencies=(Dependency(first.component_id, "package-dependency"),),
    )
    report = _analyze(first, second)
    assert [item.rule_id for item in report.diagnostics] == ["architecture/dependencies/policy"]
    assert report.diagnostics[0].severity == "error"


def test_forbidden_edges_do_not_cascade_into_cycle_warning() -> None:
    first, second = _edge_components("application", "application")
    second = Component(
        second.component_id,
        second.kind,
        second.path,
        second.owner,
        product=second.product,
        dependencies=(Dependency(first.component_id, "package-dependency"),),
    )
    report = _analyze(first, second)
    assert [item.rule_id for item in report.diagnostics] == [
        "architecture/dependencies/policy",
        "architecture/dependencies/policy",
    ]


def test_cycle_analysis_handles_graph_larger_than_python_recursion_limit() -> None:
    count = 1_200
    components = tuple(
        Component(
            ComponentId(f"alpha.lib-{index}"),
            "product-library",
            f"libraries/python/alpha/lib-{index}",
            "@example/alpha",
            product="alpha",
            capability=f"lib-{index}",
            dependencies=(
                (Dependency(ComponentId(f"alpha.lib-{index + 1}"), "package-dependency"),)
                if index + 1 < count
                else ()
            ),
        )
        for index in range(count)
    )
    assert _analyze(*components).diagnostics == ()
