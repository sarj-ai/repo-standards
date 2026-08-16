"""Labeled Sarj policy evaluation cases."""

from __future__ import annotations

import pytest
from repo_lint_core.engine import analyze
from repo_lint_core.models import (
    AnalysisReport,
    Component,
    ComponentId,
    Dependency,
    Manifest,
    Mode,
    PolicyId,
    RepositoryId,
    RuleId,
)
from repo_lint_policy_sarj import (
    POLICY_SPEC,
    RULE_GOVERNANCE,
    RuleClassification,
    RuleMaturity,
    SarjPolicy,
)


def _analyze(*components: Component) -> AnalysisReport:
    return analyze(
        Manifest(
            RepositoryId("example-repository"),
            PolicyId("sarj"),
            SarjPolicy.policy_version,
            components,
        ),
        SarjPolicy(),
        mode=Mode("report"),
    )


def test_canonical_application_is_clean() -> None:
    report = _analyze(
        Component(
            ComponentId("platform.agent"),
            "application",
            "applications/platform/agent",
            "@example/platform",
            product="platform",
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
            ComponentId(f"platform.{component_name}"),
            "application",
            f"applications/platform/{component_name}",
            "@example/platform",
            product="platform",
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
def test_noncanonical_application_roles_are_rejected(component_name: str) -> None:
    report = _analyze(
        Component(
            ComponentId(f"platform.{component_name}"),
            "application",
            f"applications/platform/{component_name}",
            "@example/platform",
            product="platform",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["sarj/naming/application-role"]
    assert report.diagnostics[0].severity == "warning"


def test_invalid_application_path_does_not_cascade_into_role_warning() -> None:
    report = _analyze(
        Component(
            ComponentId("platform.helpers"),
            "application",
            "python/helpers",
            "@example/platform",
            product="platform",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["sarj/layout/component-path"]


def test_product_component_id_must_match_declared_product() -> None:
    report = _analyze(
        Component(
            ComponentId("vb.agent"),
            "application",
            "applications/platform/agent",
            "@example/platform",
            product="platform",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["sarj/naming/component-id"]


def test_library_capability_must_be_one_kebab_case_token() -> None:
    report = _analyze(
        Component(
            ComponentId("platform.request-signing"),
            "product-library",
            "libraries/python/platform/request.signing",
            "@example/platform",
            product="platform",
            capability="request.signing",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["sarj/naming/capability-token"]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("platform.api"),
                "application",
                "applications/platform/api",
                "@example/platform",
                product="platform",
                capability="api",
            ),
            id="application-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.request-signing"),
                "product-library",
                "libraries/python/platform/request-signing",
                "@example/platform",
                product="platform",
            ),
            id="product-library-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.request-signing"),
                "shared-library",
                "libraries/python/shared/request-signing",
                "@example/platform",
                product="platform",
                capability="request-signing",
            ),
            id="shared-library-forbids-product",
        ),
        pytest.param(
            Component(
                ComponentId("platform.identity"),
                "foundation-service",
                "foundation/components/identity",
                "@example/platform",
                product="platform",
            ),
            id="foundation-forbids-product",
        ),
        pytest.param(
            Component(
                ComponentId("shared.events"),
                "contract",
                "contracts/shared/events",
                "@example/platform",
                capability="events",
            ),
            id="contract-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.billing-client"),
                "generated-client",
                "clients/generated/platform/billing/python",
                "@example/platform",
                product="platform",
            ),
            id="generated-client-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.primary-migrations"),
                "migration-set",
                "migrations/platform/primary",
                "@example/platform",
                product="platform",
                capability="primary",
            ),
            id="migration-set-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.terraform"),
                "terraform-root",
                "deployments/platform/terraform",
                "@example/platform",
                product="platform",
                capability="core",
            ),
            id="terraform-root-forbids-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.api-build"),
                "cloud-build",
                "deployments/platform/cloud-build/api/cloudbuild.yaml",
                "@example/platform",
                product="platform",
            ),
            id="cloud-build-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.api-kubernetes"),
                "kubernetes",
                "deployments/platform/kubernetes/api",
                "@example/platform",
                product="platform",
            ),
            id="kubernetes-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.web-cloudflare"),
                "cloudflare",
                "deployments/platform/cloudflare/web",
                "@example/platform",
                product="platform",
            ),
            id="cloudflare-requires-capability",
        ),
        pytest.param(
            Component(
                ComponentId("platform.release"),
                "tool",
                "tools/ci/release",
                "@example/platform",
                product="platform",
                capability="release",
            ),
            id="tool-forbids-product",
        ),
    ],
)
def test_component_kind_fields_are_exact_without_cascades(component: Component) -> None:
    report = _analyze(component)
    assert [item.rule_id for item in report.diagnostics] == ["sarj/schema/component-fields"]
    assert report.diagnostics[0].severity == "error"


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("platform.request-signing"),
                "product-library",
                "libraries/python/platform/request-signing",
                "@example/platform",
                product="platform",
                capability="request-signing",
            ),
            id="product-library",
        ),
        pytest.param(
            Component(
                ComponentId("shared.request-signing"),
                "shared-library",
                "libraries/typescript/shared/request-signing",
                "@example/platform",
                capability="request-signing",
            ),
            id="shared-library",
        ),
        pytest.param(
            Component(
                ComponentId("foundation.identity"),
                "foundation-service",
                "foundation/components/identity",
                "@example/platform",
            ),
            id="foundation-service",
        ),
        pytest.param(
            Component(
                ComponentId("platform.events"),
                "contract",
                "contracts/platform/events",
                "@example/platform",
                product="platform",
            ),
            id="product-contract",
        ),
        pytest.param(
            Component(
                ComponentId("shared.events"),
                "contract",
                "contracts/shared/events",
                "@example/platform",
            ),
            id="shared-contract",
        ),
        pytest.param(
            Component(
                ComponentId("platform.billing-client"),
                "generated-client",
                "clients/generated/platform/billing/python",
                "@example/platform",
                product="platform",
                capability="billing",
            ),
            id="generated-client",
        ),
        pytest.param(
            Component(
                ComponentId("platform.primary-migrations"),
                "migration-set",
                "migrations/platform/primary",
                "@example/platform",
                product="platform",
            ),
            id="migration-set",
        ),
        pytest.param(
            Component(
                ComponentId("platform.terraform"),
                "terraform-root",
                "deployments/platform/terraform",
                "@example/platform",
                product="platform",
            ),
            id="terraform-root",
        ),
        pytest.param(
            Component(
                ComponentId("platform.api-build"),
                "cloud-build",
                "deployments/platform/cloud-build/api/cloudbuild.yaml",
                "@example/platform",
                product="platform",
                capability="api",
            ),
            id="cloud-build",
        ),
        pytest.param(
            Component(
                ComponentId("platform.api-kubernetes"),
                "kubernetes",
                "deployments/platform/kubernetes/api",
                "@example/platform",
                product="platform",
                capability="api",
            ),
            id="kubernetes",
        ),
        pytest.param(
            Component(
                ComponentId("platform.web-cloudflare"),
                "cloudflare",
                "deployments/platform/cloudflare/web",
                "@example/platform",
                product="platform",
                capability="web",
            ),
            id="cloudflare",
        ),
        pytest.param(
            Component(
                ComponentId("tool.release"),
                "tool",
                "tools/ci/release",
                "@example/platform",
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
                ComponentId("platform.request-signing"),
                "product-library",
                "libraries/go/platform/request-signing",
                "@example/platform",
                product="platform",
                capability="request-signing",
            ),
            id="unsupported-library-language",
        ),
        pytest.param(
            Component(
                ComponentId("platform.primary-migrations"),
                "migration-set",
                "datastores/platform/primary/migrations",
                "@example/platform",
                product="platform",
            ),
            id="legacy-datastore-path",
        ),
        pytest.param(
            Component(
                ComponentId("tool.release"),
                "tool",
                "tools/random/release",
                "@example/platform",
                capability="release",
            ),
            id="unknown-tool-category",
        ),
    ],
)
def test_noncanonical_component_layouts_are_rejected(component: Component) -> None:
    assert [item.rule_id for item in _analyze(component).diagnostics] == [
        "sarj/layout/component-path"
    ]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param(
            Component(
                ComponentId("platform.terraform"),
                "terraform-root",
                "iac/platform",
                "@example/platform",
                product="platform",
            ),
            id="terraform",
        ),
        pytest.param(
            Component(
                ComponentId("platform.api-build"),
                "cloud-build",
                "cloudbuild.yaml",
                "@example/platform",
                product="platform",
                capability="api",
            ),
            id="cloud-build",
        ),
        pytest.param(
            Component(
                ComponentId("platform.api-kubernetes"),
                "kubernetes",
                "k8s/api",
                "@example/platform",
                product="platform",
                capability="api",
            ),
            id="kubernetes",
        ),
        pytest.param(
            Component(
                ComponentId("platform.web-cloudflare"),
                "cloudflare",
                "applications/platform/web/wrangler.jsonc",
                "@example/platform",
                product="platform",
                capability="web",
            ),
            id="cloudflare",
        ),
    ],
)
def test_operational_layout_targets_are_advisory(component: Component) -> None:
    report = _analyze(component)
    assert [item.rule_id for item in report.diagnostics] == ["sarj/layout/operational-path"]
    assert report.diagnostics[0].severity == "warning"


def test_product_contract_cannot_use_shared_path() -> None:
    report = _analyze(
        Component(
            ComponentId("platform.events"),
            "contract",
            "contracts/shared/events",
            "@example/platform",
            product="platform",
        )
    )
    assert [item.rule_id for item in report.diagnostics] == ["sarj/layout/component-path"]


def test_application_source_import_is_rejected_but_runtime_call_is_allowed() -> None:
    source = Component(
        ComponentId("platform.api"),
        "application",
        "applications/platform/api",
        "@example/platform",
        product="platform",
        dependencies=(Dependency(ComponentId("platform.worker"), "source-import"),),
    )
    target = Component(
        ComponentId("platform.worker"),
        "application",
        "applications/platform/worker",
        "@example/platform",
        product="platform",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "sarj/graph/application-imports-application"
    ]
    runtime = replace_dependency(source, Dependency(ComponentId("platform.worker"), "runtime-call"))
    assert _analyze(runtime, target).diagnostics == ()


def replace_dependency(component: Component, dependency: Dependency) -> Component:
    """Return a fixture component with one dependency."""
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
        ComponentId("vb.client"),
        "product-library",
        "libraries/python/vb/client",
        "@example/vb",
        product="vb",
        capability="client",
        dependencies=(Dependency(ComponentId("platform.contract"), "package-dependency"),),
    )
    target = Component(
        ComponentId("platform.contract"),
        "contract",
        "contracts/platform/events",
        "@example/platform",
        product="platform",
    )
    assert "sarj/graph/cross-product-import" in {
        item.rule_id for item in _analyze(source, target).diagnostics
    }


def test_vague_capability_stays_warning() -> None:
    report = _analyze(
        Component(
            ComponentId("platform.utils"),
            "product-library",
            "libraries/python/platform/utils",
            "@example/platform",
            product="platform",
            capability="utils",
        )
    )
    finding = next(
        item for item in report.diagnostics if item.rule_id == "sarj/reuse/vague-capability"
    )
    assert finding.severity == "warning"


def test_shared_contract_and_migration_paths_are_canonical() -> None:
    shared_contract = Component(
        ComponentId("shared.events"),
        "contract",
        "contracts/shared/events",
        "@example/platform",
    )
    migrations = Component(
        ComponentId("platform.primary-migrations"),
        "migration-set",
        "migrations/platform/primary",
        "@example/platform",
        product="platform",
    )
    assert _analyze(shared_contract, migrations).diagnostics == ()


def test_library_importing_application_is_rejected() -> None:
    library = Component(
        ComponentId("platform.client"),
        "product-library",
        "libraries/python/platform/client",
        "@example/platform",
        product="platform",
        capability="client",
        dependencies=(Dependency(ComponentId("platform.api"), "source-import"),),
    )
    application = Component(
        ComponentId("platform.api"),
        "application",
        "applications/platform/api",
        "@example/platform",
        product="platform",
    )
    assert [item.rule_id for item in _analyze(library, application).diagnostics] == [
        "sarj/graph/library-imports-application"
    ]


def test_policy_spec_is_closed_and_governance_covers_every_rule() -> None:
    assert POLICY_SPEC.profile_id == "sarj/consolidation"
    assert POLICY_SPEC.products == ("najm", "platform", "vb")
    assert POLICY_SPEC.profile.product_registry_mode == "closed"
    assert POLICY_SPEC.profile.repository_overrides is False
    assert POLICY_SPEC.profile.target_repository_plugins is False
    assert POLICY_SPEC.policy_version == SarjPolicy.policy_version == 5
    assert {item.rule_id for item in RULE_GOVERNANCE} == {
        item.rule_id for item in SarjPolicy.rules()
    }
    assert {item.evidence for item in RULE_GOVERNANCE} == {
        "declared",
        "external",
        "verified",
    }
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


def test_delivery_rule_governance_keeps_only_the_objective_invariant_blocking() -> None:
    rules = {
        rule.rule_id: rule
        for rule in SarjPolicy.rules()
        if rule.rule_id.startswith(("sarj/delivery/", "sarj/github/"))
    }
    assert set(rules) == {
        "sarj/delivery/hotfix-backsync",
        "sarj/github/actions-sha-pinning",
        "sarj/github/explicit-permissions",
        "sarj/github/job-timeouts",
        "sarj/github/immutable-installs",
        "sarj/github/vulnerability-gate",
        "sarj/github/merge-queue-trigger",
        "sarj/github/repository-governance",
    }
    assert rules[RuleId("sarj/delivery/hotfix-backsync")].severity == "error"
    assert {
        rule.severity for rule_id, rule in rules.items() if rule_id.startswith("sarj/github/")
    } == {"warning"}
    assert {
        rule.maturity for rule_id, rule in rules.items() if rule_id.startswith("sarj/github/")
    } == {"beta"}


def test_public_expected_path_is_a_template_not_a_regex() -> None:
    report = _analyze(
        Component(
            ComponentId("platform.signing"),
            "product-library",
            "python/signing",
            "@example/platform",
            product="platform",
            capability="signing",
        )
    )
    expected = report.diagnostics[0].expected
    assert expected == "libraries/{kotlin,python,swift,typescript}/platform/signing"
    assert "(?:" not in expected
    assert "\\" not in expected


def test_invalid_source_fields_precede_and_suppress_graph_rules() -> None:
    source = Component(
        ComponentId("platform.client"),
        "product-library",
        "libraries/python/platform/client",
        "@example/platform",
        product="platform",
        dependencies=(Dependency(ComponentId("platform.api"), "source-import"),),
    )
    target = Component(
        ComponentId("platform.api"),
        "application",
        "applications/platform/api",
        "@example/platform",
        product="platform",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "sarj/schema/component-fields"
    ]


def test_invalid_target_fields_precede_and_suppress_graph_rules() -> None:
    source = Component(
        ComponentId("platform.client"),
        "product-library",
        "libraries/python/platform/client",
        "@example/platform",
        product="platform",
        capability="client",
        dependencies=(Dependency(ComponentId("platform.api"), "source-import"),),
    )
    target = Component(
        ComponentId("platform.api"),
        "application",
        "applications/platform/api",
        "@example/platform",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "sarj/schema/component-fields"
    ]


def _edge_components(
    source_kind: str,
    target_kind: str,
    *,
    edge_kind: str = "package-dependency",
) -> tuple[Component, Component]:
    fixtures = {
        "application": ("platform.app", "applications/platform/api", "platform", None),
        "product-library": (
            "platform.library",
            "libraries/python/platform/library",
            "platform",
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
        "contract": ("platform.contract", "contracts/platform/events", "platform", None),
        "generated-client": (
            "platform.generated",
            "clients/generated/platform/generated/python",
            "platform",
            "generated",
        ),
        "migration-set": (
            "platform.migrations",
            "migrations/platform/primary",
            "platform",
            None,
        ),
        "tool": ("tool.release", "tools/ci/release", None, "release"),
    }
    source_id, source_path, source_product, source_capability = fixtures[source_kind]
    target_id, target_path, target_product, target_capability = fixtures[target_kind]
    if source_kind == target_kind:
        if target_kind == "application":
            target_id, target_path = "platform.target-api", "applications/platform/target-api"
        elif target_kind == "product-library":
            target_id = "platform.target-library"
            target_path = "libraries/python/platform/target-library"
            target_capability = "target-library"
        elif target_kind == "contract":
            target_id, target_path = "platform.target-contract", "contracts/platform/target-events"
    source = Component(
        ComponentId(source_id),
        source_kind,
        source_path,
        "@example/platform",
        product=source_product,
        capability=source_capability,
        dependencies=(Dependency(ComponentId(target_id), edge_kind),),
    )
    target = Component(
        ComponentId(target_id),
        target_kind,
        target_path,
        "@example/platform",
        product=target_product,
        capability=target_capability,
    )
    return source, target


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
            "sarj/graph/application-imports-application",
            id="application-application",
        ),
        pytest.param(
            "contract",
            "product-library",
            "sarj/graph/contract-imports-implementation",
            id="contract-implementation",
        ),
        pytest.param(
            "product-library",
            "application",
            "sarj/graph/library-imports-application",
            id="library-application",
        ),
        pytest.param(
            "migration-set",
            "contract",
            "sarj/graph/disallowed-code-dependency",
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
    assert [item.rule_id for item in report.diagnostics] == ["sarj/graph/edge-endpoints"]


def test_typed_edge_endpoints_allow_application_runtime_call() -> None:
    source, target = _edge_components("application", "application", edge_kind="runtime-call")
    target = Component(
        ComponentId("platform.target-api"),
        target.kind,
        "applications/platform/target-api",
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


def test_boundary_clean_cycle_is_one_warning() -> None:
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
    assert [item.rule_id for item in report.diagnostics] == ["sarj/graph/code-cycle"]
    assert report.diagnostics[0].severity == "warning"


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
        "sarj/graph/application-imports-application",
        "sarj/graph/application-imports-application",
    ]


def test_cycle_analysis_handles_graph_larger_than_python_recursion_limit() -> None:
    count = 1_200
    components = tuple(
        Component(
            ComponentId(f"platform.lib-{index}"),
            "product-library",
            f"libraries/python/platform/lib-{index}",
            "@example/platform",
            product="platform",
            capability=f"lib-{index}",
            dependencies=(
                (Dependency(ComponentId(f"platform.lib-{index + 1}"), "package-dependency"),)
                if index + 1 < count
                else ()
            ),
        )
        for index in range(count)
    )
    assert _analyze(*components).diagnostics == ()
