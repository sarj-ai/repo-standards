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
)
from repo_lint_policy_sarj import SarjPolicy


def _analyze(*components: Component) -> AnalysisReport:
    return analyze(
        Manifest(RepositoryId("example-repository"), PolicyId("sarj"), 2, components),
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
    assert [item.rule_id for item in report.diagnostics] == [
        "sarj/layout/component-path"
    ]


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
    assert [item.rule_id for item in report.diagnostics] == [
        "sarj/naming/component-id"
    ]


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
    assert [item.rule_id for item in report.diagnostics] == [
        "sarj/naming/capability-token"
    ]


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
    assert [item.rule_id for item in report.diagnostics] == [
        "sarj/schema/component-fields"
    ]
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
    assert [item.rule_id for item in report.diagnostics] == [
        "sarj/layout/operational-path"
    ]
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
    assert [item.rule_id for item in report.diagnostics] == [
        "sarj/layout/component-path"
    ]


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
