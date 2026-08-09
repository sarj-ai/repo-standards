"""Labeled Sarj policy evaluation cases."""

from __future__ import annotations

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
        Manifest(RepositoryId("example-repository"), PolicyId("sarj"), 1, components),
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
