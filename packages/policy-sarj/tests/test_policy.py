"""Labeled Sarj policy evaluation cases."""

from __future__ import annotations

from repo_lint_core.engine import analyze
from repo_lint_core.models import Component, Dependency, Manifest
from repo_lint_policy_sarj import SarjPolicy


def _analyze(*components: Component):
    return analyze(
        Manifest("example-repository", "sarj", 1, components),
        SarjPolicy(),
        mode="report",
    )


def test_canonical_application_is_clean() -> None:
    report = _analyze(
        Component(
            "platform.agent",
            "application",
            "products/platform/components/agent",
            "@example/platform",
            product="platform",
        )
    )
    assert report.diagnostics == ()


def test_application_source_import_is_rejected_but_runtime_call_is_allowed() -> None:
    source = Component(
        "platform.api",
        "application",
        "products/platform/components/api",
        "@example/platform",
        product="platform",
        dependencies=(Dependency("platform.worker", "source-import"),),
    )
    target = Component(
        "platform.worker",
        "application",
        "products/platform/components/worker",
        "@example/platform",
        product="platform",
    )
    assert [item.rule_id for item in _analyze(source, target).diagnostics] == [
        "sarj/graph/application-imports-application"
    ]
    runtime = replace_dependency(source, Dependency("platform.worker", "runtime-call"))
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
        "vb.client",
        "product-library",
        "products/vb/libraries/python/client",
        "@example/vb",
        product="vb",
        capability="client",
        dependencies=(Dependency("platform.contract", "package-dependency"),),
    )
    target = Component(
        "platform.contract",
        "contract",
        "products/platform/contracts/events",
        "@example/platform",
        product="platform",
    )
    assert "sarj/graph/cross-product-import" in {
        item.rule_id for item in _analyze(source, target).diagnostics
    }


def test_vague_capability_stays_warning() -> None:
    report = _analyze(
        Component(
            "platform.utils",
            "product-library",
            "products/platform/libraries/python/utils",
            "@example/platform",
            product="platform",
            capability="utils",
        )
    )
    finding = next(
        item for item in report.diagnostics if item.rule_id == "sarj/reuse/vague-capability"
    )
    assert finding.severity == "warning"
