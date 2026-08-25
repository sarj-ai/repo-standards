from __future__ import annotations

from dataclasses import dataclass
import re
import tomllib
from typing import TYPE_CHECKING, NoReturn

from repo_standards.core.engine import core_diagnostics
from repo_standards.core.models import (
    ActiveConfiguration,
    AuthorityId,
    Component,
    ComponentId,
    ConfigurationFormat,
    DeliveryConfig,
    Dependency,
    DeploymentAuthority,
    DocumentationConfig,
    FixtureId,
    GitObjectId,
    InputProvenance,
    Manifest,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedContentEvidence,
    TrackedFileEvidence,
)

from .policy import RULES, SarjPolicy


if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class RuleExampleResult:
    rule_ids: tuple[RuleId, ...]
    complete: bool
    execution_issue_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleExampleCase:
    fixture_id: FixtureId
    rule_id: RuleId
    flagged: str
    passes: str


class _ExampleInputError(ValueError):
    @classmethod
    def fail(cls, message: str) -> NoReturn:
        raise cls(message)


def rule_example_cases() -> tuple[RuleExampleCase, ...]:
    return tuple(
        RuleExampleCase(example.example_id, rule.rule_id, example.before, example.after)
        for rule in RULES
        for example in rule.examples
    )


def run_rule_example(fixture_id: FixtureId, source: str) -> RuleExampleResult:
    identifier = str(fixture_id)
    if identifier in {
        "sarj-artifact-no-example-tfvars",
        "sarj-artifact-no-schema-derived-config-examples",
        "sarj-artifact-no-bespoke-iac-verifiers",
        "sarj-artifact-no-terraform-test-files",
        "sarj-layout-markdown-placement",
    }:
        return _run_repository_path(source)
    if identifier == "sarj-documentation-reachability":
        return _run_documentation_example(source)
    if identifier == "sarj-configuration-unresolved-placeholder":
        return _run_configuration_example(source)
    if identifier == "sarj-delivery-duplicate-authority":
        return _run_authority_example(source)
    manifest = _manifest(fixture_id=identifier, source=source)
    diagnostics = (
        core_diagnostics(manifest)
        if identifier == "sarj-layout-overlapping-roots"
        else SarjPolicy().evaluate(manifest)
    )
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )


def _run_repository_path(source: str) -> RuleExampleResult:
    path = source.strip()
    snapshot = RepositorySnapshot(
        manifest=Manifest(repository_id=RepositoryId("example-repository"), components=()),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            tracked_file_count=1,
            packages=(),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=(TrackedFileEvidence(path=path, object_id="a" * 40),),
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            manifest_path=".repo-lint/repository.toml",
            manifest_object_id=GitObjectId("d" * 40),
            manifest_digest="e" * 64,
        ),
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )


def _repository_snapshot(*, manifest: Manifest, files: dict[str, bytes]) -> RepositorySnapshot:
    tracked = tuple(
        TrackedFileEvidence(path=path, object_id=f"{index + 1:040x}")
        for index, path in enumerate(sorted(files))
    )
    return RepositorySnapshot(
        manifest=manifest,
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            tracked_file_count=len(tracked),
            packages=(),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=tracked,
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="b" * 40,
            tree_digest="c" * 40,
            manifest_path=".repo-standards/repository.toml",
            manifest_object_id=GitObjectId("d" * 40),
            manifest_digest="e" * 64,
        ),
        content=tuple(
            TrackedContentEvidence(path, f"{index + 1:040x}", "f" * 64, content)
            for index, (path, content) in enumerate(sorted(files.items()))
        ),
    )


def _run_documentation_example(source: str) -> RuleExampleResult:
    orphan = "orphan" in source
    files = {
        "README.md": b"[Docs](docs/index.md)\n",
        "docs/index.md": (b"# Index\n" if orphan else b"[Guide](guide.md)\n"),
        ("docs/orphan.md" if orphan else "docs/guide.md"): b"# Guide\n",
    }
    snapshot = _repository_snapshot(
        manifest=Manifest(
            RepositoryId("example-repository"),
            (),
            documentation=DocumentationConfig(("README.md",)),
        ),
        files=files,
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )


def _run_configuration_example(source: str) -> RuleExampleResult:
    path = "config/production.yaml"
    component = _application("api")
    snapshot = _repository_snapshot(
        manifest=Manifest(
            RepositoryId("example-repository"),
            (component,),
            active_configuration=(
                ActiveConfiguration(component.component_id, path, ConfigurationFormat.YAML),
            ),
        ),
        files={path: source.encode()},
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )


def _run_authority_example(source: str) -> RuleExampleResult:
    component = _application("api")
    count = 2 if "two primary" in source else 1
    authorities = tuple(
        DeploymentAuthority(
            AuthorityId(f"writer-{index}"),
            component.component_id,
            "production",
            "cloud-deploy",
            f"deploy/writer-{index}.yaml",
            "primary",
        )
        for index in range(count)
    )
    files = {item.path: b"apiVersion: serving.knative.dev/v1\n" for item in authorities}
    snapshot = _repository_snapshot(
        manifest=Manifest(
            RepositoryId("example-repository"), (component,), delivery=DeliveryConfig(authorities)
        ),
        files=files,
    )
    diagnostics = SarjPolicy.evaluate_repository(snapshot)
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )


def _manifest(*, fixture_id: str, source: str) -> Manifest:
    components = _manifest_components(fixture_id=fixture_id, source=source)
    return Manifest(
        repository_id=RepositoryId("example-repository"),
        components=components,
    )


def _manifest_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    if fixture_id.startswith(("sarj-layout-", "sarj-schema-")):
        return _layout_components(fixture_id=fixture_id, source=source)
    if fixture_id.startswith("sarj-graph-"):
        return _graph_components(fixture_id=fixture_id, source=source)
    return _naming_components(fixture_id=fixture_id, source=source)


def _layout_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    match fixture_id:
        case "sarj-layout-overlapping-roots":
            parent, child = source.splitlines()
            return (
                Component(ComponentId("parent"), "service", parent, "@example/team"),
                Component(ComponentId("child"), "service", child, "@example/team"),
            )
        case "sarj-layout-component-path":
            return (_application("agent", path=_value(source=source, key="path")),)
        case "sarj-layout-operational-path":
            return (
                Component(
                    ComponentId("alpha.terraform"),
                    "terraform-root",
                    _value(source=source, key="path"),
                    "@example/alpha",
                    product="alpha",
                ),
            )
        case "sarj-schema-component-fields":
            values = _toml(source)
            return (
                Component(
                    ComponentId("shared.request-signing"),
                    _required_string(values, "kind"),
                    "libraries/python/shared/request-signing",
                    "@example/shared",
                    product=_optional_string(values, "product"),
                    capability=_optional_string(values, "capability"),
                ),
            )
        case _:
            message = f"unknown Sarj layout example fixture: {fixture_id}"
            _ExampleInputError.fail(message)


def _graph_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    if fixture_id in {
        "sarj-graph-edge-endpoints",
        "sarj-graph-application-dependency",
        "sarj-graph-library-application-dependency",
        "sarj-graph-self-dependency",
        "sarj-graph-cross-product-dependency",
    }:
        return _code_boundary_components(fixture_id=fixture_id, source=source)
    if fixture_id == "sarj-graph-code-cycle":
        return _cycle_components(source)
    return _ownership_boundary_components(fixture_id=fixture_id, source=source)


def _code_boundary_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    if fixture_id in {
        "sarj-graph-edge-endpoints",
        "sarj-graph-application-dependency",
    }:
        return _application_boundary_components(fixture_id=fixture_id, source=source)
    return _remaining_code_boundary_components(fixture_id=fixture_id, source=source)


def _application_boundary_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    match fixture_id:
        case "sarj-graph-edge-endpoints":
            target = (
                _application("target-api")
                if source.endswith("application")
                else _contract("alpha", "events")
            )
            return (
                _application("api", (Dependency(target.component_id, "implements-contract"),)),
                target,
            )
        case "sarj-graph-application-dependency":
            target = (
                _application("target-api")
                if source.endswith("application B")
                else _product_library("alpha", "request-signing")
            )
            return (_application("api", (Dependency(target.component_id, _edge(source)),)), target)
        case _:
            message = f"unknown application-boundary example fixture: {fixture_id}"
            _ExampleInputError.fail(message)


def _remaining_code_boundary_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    match fixture_id:
        case "sarj-graph-library-application-dependency":
            if source.startswith("product library"):
                target = _application("api")
                return (
                    _product_library(
                        "alpha", "client", (Dependency(target.component_id, _edge(source)),)
                    ),
                    target,
                )
            target = _product_library("alpha", "client")
            return (_application("api", (Dependency(target.component_id, _edge(source)),)), target)
        case "sarj-graph-self-dependency":
            component = _product_library("alpha", "client")
            if "--" not in source:
                return (component,)
            return (
                _product_library(
                    "alpha",
                    "client",
                    (Dependency(component.component_id, _edge(source)),),
                ),
            )
        case "sarj-graph-cross-product-dependency":
            if source.startswith("beta library"):
                target = _product_library("alpha", "client")
                return (
                    _product_library(
                        "beta", "client", (Dependency(target.component_id, _edge(source)),)
                    ),
                    target,
                )
            target = _application("api", product="alpha")
            return (
                _application(
                    "web", (Dependency(target.component_id, _edge(source)),), product="beta"
                ),
                target,
            )
        case _:
            message = f"unknown code-boundary example fixture: {fixture_id}"
            _ExampleInputError.fail(message)


def _ownership_boundary_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    match fixture_id:
        case "sarj-graph-shared-product-dependency":
            shared = _shared_library("request-signing")
            product = _product_library("beta", "client")
            if source.startswith("shared library"):
                return (
                    _shared_library(
                        "request-signing", (Dependency(product.component_id, _edge(source)),)
                    ),
                    product,
                )
            return (
                _application(
                    "api", (Dependency(shared.component_id, _edge(source)),), product="beta"
                ),
                shared,
            )
        case "sarj-graph-contract-implementation-dependency":
            if source.endswith("product library"):
                target = _product_library("alpha", "events-impl")
            else:
                target = _contract(None, "events")
            return (
                _contract(
                    "alpha",
                    "events",
                    (Dependency(target.component_id, _edge(source)),),
                ),
                target,
            )
        case "sarj-graph-disallowed-code-dependency":
            target = (
                _contract("alpha", "events")
                if source.endswith("contract")
                else _shared_library("request-signing")
            )
            return (
                _migration_set(
                    "alpha", "primary", (Dependency(target.component_id, _edge(source)),)
                ),
                target,
            )
        case _:
            message = f"unknown ownership-boundary example fixture: {fixture_id}"
            _ExampleInputError.fail(message)


def _cycle_components(source: str) -> tuple[Component, ...]:
    if source.endswith("library A"):
        first = _product_library("alpha", "first")
        second = _product_library("alpha", "second")
        return (
            _product_library(
                "alpha", "first", (Dependency(second.component_id, "package-dependency"),)
            ),
            _product_library(
                "alpha", "second", (Dependency(first.component_id, "package-dependency"),)
            ),
        )
    shared = _shared_library("request-signing")
    library = _product_library(
        "alpha",
        "client",
        (Dependency(shared.component_id, "package-dependency"),),
    )
    return (
        _application("api", (Dependency(library.component_id, "package-dependency"),)),
        library,
        shared,
    )


def _naming_components(*, fixture_id: str, source: str) -> tuple[Component, ...]:
    match fixture_id:
        case "sarj-reuse-vague-capability":
            return (_product_library("alpha", _value(source=source, key="capability")),)
        case "sarj-naming-application-role":
            path = source.strip()
            return (_application(path.rsplit("/", maxsplit=1)[-1], path=path),)
        case "sarj-naming-component-id":
            values = _toml(source)
            return (
                Component(
                    ComponentId(_required_string(values, "id")),
                    "application",
                    "applications/alpha/agent",
                    "@example/alpha",
                    product=_required_string(values, "product"),
                ),
            )
        case "sarj-naming-capability-token":
            capability = _value(source=source, key="capability")
            return (
                Component(
                    ComponentId("alpha.request-signing"),
                    "product-library",
                    f"libraries/python/alpha/{capability}",
                    "@example/alpha",
                    product="alpha",
                    capability=capability,
                ),
            )
        case _:
            message = f"unknown Sarj naming example fixture: {fixture_id}"
            _ExampleInputError.fail(message)


def _toml(source: str) -> Mapping[str, object]:
    return tomllib.loads(source)


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        message = f"example field must be a nonempty string: {key}"
        _ExampleInputError.fail(message)
    return value


def _optional_string(values: Mapping[str, object], key: str) -> str | None:
    value = values.get(key)
    if value is None:
        return None
    return _required_string(values, key)


def _value(*, source: str, key: str) -> str:
    return _required_string(_toml(source), key)


def _edge(source: str) -> str:
    match = re.search(r"--([a-z-]+)-->", source)
    if match is None:
        _ExampleInputError.fail("graph example must declare an edge")
    return match.group(1)


def _application(
    name: str,
    dependencies: tuple[Dependency, ...] = (),
    *,
    product: str = "alpha",
    path: str | None = None,
) -> Component:
    return Component(
        ComponentId(f"{product}.{name}"),
        "application",
        path or f"applications/{product}/{name}",
        f"@example/{product}",
        product=product,
        dependencies=dependencies,
    )


def _product_library(
    product: str, name: str, dependencies: tuple[Dependency, ...] = ()
) -> Component:
    return Component(
        ComponentId(f"{product}.{name}"),
        "product-library",
        f"libraries/python/{product}/{name}",
        f"@example/{product}",
        product=product,
        capability=name,
        dependencies=dependencies,
    )


def _shared_library(name: str, dependencies: tuple[Dependency, ...] = ()) -> Component:
    return Component(
        ComponentId(f"shared.{name}"),
        "shared-library",
        f"libraries/python/shared/{name}",
        "@example/shared",
        capability=name,
        dependencies=dependencies,
    )


def _contract(
    product: str | None, name: str, dependencies: tuple[Dependency, ...] = ()
) -> Component:
    owner = product or "shared"
    return Component(
        ComponentId(f"{owner}.{name}"),
        "contract",
        f"contracts/{owner}/{name}",
        f"@example/{owner}",
        product=product,
        dependencies=dependencies,
    )


def _migration_set(product: str, name: str, dependencies: tuple[Dependency, ...] = ()) -> Component:
    return Component(
        ComponentId(f"{product}.{name}-migrations"),
        "migration-set",
        f"migrations/{product}/{name}",
        f"@example/{product}",
        product=product,
        dependencies=dependencies,
    )
