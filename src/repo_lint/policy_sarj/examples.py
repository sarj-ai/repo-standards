from __future__ import annotations

from dataclasses import dataclass
import re
import tomllib
from typing import TYPE_CHECKING, NamedTuple, NoReturn

from repo_lint.core.engine import core_diagnostics
from repo_lint.core.models import (
    Component,
    ComponentId,
    Dependency,
    FixtureId,
    Manifest,
    PolicyId,
    RepositoryId,
    RuleId,
)
from repo_lint.github.analyzer import analyze as analyze_github
from repo_lint.github.models import (
    BranchEvidence,
    RepositoryEvidence,
    RulesetEvidence,
    WorkflowDocument,
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


class _GovernanceInput(NamedTuple):
    evidence: RepositoryEvidence
    repository_files: tuple[str, ...]


def rule_example_cases() -> tuple[RuleExampleCase, ...]:
    return tuple(
        RuleExampleCase(example.example_id, rule.rule_id, example.before, example.after)
        for rule in RULES
        for example in rule.examples
    )


def run_rule_example(fixture_id: FixtureId, source: str) -> RuleExampleResult:
    identifier = str(fixture_id)
    if identifier.startswith(("sarj-github-", "sarj-delivery-")):
        return _run_github(fixture_id=identifier, source=source)
    manifest = _manifest(fixture_id=identifier, source=source)
    diagnostics = (
        core_diagnostics(manifest)
        if identifier == "sarj-layout-overlapping-roots"
        else SarjPolicy().evaluate(manifest)
    )
    return RuleExampleResult(
        tuple(sorted((item.rule_id for item in diagnostics), key=str)), complete=True
    )


def _manifest(*, fixture_id: str, source: str) -> Manifest:
    components = _manifest_components(fixture_id=fixture_id, source=source)
    return Manifest(
        repository_id=RepositoryId("example-repository"),
        policy_id=PolicyId("sarj"),
        policy_version=SarjPolicy.policy_version,
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


def _run_github(*, fixture_id: str, source: str) -> RuleExampleResult:
    evidence: RepositoryEvidence | None = None
    repository_files: tuple[str, ...] = ()
    selected_revision: str | None = None
    if fixture_id == "sarj-github-repository-governance":
        governance = _governance_input(source)
        evidence = governance.evidence
        repository_files = governance.repository_files
        workflows: tuple[WorkflowDocument, ...] = ()
    elif fixture_id == "sarj-delivery-hotfix-backsync":
        evidence = _evidence()
        repository_files = (".github/CODEOWNERS", ".github/dependabot.yml")
        selected_revision = "a" * 40
        workflows = (WorkflowDocument(".github/workflows/backsync.yml", _backsync(source)),)
    else:
        if fixture_id == "sarj-github-merge-queue-trigger":
            evidence = _evidence(merge_queue=True, delivery=False)
            repository_files = (".github/CODEOWNERS", ".github/dependabot.yml")
        workflows = (
            WorkflowDocument(
                ".github/workflows/ci.yml",
                _workflow(fixture_id=fixture_id, source=source).encode(),
            ),
        )
    report = analyze_github(
        None,
        evidence,
        workflows,
        repository_files=repository_files,
        selected_revision=selected_revision,
    )
    return RuleExampleResult(
        tuple(item.rule_id for item in report.diagnostics),
        report.completion == "complete",
        tuple(item.code for item in report.execution_issues),
    )


def _workflow(*, fixture_id: str, source: str) -> str:
    if fixture_id == "sarj-github-explicit-permissions":
        return f"on: pull_request\n{source}\n"
    if fixture_id == "sarj-github-job-timeouts":
        return f"on: pull_request\npermissions:\n  contents: read\n{source}\n"
    if fixture_id == "sarj-github-merge-queue-trigger":
        return (
            f"{source}\npermissions:\n  contents: read\njobs:\n  test:\n"
            "    timeout-minutes: 15\n    steps:\n      - run: echo ok\n"
        )
    return (
        "on: pull_request\npermissions:\n  contents: read\njobs:\n  test:\n"
        "    timeout-minutes: 15\n    steps:\n"
        f"      - {source}\n"
    )


def _governance_input(source: str) -> _GovernanceInput:
    values = {item.strip() for item in source.split(";")}
    files = [".github/dependabot.yml"]
    if "CODEOWNERS" in values:
        files.append(".github/CODEOWNERS")
    return _GovernanceInput(_evidence(delivery=False), tuple(files))


def _evidence(*, merge_queue: bool = False, delivery: bool = True) -> RepositoryEvidence:
    names = ("main", "preview", "dev") if delivery else ("main",)
    branches = tuple(
        BranchEvidence(
            name=name,
            protected=True,
            required_status_checks=("gate",),
            head_sha="a" * 40 if name == "main" else "b" * 40,
        )
        for name in names
    )
    rulesets = (
        (RulesetEvidence("queue", "active", "branch", ("merge_queue",)),) if merge_queue else ()
    )
    return RepositoryEvidence(
        repository="acme/widgets",
        default_branch="main",
        branches=branches,
        rulesets=rulesets,
        allow_auto_merge=True,
        actions_default_workflow_permissions="read",
        actions_can_approve_pull_requests=False,
    )


def _backsync(source: str) -> bytes:
    preview_to_dev = source.startswith("main -> preview -> dev")
    second_job = _BACKSYNC_DEV_JOB if preview_to_dev else ""
    return f"{_BACKSYNC_HEADER}{second_job}".encode()


_BACKSYNC_HEADER = """on:
  push:
    branches: [main, preview]
  schedule:
    - cron: '17 * * * *'
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
concurrency:
  group: backsync
  cancel-in-progress: false
jobs:
  main-to-preview:
    if: github.event_name != 'push' || github.ref == 'refs/heads/main'
    timeout-minutes: 35
    env:
      AUTHOR_TOKEN: ${{ secrets.BACKSYNC_TOKEN }}
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - run: |
          main_sha=$(GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/ref/heads/main)
          git merge-tree --write-tree origin/preview origin/main
          git rev-parse 'origin/preview^{tree}'
          sync_branch="sync-main-$main_sha"
          GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/refs \
            -f ref="refs/heads/$sync_branch"
          number=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr list --base preview --head "$sync_branch")
          if [ -z "$number" ]; then
            GH_TOKEN="$AUTHOR_TOKEN" gh pr create --base preview --head "$sync_branch"
          fi
          head_oid=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr view "$number" --json headRefOid,mergeable)
          if [ "$head_oid" != "$main_sha" ]; then exit 1; fi
          if [ "$mergeable" = "CONFLICTING" ]; then exit 1; fi
          GH_TOKEN="$AUTHOR_TOKEN" gh pr merge "$number" --auto --squash \
            --match-head-commit "$main_sha"
"""

_BACKSYNC_DEV_JOB = """  preview-to-dev:
    if: github.event_name != 'push' || github.ref == 'refs/heads/preview'
    timeout-minutes: 35
    env:
      AUTHOR_TOKEN: ${{ secrets.BACKSYNC_TOKEN }}
    steps:
      - run: |
          preview_sha=$(GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/ref/heads/preview)
          old_dev=$(GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/ref/heads/dev)
          GH_TOKEN="$AUTHOR_TOKEN" gh api "repos/acme/widgets/compare/$preview_sha...$old_dev"
          git merge --no-edit origin/preview
          sync_branch="sync-preview-$preview_sha"
          GH_TOKEN="$AUTHOR_TOKEN" gh api repos/acme/widgets/git/refs \
            -f ref="refs/heads/$sync_branch"
          number=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr list --base dev --head "$sync_branch")
          if [ -z "$number" ]; then
            GH_TOKEN="$AUTHOR_TOKEN" gh pr create --base dev --head "$sync_branch"
          fi
          head_oid=$(GH_TOKEN="$AUTHOR_TOKEN" gh pr view "$number" --json headRefOid,mergeable)
          if [ "$head_oid" != "$preview_sha" ]; then exit 1; fi
          if [ "$mergeable" = "CONFLICTING" ]; then exit 1; fi
          GH_TOKEN="$AUTHOR_TOKEN" gh pr merge "$number" --auto --merge \
            --match-head-commit "$preview_sha"
"""


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
