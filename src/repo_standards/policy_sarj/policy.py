from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
import json
from pathlib import PurePosixPath
import posixpath
import re
import tomllib
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt
from pydantic import TypeAdapter
import yaml

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import (
    Component,
    ComponentId,
    ConfigurationFormat,
    DeploymentAuthority,
    Diagnostic,
    ExampleLanguage,
    FixtureId,
    JSONValue,
    Manifest,
    PolicyId,
    Remediation,
    RepositorySnapshot,
    Rule,
    RuleExamplePair,
    RuleId,
    SourceLocation,
    WorkspaceEvidence,
)
from repo_standards.core.taxonomy import (
    ARCHITECTURE,
    COMPONENT_SCHEMA,
    DEPENDENCY_BOUNDARIES,
    REPOSITORY_LAYOUT,
    taxonomy,
)

from .spec import (
    PATH_TEMPLATE_BY_KIND,
    PATH_TEMPLATES,
    PROFILE_ID,
    ChoiceSegment,
    FieldSegment,
    LiteralSegment,
    OptionalTail,
    OwnershipSegment,
    PathTemplate,
    PolicySpec,
    ProfileId,
    RuleClassification,
    RuleGovernance,
    RuleMaturity,
    TokenSegment,
)


if TYPE_CHECKING:
    from collections.abc import Mapping


class _DependencyAnalysis(NamedTuple):
    diagnostics: list[Diagnostic]
    accepted_edges: list[tuple[ComponentId, ComponentId]]


class _CodeBoundary(NamedTuple):
    rule_id: RuleId
    expected: str


class _ScalarLocation(NamedTuple):
    pointer: str
    value: str


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
_MIN_CYCLE_COMPONENTS = 2
_PATH_TOKEN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"  # ruff: ignore[hardcoded-password-string] - regex, not a secret
_DOCUMENTATION_ROOTS = frozenset({"adr", "architecture", "docs"})
_PACKAGE_DOCUMENT_NAMES = frozenset(
    {
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "HISTORY.md",
        "LICENSE.md",
        "README.md",
        "SECURITY.md",
    }
)
_AGENT_CONTRACT_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "SKILL.md"})
_AGENT_CONTRACT_ROOTS = (
    (".agents", "skills"),
    (".claude", "commands"),
    (".claude", "skills"),
    (".codex", "skills"),
)
_RETIRED_IAC_VERIFIER_NAMES = frozenset({"verify-dev-apply-plan.jq"})
_TERRAFORM_TEST_SUFFIXES = (".tftest.hcl", ".tftest.json")
_ENV_SCHEMA_SUFFIXES = (
    ".schema",
    ".schema.json",
    ".schema.toml",
    ".schema.yaml",
    ".schema.yml",
)
_ENV_EXAMPLE_SUFFIXES = (".example", ".sample", ".template")
_TFVARS_EXAMPLE_SUFFIXES = tuple(f".tfvars{suffix}" for suffix in _ENV_EXAMPLE_SUFFIXES)
_DERIVED_ENV_BASENAMES = frozenset(
    {
        *(f"{kind}.env" for kind in ("example", "sample", "template")),
        *(f"env.{kind}" for kind in ("example", "sample", "template")),
    }
)
_DERIVED_BACKEND_BASENAMES = frozenset(f"backend.conf{suffix}" for suffix in _ENV_EXAMPLE_SUFFIXES)
_EXECUTABLE_SCRIPT_EXTENSIONS = frozenset(
    {"bash", "cjs", "cts", "jq", "js", "jsx", "mjs", "mts", "py", "sh", "ts", "tsx", "zsh"}
)
_PACKAGE_TEST_DIRECTORY_NAMES = frozenset({"spec", "specs", "test", "tests", "__tests__"})
_CONVENTIONAL_OPERATIONAL_ROOTS = frozenset(
    {
        "cloudbuild",
        "ci",
        "deploy",
        "deployments",
        "examples",
        "iac",
        "infra",
        "k8s",
        "ops",
        "samples",
        "scripts",
        "templates",
        "terraform",
        "tools",
    }
)
_NESTED_OPERATIONAL_DIRECTORY_NAMES = frozenset(
    {"cloudbuild", "ci", "deploy", "deployments", "iac", "infra", "k8s", "ops", "terraform"}
)
_NON_OPERATIONAL_COMPONENT_KINDS = frozenset(
    {
        "application",
        "contract",
        "foundation-service",
        "generated-client",
        "product-library",
        "shared-library",
        "tool",
    }
)
_COMPONENT_FIELDS: Mapping[ComponentKind, tuple[frozenset[str], frozenset[str]]] = MappingProxyType(
    {
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
    }
)

_ALLOWED_CODE_TARGETS: Mapping[ComponentKind, frozenset[ComponentKind]] = MappingProxyType(
    {
        ComponentKind.APPLICATION: frozenset(
            {
                ComponentKind.PRODUCT_LIBRARY,
                ComponentKind.SHARED_LIBRARY,
                ComponentKind.CONTRACT,
                ComponentKind.GENERATED_CLIENT,
            }
        ),
        ComponentKind.PRODUCT_LIBRARY: frozenset(
            {
                ComponentKind.PRODUCT_LIBRARY,
                ComponentKind.SHARED_LIBRARY,
                ComponentKind.CONTRACT,
                ComponentKind.GENERATED_CLIENT,
            }
        ),
        ComponentKind.SHARED_LIBRARY: frozenset(
            {ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}
        ),
        ComponentKind.FOUNDATION_SERVICE: frozenset(
            {ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}
        ),
        ComponentKind.CONTRACT: frozenset({ComponentKind.CONTRACT}),
        ComponentKind.GENERATED_CLIENT: frozenset(
            {ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}
        ),
        ComponentKind.MIGRATION_SET: frozenset({ComponentKind.SHARED_LIBRARY}),
        ComponentKind.TERRAFORM_ROOT: frozenset(),
        ComponentKind.CLOUD_BUILD: frozenset(),
        ComponentKind.KUBERNETES: frozenset(),
        ComponentKind.CLOUDFLARE: frozenset(),
        ComponentKind.TOOL: frozenset({ComponentKind.SHARED_LIBRARY, ComponentKind.CONTRACT}),
    }
)


def _example(  # ruff: ignore[too-many-arguments] - keyword-only declarative fixture
    *,
    example_id: str,
    title: str,
    language: ExampleLanguage,
    before: str,
    after: str,
    expected_severity: Literal["warning", "error"] = "error",
) -> RuleExamplePair:
    return RuleExamplePair(
        example_id=FixtureId(example_id),
        title=title,
        language=language,
        before=before,
        after=after,
        expected_severity=expected_severity,
    )


RULES = (
    Rule(
        rule_id=RuleId("architecture/dependencies/policy"),
        version=1,
        default_severity="error",
        title="Enforce dependency boundaries",
        description="Every dependency edge is legal, ownership-safe, and acyclic.",
        why="One dependency policy keeps ownership, release, and build direction explicit.",
        fix="Remove the edge or replace it with an allowed dependency or runtime contract.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        examples=(
            _example(
                example_id="sarj-graph-edge-endpoints",
                title="Edge endpoints",
                language="text",
                before="library --implements-contract--> application",
                after="application --implements-contract--> contract",
            ),
            _example(
                example_id="sarj-graph-application-dependency",
                title="Application dependency",
                language="text",
                before="application A --source-import--> application B",
                after="application A --package-dependency--> product library B",
            ),
            _example(
                example_id="sarj-graph-library-application-dependency",
                title="Library application dependency",
                language="text",
                before="product library --source-import--> application",
                after="application --package-dependency--> product library",
            ),
            _example(
                example_id="sarj-graph-self-dependency",
                title="Self dependency",
                language="text",
                before="component A --source-import--> component A",
                after="component A has no edge to itself",
            ),
            _example(
                example_id="sarj-graph-cross-product-dependency",
                title="Cross-product dependency",
                language="text",
                before="beta library --source-import--> alpha library",
                after="beta application --runtime-call--> alpha API",
            ),
            _example(
                example_id="sarj-graph-shared-product-dependency",
                title="Shared-product dependency",
                language="text",
                before="shared library --package-dependency--> beta library",
                after="beta application --package-dependency--> shared library",
            ),
            _example(
                example_id="sarj-graph-contract-implementation-dependency",
                title="Contract implementation dependency",
                language="text",
                before="contract --source-import--> product library",
                after="product contract --package-dependency--> shared contract",
            ),
            _example(
                example_id="sarj-graph-disallowed-code-dependency",
                title="Disallowed code dependency",
                language="text",
                before="migration set --source-import--> contract",
                after="migration set --package-dependency--> shared library",
            ),
            _example(
                example_id="sarj-graph-code-cycle",
                title="Code cycle",
                language="text",
                before="library A -> library B -> library A",
                after="application -> product library -> shared library",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("architecture/layout/component-paths"),
        version=1,
        default_severity="error",
        title="Use canonical component paths",
        description="Every component has one canonical ownership root.",
        why="Canonical disjoint roots make ownership and impact analysis deterministic.",
        fix="Move the component to its canonical path and keep ownership roots disjoint.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-layout-component-path",
                title="Component path",
                language="toml",
                before="path = 'python/agent'",
                after="path = 'applications/alpha/agent'",
            ),
            _example(
                example_id="sarj-layout-operational-path",
                title="Operational path",
                language="toml",
                before="path = 'iac/alpha'",
                after="path = 'deployments/alpha/terraform'",
            ),
            _example(
                example_id="sarj-layout-overlapping-roots",
                title="Overlapping component roots",
                language="text",
                before="services/payments\nservices/payments/worker",
                after="services/payments\nservices/worker",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("architecture/schema/component"),
        version=1,
        default_severity="error",
        title="Keep component identity consistent",
        description="Component kind, ownership, ID, and capability token agree.",
        why="Trustworthy component identity prevents cascading layout and dependency mistakes.",
        fix="Add required fields, remove forbidden fields, and align IDs and capability tokens.",
        taxonomy=taxonomy(ARCHITECTURE, COMPONENT_SCHEMA),
        examples=(
            _example(
                example_id="sarj-schema-component-fields",
                title="Component fields",
                language="toml",
                before="kind = 'shared-library'\nproduct = 'alpha'",
                after="kind = 'shared-library'\ncapability = 'request-signing'",
            ),
            _example(
                example_id="sarj-naming-capability-token",
                title="Capability token",
                language="toml",
                before="capability = 'request.signing'",
                after="capability = 'request-signing'",
            ),
            _example(
                example_id="sarj-naming-component-id",
                title="Component ID",
                language="toml",
                before="id = 'beta.agent'\nproduct = 'alpha'",
                after="id = 'alpha.agent'\nproduct = 'alpha'",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/terraform-examples"),
        version=1,
        default_severity="error",
        title="Do not commit example tfvars files",
        description=(
            "Tracked filenames ending in .tfvars.example, .tfvars.sample, or "
            ".tfvars.template are prohibited."
        ),
        why="One typed variable interface prevents copied configuration from drifting.",
        fix="Delete the example file and document validated inputs in variables.tf.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-artifact-no-example-tfvars",
                title="Terraform example variables",
                language="text",
                before="deployments/alpha/terraform/terraform.tfvars.example",
                after="deployments/alpha/terraform/variables.tf",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/schema-derived-config-examples"),
        version=2,
        default_severity="warning",
        title="Generate configuration examples from schemas",
        description=(
            "Tracked backend.conf and env example, sample, template, or schema basenames are "
            "prohibited, case-insensitively."
        ),
        why=(
            "Hand-maintained configuration examples duplicate Terraform, Zod, or Pydantic "
            "contracts and drift from the settings the application actually accepts."
        ),
        fix=(
            "Delete the duplicate artifact and generate developer-facing configuration from "
            "the authoritative Terraform, Zod, Pydantic, or deployment schema."
        ),
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-artifact-no-schema-derived-config-examples",
                title="Schema-derived configuration example",
                language="text",
                before="services/api/.env.local.example",
                after="services/api/settings.py",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/bespoke-iac-verifiers"),
        version=3,
        default_severity="error",
        title="Do not commit bespoke verifier scripts",
        description=(
            "Retired verifier basenames are prohibited everywhere. Other executable-script "
            "basenames beginning with verify are prohibited when operational placement or a "
            "non-root path lacks objective source, test, script, bin, or component ownership."
        ),
        why=(
            "Repository-specific verifier entrypoints create parallel validation paths that "
            "drift from shared policy, owned test suites, and deployment contracts."
        ),
        fix=(
            "Delete the operational verifier and every invocation. Moving or renaming it is "
            "not remediation; express the invariant in Terraform, shared policy, or a provider "
            "or runtime contract."
        ),
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-artifact-no-bespoke-iac-verifiers",
                title="Bespoke IaC verifier",
                language="text",
                before="iac/scripts/verify-dev-apply-plan.jq",
                after="explicit environment tfvars",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/operational-script-tests"),
        version=1,
        default_severity="warning",
        title="Keep operational safety in owned contracts",
        description=(
            "Executable script test/spec artifacts are prohibited in operational trees. "
            "Repository Standards owns this path boundary; semantic workflow analysis belongs "
            "in Code Standards."
        ),
        why=(
            "Bespoke deployment tests create parallel contracts that drift from "
            "Terraform, providers, shared policy, and runtime behavior. Workflow contents are "
            "outside this exact-tree rule's evidence boundary."
        ),
        fix=(
            "Delete the operational test and every invocation. Moving or renaming it is not "
            "remediation; express the invariant in Terraform, shared policy, provider state, "
            "or runtime behavior."
        ),
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-artifact-no-operational-script-tests",
                title="Operational source-coupled test",
                language="text",
                before="iac/bell/preview-contract.test.mjs",
                after="Terraform validation, precondition, or shared policy",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/terraform-test-files"),
        version=1,
        default_severity="error",
        title="Do not commit native Terraform test files",
        description=(
            "Tracked paths ending in .tftest.hcl or .tftest.json are prohibited, "
            "case-insensitively."
        ),
        why=(
            "A separate Terraform-native test harness duplicates setup and review conventions; "
            "one shared rendered-plan, provider, or runtime validation path keeps "
            "infrastructure checks discoverable and consistent."
        ),
        fix=(
            "Delete the Terraform-native test file and move the durable assertion into shared "
            "rendered-plan, provider, or runtime validation."
        ),
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-artifact-no-terraform-test-files",
                title="Terraform-native test file",
                language="text",
                before="iac/tests/routing.tftest.hcl",
                after="shared rendered-plan validation",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/documentation/placement"),
        version=2,
        default_severity="error",
        title="Keep Markdown in durable owned locations",
        description="Tracked Markdown must have a durable documentation or tool-contract role.",
        why="Owned documentation stays discoverable instead of becoming repository debris.",
        fix="Move durable guidance into an approved docs root or delete transient notes.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-layout-markdown-placement",
                title="Markdown placement",
                language="text",
                before="deployments/alpha/terraform/README.md",
                after="docs/deployment/alpha-terraform.md",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/documentation/reachability"),
        version=1,
        default_severity="warning",
        title="Keep durable documentation reachable",
        description="Declared documentation entrypoints lead to every durable Markdown page.",
        why="Connected documentation remains discoverable and maintainable.",
        fix="Link the page from a reachable index, declare it as an entrypoint, or remove it.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-documentation-reachability",
                title="Documentation reachability",
                language="text",
                before="README.md -> docs/index.md\ndocs/orphan.md",
                after="README.md -> docs/index.md -> docs/guide.md",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/configuration/unresolved-placeholders"),
        version=1,
        default_severity="warning",
        title="Resolve active configuration placeholders",
        description="Declared active configuration contains reviewed deployable values.",
        why="Placeholder values can make configured deployments fail at runtime.",
        fix="Replace the sentinel with reviewed configuration or remove the unused setting.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-configuration-unresolved-placeholder",
                title="Active configuration placeholder",
                language="yaml",
                before="endpoint: change-me",
                after="endpoint: ${SERVICE_ENDPOINT}",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("architecture/delivery/authority"),
        version=1,
        default_severity="warning",
        title="Keep one deployment authority",
        description="Each workload and environment has one declared primary deployment writer.",
        why="A single writer makes release and rollback ownership deterministic.",
        fix="Retain one primary authority and classify helpers as delegates or recovery paths.",
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        examples=(
            _example(
                example_id="sarj-delivery-duplicate-authority",
                title="Deployment authority",
                language="toml",
                before="two primary production writers",
                after="one primary plus delegates",
                expected_severity="warning",
            ),
        ),
    ),
)

_RULE_CLASSIFICATION: Mapping[RuleId, RuleClassification] = MappingProxyType(
    {
        RuleId("architecture/layout/component-paths"): RuleClassification.OBJECTIVE,
        RuleId("architecture/schema/component"): RuleClassification.SCHEMA,
        RuleId("architecture/dependencies/policy"): RuleClassification.OBJECTIVE,
        RuleId("repository/artifacts/terraform-examples"): RuleClassification.OBJECTIVE,
        RuleId("repository/artifacts/schema-derived-config-examples"): RuleClassification.JUDGMENT,
        RuleId("repository/artifacts/bespoke-iac-verifiers"): RuleClassification.OBJECTIVE,
        RuleId("repository/artifacts/operational-script-tests"): RuleClassification.JUDGMENT,
        RuleId("repository/artifacts/terraform-test-files"): RuleClassification.OBJECTIVE,
        RuleId("repository/documentation/placement"): RuleClassification.OBJECTIVE,
        RuleId("repository/documentation/reachability"): RuleClassification.JUDGMENT,
        RuleId("repository/configuration/unresolved-placeholders"): RuleClassification.JUDGMENT,
        RuleId("architecture/delivery/authority"): RuleClassification.OPERATIONAL,
    }
)
_RULE_PRECEDENCE: Mapping[RuleId, int] = MappingProxyType(
    {
        RuleId("architecture/schema/component"): 10,
        RuleId("architecture/dependencies/policy"): 20,
        RuleId("architecture/layout/component-paths"): 30,
        RuleId("repository/artifacts/terraform-examples"): 40,
        RuleId("repository/artifacts/schema-derived-config-examples"): 44,
        RuleId("repository/artifacts/bespoke-iac-verifiers"): 45,
        RuleId("repository/artifacts/operational-script-tests"): 46,
        RuleId("repository/artifacts/terraform-test-files"): 47,
        RuleId("repository/documentation/placement"): 50,
        RuleId("repository/documentation/reachability"): 60,
        RuleId("repository/configuration/unresolved-placeholders"): 70,
        RuleId("architecture/delivery/authority"): 80,
    }
)
_UPSTREAM_BY_CLASSIFICATION: Mapping[RuleClassification, tuple[str, ...]] = MappingProxyType(
    {
        RuleClassification.SCHEMA: ("repository manifest parser",),
        RuleClassification.OBJECTIVE: (
            "Import Linter",
            "dependency-cruiser",
            "native package dependency graphs",
        ),
        RuleClassification.JUDGMENT: ("organization architecture review",),
        RuleClassification.OPERATIONAL: (
            "Terraform plan",
            "deployment control planes",
        ),
    }
)

_RULE_EVIDENCE: Mapping[RuleId, Literal["declared", "verified", "external"]] = MappingProxyType(
    {
        rule.rule_id: ("verified" if str(rule.rule_id).startswith("repository/") else "declared")
        for rule in RULES
    }
)

RULE_GOVERNANCE = tuple(
    RuleGovernance(
        rule_id=rule.rule_id,
        maturity=(
            RuleMaturity.WARNING if rule.severity == "warning" else RuleMaturity.STABLE_ERROR
        ),
        classification=_RULE_CLASSIFICATION[rule.rule_id],
        evidence=_RULE_EVIDENCE[rule.rule_id],
        upstream=_UPSTREAM_BY_CLASSIFICATION[_RULE_CLASSIFICATION[rule.rule_id]],
        precedence=_RULE_PRECEDENCE[rule.rule_id],
    )
    for rule in RULES
)

POLICY_SPEC = PolicySpec(
    schema_version=2,
    policy_id=PolicyId("sarj"),
    policy_version=11,
    profile_id=PROFILE_ID,
    title="Sarj repository standard",
    component_kinds=tuple(kind.value for kind in ComponentKind),
    edge_kinds=tuple(sorted(EDGE_KINDS)),
    path_templates=PATH_TEMPLATES,
    rule_governance=RULE_GOVERNANCE,
)


def _remediation(summary: str, *steps: str) -> Remediation:
    return Remediation(
        summary=summary,
        steps=steps,
        validation=("Run repo-standards check again and inspect the typed dependency graph.",),
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


def _path_matches(template: PathTemplate, component: Component) -> bool:
    actual = component.path.split("/")
    expected = template.segments
    for index, segment in enumerate(expected):
        match segment:
            case OptionalTail():
                return index == len(expected) - 1
            case _:
                if index >= len(actual) or not _segment_matches(segment, actual[index], component):
                    return False
    return len(actual) == len(expected)


def _segment_matches(segment: object, actual: str, component: Component) -> bool:
    match segment:
        case LiteralSegment(value=value):
            return actual == value
        case ChoiceSegment(values=values):
            return actual in values
        case FieldSegment(field=field):
            return actual == _component_field_value(component, field)
        case TokenSegment():
            return re.fullmatch(_PATH_TOKEN, actual) is not None
        case OwnershipSegment():
            return actual == (component.product or "shared")
        case _:
            return False


def _expected_path(template: PathTemplate, component: Component) -> str:
    rendered: list[str] = []
    for segment in template.segments:
        match segment:
            case LiteralSegment(value=value):
                rendered.append(value)
            case ChoiceSegment(values=values):
                rendered.append("{" + ",".join(values) + "}")
            case FieldSegment(field=field):
                rendered.append(_component_field_value(component, field) or f"<{field}>")
            case TokenSegment(label=label):
                rendered.append(f"<{label}>")
            case OwnershipSegment():
                rendered.append(component.product or "shared")
            case OptionalTail():
                rendered.append("...")
    return "/".join(rendered)


def _repository_artifact_diagnostics(
    snapshot: RepositorySnapshot,
) -> tuple[Diagnostic, ...]:
    package_test_roots = _owned_package_roots(snapshot)
    document_package_roots = package_test_roots
    diagnostics: list[Diagnostic] = []
    for tracked in snapshot.inspection.tracked_files:
        path = tracked.path
        component = _nearest_component(path, snapshot.manifest.components)
        if path.casefold().endswith(_TFVARS_EXAMPLE_SUFFIXES):
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/artifacts/terraform-examples"),
                    component=component,
                    subject_kind="tracked-terraform-example",
                    observed=path,
                    expected="no tracked .tfvars example, sample, or template filename",
                    message="tracked Terraform example variable file is prohibited",
                    path=path,
                    remediation=Remediation(
                        summary=(
                            "Remove the example file and keep one authoritative input contract."
                        ),
                        steps=(
                            "Delete the tracked .tfvars example, sample, or template file.",
                            "Describe inputs and validation in variables.tf.",
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
        basename = PurePosixPath(path).name.casefold()
        is_derived_env_artifact = basename in _DERIVED_ENV_BASENAMES or (
            (basename == ".env" or basename.startswith(".env."))
            and basename.endswith((*_ENV_EXAMPLE_SUFFIXES, *_ENV_SCHEMA_SUFFIXES))
        )
        is_derived_backend_artifact = basename in _DERIVED_BACKEND_BASENAMES
        if is_derived_backend_artifact or is_derived_env_artifact:
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/artifacts/schema-derived-config-examples"),
                    component=component,
                    subject_kind="tracked-schema-derived-config-example",
                    observed=path,
                    expected="no tracked schema-derived configuration example basename",
                    message="tracked configuration artifact duplicates source settings",
                    path=path,
                    remediation=Remediation(
                        summary="Generate configuration guidance from source settings.",
                        steps=(
                            "Delete the derived example or schema artifact.",
                            (
                                "Generate developer-facing configuration directly from Terraform "
                                "declarations, Zod settings, Pydantic settings, or the "
                                "deployment schema."
                            ),
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
        is_terraform_path = _is_terraform_artifact_path(path, snapshot.inspection.terraform_modules)
        is_github_automation_path = _is_github_automation_path(path)
        is_operational_path = is_terraform_path or _is_operational_path(
            path,
            component=component,
            terraform_modules=snapshot.inspection.terraform_modules,
        )
        is_operational_script_test = (
            _is_script_test(basename)
            and is_operational_path
            and (
                is_terraform_path
                or is_github_automation_path
                or not _is_owned_tool_test(path, component, package_test_roots)
            )
        )
        is_bespoke_verifier = basename in _RETIRED_IAC_VERIFIER_NAMES or (
            _is_verifier_script(basename)
            and (is_operational_path or bool(_parent_path(path)))
            and (
                is_terraform_path
                or is_github_automation_path
                or not _is_owned_verifier_path(path, component, package_test_roots)
            )
        )
        if is_bespoke_verifier:
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/artifacts/bespoke-iac-verifiers"),
                    component=component,
                    subject_kind="tracked-bespoke-iac-verifier",
                    observed=path,
                    expected="no retired, operational, or unowned verifier artifact",
                    message="tracked retired, operational, or unowned verifier is prohibited",
                    path=path,
                    remediation=Remediation(
                        summary=("Remove the operational verifier instead of relocating it."),
                        steps=(
                            "Delete the verifier and every workflow invocation.",
                            (
                                "Express durable safety in Terraform, shared policy, provider "
                                "state, or runtime behavior."
                            ),
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
        elif is_operational_script_test:
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/artifacts/operational-script-tests"),
                    component=component,
                    subject_kind="tracked-operational-script-test",
                    observed=path,
                    expected="no tracked operational script test artifact",
                    message="tracked operational script test creates a parallel contract",
                    path=path,
                    remediation=Remediation(
                        summary="Remove the operational test instead of relocating it.",
                        steps=(
                            "Delete the test and every workflow invocation.",
                            (
                                "Express durable safety in Terraform, shared policy, provider "
                                "state, or runtime behavior."
                            ),
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
        if path.casefold().endswith(_TERRAFORM_TEST_SUFFIXES):
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/artifacts/terraform-test-files"),
                    component=component,
                    subject_kind="tracked-terraform-test-file",
                    observed=path,
                    expected="no tracked .tftest.hcl or .tftest.json filename",
                    message="tracked native Terraform test file is prohibited by repository policy",
                    path=path,
                    remediation=Remediation(
                        summary="Move the assertion into the shared validation path.",
                        steps=(
                            "Delete the tracked Terraform-native test file.",
                            (
                                "Validate the behavior through a rendered plan, provider, or "
                                "runtime contract."
                            ),
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
        if path.casefold().endswith(".md") and not _markdown_path_is_owned(
            path,
            package_roots=document_package_roots,
            component=component,
            terraform_modules=snapshot.inspection.terraform_modules,
            documentation_entrypoints=(
                snapshot.manifest.documentation.entrypoints
                if snapshot.manifest.documentation is not None
                else ()
            ),
        ):
            diagnostics.append(
                _repository_diagnostic(
                    rule_id=RuleId("repository/documentation/placement"),
                    component=component,
                    subject_kind="tracked-markdown",
                    observed=path,
                    expected="a root, durable docs, package, generated, GitHub, or agent path",
                    message="tracked Markdown is outside an approved owned location",
                    path=path,
                    remediation=Remediation(
                        summary=(
                            "Move durable guidance to an owned documentation surface or remove it."
                        ),
                        steps=(
                            "Move durable guidance beneath docs, architecture, or adr.",
                            (
                                "Delete transient plans, handoffs, summaries, and "
                                "implementation notes."
                            ),
                        ),
                        validation=("Inspect the selected Git tree and rerun repo-standards.",),
                    ),
                )
            )
    diagnostics.extend(
        _documentation_reachability_diagnostics(
            snapshot,
            document_package_roots,
        )
    )
    diagnostics.extend(_active_configuration_diagnostics(snapshot))
    diagnostics.extend(_deployment_authority_diagnostics(snapshot))
    return tuple(
        sorted(diagnostics, key=lambda item: (item.path, item.rule_id, item.manifest_anchor))
    )


def _parent_path(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def _nearest_component(path: str, components: tuple[Component, ...]) -> Component | None:
    owners = tuple(
        component
        for component in components
        if path == component.path or path.startswith(f"{component.path}/")
    )
    return max(owners, key=lambda item: len(item.path), default=None)


def _markdown_path_is_owned(
    path: str,
    *,
    package_roots: frozenset[str],
    component: Component | None,
    terraform_modules: tuple[str, ...],
    documentation_entrypoints: tuple[str, ...],
) -> bool:
    pure_path = PurePosixPath(path)
    parts = pure_path.parts
    is_root_document = len(parts) == 1 and (
        pure_path.name in _PACKAGE_DOCUMENT_NAMES or path in documentation_entrypoints
    )
    is_workflow_document = parts[:2] == (".github", "workflows")
    is_github_action_document = parts[:2] == (".github", "actions")
    is_durable_tree = parts[0] in _DOCUMENTATION_ROOTS or (
        parts[0] == ".github" and not is_workflow_document
    )
    is_agent_contract = pure_path.name in _AGENT_CONTRACT_NAMES or any(
        parts[: len(root)] == root for root in _AGENT_CONTRACT_ROOTS
    )
    if is_workflow_document or (
        not is_github_action_document
        and _is_operational_path(path, component=component, terraform_modules=terraform_modules)
    ):
        return False
    if is_root_document or is_durable_tree or is_agent_contract:
        return True
    parent = _parent_path(path)
    if pure_path.name in _PACKAGE_DOCUMENT_NAMES and parent in package_roots:
        return True
    if component is None:
        return False
    if component.kind == "generated-client":
        return True
    return (
        component.kind in _NON_OPERATIONAL_COMPONENT_KINDS
        and parent == component.path
        and pure_path.name in _PACKAGE_DOCUMENT_NAMES
    )


def _owned_package_roots(snapshot: RepositorySnapshot) -> frozenset[str]:
    roots: set[str] = set()
    for project in snapshot.inspection.packages:
        root = _parent_path(project.path)
        if not project.name:
            continue
        component = _nearest_component(root, snapshot.manifest.components)
        explicitly_owned = (
            component is not None
            and component.path == root
            and component.kind in _NON_OPERATIONAL_COMPONENT_KINDS
        )
        root_workspace_owned = any(
            workspace.ecosystem == project.ecosystem
            and not _parent_path(workspace.path)
            and _workspace_includes(workspace, project.path)
            for workspace in snapshot.inspection.workspaces
        )
        root_project = not root
        conventionally_owned = (root_workspace_owned or root_project) and not _is_operational_path(
            root, component=component, terraform_modules=snapshot.inspection.terraform_modules
        )
        if explicitly_owned or conventionally_owned:
            roots.add(root)
    return frozenset(roots)


def _workspace_includes(workspace: WorkspaceEvidence, project_path: str) -> bool:
    workspace_root = PurePosixPath(workspace.path).parent
    project_directory = PurePosixPath(project_path).parent
    try:
        relative = project_directory.relative_to(workspace_root)
    except ValueError:
        return False
    return any(relative.match(pattern) for pattern in workspace.member_patterns) and not any(
        relative.match(pattern) for pattern in workspace.exclude_patterns
    )


def _is_owned_verifier_path(
    path: str,
    component: Component | None,
    package_roots: frozenset[str],
) -> bool:
    component_owned = (
        component is not None
        and component.kind in _NON_OPERATIONAL_COMPONENT_KINDS
        and (path == component.path or path.startswith(f"{component.path}/"))
    )
    return component_owned or _is_owned_package_code_path(path, package_roots)


def _is_owned_package_code_path(path: str, package_roots: frozenset[str]) -> bool:
    owned_directories = _PACKAGE_TEST_DIRECTORY_NAMES | {"bin", "scripts", "src"}
    parts = _owned_package_relative_parts(path, package_roots)
    return bool(parts) and parts[0].casefold() in owned_directories


def _is_owned_tool_test(
    path: str,
    component: Component | None,
    package_roots: frozenset[str],
) -> bool:
    return (
        component is not None
        and component.kind == "tool"
        and PurePosixPath(component.path).parts[:1] == ("tools",)
        and component.path in package_roots
        and _is_owned_package_test(path, package_roots)
    )


def _is_owned_package_test(path: str, package_roots: frozenset[str]) -> bool:
    parts = _owned_package_relative_parts(path, package_roots)
    return any(part.casefold() in _PACKAGE_TEST_DIRECTORY_NAMES for part in parts[:-1])


def _owned_package_relative_parts(path: str, package_roots: frozenset[str]) -> tuple[str, ...]:
    pure = PurePosixPath(path)
    for root in sorted(package_roots, key=len, reverse=True):
        root_path = PurePosixPath(root) if root else PurePosixPath()
        try:
            return pure.relative_to(root_path).parts
        except ValueError:
            continue
    return ()


def _is_script_test(basename: str) -> bool:
    stem, separator, extension = basename.rpartition(".")
    if not separator or extension not in _EXECUTABLE_SCRIPT_EXTENSIONS:
        return False
    return (
        stem in {"test", "spec"}
        or stem.startswith(("test-", "test_", "spec-", "spec_"))
        or stem.endswith((".test", ".spec"))
        or (extension == "py" and stem.endswith("_test"))
    )


def _is_verifier_script(basename: str) -> bool:
    _stem, separator, extension = basename.rpartition(".")
    return (
        bool(separator)
        and extension in _EXECUTABLE_SCRIPT_EXTENSIONS
        and basename.startswith("verify")
    )


def _is_operational_path(
    path: str,
    *,
    component: Component | None,
    terraform_modules: tuple[str, ...],
) -> bool:
    pure = PurePosixPath(path)
    if _is_terraform_path(path, terraform_modules):
        return True
    parts = tuple(part.casefold() for part in pure.parts)
    if _is_github_automation_path(path):
        return True
    if bool(parts) and parts[0] in _CONVENTIONAL_OPERATIONAL_ROOTS:
        return True
    if any(part in _NESTED_OPERATIONAL_DIRECTORY_NAMES for part in parts[1:-1]):
        return True
    if component is not None:
        return component.kind not in _NON_OPERATIONAL_COMPONENT_KINDS
    return False


def _is_terraform_artifact_path(path: str, terraform_modules: tuple[str, ...]) -> bool:
    return "" in terraform_modules or _is_terraform_path(path, terraform_modules)


def _is_terraform_path(path: str, terraform_modules: tuple[str, ...]) -> bool:
    return any(
        bool(root) and (path == root or path.startswith(f"{root}/")) for root in terraform_modules
    )


def _is_github_automation_path(path: str) -> bool:
    return tuple(part.casefold() for part in PurePosixPath(path).parts[:2]) in {
        (".github", "actions"),
        (".github", "workflows"),
    }


_MARKDOWN = MarkdownIt("commonmark")
_CONFIG_VALUE: TypeAdapter[JSONValue] = TypeAdapter(JSONValue)
_PLACEHOLDER_SENTINELS = frozenset(
    {
        "<replace-me>",
        "<required>",
        "change-me",
        "change_me",
        "changeme",
        "replace-me",
        "replace-this",
        "replace_me",
        "your-value-here",
        "your_value_here",
    }
)
_MIN_QUOTED_VALUE_LENGTH = 2
_MIN_COMPETING_AUTHORITIES = 2


def _documentation_reachability_diagnostics(  # ruff: ignore[too-many-branches]
    snapshot: RepositorySnapshot,
    package_roots: frozenset[str],
) -> tuple[Diagnostic, ...]:
    documentation = snapshot.manifest.documentation
    if documentation is None:
        return ()
    contents = {
        item.path: item.content for item in snapshot.content if item.path.casefold().endswith(".md")
    }
    tracked = frozenset(item.path for item in snapshot.inspection.tracked_files)
    eligible: set[str] = set()
    candidates: set[str] = set()
    seeds: set[str] = set(documentation.entrypoints)
    for path in sorted(contents):
        component = _nearest_component(path, snapshot.manifest.components)
        if not _markdown_path_is_owned(
            path,
            package_roots=package_roots,
            component=component,
            terraform_modules=snapshot.inspection.terraform_modules,
            documentation_entrypoints=documentation.entrypoints,
        ):
            continue
        pure = PurePosixPath(path)
        parts = pure.parts
        if (
            parts[0] == ".github"
            or pure.name in _AGENT_CONTRACT_NAMES
            or any(parts[: len(root)] == root for root in _AGENT_CONTRACT_ROOTS)
            or (component is not None and component.kind == "generated-client")
        ):
            continue
        eligible.add(path)
        parent = _parent_path(path)
        if pure.name in _PACKAGE_DOCUMENT_NAMES and (not parent or parent in package_roots):
            seeds.add(path)
        else:
            candidates.add(path)
    graph: dict[str, set[str]] = {path: set() for path in eligible}
    for source in sorted(eligible):
        try:
            tokens = _MARKDOWN.parse(contents[source].decode("utf-8"))
        except UnicodeDecodeError:
            ConfigurationError.fail("declared documentation must be UTF-8")
        for parent in tokens:
            for token in parent.children or ():
                if token.type == "link_open":
                    href = token.attrGet("href")
                    target = _markdown_link_target(
                        source, href if isinstance(href, str) else None, tracked
                    )
                    if target in eligible:
                        graph[source].add(target)
    reachable = set(seeds & eligible)
    pending = list(reachable)
    while pending:
        for target in graph.get(pending.pop(), ()):
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    return tuple(
        replace(
            _repository_diagnostic(
                rule_id=RuleId("repository/documentation/reachability"),
                component=_nearest_component(path, snapshot.manifest.components),
                subject_kind="unreachable-documentation",
                observed=path,
                expected="reachable from a declared documentation entrypoint",
                message="durable Markdown is unreachable from declared documentation entrypoints",
                path=path,
                remediation=Remediation(
                    summary="Connect the page to the documentation graph or remove it.",
                    steps=("Link it from a reachable index or declare it as an entrypoint.",),
                    validation=("Rerun repo-standards.",),
                ),
            ),
            manifest_anchor=f"documentation.reachability.{path}",
        )
        for path in sorted(candidates - reachable)
    )


def _markdown_link_target(source: str, href: str | None, tracked: frozenset[str]) -> str | None:
    if not href:
        return None
    parsed = urlsplit(href)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    decoded = unquote(parsed.path)
    raw = (
        decoded.removeprefix("/")
        if decoded.startswith("/")
        else posixpath.join(_parent_path(source), decoded)
    )
    normalized = posixpath.normpath(raw)
    if normalized in {".", ".."} or normalized.startswith("../"):
        return None
    if normalized in tracked and normalized.casefold().endswith(".md"):
        return normalized
    index = f"{normalized.rstrip('/')}/README.md"
    return index if index in tracked else None


def _active_configuration_diagnostics(snapshot: RepositorySnapshot) -> tuple[Diagnostic, ...]:
    content_by_path = {item.path: item.content for item in snapshot.content}
    components = {item.component_id: item for item in snapshot.manifest.components}
    diagnostics: list[Diagnostic] = []
    for declaration in snapshot.manifest.active_configuration:
        for pointer, value in _parse_active_configuration(
            declaration.path, declaration.format, content_by_path[declaration.path]
        ):
            if value.strip().casefold() not in _PLACEHOLDER_SENTINELS:
                continue
            diagnostics.append(
                replace(
                    _repository_diagnostic(
                        rule_id=RuleId("repository/configuration/unresolved-placeholders"),
                        component=components[declaration.component_id],
                        subject_kind="active-configuration-placeholder",
                        observed=f"unresolved placeholder sentinel at {pointer}",
                        expected="reviewed active configuration or a typed runtime reference",
                        message="active configuration contains an unresolved placeholder sentinel",
                        path=declaration.path,
                        remediation=Remediation(
                            summary="Replace the sentinel or remove the setting.",
                            steps=("Use typed configuration or a secret reference.",),
                            validation=("Rerun repo-standards.",),
                        ),
                    ),
                    manifest_anchor=f"active_configuration.{declaration.path}.{pointer}",
                    observed_value={"category": "unresolved-placeholder", "pointer": pointer},
                )
            )
    return tuple(diagnostics)


def _parse_active_configuration(
    path: str, format_name: ConfigurationFormat, content: bytes
) -> tuple[tuple[str, str], ...]:
    try:
        text = content.decode("utf-8")
        decoded = _decode_active_configuration(format_name, text)
        value = _CONFIG_VALUE.validate_python(decoded, strict=True)
    except (
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
    ):
        ConfigurationError.fail(f"cannot parse declared active configuration: {path}")
    return tuple(_string_scalars(value))


def _decode_active_configuration(format_name: ConfigurationFormat, text: str) -> object:
    match format_name:
        case ConfigurationFormat.JSON:
            return json.loads(  # pyright: ignore[reportAny]
                text, object_pairs_hook=_unique_json_mapping
            )
        case ConfigurationFormat.TOML:
            return tomllib.loads(text)
        case ConfigurationFormat.YAML:
            return yaml.safe_load(text)  # pyright: ignore[reportAny]
        case ConfigurationFormat.DOTENV:
            return _parse_dotenv(text)


def _unique_json_mapping(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            ConfigurationError.fail("active JSON configuration contains a duplicate key")
        result[key] = value
    return result


def _parse_dotenv(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if (
            separator != "="
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None
            or key in result
        ):
            ConfigurationError.fail(
                f"active dotenv configuration has an invalid assignment at line {number}"
            )
        value = value.strip()
        if len(value) >= _MIN_QUOTED_VALUE_LENGTH and value[0] in {'"', "'"}:
            closing = value.find(value[0], 1)
            if closing < 1 or (
                value[closing + 1 :].strip() and not value[closing + 1 :].strip().startswith("#")
            ):
                ConfigurationError.fail(
                    f"active dotenv configuration has an invalid value at line {number}"
                )
            value = value[1:closing]
        elif " #" in value:
            value = value.partition(" #")[0].rstrip()
        result[key] = value
    return result


def _string_scalars(value: JSONValue, pointer: str = "$") -> list[_ScalarLocation]:
    match value:
        case str():
            return [_ScalarLocation(pointer, value)]
        case dict():
            return [
                item
                for key in sorted(value, key=str)
                for item in _string_scalars(
                    value[key], f"{pointer}/{str(key).replace('~', '~0').replace('/', '~1')}"
                )
            ]
        case list():
            return [
                item
                for index, child in enumerate(value)
                for item in _string_scalars(child, f"{pointer}/{index}")
            ]
        case _:
            return []


def _deployment_authority_diagnostics(snapshot: RepositorySnapshot) -> tuple[Diagnostic, ...]:
    if snapshot.manifest.delivery is None:
        return ()
    groups: dict[tuple[ComponentId, str], list[DeploymentAuthority]] = {}
    for authority in snapshot.manifest.delivery.authorities:
        if authority.authority == "primary":
            groups.setdefault((authority.component_id, authority.environment), []).append(authority)
    diagnostics: list[Diagnostic] = []
    for (component_id, environment), values in sorted(groups.items()):
        if len(values) < _MIN_COMPETING_AUTHORITIES:
            continue
        authorities = sorted(values, key=lambda item: item.authority_id)
        first = authorities[0]
        diagnostics.append(
            replace(
                _diagnostic(
                    rule_id=RuleId("architecture/delivery/authority"),
                    component_id=component_id,
                    subject_kind="deployment-authority",
                    observed=", ".join(item.authority_id for item in authorities),
                    expected=f"one primary authority for {component_id} in {environment}",
                    message=(
                        "multiple primary deployment authorities target one workload environment"
                    ),
                    path=first.path,
                    anchor=f"delivery.authorities.{component_id}.{environment}",
                    remediation=_remediation(
                        "Retain one primary deployment authority.",
                        "Move helpers to delegates or recovery.",
                    ),
                ),
                related_locations=tuple(SourceLocation(path=item.path) for item in authorities[1:]),
            )
        )
    return tuple(diagnostics)


def _repository_diagnostic(  # ruff: ignore[too-many-arguments] - fields are explicit
    *,
    rule_id: RuleId,
    component: Component | None,
    subject_kind: str,
    observed: str,
    expected: str,
    message: str,
    path: str,
    remediation: Remediation,
) -> Diagnostic:
    rule = next(item for item in RULES if item.rule_id == rule_id)
    component_id = component.component_id if component is not None else ComponentId("repository")
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=component_id,
        subject_kind=subject_kind,
        observed=observed,
        expected=expected,
        message=message,
        path=path,
        manifest_anchor=f"tracked_files.{path}",
        remediation=remediation,
    )


def _component_field_value(
    component: Component, field: Literal["product", "capability"]
) -> str | None:
    if field == "product":
        return component.product
    return component.capability


class SarjPolicy:
    policy_id: ClassVar[PolicyId] = PolicyId("sarj")
    policy_version: ClassVar[int] = POLICY_SPEC.policy_version
    profile_id: ClassVar[ProfileId] = PROFILE_ID

    @staticmethod
    def spec() -> PolicySpec:
        return POLICY_SPEC

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        return RULES

    @staticmethod
    def evaluate_repository(snapshot: RepositorySnapshot) -> tuple[Diagnostic, ...]:
        return _repository_artifact_diagnostics(snapshot)

    @staticmethod
    def evaluate(manifest: Manifest) -> tuple[Diagnostic, ...]:
        diagnostics: list[Diagnostic] = []
        by_id = {item.component_id: item for item in manifest.components}
        kinds: dict[ComponentId, ComponentKind] = {}
        invalid: set[ComponentId] = set()

        # First pass: establish trustworthy kinds and ownership fields for every
        # endpoint. Graph rules never reason from contradictory component facts.
        for component in manifest.components:
            try:
                component_kind = ComponentKind(component.kind)
            except ValueError:
                ConfigurationError.fail(
                    f"component {component.component_id} has unsupported kind {component.kind}"
                )
            kinds[component.component_id] = component_kind
            field_diagnostic = _component_field_diagnostic(component, component_kind)
            if field_diagnostic is not None:
                diagnostics.append(field_diagnostic)
                invalid.add(component.component_id)
                continue
        clean_code_edges: list[tuple[ComponentId, ComponentId]] = []
        for component in manifest.components:
            if component.component_id in invalid:
                continue
            edge_diagnostics, accepted = _dependency_diagnostics(component, by_id, kinds, invalid)
            diagnostics.extend(edge_diagnostics)
            clean_code_edges.extend(accepted)

        # Second pass: naming and layout apply only after the component's
        # identity is valid, preventing regex/path noise from masking schema work.
        for component in manifest.components:
            if component.component_id in invalid:
                continue
            component_kind = kinds[component.component_id]
            diagnostics.extend(_naming_diagnostics(component, component_kind))
            template = PATH_TEMPLATE_BY_KIND[component_kind.value]
            if not _path_matches(template, component):
                diagnostics.append(
                    _diagnostic(
                        rule_id=RuleId("architecture/layout/component-paths"),
                        component_id=component.component_id,
                        subject_kind="component-path",
                        observed=component.path,
                        expected=_expected_path(template, component),
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
        diagnostics.extend(_cycle_diagnostics(clean_code_edges, by_id))
        return tuple(diagnostics)


def _naming_diagnostics(component: Component, component_kind: ComponentKind) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if component.capability is not None and re.fullmatch(_PATH_TOKEN, component.capability) is None:
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("architecture/schema/component"),
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
                rule_id=RuleId("architecture/schema/component"),
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
        rule_id=RuleId("architecture/schema/component"),
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
            "Then rerun repo-standards so dependent naming and path rules can evaluate.",
        ),
    )


def _component_id_prefix(component: Component, component_kind: ComponentKind) -> str | None:
    if component_kind is ComponentKind.SHARED_LIBRARY or (
        component_kind is ComponentKind.CONTRACT and component.product is None
    ):
        return "shared."
    if component_kind is ComponentKind.FOUNDATION_SERVICE:
        return "foundation."
    if component_kind is ComponentKind.TOOL:
        return "tool."
    if component.product is not None:
        return f"{component.product}."
    return None


def _dependency_diagnostics(
    component: Component,
    by_id: dict[ComponentId, Component],
    kinds: dict[ComponentId, ComponentKind],
    invalid: set[ComponentId],
) -> _DependencyAnalysis:
    diagnostics: list[Diagnostic] = []
    accepted: list[tuple[ComponentId, ComponentId]] = []
    for dependency in component.dependencies:
        if dependency.kind not in EDGE_KINDS:
            ConfigurationError.fail(
                f"component {component.component_id} has unsupported edge type {dependency.kind}"
            )
        target = by_id[dependency.target]
        if target.component_id in invalid:
            continue
        source_kind = kinds[component.component_id]
        target_kind = kinds[target.component_id]
        if dependency.kind not in CODE_EDGES:
            endpoint_diagnostic = _edge_endpoint_diagnostic(
                component, source_kind, target, target_kind, dependency.kind
            )
            if endpoint_diagnostic is not None:
                diagnostics.append(endpoint_diagnostic)
            continue
        boundary = _code_boundary(component, source_kind, target, target_kind)
        if boundary is None:
            accepted.append((component.component_id, target.component_id))
            continue
        rule_id, expected = boundary
        diagnostics.append(
            _edge_diagnostic(
                rule_id,
                component,
                target,
                dependency.kind,
                expected,
                "declared code dependency violates ownership direction",
            )
        )
    return _DependencyAnalysis(diagnostics, accepted)


def _code_boundary(  # ruff: ignore[too-many-return-statements] - precedence is intentionally linear
    source: Component,
    source_kind: ComponentKind,
    target: Component,
    target_kind: ComponentKind,
) -> _CodeBoundary | None:
    if source.component_id == target.component_id:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"), "remove the self dependency"
        )
    if source_kind is ComponentKind.APPLICATION and target_kind is ComponentKind.APPLICATION:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "depend on a library or use a runtime-call edge",
        )
    if source_kind is ComponentKind.CONTRACT and target_kind is not ComponentKind.CONTRACT:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "contracts may depend only on contracts",
        )
    if source_kind in {ComponentKind.PRODUCT_LIBRARY, ComponentKind.SHARED_LIBRARY} and (
        target_kind is ComponentKind.APPLICATION
    ):
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "applications may import libraries; libraries may not import applications",
        )
    if _is_shared_source(source, source_kind) and target.product is not None:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "shared components import no product implementation",
        )
    if source.product and target.product and source.product != target.product:
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            "use a shared contract/library or runtime-call edge",
        )
    if target_kind not in _ALLOWED_CODE_TARGETS[source_kind]:
        allowed = ",".join(sorted(kind.value for kind in _ALLOWED_CODE_TARGETS[source_kind]))
        return _CodeBoundary(
            RuleId("architecture/dependencies/policy"),
            f"{source_kind.value} code targets one of: {allowed or '<none>'}",
        )
    return None


def _is_shared_source(component: Component, kind: ComponentKind) -> bool:
    return kind in {
        ComponentKind.SHARED_LIBRARY,
        ComponentKind.FOUNDATION_SERVICE,
        ComponentKind.TOOL,
    } or (kind is ComponentKind.CONTRACT and component.product is None)


_EDGE_ENDPOINTS: Mapping[str, tuple[frozenset[ComponentKind] | None, frozenset[ComponentKind]]] = (
    MappingProxyType(
        {
            "implements-contract": (
                frozenset(
                    {
                        ComponentKind.APPLICATION,
                        ComponentKind.PRODUCT_LIBRARY,
                        ComponentKind.SHARED_LIBRARY,
                        ComponentKind.FOUNDATION_SERVICE,
                    }
                ),
                frozenset({ComponentKind.CONTRACT}),
            ),
            "generates": (
                frozenset({ComponentKind.CONTRACT, ComponentKind.TOOL}),
                frozenset({ComponentKind.GENERATED_CLIENT}),
            ),
            "runtime-call": (
                None,
                frozenset({ComponentKind.APPLICATION, ComponentKind.FOUNDATION_SERVICE}),
            ),
            "deploys": (
                frozenset({ComponentKind.CLOUD_BUILD, ComponentKind.TOOL}),
                frozenset({ComponentKind.APPLICATION, ComponentKind.FOUNDATION_SERVICE}),
            ),
            "owns-data": (
                frozenset({ComponentKind.APPLICATION, ComponentKind.FOUNDATION_SERVICE}),
                frozenset({ComponentKind.MIGRATION_SET}),
            ),
            "applies-migration": (
                frozenset(
                    {ComponentKind.APPLICATION, ComponentKind.CLOUD_BUILD, ComponentKind.TOOL}
                ),
                frozenset({ComponentKind.MIGRATION_SET}),
            ),
            "terraform-consumes": (None, frozenset({ComponentKind.TERRAFORM_ROOT})),
        }
    )
)


def _edge_endpoint_diagnostic(
    source: Component,
    source_kind: ComponentKind,
    target: Component,
    target_kind: ComponentKind,
    edge_kind: str,
) -> Diagnostic | None:
    constraint = _EDGE_ENDPOINTS.get(edge_kind)
    if constraint is None:
        return None
    allowed_sources, allowed_targets = constraint
    if (allowed_sources is None or source_kind in allowed_sources) and (
        target_kind in allowed_targets
    ):
        return None
    sources = (
        "*" if allowed_sources is None else ",".join(sorted(kind.value for kind in allowed_sources))
    )
    targets = ",".join(sorted(kind.value for kind in allowed_targets))
    return _edge_diagnostic(
        RuleId("architecture/dependencies/policy"),
        source,
        target,
        edge_kind,
        f"source={sources}; target={targets}",
        "typed dependency has incompatible endpoint kinds",
    )


def _edge_diagnostic(  # ruff: ignore[too-many-arguments,too-many-positional-arguments] - edge evidence remains explicit
    rule_id: RuleId,
    source: Component,
    target: Component,
    edge_kind: str,
    expected: str,
    message: str,
) -> Diagnostic:
    return _diagnostic(
        rule_id=rule_id,
        component_id=source.component_id,
        subject_kind=edge_kind,
        observed=f"{source.component_id}->{target.component_id}",
        expected=expected,
        message=message,
        path=source.path,
        anchor=(f"components.{source.component_id}.dependencies.{edge_kind}.{target.component_id}"),
        remediation=_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Classify the shared semantic contract.",
            "Move reusable implementation to the correct product or shared library.",
            "Keep runtime integration represented as runtime-call, not source-import.",
        ),
    )


def _cycle_diagnostics(
    edges: list[tuple[ComponentId, ComponentId]],
    by_id: dict[ComponentId, Component],
) -> list[Diagnostic]:
    adjacency: dict[ComponentId, set[ComponentId]] = {item: set() for item in by_id}
    for source, target in edges:
        adjacency[source].add(target)
    diagnostics: list[Diagnostic] = []
    for members in _strongly_connected_components(adjacency):
        if len(members) < _MIN_CYCLE_COMPONENTS:
            continue
        anchor = members[0]
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("architecture/dependencies/policy"),
                component_id=anchor,
                subject_kind="code-cycle",
                observed=" -> ".join((*members, members[0])),
                expected="an acyclic production code dependency graph",
                message="boundary-clean code dependencies form a cycle",
                path=by_id[anchor].path,
                anchor=f"components.{anchor}.dependencies",
                remediation=_remediation(
                    "Break the cycle at a stable semantic boundary.",
                    "Identify the smallest contract shared by the cycle members.",
                    "Move that contract below the cycle without changing runtime identities.",
                ),
            )
        )
    return diagnostics


def _strongly_connected_components(
    adjacency: dict[ComponentId, set[ComponentId]],
) -> tuple[tuple[ComponentId, ...], ...]:
    visited: set[ComponentId] = set()
    finish_order: list[ComponentId] = []
    for root in sorted(adjacency):
        if root in visited:
            continue
        pending: list[tuple[ComponentId, bool]] = [(root, False)]
        while pending:
            node, expanded = pending.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            pending.append((node, True))
            pending.extend(
                (target, False)
                for target in sorted(adjacency[node], reverse=True)
                if target not in visited
            )

    reverse: dict[ComponentId, set[ComponentId]] = {item: set() for item in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].add(source)

    assigned: set[ComponentId] = set()
    result: list[tuple[ComponentId, ...]] = []
    for root in reversed(finish_order):
        if root in assigned:
            continue
        members: list[ComponentId] = []
        pending = [(root, False)]
        assigned.add(root)
        while pending:
            node, _ = pending.pop()
            members.append(node)
            for source in sorted(reverse[node], reverse=True):
                if source not in assigned:
                    assigned.add(source)
                    pending.append((source, False))
        result.append(tuple(sorted(members)))
    return tuple(sorted(result))
