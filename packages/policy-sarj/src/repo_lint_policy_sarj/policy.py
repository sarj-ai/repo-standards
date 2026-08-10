"""Declarative Sarj repository architecture policy."""

from __future__ import annotations

from enum import StrEnum
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Literal

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
    ProfileDescriptor,
    RuleClassification,
    RuleGovernance,
    RuleMaturity,
    TokenSegment,
)
from .spec import PRODUCTS as SPEC_PRODUCTS


if TYPE_CHECKING:
    from collections.abc import Mapping


PRODUCTS = frozenset(SPEC_PRODUCTS)


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
_MIN_CYCLE_COMPONENTS = 2
_PATH_TOKEN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"  # ruff: ignore[hardcoded-password-string] - regex, not a secret
_APPLICATION_ROLE = rf"(?:api|agent|worker|web|{_PATH_TOKEN}-(?:api|agent|worker|web))"
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

_PRODUCT_OWNED_KINDS = frozenset(
    {
        ComponentKind.APPLICATION,
        ComponentKind.PRODUCT_LIBRARY,
        ComponentKind.GENERATED_CLIENT,
        ComponentKind.MIGRATION_SET,
        ComponentKind.TERRAFORM_ROOT,
        ComponentKind.CLOUD_BUILD,
        ComponentKind.KUBERNETES,
        ComponentKind.CLOUDFLARE,
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
        rule_id=RuleId("sarj/layout/operational-path"),
        version=1,
        severity="warning",
        summary="Operational configuration has a declared consolidation target.",
        rationale=(
            "Operational configuration moves can affect build context, state, triggers, and "
            "runtime behavior, so target placement remains advisory until verified."
        ),
        bad_example="path = 'iac/platform'",
        good_example="path = 'deployments/platform/terraform'",
    ),
    Rule(
        rule_id=RuleId("sarj/schema/component-fields"),
        version=1,
        severity="error",
        summary="Each component kind has exact required and forbidden identity fields.",
        rationale=(
            "Contradictory ownership fields make path and component-name derivation ambiguous."
        ),
        bad_example="kind = 'shared-library', product = 'platform'",
        good_example="kind = 'shared-library', capability = 'request-signing'",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/edge-endpoints"),
        version=1,
        severity="error",
        summary="Typed non-code edges connect compatible component kinds.",
        rationale="An edge whose endpoints contradict its declared meaning is invalid graph data.",
        bad_example="library --implements-contract--> application",
        good_example="application --implements-contract--> contract",
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
        summary="Organization-shared components do not import product code.",
        rationale="A shared dependency on one product reverses the intended dependency direction.",
        bad_example="shared library --package-dependency--> vb library",
        good_example="vb application --package-dependency--> shared library",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/contract-imports-implementation"),
        version=1,
        severity="error",
        summary="Contracts depend only on other contracts.",
        rationale="A contract that imports implementation cannot remain a stable boundary.",
        bad_example="contract --source-import--> product library",
        good_example="product contract --package-dependency--> shared contract",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/disallowed-code-dependency"),
        version=1,
        severity="error",
        summary="Production code dependencies follow the closed component-kind matrix.",
        rationale="A closed matrix keeps reusable and deployable layers independently releasable.",
        bad_example="tool --source-import--> application",
        good_example="tool --package-dependency--> shared library",
    ),
    Rule(
        rule_id=RuleId("sarj/graph/code-cycle"),
        version=1,
        severity="warning",
        summary="Boundary-clean production code dependencies are acyclic.",
        rationale=(
            "Cycles often conceal a missing contract, but remediation requires design judgment."
        ),
        bad_example="library A -> library B -> library A",
        good_example="application -> product library -> shared library",
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
    Rule(
        rule_id=RuleId("sarj/naming/application-role"),
        version=1,
        severity="warning",
        summary="Application names end in a controlled deployable role.",
        rationale=(
            "Role-bearing names make deployment ownership and repository navigation explicit."
        ),
        bad_example="applications/platform/integration",
        good_example="applications/platform/integration-api",
    ),
    Rule(
        rule_id=RuleId("sarj/naming/component-id"),
        version=1,
        severity="error",
        summary="Stable component IDs include their declared ownership namespace.",
        rationale=(
            "An ID that disagrees with product ownership makes diagnostics and "
            "migrations ambiguous."
        ),
        bad_example="id = 'vb.agent', product = 'platform'",
        good_example="id = 'platform.agent', product = 'platform'",
    ),
    Rule(
        rule_id=RuleId("sarj/naming/capability-token"),
        version=1,
        severity="error",
        summary="Capabilities use one lowercase ASCII kebab-case token.",
        rationale="One canonical token derives stable paths without ecosystem-specific ambiguity.",
        bad_example="capability = 'request.signing'",
        good_example="capability = 'request-signing'",
    ),
    Rule(
        rule_id=RuleId("sarj/delivery/hotfix-backsync"),
        version=1,
        severity="error",
        summary="Production hotfixes automatically flow through preview to development.",
        rationale=(
            "A release fix that does not reach every longer-lived integration branch can be "
            "silently reverted by the next promotion."
        ),
        bad_example="main is synchronized to preview, but preview is never synchronized to dev",
        good_example="main -> preview -> dev through guarded pull requests and required CI",
        problem=(
            "Repositories with production, preview, and development branches need both "
            "backsync edges to be safe, repeatable, and observable."
        ),
        harm="The next preview or development promotion can reintroduce a fixed production bug.",
        non_goals=(
            "creating branches or workflows",
            "merging pull requests",
            "automatically resolving merge conflicts",
        ),
        evidence_required=(
            "all three delivery branches exist or are explicitly declared",
            "both synchronization edges have guarded pull-request workflow structure",
            "live repository settings expose protected branches and required CI",
        ),
        upstream=("GitHub Actions", "GitHub branch protection", "GitHub rulesets"),
        references=(
            "https://docs.github.com/en/actions/concepts/security/github_token",
            "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets",
        ),
        precedence="Evaluate after delivery branch discovery and before advisory CI/CD rules.",
    ),
    Rule(
        rule_id=RuleId("sarj/github/actions-sha-pinning"),
        version=1,
        severity="warning",
        summary="Non-local workflow dependencies are pinned to immutable digests.",
        rationale=(
            "A full immutable commit identifier prevents a mutable tag from changing trusted "
            "workflow code without review."
        ),
        bad_example="uses: third-party/action@v2 or uses: docker://tool:latest",
        good_example="uses: third-party/action@0123456789abcdef0123456789abcdef01234567 # v2",
        non_goals=("executing actions", "automatically updating action references"),
        evidence_required=("tracked workflow action references from the selected Git tree",),
        upstream=("GitHub secure use reference",),
        references=(
            "https://docs.github.com/en/actions/how-tos/security-for-github-actions/security-guides/security-hardening-for-github-actions",
        ),
        precedence="Evaluate tracked workflow references independently of GitHub runtime state.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/explicit-permissions"),
        version=1,
        severity="warning",
        summary="GitHub workflows declare token permissions explicitly.",
        rationale="Explicit permissions prevent jobs from inheriting broad repository defaults.",
        bad_example="a workflow and its jobs omit permissions",
        good_example="permissions: { contents: read }",
        non_goals=("proving every declared permission is semantically minimal",),
        evidence_required=("parsed workflow and job permission scopes",),
        upstream=("GitHub Actions workflow syntax",),
        precedence="Evaluate each parsed workflow independently.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/job-timeouts"),
        version=1,
        severity="warning",
        summary="Executable GitHub Actions jobs have explicit time bounds.",
        rationale="A bounded job cannot consume runner capacity indefinitely after a hang.",
        bad_example="an executable job omits timeout-minutes",
        good_example="timeout-minutes: 15",
        non_goals=("requiring timeout-minutes on reusable-workflow call jobs",),
        evidence_required=("parsed executable job definitions",),
        upstream=("GitHub Actions workflow syntax",),
        precedence="Evaluate after safe workflow parsing.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/immutable-installs"),
        version=1,
        severity="warning",
        summary="Recognized CI dependency installs enforce committed lockfiles.",
        rationale=(
            "Frozen installs prevent dependency resolution from changing between review and CI."
        ),
        bad_example="uv sync or pnpm install without a lock-enforcing option",
        good_example=(
            "uv sync --locked, pnpm install --frozen-lockfile, or yarn install --immutable"
        ),
        non_goals=("executing package managers", "requiring lockfiles for global tool installs"),
        evidence_required=("parsed executable workflow steps using a recognized package manager",),
        upstream=("uv", "npm", "pnpm", "Yarn"),
        precedence="Evaluate only recognized direct CI install commands.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/vulnerability-gate"),
        version=1,
        severity="warning",
        summary="Recognized vulnerability scanners propagate failures to CI.",
        rationale=(
            "A scanner hidden behind continue-on-error or shell success handlers cannot enforce "
            "the repository's vulnerability policy."
        ),
        bad_example="pip-audit ... || true in a continue-on-error job",
        good_example="a blocking pip-audit or OSV Scanner job with reviewed scoped exceptions",
        non_goals=("choosing vulnerability policy", "calling vulnerability alert APIs"),
        evidence_required=("parsed executable workflow steps invoking a recognized scanner",),
        upstream=("pip-audit", "OSV Scanner", "npm audit", "pnpm audit"),
        precedence="Evaluate only workflows that invoke a recognized vulnerability scanner.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/merge-queue-trigger"),
        version=1,
        severity="warning",
        summary="Required CI handles merge-group events when a merge queue is active.",
        rationale=(
            "A merge queue cannot complete when its required checks never run for merge groups."
        ),
        bad_example="an active merge queue with no merge_group workflow trigger",
        good_example="on: [pull_request, merge_group]",
        non_goals=("enabling a merge queue",),
        evidence_required=("active branch ruleset evidence", "parsed workflow triggers"),
        upstream=("GitHub merge queues", "GitHub Actions"),
        references=(
            "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue",
        ),
        precedence="Evaluate only when active merge-queue evidence is complete.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/repository-governance"),
        version=1,
        severity="warning",
        summary="Basic repository governance files and settings are present.",
        rationale=(
            "Protected long-lived branches, ownership metadata, dependency-update automation, "
            "and read-only Actions defaults provide a reviewable governance baseline."
        ),
        bad_example="unprotected delivery branches with no CODEOWNERS or update configuration",
        good_example=(
            "protected delivery branches, a tracked CODEOWNERS file, a supported dependency "
            "updater configuration, and read-only default Actions permissions"
        ),
        non_goals=("changing GitHub settings", "opening dependency update pull requests"),
        evidence_required=(
            "live branch-protection and Actions-default settings",
            "tracked CODEOWNERS and dependency-updater file presence",
        ),
        upstream=("GitHub rulesets", "CODEOWNERS", "Dependabot"),
        references=(
            "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
            "https://docs.github.com/en/code-security/dependabot",
        ),
        precedence="Evaluate after branch discovery; unavailable external facts are inconclusive.",
        maturity="beta",
    ),
)

_RULE_CLASSIFICATION: Mapping[RuleId, RuleClassification] = MappingProxyType(
    {
        RuleId("sarj/layout/unknown-product"): RuleClassification.SCHEMA,
        RuleId("sarj/layout/component-path"): RuleClassification.OBJECTIVE,
        RuleId("sarj/layout/operational-path"): RuleClassification.OPERATIONAL,
        RuleId("sarj/schema/component-fields"): RuleClassification.SCHEMA,
        RuleId("sarj/graph/edge-endpoints"): RuleClassification.SCHEMA,
        RuleId("sarj/graph/application-imports-application"): RuleClassification.OBJECTIVE,
        RuleId("sarj/graph/library-imports-application"): RuleClassification.OBJECTIVE,
        RuleId("sarj/graph/self-dependency"): RuleClassification.SCHEMA,
        RuleId("sarj/graph/cross-product-import"): RuleClassification.OBJECTIVE,
        RuleId("sarj/graph/shared-imports-product"): RuleClassification.OBJECTIVE,
        RuleId("sarj/graph/contract-imports-implementation"): RuleClassification.OBJECTIVE,
        RuleId("sarj/graph/disallowed-code-dependency"): RuleClassification.OBJECTIVE,
        RuleId("sarj/graph/code-cycle"): RuleClassification.JUDGMENT,
        RuleId("sarj/reuse/vague-capability"): RuleClassification.JUDGMENT,
        RuleId("sarj/naming/application-role"): RuleClassification.JUDGMENT,
        RuleId("sarj/naming/component-id"): RuleClassification.SCHEMA,
        RuleId("sarj/naming/capability-token"): RuleClassification.SCHEMA,
        RuleId("sarj/delivery/hotfix-backsync"): RuleClassification.OBJECTIVE,
        RuleId("sarj/github/actions-sha-pinning"): RuleClassification.OPERATIONAL,
        RuleId("sarj/github/explicit-permissions"): RuleClassification.OPERATIONAL,
        RuleId("sarj/github/job-timeouts"): RuleClassification.OPERATIONAL,
        RuleId("sarj/github/immutable-installs"): RuleClassification.OPERATIONAL,
        RuleId("sarj/github/vulnerability-gate"): RuleClassification.OPERATIONAL,
        RuleId("sarj/github/merge-queue-trigger"): RuleClassification.OPERATIONAL,
        RuleId("sarj/github/repository-governance"): RuleClassification.JUDGMENT,
    }
)
_RULE_PRECEDENCE: Mapping[RuleId, int] = MappingProxyType(
    {
        RuleId("sarj/schema/component-fields"): 10,
        RuleId("sarj/layout/unknown-product"): 20,
        RuleId("sarj/graph/self-dependency"): 30,
        RuleId("sarj/graph/edge-endpoints"): 40,
        RuleId("sarj/graph/application-imports-application"): 50,
        RuleId("sarj/graph/contract-imports-implementation"): 60,
        RuleId("sarj/graph/library-imports-application"): 70,
        RuleId("sarj/graph/shared-imports-product"): 80,
        RuleId("sarj/graph/cross-product-import"): 90,
        RuleId("sarj/graph/disallowed-code-dependency"): 100,
        RuleId("sarj/naming/capability-token"): 110,
        RuleId("sarj/naming/component-id"): 120,
        RuleId("sarj/layout/component-path"): 130,
        RuleId("sarj/layout/operational-path"): 130,
        RuleId("sarj/naming/application-role"): 140,
        RuleId("sarj/reuse/vague-capability"): 150,
        RuleId("sarj/graph/code-cycle"): 160,
        RuleId("sarj/delivery/hotfix-backsync"): 170,
        RuleId("sarj/github/actions-sha-pinning"): 180,
        RuleId("sarj/github/explicit-permissions"): 190,
        RuleId("sarj/github/job-timeouts"): 200,
        RuleId("sarj/github/immutable-installs"): 210,
        RuleId("sarj/github/vulnerability-gate"): 220,
        RuleId("sarj/github/merge-queue-trigger"): 230,
        RuleId("sarj/github/repository-governance"): 240,
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
        rule.rule_id: (
            "external"
            if rule.rule_id
            in {
                RuleId("sarj/delivery/hotfix-backsync"),
                RuleId("sarj/github/merge-queue-trigger"),
                RuleId("sarj/github/repository-governance"),
            }
            else "verified"
            if rule.rule_id
            in {
                RuleId("sarj/github/actions-sha-pinning"),
                RuleId("sarj/github/explicit-permissions"),
                RuleId("sarj/github/job-timeouts"),
                RuleId("sarj/github/immutable-installs"),
                RuleId("sarj/github/vulnerability-gate"),
            }
            else "declared"
        )
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
        upstream=rule.upstream or _UPSTREAM_BY_CLASSIFICATION[_RULE_CLASSIFICATION[rule.rule_id]],
        precedence=_RULE_PRECEDENCE[rule.rule_id],
    )
    for rule in RULES
)

POLICY_SPEC = PolicySpec(
    schema_version=1,
    policy_id=PolicyId("sarj"),
    policy_version=4,
    profile=ProfileDescriptor(
        profile_id=PROFILE_ID,
        title="Sarj organization consolidation target",
        product_registry_mode="closed",
        products=SPEC_PRODUCTS,
        repository_overrides=False,
        target_repository_plugins=False,
    ),
    component_kinds=tuple(kind.value for kind in ComponentKind),
    edge_kinds=tuple(sorted(EDGE_KINDS)),
    path_templates=PATH_TEMPLATES,
    rule_governance=RULE_GOVERNANCE,
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


def _component_field_value(
    component: Component, field: Literal["product", "capability"]
) -> str | None:
    if field == "product":
        return component.product
    return component.capability


class SarjPolicy:
    """Versioned Sarj conventions implemented only against neutral core types."""

    policy_id: ClassVar[PolicyId] = PolicyId("sarj")
    policy_version: ClassVar[int] = POLICY_SPEC.policy_version
    profile_id: ClassVar[str] = PROFILE_ID

    @staticmethod
    def spec() -> PolicySpec:
        """Return the immutable strict consolidation profile descriptor."""
        return POLICY_SPEC

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        """Return immutable rule metadata."""
        return RULES

    @staticmethod
    def evaluate(manifest: Manifest) -> tuple[Diagnostic, ...]:
        """Evaluate Sarj ownership and dependency declarations."""
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
            product_diagnostic = _product_diagnostic(component, component_kind)
            if product_diagnostic is not None:
                diagnostics.append(product_diagnostic)
                invalid.add(component.component_id)

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
                rule_id = (
                    RuleId("sarj/layout/operational-path")
                    if template.operational
                    else RuleId("sarj/layout/component-path")
                )
                diagnostics.append(
                    _diagnostic(
                        rule_id=rule_id,
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
        diagnostics.extend(_cycle_diagnostics(clean_code_edges, by_id))
        return tuple(diagnostics)


def _naming_diagnostics(component: Component, component_kind: ComponentKind) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if component.capability is not None and re.fullmatch(_PATH_TOKEN, component.capability) is None:
        diagnostics.append(
            _diagnostic(
                rule_id=RuleId("sarj/naming/capability-token"),
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
                rule_id=RuleId("sarj/naming/component-id"),
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
    if component_kind is ComponentKind.APPLICATION:
        application_name = component.path.rsplit("/", maxsplit=1)[-1]
        canonical_application_path = (
            rf"applications/{re.escape(component.product or '')}/{_PATH_TOKEN}"
        )
        if (
            re.fullmatch(canonical_application_path, component.path) is not None
            and re.fullmatch(_APPLICATION_ROLE, application_name) is None
        ):
            diagnostics.append(
                _diagnostic(
                    rule_id=RuleId("sarj/naming/application-role"),
                    component_id=component.component_id,
                    subject_kind="application-role",
                    observed=application_name,
                    expected="api|agent|worker|web|<domain>-(api|agent|worker|web)",
                    message="application name does not end in a controlled deployable role",
                    path=component.path,
                    anchor=f"components.{component.component_id}.path",
                    remediation=_remediation(
                        "Name the deployable by its role or domain and role.",
                        "Use api, agent, worker, or web as the final role token.",
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
        rule_id=RuleId("sarj/schema/component-fields"),
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
            "Then rerun repo-lint so dependent naming and path rules can evaluate.",
        ),
    )


def _product_diagnostic(component: Component, component_kind: ComponentKind) -> Diagnostic | None:
    product_owned = component_kind in _PRODUCT_OWNED_KINDS or (
        component_kind is ComponentKind.CONTRACT and component.product is not None
    )
    if not product_owned or component.product in PRODUCTS:
        return None
    return _diagnostic(
        rule_id=RuleId("sarj/layout/unknown-product"),
        component_id=component.component_id,
        subject_kind="product",
        observed=component.product or "<missing>",
        expected="najm|platform|vb",
        message="component uses an unregistered product",
        path=component.path,
        anchor=f"components.{component.component_id}.product",
        remediation=_remediation(
            "Use an allocated Sarj product ID.",
            "Select platform, vb, or najm, or update the reviewed Sarj policy first.",
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
    if component.product in PRODUCTS:
        return f"{component.product}."
    return None


def _dependency_diagnostics(
    component: Component,
    by_id: dict[ComponentId, Component],
    kinds: dict[ComponentId, ComponentKind],
    invalid: set[ComponentId],
) -> tuple[list[Diagnostic], list[tuple[ComponentId, ComponentId]]]:
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
    return diagnostics, accepted


def _code_boundary(  # ruff: ignore[too-many-return-statements] - precedence is intentionally linear
    source: Component,
    source_kind: ComponentKind,
    target: Component,
    target_kind: ComponentKind,
) -> tuple[RuleId, str] | None:
    """Return the first applicable code-boundary rule in documented precedence order."""
    if source.component_id == target.component_id:
        return RuleId("sarj/graph/self-dependency"), "remove the self dependency"
    if source_kind is ComponentKind.APPLICATION and target_kind is ComponentKind.APPLICATION:
        return (
            RuleId("sarj/graph/application-imports-application"),
            "depend on a library or use a runtime-call edge",
        )
    if source_kind is ComponentKind.CONTRACT and target_kind is not ComponentKind.CONTRACT:
        return (
            RuleId("sarj/graph/contract-imports-implementation"),
            "contracts may depend only on contracts",
        )
    if source_kind in {ComponentKind.PRODUCT_LIBRARY, ComponentKind.SHARED_LIBRARY} and (
        target_kind is ComponentKind.APPLICATION
    ):
        return (
            RuleId("sarj/graph/library-imports-application"),
            "applications may import libraries; libraries may not import applications",
        )
    if _is_shared_source(source, source_kind) and target.product is not None:
        return (
            RuleId("sarj/graph/shared-imports-product"),
            "shared components import no product implementation",
        )
    if source.product and target.product and source.product != target.product:
        return (
            RuleId("sarj/graph/cross-product-import"),
            "use a shared contract/library or runtime-call edge",
        )
    if target_kind not in _ALLOWED_CODE_TARGETS[source_kind]:
        allowed = ",".join(sorted(kind.value for kind in _ALLOWED_CODE_TARGETS[source_kind]))
        return (
            RuleId("sarj/graph/disallowed-code-dependency"),
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
        RuleId("sarj/graph/edge-endpoints"),
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
                rule_id=RuleId("sarj/graph/code-cycle"),
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
    """Return deterministic iterative Kosaraju components with bounded stack use."""
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
