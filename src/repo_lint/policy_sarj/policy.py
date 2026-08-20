from __future__ import annotations

from dataclasses import replace
from enum import StrEnum
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from repo_lint.core.errors import ConfigurationError
from repo_lint.core.models import (
    Component,
    ComponentId,
    Diagnostic,
    ExampleLanguage,
    FixtureId,
    Manifest,
    PolicyId,
    Remediation,
    Rule,
    RuleExamplePair,
    RuleId,
    RuleRemediation,
)
from repo_lint.core.taxonomy import (
    ARCHITECTURE,
    COMPONENT_SCHEMA,
    DELIVERY,
    DEPENDENCY_BOUNDARIES,
    GITHUB_ACTIONS,
    NAMING,
    RELEASE_FLOW,
    REPOSITORY_GOVERNANCE,
    REPOSITORY_LAYOUT,
    REUSE,
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
    ProfileDescriptor,
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

_WARNING_EXAMPLE_FIXTURES = frozenset(
    {
        "sarj-graph-code-cycle",
        "sarj-reuse-vague-capability",
        "sarj-naming-application-role",
        "sarj-github-actions-sha-pinning",
        "sarj-github-explicit-permissions",
        "sarj-github-job-timeouts",
        "sarj-github-immutable-installs",
        "sarj-github-vulnerability-gate",
        "sarj-github-merge-queue-trigger",
        "sarj-github-repository-governance",
    }
)


def _example(
    fixture_id: str, language: ExampleLanguage, flagged: str, passes: str
) -> tuple[RuleExamplePair, ...]:
    title_source = fixture_id.removeprefix("sarj-").partition("-")[2]
    title = " ".join(
        {"github": "GitHub", "sha": "SHA", "id": "ID"}.get(word, word.title())
        for word in title_source.split("-")
    )
    return (
        RuleExamplePair(
            fixture_id=FixtureId(fixture_id),
            language=language,
            flagged=flagged,
            passes=passes,
            title=title,
            severity="warning" if fixture_id in _WARNING_EXAMPLE_FIXTURES else "error",
        ),
    )


def _rule_remediation(summary: str, *steps: str) -> RuleRemediation:
    return RuleRemediation(
        summary=summary,
        steps=steps,
        validation=("Run repo-standards again and confirm the rule passes.",),
    )


_RULE_PARTS = (
    Rule(
        rule_id=RuleId("sarj/layout/component-path"),
        version=1,
        default_severity="error",
        title="Use canonical component paths",
        summary="Component paths match their declared ownership kind.",
        detects="A non-operational component path does not match its kind and ownership fields.",
        impact=(
            "Canonical paths make ownership, impact analysis, and merge preflight deterministic."
        ),
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        remediation=_rule_remediation(
            "Move the component through an explicit path-only migration.",
            "Add an old-to-new migration path declaration.",
            "Move only this component and update path-sensitive references.",
        ),
        examples=_example(
            "sarj-layout-component-path",
            "toml",
            "path = 'python/agent'",
            "path = 'applications/alpha/agent'",
        ),
        evidence_required=("component kind, ownership fields, and declared path",),
    ),
    Rule(
        rule_id=RuleId("sarj/layout/operational-path"),
        version=1,
        default_severity="warning",
        title="Use canonical operational paths",
        summary="Operational components use canonical deployment paths.",
        detects="An operational component path does not match its kind and ownership fields.",
        impact=(
            "Operational configuration moves can affect build context, state, triggers, and "
            "runtime behavior, so target placement remains advisory until verified."
        ),
        taxonomy=taxonomy(ARCHITECTURE, REPOSITORY_LAYOUT),
        remediation=_rule_remediation(
            "Move the component through an explicit path-only migration.",
            "Preserve state, build context, triggers, and runtime identity during the move.",
        ),
        examples=_example(
            "sarj-layout-operational-path",
            "toml",
            "path = 'iac/alpha'",
            "path = 'deployments/alpha/terraform'",
        ),
        evidence_required=("operational component kind, ownership fields, and path",),
    ),
    Rule(
        rule_id=RuleId("sarj/schema/component-fields"),
        version=1,
        default_severity="error",
        title="Match fields to component kind",
        summary="Each component kind has exact required and forbidden identity fields.",
        detects="A component omits a required identity field or declares a forbidden field.",
        impact=(
            "Contradictory ownership fields make path and component-name derivation ambiguous."
        ),
        taxonomy=taxonomy(ARCHITECTURE, COMPONENT_SCHEMA),
        remediation=_rule_remediation(
            "Make the component fields match the selected component kind.",
            "Add required identity fields and remove fields forbidden for this kind.",
        ),
        examples=_example(
            "sarj-schema-component-fields",
            "toml",
            "kind = 'shared-library'\nproduct = 'alpha'",
            "kind = 'shared-library'\ncapability = 'request-signing'",
        ),
        evidence_required=("component kind, product, and capability fields",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/edge-endpoints"),
        version=1,
        default_severity="error",
        title="Use compatible edge endpoints",
        summary="Constrained non-code edges connect compatible component kinds.",
        detects="A constrained non-code edge has an incompatible source or target kind.",
        impact="An edge whose endpoints contradict its meaning is invalid dependency evidence.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Correct the edge type or connect component kinds allowed for that edge.",
        ),
        examples=_example(
            "sarj-graph-edge-endpoints",
            "text",
            "library --implements-contract--> application",
            "application --implements-contract--> contract",
        ),
        evidence_required=("declared edge kind and endpoint component kinds",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/application-imports-application"),
        version=1,
        default_severity="error",
        title="Keep applications independent",
        summary="Applications do not depend on another application's implementation.",
        detects="An application has a code dependency on another application.",
        impact="Application-to-application coupling prevents independent release and rollback.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Move reusable code into a product library or use a runtime-call edge.",
        ),
        examples=_example(
            "sarj-graph-application-dependency",
            "text",
            "application A --source-import--> application B",
            "application A --package-dependency--> product library B",
        ),
        evidence_required=("component kinds and declared code dependencies",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/library-imports-application"),
        version=1,
        default_severity="error",
        title="Keep libraries below applications",
        summary="Libraries do not depend on application implementation.",
        detects="A product or shared library has a code dependency on an application.",
        impact=("Reusable code must remain below deployable applications in the dependency graph."),
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Reverse the dependency or move the shared contract below the application.",
        ),
        examples=_example(
            "sarj-graph-library-application-dependency",
            "text",
            "product library --source-import--> application",
            "application --package-dependency--> product library",
        ),
        evidence_required=("component kinds and declared code dependencies",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/self-dependency"),
        version=1,
        default_severity="error",
        title="Remove self-dependencies",
        summary="Components do not declare dependencies on themselves.",
        detects="A component declares a code dependency on its own component ID.",
        impact="Self edges are invalid graph evidence and can hide resolver mistakes.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Remove the redundant self edge.",
        ),
        examples=_example(
            "sarj-graph-self-dependency",
            "text",
            "component A --source-import--> component A",
            "component A has no edge to itself",
        ),
        evidence_required=("component IDs and declared code dependencies",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/cross-product-import"),
        version=1,
        default_severity="error",
        title="Avoid cross-product code dependencies",
        summary="Product code does not depend on another product's implementation.",
        detects="A code dependency crosses two distinct declared product IDs.",
        impact="Cross-product implementation coupling hides ownership and release dependencies.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Use a shared contract or a runtime-call edge across products.",
        ),
        examples=_example(
            "sarj-graph-cross-product-dependency",
            "text",
            "beta library --source-import--> alpha library",
            "beta application --runtime-call--> alpha API",
        ),
        evidence_required=("product ownership and declared code dependencies",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/shared-imports-product"),
        version=1,
        default_severity="error",
        title="Keep shared code product-neutral",
        summary="Shared components do not depend on product implementation.",
        detects="A shared component has a code dependency on a product-owned component.",
        impact="A shared dependency on one product reverses the intended ownership direction.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Move the dependency behind a shared contract or reverse its direction.",
        ),
        examples=_example(
            "sarj-graph-shared-product-dependency",
            "text",
            "shared library --package-dependency--> beta library",
            "beta application --package-dependency--> shared library",
        ),
        evidence_required=("ownership and declared code dependencies",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/contract-imports-implementation"),
        version=1,
        default_severity="error",
        title="Keep contracts implementation-free",
        summary="Contracts depend only on other contracts.",
        detects="A contract has a code dependency on a non-contract component.",
        impact="A contract coupled to implementation cannot remain a stable boundary.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Keep contract dependencies limited to contract components.",
        ),
        examples=_example(
            "sarj-graph-contract-implementation-dependency",
            "text",
            "contract --source-import--> product library",
            "product contract --package-dependency--> shared contract",
        ),
        evidence_required=("component kinds and declared code dependencies",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/disallowed-code-dependency"),
        version=1,
        default_severity="error",
        title="Follow the code dependency matrix",
        summary="Production code dependencies follow the closed component-kind matrix.",
        detects="A code dependency targets a component kind not allowed for its source kind.",
        impact="The closed matrix keeps reusable and deployable layers independently releasable.",
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Replace implementation coupling with an owned library or runtime contract.",
            "Target an allowed library, contract, or generated-client kind.",
        ),
        examples=_example(
            "sarj-graph-disallowed-code-dependency",
            "text",
            "migration set --source-import--> contract",
            "migration set --package-dependency--> shared library",
        ),
        evidence_required=("source and target kinds plus declared code dependency",),
    ),
    Rule(
        rule_id=RuleId("sarj/graph/code-cycle"),
        version=1,
        default_severity="warning",
        title="Keep code dependencies acyclic",
        summary="Boundary-clean production code dependencies are acyclic.",
        detects="Accepted production code dependencies form a cycle of two or more components.",
        impact=(
            "Cycles often conceal a missing contract, but remediation requires design judgment."
        ),
        taxonomy=taxonomy(ARCHITECTURE, DEPENDENCY_BOUNDARIES),
        remediation=_rule_remediation(
            "Break the cycle at a stable semantic boundary.",
            "Move the smallest shared contract below the cycle.",
        ),
        examples=_example(
            "sarj-graph-code-cycle",
            "text",
            "library A -> library B -> library A",
            "application -> product library -> shared library",
        ),
        evidence_required=("boundary-clean production code dependency graph",),
    ),
    Rule(
        rule_id=RuleId("sarj/reuse/vague-capability"),
        version=1,
        default_severity="warning",
        title="Use specific capability names",
        summary="Reusable libraries avoid controlled generic capability names.",
        detects=(
            "A reusable library uses common, core, helpers, shared, or utils as its capability."
        ),
        impact="Generic names become dependency magnets and conceal ownership.",
        taxonomy=taxonomy(ARCHITECTURE, REUSE),
        remediation=_rule_remediation(
            "Name the stable capability rather than its generic utility role.",
            "Choose the cohesive public contract as the capability name.",
        ),
        examples=_example(
            "sarj-reuse-vague-capability",
            "toml",
            "capability = 'utils'",
            "capability = 'request-signing'",
        ),
        evidence_required=("reusable component kind and capability",),
    ),
    Rule(
        rule_id=RuleId("sarj/naming/application-role"),
        version=1,
        default_severity="warning",
        title="Name the application role",
        summary="Application names end in a controlled deployable role.",
        detects="A canonically placed application name lacks an api, agent, worker, or web suffix.",
        impact=("Role-bearing names make deployment ownership and repository navigation explicit."),
        taxonomy=taxonomy(ARCHITECTURE, NAMING),
        remediation=_rule_remediation(
            "Name the deployable by its role or domain and role.",
            "Use api, agent, worker, or web as the final role token.",
        ),
        examples=_example(
            "sarj-naming-application-role",
            "text",
            "applications/alpha/integration",
            "applications/alpha/integration-api",
        ),
        evidence_required=("canonical application path",),
    ),
    Rule(
        rule_id=RuleId("sarj/naming/component-id"),
        version=1,
        default_severity="error",
        title="Align IDs with ownership",
        summary="Stable component IDs include their declared ownership namespace.",
        detects="A valid component ID does not start with its product or shared ownership prefix.",
        impact=(
            "An ID that disagrees with product ownership makes diagnostics and "
            "migrations ambiguous."
        ),
        taxonomy=taxonomy(ARCHITECTURE, NAMING),
        remediation=_rule_remediation(
            "Use the declared ownership namespace in the stable component ID.",
            "Update exact manifest references and migration evidence together.",
        ),
        examples=_example(
            "sarj-naming-component-id",
            "toml",
            "id = 'beta.agent'\nproduct = 'alpha'",
            "id = 'alpha.agent'\nproduct = 'alpha'",
        ),
        evidence_required=("component kind, ownership, and stable ID",),
    ),
    Rule(
        rule_id=RuleId("sarj/naming/capability-token"),
        version=1,
        default_severity="error",
        title="Use kebab-case capabilities",
        summary="Capabilities use one lowercase ASCII kebab-case token.",
        detects="A capability is not one lowercase ASCII kebab-case token.",
        impact="One canonical token derives stable paths without ecosystem-specific ambiguity.",
        taxonomy=taxonomy(ARCHITECTURE, NAMING),
        remediation=_rule_remediation(
            "Choose one lowercase ASCII kebab-case capability token.",
            "Keep distribution, import, and runtime aliases separate from this identity.",
        ),
        examples=_example(
            "sarj-naming-capability-token",
            "toml",
            "capability = 'request.signing'",
            "capability = 'request-signing'",
        ),
        evidence_required=("declared component capability",),
    ),
    Rule(
        rule_id=RuleId("sarj/delivery/hotfix-backsync"),
        version=1,
        default_severity="error",
        title="Back-sync production hotfixes",
        summary="Production hotfixes automatically flow through preview to development.",
        detects=(
            "An active main, preview, and development chain lacks a guarded pull-request "
            "back-sync edge or its required repository controls."
        ),
        impact="A later promotion can reintroduce a production fix that was not back-synced.",
        taxonomy=taxonomy(DELIVERY, RELEASE_FLOW),
        remediation=_rule_remediation(
            "Add idempotent PR-based backsync workflows and protect every long-lived branch.",
            "Implement guarded main-to-preview and preview-to-development pull requests.",
            "Require CI and auto-merge only the verified source commit.",
        ),
        examples=_example(
            "sarj-delivery-hotfix-backsync",
            "text",
            "main -> preview; preview -/-> dev",
            "main -> preview -> dev through guarded pull requests and required CI",
        ),
        evidence_required=(
            "all three delivery branches exist or are explicitly declared",
            "both synchronization edges have guarded pull-request workflow structure",
            "live repository settings expose protected branches and required CI",
        ),
        non_goals=(
            "creating branches or workflows",
            "merging pull requests",
            "automatically resolving merge conflicts",
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
        default_severity="warning",
        title="Pin workflow dependencies",
        summary="Non-local workflow dependencies are pinned to immutable digests.",
        detects=(
            "A non-local uses reference is not a full 40-character Action SHA or sha256 "
            "container digest."
        ),
        impact="A mutable tag can change trusted workflow code without repository review.",
        taxonomy=taxonomy(DELIVERY, GITHUB_ACTIONS),
        remediation=_rule_remediation(
            "Replace the mutable reference with a reviewed immutable digest.",
            "Pin an Action to its full commit SHA or a container to its sha256 digest.",
        ),
        examples=_example(
            "sarj-github-actions-sha-pinning",
            "yaml",
            "uses: third-party/action@v2",
            "uses: third-party/action@0123456789abcdef0123456789abcdef01234567 # v2",
        ),
        evidence_required=("tracked workflow action references from the selected Git tree",),
        non_goals=("executing actions", "automatically updating action references"),
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
        default_severity="warning",
        title="Declare Actions permissions",
        summary="GitHub workflows declare token permissions explicitly.",
        detects=(
            "A workflow has neither top-level permissions nor explicit permissions on every job."
        ),
        impact="Jobs inherit repository defaults that may grant more token access than intended.",
        taxonomy=taxonomy(DELIVERY, GITHUB_ACTIONS),
        remediation=_rule_remediation(
            "Declare permissions at workflow or job scope.",
            "Add top-level permissions or declare permissions on every job.",
        ),
        examples=_example(
            "sarj-github-explicit-permissions",
            "yaml",
            "jobs:\n  test:\n    timeout-minutes: 15\n    steps:\n      - run: echo ok",
            (
                "permissions:\n  contents: read\njobs:\n  test:\n"
                "    timeout-minutes: 15\n    steps:\n      - run: echo ok"
            ),
        ),
        evidence_required=("parsed workflow and job permission declarations",),
        non_goals=("proving every declared permission is semantically minimal",),
        upstream=("GitHub Actions workflow syntax",),
        precedence="Evaluate each parsed workflow independently.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/job-timeouts"),
        version=1,
        default_severity="warning",
        title="Set job timeouts",
        summary="Executable GitHub Actions jobs have explicit time bounds.",
        detects="An executable job omits timeout-minutes; reusable-workflow call jobs are exempt.",
        impact="A hung job can consume runner capacity indefinitely.",
        taxonomy=taxonomy(DELIVERY, GITHUB_ACTIONS),
        remediation=_rule_remediation(
            "Bound every executable job with timeout-minutes.",
            "Choose a reviewed upper bound for each executable job.",
        ),
        examples=_example(
            "sarj-github-job-timeouts",
            "yaml",
            "jobs:\n  test:\n    steps:\n      - run: echo ok",
            "jobs:\n  test:\n    timeout-minutes: 15\n    steps:\n      - run: echo ok",
        ),
        evidence_required=("parsed executable job definitions",),
        non_goals=("requiring timeout-minutes on reusable-workflow call jobs",),
        upstream=("GitHub Actions workflow syntax",),
        precedence="Evaluate after safe workflow parsing.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/immutable-installs"),
        version=1,
        default_severity="warning",
        title="Use lock-enforcing installs",
        summary="Recognized CI installs use lock-enforcing modes.",
        detects=(
            "A recognized uv, pnpm, Yarn, or npm install command does not use its immutable mode."
        ),
        impact="CI can resolve dependencies differently from the reviewed lockfile.",
        taxonomy=taxonomy(DELIVERY, GITHUB_ACTIONS),
        remediation=_rule_remediation(
            "Use the package manager's lock-enforcing install mode in CI.",
            "Use uv --locked, pnpm --frozen-lockfile, Yarn --immutable, or npm ci.",
        ),
        examples=_example(
            "sarj-github-immutable-installs",
            "yaml",
            "run: uv sync",
            "run: uv sync --locked",
        ),
        evidence_required=("recognized dependency install commands in executable workflow steps",),
        non_goals=("executing package managers", "requiring lockfiles for global tool installs"),
        upstream=("uv", "npm", "pnpm", "Yarn"),
        precedence="Evaluate only recognized direct CI install commands.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/vulnerability-gate"),
        version=1,
        default_severity="warning",
        title="Keep scanner failures blocking",
        summary="Recognized vulnerability scanner failures propagate to CI.",
        detects=("A recognized scanner runs with continue-on-error or shell failure suppression."),
        impact="CI can pass while the scanner reports vulnerabilities or fails to run correctly.",
        taxonomy=taxonomy(DELIVERY, GITHUB_ACTIONS),
        remediation=_rule_remediation(
            "Remove failure suppression from the vulnerability scanning gate.",
            "Let the scanner's nonzero exit status fail its workflow job.",
        ),
        examples=_example(
            "sarj-github-vulnerability-gate",
            "yaml",
            "run: pip-audit || true",
            "run: pip-audit",
        ),
        evidence_required=("workflow steps invoking a recognized vulnerability scanner",),
        non_goals=("choosing vulnerability policy", "calling vulnerability alert APIs"),
        upstream=("pip-audit", "OSV Scanner", "npm audit", "pnpm audit"),
        precedence="Evaluate only workflows that invoke a recognized vulnerability scanner.",
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("sarj/github/merge-queue-trigger"),
        version=1,
        default_severity="warning",
        title="Handle merge-group events",
        summary="An inspected workflow handles merge-group events when a merge queue is active.",
        detects=(
            "An active branch merge queue exists, but no inspected workflow declares merge_group."
        ),
        impact="Required checks may never run for queued merge groups.",
        taxonomy=taxonomy(DELIVERY, GITHUB_ACTIONS),
        remediation=_rule_remediation(
            "Add merge_group to the required CI workflow triggers.",
            "Run the same required checks for pull_request and merge_group events.",
        ),
        examples=_example(
            "sarj-github-merge-queue-trigger",
            "yaml",
            "on: [pull_request]",
            "on: [pull_request, merge_group]",
        ),
        evidence_required=("active branch ruleset evidence", "parsed workflow triggers"),
        non_goals=("enabling a merge queue",),
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
        default_severity="warning",
        title="Configure repository safeguards",
        summary="Repositories provide baseline ownership, maintenance, and review safeguards.",
        detects=(
            "CODEOWNERS, dependency updates, long-lived branch protection, or read-only default "
            "Actions permissions are missing."
        ),
        impact=(
            "Protected long-lived branches, ownership metadata, dependency-update automation, "
            "and read-only Actions defaults provide a reviewable governance baseline."
        ),
        taxonomy=taxonomy(DELIVERY, REPOSITORY_GOVERNANCE),
        remediation=_rule_remediation(
            "Add the missing ownership, maintenance, and GitHub repository controls.",
            "Add each missing file or repository setting named by the diagnostic.",
        ),
        examples=_example(
            "sarj-github-repository-governance",
            "text",
            "protected branches; Dependabot; no CODEOWNERS; read-only Actions",
            "protected branches; Dependabot; CODEOWNERS; read-only Actions",
        ),
        evidence_required=(
            "live branch-protection and Actions-default settings",
            "tracked CODEOWNERS and dependency-updater file presence",
        ),
        non_goals=("changing GitHub settings", "opening dependency update pull requests"),
        upstream=("GitHub rulesets", "CODEOWNERS", "Dependabot"),
        references=(
            "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
            "https://docs.github.com/en/code-security/dependabot",
        ),
        precedence="Evaluate after branch discovery; unavailable external facts are inconclusive.",
        maturity="beta",
    ),
)


def _consolidated_rules(parts: tuple[Rule, ...]) -> tuple[Rule, ...]:
    by_id = {str(rule.rule_id): rule for rule in parts}
    groups = (
        (
            "architecture/layout/component-paths",
            ("sarj/layout/component-path", "sarj/layout/operational-path"),
            "Use canonical component paths",
            "Every component has one canonical ownership root.",
            "Reports a component path that violates its kind template or overlaps another root.",
            "Canonical disjoint roots make ownership and impact analysis deterministic.",
            "error",
        ),
        (
            "architecture/schema/component",
            (
                "sarj/schema/component-fields",
                "sarj/naming/capability-token",
                "sarj/naming/component-id",
            ),
            "Keep component identity consistent",
            "Component kind, ownership fields, identifiers, and capability tokens agree.",
            (
                "Reports missing or forbidden fields, invalid capability tokens, or "
                "ownership-ID mismatches."
            ),
            "Trustworthy component identity prevents cascading layout and dependency mistakes.",
            "error",
        ),
        (
            "architecture/dependencies/policy",
            (
                "sarj/graph/edge-endpoints",
                "sarj/graph/application-imports-application",
                "sarj/graph/library-imports-application",
                "sarj/graph/self-dependency",
                "sarj/graph/cross-product-import",
                "sarj/graph/shared-imports-product",
                "sarj/graph/contract-imports-implementation",
                "sarj/graph/disallowed-code-dependency",
            ),
            "Enforce dependency boundaries",
            "Every dependency edge has legal endpoint kinds and ownership direction.",
            (
                "Reports self edges, forbidden code coupling, cross-product imports, or "
                "invalid typed endpoints."
            ),
            "A single dependency policy keeps ownership and release boundaries explicit.",
            "error",
        ),
        (
            "architecture/dependencies/acyclic",
            ("sarj/graph/code-cycle",),
            "Keep production code dependencies acyclic",
            "Accepted production code dependencies form a directed acyclic graph.",
            "Reports each strongly connected component containing two or more components.",
            "Acyclic dependencies keep build, ownership, and extraction direction clear.",
            "warning",
        ),
        (
            "delivery/branches/hotfix-back-sync",
            ("sarj/delivery/hotfix-backsync",),
            "Back-sync production hotfixes",
            "Production changes flow back through preview and development branches.",
            "Reports a missing guarded pull-request back-sync edge or repository control.",
            "Reliable back-sync prevents production fixes from disappearing in later releases.",
            "error",
        ),
        (
            "delivery/actions/safety",
            (
                "sarj/github/actions-sha-pinning",
                "sarj/github/explicit-permissions",
                "sarj/github/job-timeouts",
                "sarj/github/immutable-installs",
                "sarj/github/vulnerability-gate",
            ),
            "Harden GitHub Actions",
            (
                "Workflow jobs are pinned, least-privileged, time-bounded, reproducible, "
                "and fail closed."
            ),
            (
                "Reports mutable dependencies or installs, implicit permissions, missing "
                "timeouts, or bypassed scanners."
            ),
            "A hardened workflow baseline limits supply-chain and unbounded-execution risk.",
            "warning",
        ),
        (
            "delivery/repository/controls",
            ("sarj/github/repository-governance", "sarj/github/merge-queue-trigger"),
            "Configure repository delivery controls",
            (
                "Repository ownership, updates, protection, token defaults, and merge-queue "
                "coverage are explicit."
            ),
            "Reports missing repository safeguards or workflows that omit active merge queues.",
            "Repository controls provide a consistent, reviewable delivery boundary.",
            "warning",
        ),
    )
    compact_content = {
        "architecture/layout/component-paths": (
            _rule_remediation(
                "Move the component to one canonical, disjoint ownership root.",
                "Declare the old and new paths before moving tracked files.",
            ),
            ("component kinds, ownership fields, and declared paths",),
            (),
        ),
        "architecture/schema/component": (
            _rule_remediation(
                "Align component fields and identifiers with its kind and ownership.",
                "Add required fields, remove forbidden fields, and correct IDs and tokens.",
            ),
            ("component kind, ownership fields, stable ID, and capability token",),
            (),
        ),
        "architecture/dependencies/policy": (
            _rule_remediation(
                "Correct or remove the invalid dependency edge.",
                "Use an allowed edge type and compatible source and target component kinds.",
            ),
            ("edge type, endpoint kinds, component IDs, and product ownership",),
            (),
        ),
        "delivery/actions/safety": (
            _rule_remediation(
                "Apply the missing workflow safety control.",
                "Pin dependencies, bound permissions and time, enforce lockfiles, and fail closed.",
            ),
            ("parsed workflow references, jobs, steps, permissions, installs, and scanners",),
            (
                "executing workflows or package managers",
                "automatically updating workflow references",
                "choosing repository vulnerability policy",
            ),
        ),
        "delivery/branches/hotfix-back-sync": (
            _rule_remediation(
                "Add guarded PR back-syncs and protect all three branches.",
                "Implement main-to-preview and preview-to-development pull requests.",
            ),
            ("delivery branches, guarded synchronization workflows, and live protections",),
            (),
        ),
    }
    merged: list[Rule] = []
    for target, source_ids, title, summary, detects, impact, severity in groups:
        sources = tuple(by_id[source_id] for source_id in source_ids)
        representative = sources[0]
        compact = compact_content.get(target)
        examples = tuple(example for rule in sources for example in rule.examples)
        if target == "architecture/layout/component-paths":
            examples += (
                RuleExamplePair(
                    fixture_id=FixtureId("sarj-layout-overlapping-roots"),
                    language="text",
                    flagged="services/payments\nservices/payments/worker",
                    passes="services/payments\nservices/worker",
                    title="Overlapping component roots",
                    severity="error",
                ),
            )
        merged.append(
            replace(
                representative,
                rule_id=RuleId(target),
                default_severity=severity,
                title=title,
                summary=summary,
                detects=detects,
                impact=impact,
                remediation=compact[0] if compact else representative.remediation,
                examples=examples,
                evidence_required=(
                    compact[1]
                    if compact
                    else tuple(
                        dict.fromkeys(item for rule in sources for item in rule.evidence_required)
                    )
                ),
                non_goals=(
                    compact[2]
                    if compact
                    else tuple(dict.fromkeys(item for rule in sources for item in rule.non_goals))
                ),
                false_positive_controls=tuple(
                    dict.fromkeys(item for rule in sources for item in rule.false_positive_controls)
                ),
                upstream=tuple(dict.fromkeys(item for rule in sources for item in rule.upstream)),
                references=tuple(
                    dict.fromkeys(item for rule in sources for item in rule.references)
                ),
            )
        )
    return tuple(sorted(merged, key=lambda item: item.rule_id))


RULES = _consolidated_rules(_RULE_PARTS)

_RULE_CLASSIFICATION: Mapping[RuleId, RuleClassification] = MappingProxyType(
    {
        RuleId("architecture/layout/component-paths"): RuleClassification.OBJECTIVE,
        RuleId("architecture/schema/component"): RuleClassification.SCHEMA,
        RuleId("architecture/dependencies/policy"): RuleClassification.OBJECTIVE,
        RuleId("architecture/dependencies/acyclic"): RuleClassification.JUDGMENT,
        RuleId("delivery/branches/hotfix-back-sync"): RuleClassification.OBJECTIVE,
        RuleId("delivery/actions/safety"): RuleClassification.OPERATIONAL,
        RuleId("delivery/repository/controls"): RuleClassification.JUDGMENT,
    }
)
_RULE_PRECEDENCE: Mapping[RuleId, int] = MappingProxyType(
    {
        RuleId("architecture/schema/component"): 10,
        RuleId("architecture/dependencies/policy"): 20,
        RuleId("architecture/layout/component-paths"): 30,
        RuleId("architecture/dependencies/acyclic"): 40,
        RuleId("delivery/branches/hotfix-back-sync"): 50,
        RuleId("delivery/actions/safety"): 60,
        RuleId("delivery/repository/controls"): 70,
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
                RuleId("delivery/branches/hotfix-back-sync"),
                RuleId("delivery/repository/controls"),
            }
            else "verified"
            if rule.rule_id == RuleId("delivery/actions/safety")
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
    schema_version=2,
    policy_id=PolicyId("sarj"),
    policy_version=5,
    profile=ProfileDescriptor(
        profile_id=PROFILE_ID,
        title="Sarj repository standard",
        product_registry_mode="open",
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


def _component_field_value(
    component: Component, field: Literal["product", "capability"]
) -> str | None:
    if field == "product":
        return component.product
    return component.capability


class SarjPolicy:
    policy_id: ClassVar[PolicyId] = PolicyId("sarj")
    policy_version: ClassVar[int] = POLICY_SPEC.policy_version
    profile_id: ClassVar[str] = PROFILE_ID

    @staticmethod
    def spec() -> PolicySpec:
        return POLICY_SPEC

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        return RULES

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
                rule_id=RuleId("architecture/dependencies/acyclic"),
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
