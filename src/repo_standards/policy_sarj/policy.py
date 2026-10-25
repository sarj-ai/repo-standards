from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple

from repo_standards.core.canonical import (
    ComponentIndex,
    canonical_json,
    nearest_component,
    workspace_pattern_matches,
)
from repo_standards.core.models import (
    Component,
    ComponentId,
    Diagnostic,
    ExampleLanguage,
    FixtureId,
    PackageEvidence,
    PolicyId,
    Remediation,
    RepositorySnapshot,
    Rule,
    RuleExamplePair,
    RuleId,
    WorkspaceEvidence,
)
from repo_standards.core.taxonomy import (
    ARTIFACTS,
    CHANGE_SAFETY,
    DOCUMENTATION,
    taxonomy,
)

from .javascript import UNTYPED_JAVASCRIPT_RULE_ID, javascript_diagnostics
from .local_residue import LOCAL_RESIDUE_RULE_ID, local_residue_diagnostics
from .makefiles import MAKEFILE_GROWTH_RULE_ID, makefile_diagnostics
from .pull_request_templates import (
    PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID,
    pull_request_template_diagnostics,
)
from .spec import (
    PATH_TEMPLATES,
    PROFILE_ID,
    PolicySpec,
    ProfileId,
    RuleClassification,
    RuleGovernance,
    RuleMaturity,
)


if TYPE_CHECKING:
    from collections.abc import Collection, Mapping


class _ArtifactRoots(NamedTuple):
    packages: frozenset[str]
    python_imports: frozenset[str]
    standalone: frozenset[str]
    terraform: frozenset[str]


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


def _tracked_files_example(*paths: str) -> str:
    return canonical_json(
        {
            "tracked": paths,
            "manifest": 'repository_id = "example-repository"\ncomponents = []\n',
        }
    )


RULES = (
    Rule(
        rule_id=LOCAL_RESIDUE_RULE_ID,
        version=1,
        default_severity="warning",
        title="Review tracked caches, bytecode, coverage data and OS metadata",
        description=(
            "Tracked .pyc, .pyo and .tsbuildinfo filenames, and exact .DS_Store and "
            "Thumbs.db, .eslintcache and .coverage basenames, case-insensitively, need review "
            "as local residue. "
            "Only the final filename is matched; directories grant no exemptions."
        ),
        why=(
            "Interpreter bytecode, incremental build or lint state, coverage data and desktop "
            "metadata can drift from checked source or local tools. Some distributions and "
            "fixtures are intentional, so a matching filename is review evidence rather than proof "
            "that deletion is safe."
        ),
        fix=(
            "Review the file's behavior and distribution contract. Untrack disposable output "
            "and ignore future copies; gitignore does not affect existing tracked files. "
            "Retain required fixtures or runtime artifacts with an existing exact, dated "
            "fingerprint exception. Do not rename the file or delete a distinct test contract "
            "merely to silence the warning."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
        examples=(
            _example(
                example_id="sarj-artifact-local-residue-bytecode",
                title="Retain Python source and untrack its local cache",
                language="json",
                before=_tracked_files_example(
                    "src/package/client.py", "src/package/__pycache__/client.cpython-315.pyc"
                ),
                after=_tracked_files_example("src/package/client.py"),
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-artifact-local-residue-build-cache",
                title="Retain build settings and untrack incremental state",
                language="json",
                before=_tracked_files_example("tsconfig.json", "tsconfig.tsbuildinfo"),
                after=_tracked_files_example("tsconfig.json"),
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-artifact-local-residue-desktop-metadata",
                title="Retain the asset and untrack desktop thumbnail metadata",
                language="json",
                before=_tracked_files_example("assets/thumbnail.png", "assets/Thumbs.db"),
                after=_tracked_files_example("assets/thumbnail.png"),
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-artifact-local-residue-eslint-cache",
                title="Retain lint settings and untrack local lint state",
                language="json",
                before=_tracked_files_example("eslint.config.ts", ".eslintcache"),
                after=_tracked_files_example("eslint.config.ts"),
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-artifact-local-residue-coverage-data",
                title="Retain coverage settings and untrack measured state",
                language="json",
                before=_tracked_files_example(".coveragerc", ".coverage"),
                after=_tracked_files_example(".coveragerc"),
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=UNTYPED_JAVASCRIPT_RULE_ID,
        version=1,
        default_severity="warning",
        title="Prefer typed source and declare required JavaScript artifacts",
        description=(
            "Tracked .js, .jsx, .mjs and .cjs paths, case-insensitively, need an exact "
            "javascript.artifacts declaration or migration to typed source. Config, vendor, "
            "generated and test names do not grant automatic exemptions."
        ),
        why=(
            "Authored JavaScript can escape the TypeScript checking contract. Runtime, "
            "tool, vendor and fixture artifacts may require JavaScript; explicit declarations "
            "make that intent reviewable without inferring it from a filename."
        ),
        fix=(
            "Review module loading and callers before migrating authored code to typed "
            "TypeScript. For required JavaScript, declare the exact path, artifact kind and "
            "reason; generated output also needs a tracked non-JavaScript source. A declaration "
            "records intent and does not prove generation or semantic necessity."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
        examples=(
            _example(
                example_id="sarj-artifact-untyped-javascript-source",
                title="Typed tooling source",
                language="text",
                before="scripts/generate-catalog.mjs",
                after="scripts/generate-catalog.ts",
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-artifact-untyped-javascript-generated",
                title="Required Python-generated JavaScript",
                language="json",
                before=(
                    '{"tracked":["generated/rules.mjs","scripts/generate.py"],'
                    '"manifest":"repository_id = \\"example-repository\\"\\ncomponents = []\\n"}'
                ),
                after=(
                    '{"tracked":["generated/rules.mjs","scripts/generate.py"],'
                    '"manifest":"repository_id = \\"example-repository\\"\\ncomponents = []\\n'
                    '[[javascript.artifacts]]\\npath = \\"generated/rules.mjs\\"\\n'
                    'kind = \\"generated\\"\\nsource = \\"scripts/generate.py\\"\\n'
                    'reason = \\"External tools load this generated ESM artifact.\\"\\n"}'
                ),
                expected_severity="warning",
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
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
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
        version=3,
        default_severity="warning",
        title="Reject hand-maintained configuration examples",
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
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
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
        version=6,
        default_severity="error",
        title="Do not commit bespoke verifier scripts",
        description=(
            "Retired verifier basenames are prohibited everywhere. Other executable-script "
            "basenames beginning with verify require objective source, test, script, bin, or "
            "component ownership, including at the repository root. Operational placement "
            "remains prohibited except for conventional source inside an objectively owned "
            "tool or harness."
        ),
        why=(
            "Repository-specific verifier entrypoints create parallel validation paths that "
            "drift from shared policy, owned test suites, and deployment contracts. Durable "
            "executable verification belongs in an objectively owned tool or harness."
        ),
        fix=(
            "Identify each distinct behavior and safety contract the verifier checks. "
            "Before deleting it and its invocations, demonstrate that retained or replacement "
            "checks reject the same wrong outcomes through Terraform, shared policy, or a "
            "provider or runtime contract; if executable "
            "verification is durable product code, place it in conventional source inside a "
            "declared or workspace-backed tool or harness. Relocating, renaming, or translating "
            "the same check, including to TypeScript, is not remediation."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
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
        version=5,
        default_severity="warning",
        title="Review operational script tests for duplicate contracts",
        description=(
            "Tracked script test/spec artifacts in operational trees are review candidates. "
            "Top-level .github/scripts test/spec artifacts also require review, including "
            "nested paths and declared packages; this does not change verifier ownership. "
            "An exact declared nonoperational native package may own conventional tests "
            "when substantive tracked lockfile or source-entrypoint evidence supports it. "
            "This package exception excludes top-level operational roots, package-local "
            "operational directories, GitHub automation, and native Terraform modules. "
            "Repository Standards owns this path boundary; semantic workflow analysis belongs "
            "in Code Standards."
        ),
        why=(
            "Deployment tests can repeat contracts owned by Terraform, providers, shared "
            "policy, or runtime behavior. Filenames and placement do not establish "
            "redundancy or test value; workflow contents are outside this rule's evidence."
        ),
        fix=(
            "Review the asserted contract and existing checks. Remove a test and its "
            "invocations only when existing coverage rejects the same wrong outcomes. "
            "Retain distinct behavior and safety coverage; moving or renaming does not "
            "resolve contract duplication."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
        examples=(
            _example(
                example_id="sarj-artifact-no-operational-script-tests",
                title="Operational test requiring contract review",
                language="text",
                before="iac/bell/preview-contract.test.ts",
                after="Retained distinct coverage or an equivalent existing check",
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-artifact-github-script-tests",
                title="GitHub script test requiring contract review",
                language="text",
                before=".github/scripts/deployment-steps.test.mts",
                after="Retained distinct coverage or an equivalent existing check",
                expected_severity="warning",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/artifacts/terraform-test-files"),
        version=2,
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
            "Identify each distinct behavior and safety contract the test checks. Before "
            "deleting it and its invocations, demonstrate that retained or replacement shared "
            "rendered-plan, provider, or runtime checks reject the same wrong outcomes. "
            "Passing runs or equal coverage counts alone do not establish equivalence."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
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
        rule_id=MAKEFILE_GROWTH_RULE_ID,
        version=2,
        default_severity="error",
        title="Do not add or grow Makefiles without a scoped exception",
        description=(
            "Do not create Makefiles or grow existing ones without a scoped, documented exception. "
            "Compare exact Git snapshots per path, counting comments, blank lines and an "
            "unterminated final line; CRLF and LF count equally. New paths, including empty "
            "files and move/copy destinations, require an exception. Equal size, shrinkage and "
            "deletion pass; changes in one file do not offset another. Match Makefile, "
            "GNUmakefile, Makecall, Makefile.*, GNUmakefile.* and *.mk case-insensitively; "
            "exclude suffix variants ending in .md, .mdx, .rst, .adoc or .txt. Vendor, generated "
            "and fixture paths have no automatic exemption. Arbitrary custom names and included "
            "non-Make files "
            "are outside this scope. Exact-path makefiles.exceptions records require max_lines, "
            "owner, reason, issue, created_on and expires_on, with at most 90 days of validity. "
            "Standalone exception use requires --as-of; the Code Standards bridge supplies UTC. "
            "Baselines and generic diagnostic exceptions cannot authorize growth."
        ),
        why=(
            "Convenience wrappers duplicate native command interfaces and add maintenance "
            "and review noise."
        ),
        fix=(
            "Prefer existing native commands; remove redundant wrappers with their callers "
            "and preserve necessary contracts until safely migrated. Do not transfer aliases "
            "into replacement scripts or task files. Use --base for branch-wide committed "
            "comparisons; the local default covers the last commit and staged checks use HEAD. "
            "Missing comparison objects produce incomplete analysis."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, ARTIFACTS),
        examples=(
            _example(
                example_id="sarj-artifact-makefile-growth",
                title="Existing Makefile grows between Git snapshots",
                language="json",
                before='{"base":{"Makefile":2},"head":{"Makefile":3}}',
                after='{"base":{"Makefile":2},"head":{"Makefile":2}}',
                expected_severity="error",
            ),
            _example(
                example_id="sarj-artifact-new-empty-makefile",
                title="An empty Makefile is still a new artifact",
                language="json",
                before='{"base":{},"head":{"tools/Makefile":0}}',
                after='{"base":{},"head":{}}',
                expected_severity="error",
            ),
        ),
    ),
    Rule(
        rule_id=RuleId("repository/documentation/placement"),
        version=4,
        default_severity="error",
        title="Keep Markdown in durable owned locations",
        description="Tracked Markdown must have a durable documentation or tool-contract role.",
        why="Owned documentation stays discoverable instead of becoming repository debris.",
        fix=(
            "Move durable guidance into an approved docs root or delete transient notes. "
            "Before relocating required skill references, review the owning SKILL.md and "
            "preserve its relative-path contract. This path-only rule does not resolve "
            "Markdown references; a plugin or references directory alone proves no ownership."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, DOCUMENTATION),
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
        rule_id=PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID,
        version=1,
        default_severity="warning",
        title="Keep the PR template in sync with required sections",
        description=(
            "Each required PR section needs a heading in the PR template. "
            "Required sections are listed in required_body_sections."
        ),
        why=(
            "People write PRs from the template. "
            "If a required heading is not there, their PR fails the check."
        ),
        fix="Add the missing heading to the PR template.",
        taxonomy=taxonomy(CHANGE_SAFETY, DOCUMENTATION),
        examples=(
            _example(
                example_id="sarj-documentation-pull-request-template-sections",
                title="The PR template has no Test evidence heading",
                language="json",
                before=(
                    '{"required":["What & why","Test evidence"],"template":"## What & why\\n"}'
                ),
                after=(
                    '{"required":["What & why","Test evidence"],'
                    '"template":"## What & why\\n\\n## Test evidence\\n"}'
                ),
                expected_severity="warning",
            ),
            _example(
                example_id="sarj-documentation-pull-request-template-absent",
                title="There is no PR template",
                language="json",
                before='{"required":["What & why"],"template":null}',
                after='{"required":["What & why"],"template":"## What & why\\n"}',
                expected_severity="warning",
            ),
        ),
    ),
)

_RULE_CLASSIFICATION: Mapping[RuleId, RuleClassification] = MappingProxyType(
    {
        LOCAL_RESIDUE_RULE_ID: RuleClassification.JUDGMENT,
        UNTYPED_JAVASCRIPT_RULE_ID: RuleClassification.JUDGMENT,
        RuleId("repository/artifacts/terraform-examples"): RuleClassification.OBJECTIVE,
        RuleId("repository/artifacts/schema-derived-config-examples"): RuleClassification.JUDGMENT,
        RuleId("repository/artifacts/bespoke-iac-verifiers"): RuleClassification.OBJECTIVE,
        RuleId("repository/artifacts/operational-script-tests"): RuleClassification.JUDGMENT,
        RuleId("repository/artifacts/terraform-test-files"): RuleClassification.OBJECTIVE,
        MAKEFILE_GROWTH_RULE_ID: RuleClassification.JUDGMENT,
        RuleId("repository/documentation/placement"): RuleClassification.OBJECTIVE,
        PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID: RuleClassification.OBJECTIVE,
    }
)
_RULE_PRECEDENCE: Mapping[RuleId, int] = MappingProxyType(
    {
        LOCAL_RESIDUE_RULE_ID: 51,
        UNTYPED_JAVASCRIPT_RULE_ID: 49,
        RuleId("repository/artifacts/terraform-examples"): 40,
        RuleId("repository/artifacts/schema-derived-config-examples"): 44,
        RuleId("repository/artifacts/bespoke-iac-verifiers"): 45,
        RuleId("repository/artifacts/operational-script-tests"): 46,
        RuleId("repository/artifacts/terraform-test-files"): 47,
        MAKEFILE_GROWTH_RULE_ID: 48,
        RuleId("repository/documentation/placement"): 50,
        PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID: 52,
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
        **{
            rule.rule_id: (
                "verified" if str(rule.rule_id).startswith("repository/") else "declared"
            )
            for rule in RULES
        },
        UNTYPED_JAVASCRIPT_RULE_ID: "declared",
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
    policy_version=28,
    profile_id=PROFILE_ID,
    title="Sarj repository standard",
    component_kinds=tuple(kind.value for kind in ComponentKind),
    edge_kinds=tuple(sorted(EDGE_KINDS)),
    path_templates=PATH_TEMPLATES,
    rule_governance=RULE_GOVERNANCE,
)


def _repository_artifact_diagnostics(
    snapshot: RepositorySnapshot,
) -> tuple[Diagnostic, ...]:
    package_test_roots = _owned_package_roots(snapshot)
    tracked_files = {item.path: item.substantive for item in snapshot.inspection.tracked_files}
    standalone_package_roots = frozenset(
        _parent_path(project.path)
        for project in snapshot.inspection.packages
        if _has_standalone_package_evidence(project, _parent_path(project.path), tracked_files)
    )
    artifact_roots = _ArtifactRoots(
        package_test_roots,
        _owned_python_import_roots(snapshot, package_test_roots),
        standalone_package_roots,
        frozenset(snapshot.inspection.terraform_modules),
    )
    diagnostics: list[Diagnostic] = []
    components = ComponentIndex(snapshot.manifest.components)
    for tracked in snapshot.inspection.tracked_files:
        diagnostics.extend(
            _tracked_artifact_diagnostics(
                snapshot,
                tracked.path,
                components.nearest(tracked.path),
                artifact_roots,
            )
        )
    return tuple(
        sorted(diagnostics, key=lambda item: (item.path, item.rule_id, item.manifest_anchor))
    )


def _tracked_artifact_diagnostics(
    snapshot: RepositorySnapshot,
    path: str,
    component: Component | None,
    artifact_roots: _ArtifactRoots,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    package_test_roots = artifact_roots.packages
    standalone_package_roots = artifact_roots.standalone
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
                    summary=("Remove the example file and keep one authoritative input contract."),
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
    is_terraform_path = _is_terraform_artifact_path(path, artifact_roots.terraform)
    is_github_automation_path = _is_github_automation_path(path)
    is_operational_path = is_terraform_path or _is_operational_path(
        path,
        component=component,
        terraform_modules=artifact_roots.terraform,
    )
    is_owned_verifier = _is_owned_verifier_path(path, component, package_test_roots)
    is_owned_tool_source = path.startswith("tools/") and is_owned_verifier
    is_operational_script_test = (
        _is_script_test(basename)
        and is_operational_path
        and (
            is_terraform_path
            or is_github_automation_path
            or not _is_owned_nonoperational_test(
                path, component, package_test_roots, standalone_package_roots
            )
        )
    ) or _is_github_script_test(path)
    is_bespoke_verifier = basename in _RETIRED_IAC_VERIFIER_NAMES or (
        _is_verifier_script(basename)
        and (
            is_terraform_path
            or is_github_automation_path
            or (is_operational_path and not is_owned_tool_source)
            or not is_owned_verifier
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
                    summary="Preserve distinct contracts before removing the verifier.",
                    steps=(
                        (
                            "Identify each behavior and safety contract and demonstrate that "
                            "retained or replacement Terraform, shared-policy, provider, or "
                            "runtime checks reject the same wrong outcomes."
                        ),
                        (
                            "Then delete the verifier and every invocation; relocating it "
                            "is not remediation."
                        ),
                    ),
                    validation=(
                        "Run focused checks for the retained contracts and rerun repo-standards.",
                    ),
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
                expected="review operational script tests for redundant contracts",
                message="tracked script test is in an operational tree; review its contract",
                path=path,
                remediation=Remediation(
                    summary="Review the asserted contract and existing coverage.",
                    steps=(
                        "Retain tests that reject distinct behavior or safety regressions.",
                        (
                            "Delete the test and its invocations only after demonstrating "
                            "equivalent existing coverage; moving or renaming does not "
                            "resolve duplication."
                        ),
                    ),
                    validation=(
                        "Run focused tests for retained contracts and rerun repo-standards.",
                    ),
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
                    summary="Preserve distinct contracts in the shared validation path.",
                    steps=(
                        (
                            "Identify each behavior and safety contract and demonstrate that "
                            "retained or replacement shared rendered-plan, provider, or runtime "
                            "checks reject the same wrong outcomes."
                        ),
                        "Then delete the tracked Terraform-native test file and its invocations.",
                    ),
                    validation=(
                        (
                            "Run focused checks for retained contracts and rerun repo-standards; "
                            "passing runs or equal coverage counts alone do not prove equivalence."
                        ),
                    ),
                ),
            )
        )
    if path.casefold().endswith(".md") and not _markdown_path_is_owned(
        path,
        package_roots=artifact_roots,
        component=component,
        terraform_modules=artifact_roots.terraform,
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
                        (
                            "Review required relative references in the owning SKILL.md "
                            "before moving them."
                        ),
                        "Move durable guidance beneath docs, architecture, or adr.",
                        ("Delete transient plans, handoffs, summaries, and implementation notes."),
                    ),
                    validation=("Inspect the selected Git tree and rerun repo-standards.",),
                ),
            )
        )
    return diagnostics


def _parent_path(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def _markdown_path_is_owned(
    path: str,
    *,
    package_roots: _ArtifactRoots,
    component: Component | None,
    terraform_modules: Collection[str],
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
    if (
        is_root_document
        or is_durable_tree
        or is_agent_contract
        or _owned_package_relative_parts(path, package_roots.python_imports)
    ):
        return True
    parent = _parent_path(path)
    if _is_owned_package_document(path, package_roots.packages):
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
    tracked_files = {item.path: item.substantive for item in snapshot.inspection.tracked_files}
    for project in snapshot.inspection.packages:
        root = _owned_package_root(snapshot, project, tracked_files)
        if root is not None:
            roots.add(root)
    return frozenset(roots)


def _owned_package_root(
    snapshot: RepositorySnapshot, project: PackageEvidence, tracked_files: dict[str, bool]
) -> str | None:
    root = _parent_path(project.path)
    if not project.name:
        return None
    component = nearest_component(root, snapshot.manifest.components)
    explicitly_owned = (
        component is not None
        and component.path == root
        and component.kind in _NON_OPERATIONAL_COMPONENT_KINDS
    )
    containing_workspaces = tuple(
        workspace
        for workspace in snapshot.inspection.workspaces
        if workspace.ecosystem == project.ecosystem
        and workspace.path != project.path
        and _workspace_contains(workspace, project.path)
    )
    workspace_owned = any(
        _workspace_includes(workspace, project.path) for workspace in containing_workspaces
    )
    colocated_workspace_owned = any(
        workspace.ecosystem == project.ecosystem
        and _parent_path(workspace.path) == root
        and bool(workspace.member_patterns)
        for workspace in snapshot.inspection.workspaces
    )
    root_project = not root
    conventional_evidence = (
        root_project
        or workspace_owned
        or colocated_workspace_owned
        or (
            not containing_workspaces
            and _has_standalone_package_evidence(project, root, tracked_files)
        )
    )
    conventionally_owned = conventional_evidence and (
        colocated_workspace_owned
        or not _is_operational_path(
            root, component=component, terraform_modules=snapshot.inspection.terraform_modules
        )
    )
    return root if explicitly_owned or conventionally_owned else None


def _has_standalone_package_evidence(
    project: PackageEvidence, root: str, tracked_files: dict[str, bool]
) -> bool:
    if not project.name:
        return False
    names = (
        {
            "bun.lock",
            "bun.lockb",
            "npm-shrinkwrap.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        }
        if project.ecosystem == "npm"
        else {"Pipfile.lock", "pdm.lock", "poetry.lock", "uv.lock"}
    )
    prefix = f"{root}/" if root else ""
    if any(_is_substantive_tracked_path(f"{prefix}{name}", tracked_files) for name in names):
        return True
    if project.ecosystem == "npm":
        entrypoints = {
            "index.cjs",
            "index.js",
            "index.mjs",
            "index.ts",
            "src/index.cjs",
            "src/index.js",
            "src/index.mjs",
            "src/index.ts",
        }
    else:
        entrypoints = {
            "__main__.py",
            "app.py",
            "cli.py",
            "main.py",
            "server.py",
        }
    return any(
        _is_substantive_tracked_path(f"{prefix}{entrypoint}", tracked_files)
        for entrypoint in entrypoints
    )


def _owned_python_import_roots(
    snapshot: RepositorySnapshot, package_roots: frozenset[str]
) -> frozenset[str]:
    tracked_paths = frozenset(item.path for item in snapshot.inspection.tracked_files)
    roots: set[str] = set()
    for project in snapshot.inspection.packages:
        root = _parent_path(project.path)
        if project.ecosystem != "python" or root not in package_roots or not project.name:
            continue
        import_name = _python_import_name(project.name)
        if import_name is None:
            continue
        import_root = f"{root}/{import_name}" if root else import_name
        if f"{import_root}/__init__.py" in tracked_paths:
            roots.add(import_root)
    return frozenset(roots)


def _python_import_name(project_name: str) -> str | None:
    normalized = re.sub(r"[-.]+", "_", project_name).casefold()
    return normalized if re.fullmatch(r"[a-z0-9_]+", normalized) else None


def _is_substantive_tracked_path(path: str, tracked_files: dict[str, bool]) -> bool:
    return tracked_files.get(path, False)


def _workspace_contains(workspace: WorkspaceEvidence, project_path: str) -> bool:
    workspace_root = PurePosixPath(workspace.path).parent
    project_directory = PurePosixPath(project_path).parent
    try:
        relative = project_directory.relative_to(workspace_root)
    except ValueError:
        return False
    return bool(relative.parts)


def _workspace_includes(workspace: WorkspaceEvidence, project_path: str) -> bool:
    workspace_root = PurePosixPath(workspace.path).parent
    project_directory = PurePosixPath(project_path).parent
    try:
        relative = project_directory.relative_to(workspace_root)
    except ValueError:
        return False
    return any(
        workspace_pattern_matches(relative, pattern) for pattern in workspace.member_patterns
    ) and not any(
        workspace_pattern_matches(relative, pattern) for pattern in workspace.exclude_patterns
    )


def _is_owned_package_document(path: str, package_roots: frozenset[str]) -> bool:
    parts = _owned_package_relative_parts(path, frozenset(root for root in package_roots if root))
    if not parts:
        return False
    basename = parts[-1]
    stem = basename.removesuffix(".md")
    is_document_name = basename in _PACKAGE_DOCUMENT_NAMES or stem in {"RELEASES", "USAGE"}
    is_readme_variant = stem == "README" or stem.startswith(("README-", "README_", "README."))
    is_source_tree = parts[0].casefold() == "src"
    is_docs_tree = any(part.casefold() in {"doc", "docs"} for part in parts[:-1])
    return is_document_name or is_readme_variant or is_source_tree or is_docs_tree


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


def _is_owned_nonoperational_test(
    path: str,
    component: Component | None,
    package_roots: frozenset[str],
    standalone_package_roots: frozenset[str],
) -> bool:
    return (
        component is not None
        and component.kind == "tool"
        and PurePosixPath(component.path).parts[:1] == ("tools",)
        and component.path in package_roots
        and _is_owned_package_test(path, package_roots)
    ) or _is_owned_declared_package_test(path, component, standalone_package_roots)


def _is_owned_declared_package_test(
    path: str,
    component: Component | None,
    standalone_package_roots: frozenset[str],
) -> bool:
    return (
        component is not None
        and component.kind in _NON_OPERATIONAL_COMPONENT_KINDS
        and component.path in standalone_package_roots
        and component.path.partition("/")[0].casefold() not in _CONVENTIONAL_OPERATIONAL_ROOTS
        and _is_owned_package_test(path, frozenset({component.path}))
        and not _is_operational_path(
            PurePosixPath(path).relative_to(component.path).as_posix(),
            component=None,
            terraform_modules=(),
        )
    )


def _is_owned_package_test(path: str, package_roots: frozenset[str]) -> bool:
    parts = _owned_package_relative_parts(path, package_roots)
    return any(part.casefold() in _PACKAGE_TEST_DIRECTORY_NAMES for part in parts[:-1])


def _owned_package_relative_parts(path: str, package_roots: frozenset[str]) -> tuple[str, ...]:
    parts = PurePosixPath(path).parts
    for boundary in range(len(parts), -1, -1):
        if "/".join(parts[:boundary]) in package_roots:
            return parts[boundary:]
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


def _is_github_script_test(path: str) -> bool:
    return path.casefold().startswith(".github/scripts/") and _is_script_test(
        PurePosixPath(path).name.casefold()
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
    terraform_modules: Collection[str],
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


def _is_terraform_artifact_path(path: str, terraform_modules: Collection[str]) -> bool:
    return "" in terraform_modules or _is_terraform_path(path, terraform_modules)


def _is_terraform_path(path: str, terraform_modules: Collection[str]) -> bool:
    while path:
        if path in terraform_modules:
            return True
        path = path.rpartition("/")[0]
    return False


def _is_github_automation_path(path: str) -> bool:
    return tuple(part.casefold() for part in PurePosixPath(path).parts[:2]) in {
        (".github", "actions"),
        (".github", "workflows"),
    }


def _rule(rule_id: RuleId) -> Rule:
    return next(item for item in RULES if item.rule_id == rule_id)


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
    def evaluate_repository(
        snapshot: RepositorySnapshot, *, enabled_rule_ids: frozenset[RuleId] | None = None
    ) -> tuple[Diagnostic, ...]:
        enabled = (
            frozenset(rule.rule_id for rule in RULES)
            if enabled_rule_ids is None
            else enabled_rule_ids
        )
        separate_rules = {
            PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID,
            UNTYPED_JAVASCRIPT_RULE_ID,
            LOCAL_RESIDUE_RULE_ID,
            MAKEFILE_GROWTH_RULE_ID,
        }
        diagnostics = _repository_artifact_diagnostics(snapshot) if enabled - separate_rules else ()
        for rule_id, evaluate in (
            (PULL_REQUEST_TEMPLATE_SECTIONS_RULE_ID, pull_request_template_diagnostics),
            (UNTYPED_JAVASCRIPT_RULE_ID, javascript_diagnostics),
            (LOCAL_RESIDUE_RULE_ID, local_residue_diagnostics),
        ):
            if rule_id in enabled:
                diagnostics += evaluate(snapshot, rule=_rule(rule_id))
        if MAKEFILE_GROWTH_RULE_ID in enabled and snapshot.makefile_comparison is not None:
            diagnostics += makefile_diagnostics(snapshot, rule=_rule(MAKEFILE_GROWTH_RULE_ID))
        return tuple(item for item in diagnostics if item.rule_id in enabled)
