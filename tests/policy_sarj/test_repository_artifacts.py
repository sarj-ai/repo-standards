from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.models import (
    Component,
    ComponentId,
    DocumentationConfig,
    GitObjectId,
    InputProvenance,
    Manifest,
    PackageEvidence,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleDefinition,
    RuleId,
    TrackedFileEvidence,
    WorkspaceEvidence,
)
from repo_standards.policy_sarj import SarjPolicy, policy as sarj_policy


if TYPE_CHECKING:
    from collections.abc import Iterator


_PACKAGE_ROOT = "libraries/infra"
_PACKAGE_TEST = "tests/test_inputs.py"
_PYTHON_PACKAGE = ("python", "input-library")
_NPM_PACKAGE = ("npm", "@example/input-library")


@pytest.mark.parametrize(
    ("path", "roots", "expected"),
    [
        ("packages/one/src/main.py", ("packages/one",), ("src", "main.py")),
        (
            "packages/one/nested/tests/test_main.py",
            ("packages/one", "packages/one/nested"),
            ("tests", "test_main.py"),
        ),
        ("packages/other/src/main.py", ("packages/one",), ()),
        ("packages/one-more/src/main.py", ("packages/one",), ()),
        ("README.md", ("",), ("README.md",)),
        ("packages/one", ("packages/one",), ()),
        ("packages//one/./src/main.py", ("packages/one",), ("src", "main.py")),
        ("packages/One/src/main.py", ("packages/one",), ()),
        ("libraries/café/src/main.py", ("libraries/café",), ("src", "main.py")),
        (".github/scripts/check.py", ("", ".github"), ("scripts", "check.py")),
    ],
    ids=[
        "source",
        "nearest-nested",
        "unowned",
        "segment-boundary",
        "root",
        "exact-owner",
        "normalized",
        "case",
        "unicode",
        "dot-directory",
    ],
)
def test_package_ownership_preserves_nearest_normalized_path(
    path: str, roots: tuple[str, ...], expected: tuple[str, ...]
) -> None:
    assert sarj_policy._owned_package_relative_parts(path, frozenset(roots)) == expected  # ruff: ignore[private-member-access] # pyright: ignore[reportPrivateUsage] -- direct nearest-owner boundary regression.


def _snapshot(
    *paths: str,
    components: tuple[Component, ...] = (),
    packages: tuple[PackageEvidence, ...] = (),
    workspaces: tuple[WorkspaceEvidence, ...] = (),
    terraform_modules: tuple[str, ...] = (),
    documentation: DocumentationConfig | None = None,
) -> RepositorySnapshot:
    tracked = tuple(
        TrackedFileEvidence(path=path, object_id=f"{index + 1:040x}")
        for index, path in enumerate(sorted(paths))
    )
    return RepositorySnapshot(
        manifest=Manifest(
            repository_id=RepositoryId("example-repository"),
            components=components,
            documentation=documentation,
        ),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            tracked_file_count=len(tracked),
            packages=packages,
            workspaces=workspaces,
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=terraform_modules,
            issues=(),
            tracked_files=tracked,
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            manifest_path=".repo-lint/repository.toml",
            manifest_object_id=GitObjectId("c" * 40),
            manifest_digest="d" * 64,
        ),
    )


def _with_insubstantive_path(
    snapshot: RepositorySnapshot, evidence_path: str
) -> RepositorySnapshot:
    tracked = tuple(
        replace(
            item,
            substantive=item.path != evidence_path,
        )
        for item in snapshot.inspection.tracked_files
    )
    return replace(snapshot, inspection=replace(snapshot.inspection, tracked_files=tracked))


def _rule_ids(snapshot: RepositorySnapshot) -> list[RuleId]:
    # Declaration rules have dedicated domain, ownership and overlap cases.
    return [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.rule_id
        not in {
            "repository/artifacts/untyped-javascript",
            "repository/artifacts/undeclared-images",
        }
    ]


@pytest.mark.parametrize("rule_id", [rule.rule_id for rule in SarjPolicy.rules()])
def test_selected_evaluation_preserves_filtered_full_findings(rule_id: RuleId) -> None:
    snapshot = _snapshot(
        "infra/inputs.tfvars.example",
        "infra/.env.example",
        "infra/verify-inputs.py",
        "infra/tests/test_inputs.py",
        "infra/inputs.tftest.hcl",
        "notes/handoff.md",
        "tools/index.js",
        ".coverage",
        terraform_modules=("infra",),
    )
    expected = tuple(
        item for item in SarjPolicy.evaluate_repository(snapshot) if item.rule_id == rule_id
    )

    selected = SarjPolicy.evaluate_repository(snapshot, enabled_rule_ids=frozenset({rule_id}))

    assert selected == expected


def test_no_activated_rules_skip_all_evaluators(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_evaluation(
        _snapshot: RepositorySnapshot, *, rule: RuleDefinition | None = None
    ) -> None:
        pytest.fail(f"disabled evaluator must not run: {rule}")

    for evaluator in (
        "_repository_artifact_diagnostics",
        "pull_request_template_diagnostics",
        "javascript_diagnostics",
        "local_residue_diagnostics",
        "makefile_diagnostics",
    ):
        monkeypatch.setattr(  # sarj-noqa: SARJ445 -- injection would bypass actual dispatch.
            sarj_policy, evaluator, unexpected_evaluation
        )

    selected = SarjPolicy.evaluate_repository(_snapshot(".coverage"), enabled_rule_ids=frozenset())

    assert selected == ()


def test_residue_check_skips_unrelated_artifact_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_evaluation(_snapshot: RepositorySnapshot) -> None:
        pytest.fail("a residue check must not prepare unrelated artifact ownership")

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- injection would bypass actual dispatch.
        sarj_policy, "_repository_artifact_diagnostics", unexpected_evaluation
    )
    selected = SarjPolicy.evaluate_repository(
        _snapshot(".coverage", "infra/verify-inputs.py"),
        enabled_rule_ids=frozenset({RuleId("repository/artifacts/local-residue")}),
    )

    assert [item.path for item in selected] == [".coverage"]


def _root_package(
    ecosystem: str,
    path: str,
    name: str | None,
    *,
    workspace_root: bool,
) -> PackageEvidence:
    return PackageEvidence(
        ecosystem=ecosystem,
        path=path,
        name=name,
        private=True,
        workspace_root=workspace_root,
    )


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("terraform.tfvars.example", id="root"),
        pytest.param("minimum.tfvars.sample", id="sample"),
        pytest.param("production.tfvars.template", id="template"),
        pytest.param("iac/delivery/production.tfvars.example", id="nested"),
        pytest.param("deployments/app/CONFIG.TFVARS.EXAMPLE", id="case-insensitive"),
    ],
)
def test_tfvars_example_files_are_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/artifacts/terraform-examples")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("terraform.tfvars", id="normal"),
        pytest.param("production.auto.tfvars", id="auto"),
        pytest.param("production.tfvars.json", id="json"),
        pytest.param("docs/tfvars.example.md", id="documentation"),
        pytest.param("docs/tfvars.sample.md", id="sample-documentation"),
        pytest.param("docs/tfvars.template.md", id="template-documentation"),
    ],
)
def test_non_example_tfvars_paths_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("backend.conf.example", id="terraform-backend"),
        pytest.param("backend.conf.sample", id="terraform-backend-sample"),
        pytest.param("backend.conf.template", id="terraform-backend-template"),
        pytest.param("iac/dev/BACKEND.CONF.EXAMPLE", id="backend-case-insensitive"),
        pytest.param(".env.example", id="env-root"),
        pytest.param("services/api/.env.local.example", id="env-profile"),
        pytest.param("services/api/.ENV.DEV.EXAMPLE", id="env-case-insensitive"),
        pytest.param("services/api/.env.dev.sample", id="env-sample"),
        pytest.param("services/api/.env.dev.template", id="env-template"),
        pytest.param("services/api/example.env", id="example-env"),
        pytest.param("services/api/env.example", id="env-example"),
        pytest.param("services/api/env.sample", id="env-sample-basename"),
        pytest.param("services/api/env.template", id="env-template-basename"),
        pytest.param("examples/api/.env.sample", id="examples-tree"),
        pytest.param("samples/api/backend.conf.example", id="samples-tree"),
        pytest.param("templates/api/template.env", id="templates-tree"),
        pytest.param(".env.schema", id="env-schema"),
        pytest.param("services/api/.env.production.schema.json", id="env-schema-json"),
        pytest.param("services/api/.env.schema.yaml", id="env-schema-yaml"),
        pytest.param("services/api/.ENV.LOCAL.SCHEMA.YML", id="env-schema-yml-case-insensitive"),
        pytest.param("services/api/.env.schema.toml", id="env-schema-toml"),
    ],
)
def test_schema_derived_config_examples_are_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [
        RuleId("repository/artifacts/schema-derived-config-examples")
    ]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("backend.conf", id="backend-config"),
        pytest.param("docs/backend.conf.example.md", id="backend-documentation"),
        pytest.param("docs/backend.conf.sample.md", id="backend-sample-documentation"),
        pytest.param(".env", id="runtime-env"),
        pytest.param(".env.local", id="runtime-env-profile"),
        pytest.param("backend.confidential.example", id="backend-near-miss"),
        pytest.param(".envrc.example", id="different-basename"),
        pytest.param("docs/.env.example.md", id="env-documentation"),
        pytest.param("docs/env.template.md", id="env-template-documentation"),
        pytest.param("settings.schema.json", id="application-schema"),
    ],
)
def test_non_schema_derived_config_example_paths_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("index.mjs", id="root"),
        pytest.param("scripts/generate-catalog.mjs", id="nested"),
        pytest.param("scripts/CONFIG.MJS", id="generic-config-module"),
        pytest.param("scripts/generate.config-helper.mjs", id="config-name-near-miss"),
        pytest.param("vendor/tool/index.mjs", id="vendor-looking"),
        pytest.param("generated/client.mjs", id="generated-looking"),
        pytest.param("next.config.mjs", id="tool-config"),
        pytest.param("eslint.strict.mjs", id="standards-config"),
        pytest.param(".dependency-cruiser.mjs", id="dependency-config"),
    ],
)
def test_mjs_extensions_do_not_trigger_other_artifact_rules(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("index.js", id="javascript"),
        pytest.param("index.cjs", id="commonjs"),
        pytest.param("index.mts", id="typescript-module"),
        pytest.param("index.mjs.bak", id="suffix"),
        pytest.param("legacy.mjs/index.ts", id="directory-segment"),
    ],
)
def test_non_mjs_file_paths_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        pytest.param(
            "verify-plan.mjs",
            [RuleId("repository/artifacts/bespoke-iac-verifiers")],
            id="verifier",
        ),
        pytest.param(
            "iac/contract.test.mjs",
            [RuleId("repository/artifacts/operational-script-tests")],
            id="operational-test",
        ),
    ],
)
def test_other_artifact_rules_still_apply_to_mjs(path: str, expected: list[RuleId]) -> None:
    assert _rule_ids(_snapshot(path)) == expected


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("iac/verify-plan.js", id="javascript"),
        pytest.param("deploy/verify-plan.sh", id="shell"),
        pytest.param("tools/verify-plan.py", id="python"),
        pytest.param("tools/VERIFY-PLAN.CJS", id="case-insensitive-cjs"),
        pytest.param("verify-dev-apply-plan.jq", id="globally-retired-root"),
        pytest.param("iac/bulbul/scripts/verify-dev-apply-plan.jq", id="nested-jq"),
        pytest.param("tools/VERIFY-DEV-APPLY-PLAN.JQ", id="case-insensitive"),
    ],
)
def test_bespoke_iac_verifier_files_are_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("preverify.cjs", id="prefix-cjs"),
        pytest.param("verify-plan.cjs.bak", id="cjs-suffix"),
        pytest.param("verify-dev-apply-plan.jq.bak", id="suffix"),
        pytest.param("prefix-verify-dev-apply-plan.jq", id="prefix"),
        pytest.param("verify/plan.cjs", id="different-basename"),
    ],
)
def test_non_operational_or_nearby_verifier_names_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("verify.cjs", id="root-minimal-cjs"),
        pytest.param("verify_release_artifacts.py", id="root-release-verifier"),
        pytest.param("verify-environment-boundary.test.cjs", id="root-test-verifier"),
    ],
)
def test_unowned_root_verifier_names_are_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("random/src/verify-plan.cjs", id="unowned-src"),
        pytest.param("random/tests/verify-plan.py", id="unowned-tests"),
    ],
)
def test_conventional_directory_name_without_owner_is_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


def test_root_terraform_module_verifier_is_rejected() -> None:
    assert _rule_ids(_snapshot("verify-plan.py", terraform_modules=("",))) == [
        RuleId("repository/artifacts/bespoke-iac-verifiers")
    ]
    assert _rule_ids(_snapshot("README.md", terraform_modules=("",))) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("tools/contract.spec.ts", id="relocated"),
        pytest.param("iac/bell/PREVIEW.TEST.CJS", id="operational"),
        pytest.param("ci/contracts/preview.test.cjs", id="ci"),
        pytest.param("ops/preview.test.tsx", id="tsx-relocation"),
        pytest.param("iac/scripts/health-check.test.sh", id="shell"),
        pytest.param("scripts/iac/tests/test_inputs.py", id="undeclared-operational-package"),
        pytest.param("deploy/policy.spec.jq", id="jq"),
        pytest.param(".github/actions/release/contract.test.cjs", id="github-action"),
        pytest.param(".github/workflows/release.spec.ts", id="github-workflow"),
        pytest.param(".github/scripts/ci-efficiency.test.mts", id="github-script"),
        pytest.param(".GITHUB/SCRIPTS/nested/test_contract.py", id="github-script-nested-case"),
        pytest.param("services/api/deploy/contract.test.cjs", id="nested-deploy"),
        pytest.param("services/bell/deploy/preview.test.cjs", id="derived-terraform-root"),
    ],
)
def test_operational_script_tests_require_contract_review(path: str) -> None:
    terraform_modules = ("services/bell/deploy",) if "services/bell/deploy" in path else ()
    diagnostics = tuple(
        item
        for item in SarjPolicy.evaluate_repository(
            _snapshot(path, terraform_modules=terraform_modules)
        )
        if item.rule_id == "repository/artifacts/operational-script-tests"
    )
    assert [item.rule_id for item in diagnostics] == [
        RuleId("repository/artifacts/operational-script-tests")
    ]
    assert diagnostics[0].severity == "warning"
    assert "review its contract" in diagnostics[0].message
    remediation = diagnostics[0].remediation
    assert remediation is not None
    assert "Retain tests" in remediation.steps[0]
    assert "only after demonstrating equivalent existing coverage" in remediation.steps[1]


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        ("modules/bank/tests/test_state.py", "modules/bank", True),
        ("modules/bankruptcy/tests/test_state.py", "modules/bank", False),
        ("modules/Bank/tests/test_state.py", "modules/bank", False),
        ("modules/réseau/tests/test_state.py", "modules/réseau", True),
        ("modules/bank/nested/tests/test_state.py", "modules/bank/nested", True),
    ],
)
def test_terraform_membership_keeps_path_boundaries_among_unrelated_modules(
    path: str, root: str, expected: bool
) -> None:
    modules = (*(f"unrelated/module-{index}" for index in range(128)), root)
    diagnostics = SarjPolicy.evaluate_repository(_snapshot(path, terraform_modules=modules))
    operational = tuple(
        item
        for item in diagnostics
        if item.rule_id == "repository/artifacts/operational-script-tests"
    )
    assert bool(operational) is expected


def test_artifact_scan_does_not_reenumerate_module_roots_for_each_file() -> None:
    visits: list[str] = []

    class CountedRoots(tuple[str, ...]):
        __slots__ = ()

        def __iter__(self) -> Iterator[str]:
            for root in super().__iter__():
                visits.append(root)
                yield root

    roots = CountedRoots(tuple(f"modules/unit-{index}" for index in range(64)))
    snapshot = _snapshot(
        *(f"services/api/source-{index}.py" for index in range(100)), terraform_modules=roots
    )
    visits.clear()
    assert not SarjPolicy.evaluate_repository(snapshot)
    assert len(visits) <= 2 * len(roots)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("plan.test.cjs", id="root"),
        pytest.param("checks/test_policy.py", id="python-prefix"),
        pytest.param("checks/contract.test.py", id="python-suffix"),
        pytest.param("checks/policy_test.py", id="python-pytest-suffix"),
        pytest.param("packages/api/scripts/release.test.cjs", id="package-script"),
        pytest.param("packages/api/tests/release.test.cjs", id="package-test"),
        pytest.param(".github/script/release.test.mts", id="github-script-near-miss"),
        pytest.param(
            ".github/scripts-backup/release.test.mts", id="github-script-directory-suffix"
        ),
        pytest.param(".github/scripts/deploy.mts", id="github-script-without-test-name"),
        pytest.param(".github/scripts/release.test.mts.bak", id="github-script-file-suffix"),
        pytest.param("packages/api/src/.github/scripts/release.test.mts", id="package-source"),
        pytest.param("tests/fixtures/.github/scripts/release.test.mts", id="test-fixture"),
    ],
)
def test_non_operational_script_tests_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


def test_root_project_owns_only_conventional_test_locations() -> None:
    package = _root_package("npm", "package.json", "example", workspace_root=True)
    assert _rule_ids(_snapshot("tests/plan.test.cjs", packages=(package,))) == []
    assert _rule_ids(_snapshot("iac/plan.test.cjs", packages=(package,))) == [
        RuleId("repository/artifacts/operational-script-tests")
    ]
    assert _rule_ids(_snapshot("iac/tests/plan.test.cjs", packages=(package,))) == [
        RuleId("repository/artifacts/operational-script-tests")
    ]


def test_declared_native_package_cannot_erase_github_script_review() -> None:
    root = ".github/scripts"
    component = Component(ComponentId("ci"), "tool", root, "@example/ci")
    package = _root_package("npm", f"{root}/package.json", "ci-tools", workspace_root=False)
    assert _rule_ids(
        _snapshot(
            f"{root}/package.json",
            f"{root}/src/index.ts",
            f"{root}/verify-deploy.mts",
            f"{root}/tests/deploy.test.mts",
            components=(component,),
            packages=(package,),
        )
    ) == [RuleId("repository/artifacts/operational-script-tests")]


@pytest.mark.parametrize(
    ("package_path", "package_name", "artifact_path"),
    [
        pytest.param(
            "packages/generator/package.json",
            "@example/generator",
            "packages/generator/scripts/tests/render.test.cjs",
            id="package-test",
        ),
        pytest.param(
            "packages/application/package.json",
            "@example/application",
            "packages/application/src/verify-config.ts",
            id="application-verifier",
        ),
        pytest.param(
            "packages/application/package.json",
            "@example/application",
            "packages/application/spec/contract.spec.ts",
            id="spec-suite",
        ),
        pytest.param(
            "packages/application/package.json",
            "@example/application",
            "packages/application/specs/contract.spec.ts",
            id="specs-suite",
        ),
    ],
)
def test_root_workspace_owned_package_artifact_is_clean(
    package_path: str, package_name: str, artifact_path: str
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path=package_path,
        name=package_name,
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="package.json",
        member_patterns=("packages/*",),
        exclude_patterns=(),
    )
    assert (
        _rule_ids(
            _snapshot(
                artifact_path,
                packages=(package,),
                workspaces=(workspace,),
            )
        )
        == []
    )


def test_nested_workspace_does_not_make_non_operational_tests_invalid() -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="vendor/check/package.json",
        name="@example/check",
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="vendor/package.json",
        member_patterns=("check",),
        exclude_patterns=(),
    )
    assert (
        _rule_ids(
            _snapshot(
                "vendor/check/tests/contract.test.cjs",
                packages=(package,),
                workspaces=(workspace,),
            )
        )
        == []
    )


@pytest.mark.parametrize(
    ("package_path", "package_name", "workspace_path", "member_pattern", "artifact_path"),
    [
        pytest.param(
            "iac/bell/package.json",
            "fake-package",
            "package.json",
            "iac/*",
            "iac/bell/README.md",
            id="operational-package",
        ),
    ],
)
def test_operational_package_cannot_own_documentation(
    package_path: str,
    package_name: str,
    workspace_path: str,
    member_pattern: str,
    artifact_path: str,
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path=package_path,
        name=package_name,
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path=workspace_path,
        member_patterns=(member_pattern,),
        exclude_patterns=(),
    )
    assert _rule_ids(
        _snapshot(
            artifact_path,
            packages=(package,),
            workspaces=(workspace,),
        )
    ) == [RuleId("repository/documentation/placement")]


@pytest.mark.parametrize(
    "artifact_path",
    [
        pytest.param("typescript/packages/app/README.md", id="package-readme"),
        pytest.param("typescript/packages/app/src/features/README.md", id="nested-readme"),
        pytest.param("typescript/packages/app/src/app/doc/design-tokens.md", id="doc-tree"),
        pytest.param(
            "typescript/packages/app/src/content/lessons/welcome.md",
            id="source-content",
        ),
        pytest.param("typescript/packages/app/docs/architecture.md", id="docs-tree"),
        pytest.param(
            "typescript/packages/app/src/features/verify-connection-dialog.tsx",
            id="source-verifier",
        ),
    ],
)
def test_named_nested_workspace_member_owns_conventional_artifact(
    artifact_path: str,
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="typescript/packages/app/package.json",
        name="@example/app",
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="typescript/package.json",
        member_patterns=("packages/*",),
        exclude_patterns=(),
    )
    assert (
        _rule_ids(
            _snapshot(
                artifact_path,
                packages=(package,),
                workspaces=(workspace,),
            )
        )
        == []
    )


@pytest.mark.parametrize(
    ("package_name", "exclude_patterns"),
    [
        pytest.param(None, (), id="unnamed-child"),
        pytest.param("@example/app", ("packages/app",), id="excluded-child"),
    ],
)
def test_nested_workspace_requires_named_included_child(
    package_name: str | None,
    exclude_patterns: tuple[str, ...],
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="typescript/packages/app/package.json",
        name=package_name,
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="typescript/package.json",
        member_patterns=("packages/*",),
        exclude_patterns=exclude_patterns,
    )
    snapshot = _snapshot(
        "typescript/packages/app/README.md",
        "typescript/packages/app/src/verify-plan.cjs",
        packages=(package,),
        workspaces=(workspace,),
    )
    assert _rule_ids(snapshot) == [
        RuleId("repository/documentation/placement"),
        RuleId("repository/artifacts/bespoke-iac-verifiers"),
    ]


@pytest.mark.parametrize(
    ("package_path", "package_name", "member_pattern", "artifact_path", "expected_rule"),
    [
        pytest.param(
            "examples/demo/package.json",
            "@example/demo",
            "examples/*",
            "examples/demo/tests/contract.test.cjs",
            RuleId("repository/artifacts/operational-script-tests"),
            id="examples-tree-is-operational",
        ),
        pytest.param(
            "packages/application/package.json",
            "@example/application",
            "packages/*",
            "packages/application/src/verify-dev-apply-plan.jq",
            RuleId("repository/artifacts/bespoke-iac-verifiers"),
            id="retired-verifier-in-owned-package",
        ),
    ],
)
def test_root_workspace_owned_package_exclusions(
    package_path: str,
    package_name: str,
    member_pattern: str,
    artifact_path: str,
    expected_rule: RuleId,
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path=package_path,
        name=package_name,
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="package.json",
        member_patterns=(member_pattern,),
        exclude_patterns=(),
    )
    assert _rule_ids(
        _snapshot(
            artifact_path,
            packages=(package,),
            workspaces=(workspace,),
        )
    ) == [expected_rule]


@pytest.mark.parametrize(
    ("component_id", "root", "identity", "artifact_path", "expected_rules"),
    [
        pytest.param(
            "shared.release-tool",
            "tools/release",
            "@example/release-tool",
            "tools/release/tests/render.test.cjs",
            [],
            id="tools-root",
        ),
        pytest.param(
            "shared.release-tool",
            "tools/release",
            "@example/release-tool",
            "tools/release/src/render.test.cjs",
            [RuleId("repository/artifacts/operational-script-tests")],
            id="tools-source-is-not-test-ownership",
        ),
        pytest.param(
            "shared.iac-tool",
            "iac/bell",
            "@example/iac-tool",
            "iac/bell/tests/plan.test.cjs",
            [RuleId("repository/artifacts/operational-script-tests")],
            id="iac-root",
        ),
    ],
)
def test_operational_root_precedes_declared_tool_ownership(
    component_id: str,
    root: str,
    identity: str,
    artifact_path: str,
    expected_rules: list[RuleId],
) -> None:
    component = Component(
        ComponentId(component_id),
        "tool",
        root,
        identity,
        capability=component_id,
    )
    package = PackageEvidence(
        ecosystem="npm",
        path=f"{root}/package.json",
        name=identity,
        private=True,
        workspace_root=False,
    )
    assert (
        _rule_ids(
            _snapshot(
                artifact_path,
                components=(component,),
                packages=(package,),
            )
        )
        == expected_rules
    )


@pytest.mark.parametrize(
    ("kind", "native_package", "evidence_path", "substantive", "prohibited"),
    [
        pytest.param("shared-library", _PYTHON_PACKAGE, "uv.lock", True, False, id="python-lock"),
        pytest.param("application", _PYTHON_PACKAGE, "main.py", True, False, id="python-source"),
        pytest.param("shared-library", _NPM_PACKAGE, "src/index.ts", True, False, id="npm-source"),
        pytest.param(
            "shared-library", _PYTHON_PACKAGE, None, True, True, id="nominal-package-only"
        ),
        pytest.param(
            "shared-library", _PYTHON_PACKAGE, "uv.lock", False, True, id="empty-evidence"
        ),
        pytest.param(None, _PYTHON_PACKAGE, "uv.lock", True, True, id="undeclared-package"),
        pytest.param(
            "terraform-root", _PYTHON_PACKAGE, "uv.lock", True, True, id="operational-component"
        ),
        pytest.param("shared-library", ("python", None), "uv.lock", True, True, id="unnamed"),
    ],
)
def test_declared_package_test_requires_native_evidence(
    kind: str | None,
    native_package: tuple[str, str | None],
    evidence_path: str | None,
    substantive: bool,
    prohibited: bool,
) -> None:
    root = _PACKAGE_ROOT
    ecosystem, identity = native_package
    metadata = "package.json" if ecosystem == "npm" else "pyproject.toml"
    package = _root_package(
        ecosystem,
        f"{root}/{metadata}",
        identity,
        workspace_root=False,
    )
    component = Component(
        ComponentId("shared.input-library"),
        kind or "shared-library",
        root,
        identity or "input-library",
        capability="input-library",
    )
    artifact = "inputs.test.cjs" if ecosystem == "npm" else "test_inputs.py"
    paths = [package.path, f"{root}/tests/{artifact}"]
    if evidence_path is not None:
        paths.append(f"{root}/{evidence_path}")
    snapshot = _snapshot(*paths, components=(component,) if kind else (), packages=(package,))
    if not substantive:
        snapshot = _with_insubstantive_path(snapshot, f"{root}/{evidence_path}")
    expected = [RuleId("repository/artifacts/operational-script-tests")] if prohibited else []
    assert _rule_ids(snapshot) == expected


@pytest.mark.parametrize(
    ("root", "component_root", "artifact", "terraform_modules", "prohibited"),
    [
        pytest.param(_PACKAGE_ROOT, _PACKAGE_ROOT, _PACKAGE_TEST, (), False, id="exact-package"),
        pytest.param(_PACKAGE_ROOT, "libraries", _PACKAGE_TEST, (), True, id="ancestor-component"),
        pytest.param(
            _PACKAGE_ROOT, _PACKAGE_ROOT, "src/test_inputs.py", (), True, id="source-location"
        ),
        pytest.param(
            _PACKAGE_ROOT,
            _PACKAGE_ROOT,
            "deploy/tests/test_inputs.py",
            (),
            True,
            id="package-deployment",
        ),
        pytest.param(
            _PACKAGE_ROOT,
            _PACKAGE_ROOT,
            "tests/deploy/test_inputs.py",
            (),
            True,
            id="nested-deployment",
        ),
        pytest.param(
            "scripts/infra", "scripts/infra", _PACKAGE_TEST, (), True, id="top-operational-root"
        ),
        pytest.param(
            ".github/actions/infra",
            ".github/actions/infra",
            _PACKAGE_TEST,
            (),
            True,
            id="github-automation",
        ),
        pytest.param(
            _PACKAGE_ROOT,
            _PACKAGE_ROOT,
            _PACKAGE_TEST,
            (_PACKAGE_ROOT,),
            True,
            id="terraform-module",
        ),
        pytest.param(_PACKAGE_ROOT, _PACKAGE_ROOT, _PACKAGE_TEST, ("",), True, id="root-terraform"),
    ],
)
def test_operational_boundaries_precede_declared_package_tests(
    root: str,
    component_root: str,
    artifact: str,
    terraform_modules: tuple[str, ...],
    prohibited: bool,
) -> None:
    package = _root_package(
        "python",
        f"{root}/pyproject.toml",
        "input-library",
        workspace_root=False,
    )
    component = Component(
        ComponentId("shared.input-library"),
        "shared-library",
        component_root,
        "input-library",
        capability="input-library",
    )
    expected = [RuleId("repository/artifacts/operational-script-tests")] if prohibited else []
    assert (
        _rule_ids(
            _snapshot(
                package.path,
                f"{root}/uv.lock",
                f"{root}/{artifact}",
                components=(component,),
                packages=(package,),
                terraform_modules=terraform_modules,
            )
        )
        == expected
    )


def test_terraform_module_cannot_use_declared_tool_test_escape() -> None:
    component = Component(
        ComponentId("shared.release-tool"),
        "tool",
        "tools/release",
        "@example/release-tool",
        capability="release-tool",
    )
    package = PackageEvidence(
        ecosystem="npm",
        path="tools/release/package.json",
        name="@example/release-tool",
        private=True,
        workspace_root=False,
    )
    assert _rule_ids(
        _snapshot(
            "tools/release/tests/render.test.cjs",
            components=(component,),
            packages=(package,),
            terraform_modules=("tools/release",),
        )
    ) == [RuleId("repository/artifacts/operational-script-tests")]


def test_terraform_module_precedes_declared_application_ownership() -> None:
    component = Component(
        ComponentId("service.release"),
        "application",
        "services/release",
        "@example/release",
        capability="release",
    )
    assert _rule_ids(
        _snapshot(
            "services/release/deploy/plan.test.cjs",
            components=(component,),
            terraform_modules=("services/release/deploy",),
        )
    ) == [RuleId("repository/artifacts/operational-script-tests")]


def test_nested_deploy_precedes_declared_application_ownership() -> None:
    component = Component(
        ComponentId("service.api"),
        "application",
        "services/api",
        "@example/api",
        capability="api",
    )
    assert _rule_ids(
        _snapshot(
            "services/api/deploy/contract.test.cjs",
            components=(component,),
        )
    ) == [RuleId("repository/artifacts/operational-script-tests")]


def test_tools_package_without_declared_component_cannot_own_operational_test() -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="tools/release/package.json",
        name="@example/release-tool",
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="package.json",
        member_patterns=("tools/*",),
        exclude_patterns=(),
    )
    assert _rule_ids(
        _snapshot(
            "tools/release/tests/render.test.cjs",
            packages=(package,),
            workspaces=(workspace,),
        )
    ) == [RuleId("repository/artifacts/operational-script-tests")]


def test_declared_application_package_may_own_verifier_code() -> None:
    component = Component(
        ComponentId("alpha.api"),
        "application",
        "services/alpha",
        "@example/alpha",
        product="alpha",
    )
    package = PackageEvidence(
        ecosystem="python",
        path="services/alpha/pyproject.toml",
        name="alpha-api",
        private=True,
        workspace_root=False,
    )
    assert (
        _rule_ids(
            _snapshot(
                "services/alpha/src/verify_config.py",
                components=(component,),
                packages=(package,),
            )
        )
        == []
    )


@pytest.mark.parametrize(
    ("artifact_path", "expected_rules"),
    [
        pytest.param("src/verify_signature.py", [], id="owned-source-module"),
        pytest.param(
            "verify_signature.py",
            [RuleId("repository/artifacts/bespoke-iac-verifiers")],
            id="root-entrypoint",
        ),
        pytest.param(
            "src/repo_standards/verify_release_artifacts.py",
            [],
            id="owned-nested-source-module",
        ),
        pytest.param(
            "src/verify-dev-apply-plan.jq",
            [RuleId("repository/artifacts/bespoke-iac-verifiers")],
            id="globally-retired-basename",
        ),
    ],
)
def test_named_root_python_package_verifier_ownership(
    artifact_path: str,
    expected_rules: list[RuleId],
) -> None:
    package = _root_package("python", "pyproject.toml", "example-api", workspace_root=False)
    assert _rule_ids(_snapshot(artifact_path, packages=(package,))) == expected_rules


def test_relocated_unowned_verifier_is_rejected() -> None:
    assert _rule_ids(_snapshot("ci/contracts/verify-config.py")) == [
        RuleId("repository/artifacts/bespoke-iac-verifiers")
    ]


@pytest.mark.parametrize(
    "artifact_path",
    [
        pytest.param("packages/fake/verify-plan.cjs", id="package-root"),
        pytest.param("packages/fake/deploy/verify-plan.cjs", id="package-deploy"),
    ],
)
def test_package_manifest_alone_does_not_own_verifier(artifact_path: str) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="packages/fake/package.json",
        name="fake-package",
        private=True,
        workspace_root=False,
    )
    assert _rule_ids(_snapshot(artifact_path, packages=(package,))) == [
        RuleId("repository/artifacts/bespoke-iac-verifiers")
    ]


@pytest.mark.parametrize(
    ("artifact_path", "terraform_modules"),
    [
        pytest.param("iac/tool/src/verify-plan.cjs", (), id="iac-root"),
        pytest.param(
            "services/release/src/verify-plan.cjs",
            ("services/release",),
            id="terraform-module",
        ),
    ],
)
def test_operational_precedence_rejects_named_package_source_verifier(
    artifact_path: str,
    terraform_modules: tuple[str, ...],
) -> None:
    root = artifact_path.removesuffix("/src/verify-plan.cjs")
    package = PackageEvidence(
        ecosystem="npm",
        path=f"{root}/package.json",
        name="@example/release",
        private=True,
        workspace_root=False,
    )
    assert _rule_ids(
        _snapshot(
            artifact_path,
            packages=(package,),
            terraform_modules=terraform_modules,
        )
    ) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize("directory", ["bin", "scripts", "spec", "specs", "src", "tests"])
def test_root_workspace_package_owns_conventional_verifier_code(directory: str) -> None:
    package = PackageEvidence(
        ecosystem="python",
        path="packages/release/pyproject.toml",
        name="release-tool",
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="python",
        path="pyproject.toml",
        member_patterns=("packages/*",),
        exclude_patterns=(),
    )
    assert (
        _rule_ids(
            _snapshot(
                f"packages/release/{directory}/verify_release.py",
                packages=(package,),
                workspaces=(workspace,),
            )
        )
        == []
    )


def test_declared_nested_component_owns_conventional_verifier_source() -> None:
    component = Component(
        ComponentId("application.web"),
        "application",
        "typescript/packages/app",
        "@example/application",
        capability="web",
    )
    assert (
        _rule_ids(
            _snapshot(
                "typescript/packages/app/src/features/verify-connection-dialog.tsx",
                components=(component,),
            )
        )
        == []
    )


@pytest.mark.parametrize(
    ("artifact_path", "expected_rules"),
    [
        pytest.param("services/alpha/verify_release.py", [], id="component-root"),
        pytest.param(
            "services/alpha/deploy/verify_release.py",
            [RuleId("repository/artifacts/bespoke-iac-verifiers")],
            id="component-deploy",
        ),
    ],
)
def test_operational_path_precedes_declared_component_verifier_ownership(
    artifact_path: str,
    expected_rules: list[RuleId],
) -> None:
    component = Component(
        ComponentId("alpha.api"),
        "application",
        "services/alpha",
        "@example/alpha",
        product="alpha",
    )
    assert _rule_ids(_snapshot(artifact_path, components=(component,))) == expected_rules


@pytest.mark.parametrize(
    "artifact_path",
    [
        pytest.param(".github/actions/release/verify-plan.py", id="github-action"),
        pytest.param(".github/workflows/verify-plan.cjs", id="github-workflow"),
        pytest.param("services/api/deploy/verify-plan.py", id="nested-deploy"),
    ],
)
def test_operational_verifier_without_objective_owner_is_rejected(artifact_path: str) -> None:
    assert _rule_ids(_snapshot(artifact_path)) == [
        RuleId("repository/artifacts/bespoke-iac-verifiers")
    ]


@pytest.mark.parametrize("name", [None, ""])
def test_empty_package_identity_does_not_create_test_ownership(name: str | None) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="tools/check/package.json",
        name=name,
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="package.json",
        member_patterns=("tools/*",),
        exclude_patterns=(),
    )
    assert _rule_ids(
        _snapshot(
            "tools/check/tests/contract.test.cjs",
            packages=(package,),
            workspaces=(workspace,),
        )
    ) == [RuleId("repository/artifacts/operational-script-tests")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("routing.tftest.hcl", id="hcl"),
        pytest.param("routing.tftest.json", id="json"),
        pytest.param("iac/tests/PLAN.TFTEST.HCL", id="case-insensitive"),
    ],
)
def test_terraform_test_files_are_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/artifacts/terraform-test-files")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("routing.tf", id="terraform"),
        pytest.param("routing.hcl", id="hcl"),
        pytest.param("routing.tf.json", id="terraform-json"),
        pytest.param("routing.tftest.hcl.bak", id="suffix"),
        pytest.param("routing.tf.test.hcl", id="separated-test"),
    ],
)
def test_non_terraform_test_files_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("README.md", id="root"),
        pytest.param("docs/deployment/cloud-run.md", id="docs"),
        pytest.param("architecture/runtime.md", id="architecture"),
        pytest.param("adr/0001-runtime.md", id="adr"),
        pytest.param(".github/pull_request_template.md", id="github"),
        pytest.param(".github/actions/release/README.md", id="github-action"),
        pytest.param(".agents/skills/review/SKILL.md", id="agent-skill"),
        pytest.param(".claude/commands/release.md", id="agent-command"),
        pytest.param("nested/AGENTS.md", id="agent-contract"),
    ],
)
def test_durable_and_tool_contract_markdown_is_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


def test_declared_root_documentation_entrypoint_is_clean() -> None:
    assert (
        _rule_ids(
            _snapshot(
                "OPERATIONS.md",
                documentation=DocumentationConfig(("OPERATIONS.md",)),
            )
        )
        == []
    )


def test_package_root_readme_is_clean() -> None:
    snapshot = _snapshot(
        "applications/alpha/api/README.md",
        "applications/alpha/api/pyproject.toml",
        packages=(
            PackageEvidence(
                ecosystem="python",
                path="applications/alpha/api/pyproject.toml",
                name="alpha-api",
                private=False,
                workspace_root=False,
            ),
        ),
        workspaces=(
            WorkspaceEvidence(
                ecosystem="python",
                path="pyproject.toml",
                member_patterns=("applications/*/*",),
                exclude_patterns=(),
            ),
        ),
    )
    assert _rule_ids(snapshot) == []


@pytest.mark.parametrize(
    ("package_path", "package_name", "artifact_path", "evidence_path"),
    [
        pytest.param(
            "python/pyproject.toml",
            "python-api",
            "python/README.md",
            "python/uv.lock",
            id="python-readme",
        ),
        pytest.param(
            "python/pyproject.toml",
            "python-api",
            "python/agent/runtime/README.md",
            "python/uv.lock",
            id="python-nested-readme",
        ),
        pytest.param(
            "python/sdk/pyproject.toml",
            "python-sdk",
            "python/sdk/README-PYPI.md",
            "python/sdk/uv.lock",
            id="readme-variant",
        ),
        pytest.param(
            "python/sdk/pyproject.toml",
            "python-sdk",
            "python/sdk/USAGE.md",
            "python/sdk/uv.lock",
            id="package-usage",
        ),
        pytest.param(
            "python/sdk/pyproject.toml",
            "python-sdk",
            "python/sdk/docs/models/call.md",
            "python/sdk/uv.lock",
            id="generated-sdk-doc",
        ),
        pytest.param(
            "mcps/livekit-analytics/pyproject.toml",
            "livekit-analytics",
            "mcps/livekit-analytics/README.md",
            "mcps/livekit-analytics/uv.lock",
            id="nested-standalone-package",
        ),
        pytest.param(
            "mcps/livekit-analytics/pyproject.toml",
            "livekit-analytics",
            "mcps/livekit-analytics/src/verify_connection.py",
            "mcps/livekit-analytics/uv.lock",
            id="nested-standalone-source",
        ),
    ],
)
def test_named_standalone_package_owns_conventional_artifact(
    package_path: str,
    package_name: str,
    artifact_path: str,
    evidence_path: str,
) -> None:
    package = PackageEvidence(
        ecosystem="python",
        path=package_path,
        name=package_name,
        private=None,
        workspace_root=False,
    )
    assert _rule_ids(_snapshot(artifact_path, evidence_path, packages=(package,))) == []


@pytest.mark.parametrize(
    ("ecosystem", "manifest", "artifact"),
    [
        pytest.param(
            "npm",
            "packages/fake/package.json",
            "packages/fake/src/verify-plan.cjs",
            id="node-manifest-only",
        ),
        pytest.param(
            "python",
            "packages/fake/pyproject.toml",
            "packages/fake/src/verify_plan.py",
            id="python-manifest-only",
        ),
    ],
)
def test_nested_standalone_manifest_alone_does_not_own_verifier_source(
    ecosystem: str, manifest: str, artifact: str
) -> None:
    package = PackageEvidence(
        ecosystem=ecosystem,
        path=manifest,
        name="fake",
        private=True,
        workspace_root=False,
    )

    assert _rule_ids(_snapshot(artifact, packages=(package,))) == [
        RuleId("repository/artifacts/bespoke-iac-verifiers")
    ]


@pytest.mark.parametrize(
    ("ecosystem", "manifest", "artifact"),
    [
        pytest.param(
            "npm",
            "packages/fake/package.json",
            "packages/fake/src/verify-plan.cjs",
            id="node-empty-workspace",
        ),
        pytest.param(
            "python",
            "packages/fake/pyproject.toml",
            "packages/fake/src/verify_plan.py",
            id="python-empty-workspace",
        ),
    ],
)
def test_empty_workspace_manifest_does_not_own_verifier_source(
    ecosystem: str, manifest: str, artifact: str
) -> None:
    package = PackageEvidence(
        ecosystem=ecosystem,
        path=manifest,
        name="fake",
        private=True,
        workspace_root=True,
    )
    workspace = WorkspaceEvidence(
        ecosystem=ecosystem,
        path=manifest,
        member_patterns=(),
        exclude_patterns=(),
    )

    assert _rule_ids(_snapshot(artifact, packages=(package,), workspaces=(workspace,))) == [
        RuleId("repository/artifacts/bespoke-iac-verifiers")
    ]


@pytest.mark.parametrize(
    ("ecosystem", "manifest", "artifact", "evidence"),
    [
        pytest.param(
            "npm",
            "packages/fake/package.json",
            "packages/fake/src/verify-plan.cjs",
            "packages/fake/package-lock.json",
            id="node-empty-lock",
        ),
        pytest.param(
            "npm",
            "packages/fake/package.json",
            "packages/fake/src/verify-plan.cjs",
            "packages/fake/index.js",
            id="node-empty-entrypoint",
        ),
        pytest.param(
            "python",
            "packages/fake/pyproject.toml",
            "packages/fake/src/verify_plan.py",
            "packages/fake/uv.lock",
            id="python-empty-lock",
        ),
        pytest.param(
            "python",
            "packages/fake/pyproject.toml",
            "packages/fake/src/verify_plan.py",
            "packages/fake/main.py",
            id="python-empty-entrypoint",
        ),
        pytest.param(
            "python",
            "packages/fake/pyproject.toml",
            "packages/fake/src/verify_plan.py",
            "packages/fake/fake/__init__.py",
            id="python-empty-import-package",
        ),
    ],
)
def test_empty_standalone_evidence_does_not_own_verifier_source(
    ecosystem: str, manifest: str, artifact: str, evidence: str
) -> None:
    package = PackageEvidence(
        ecosystem=ecosystem,
        path=manifest,
        name="fake",
        private=True,
        workspace_root=False,
    )

    snapshot = _with_insubstantive_path(
        _snapshot(artifact, evidence, packages=(package,)), evidence
    )
    assert _rule_ids(snapshot) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


def test_import_package_marker_does_not_independently_own_fake_package() -> None:
    package = PackageEvidence(
        ecosystem="python",
        path="packages/fake/pyproject.toml",
        name="fake",
        private=True,
        workspace_root=False,
    )

    assert _rule_ids(
        _snapshot(
            "packages/fake/fake/__init__.py",
            "packages/fake/src/verify_plan.py",
            packages=(package,),
        )
    ) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        pytest.param(
            "python/bulbul/bulbul/integrations/ARCHITECTURE.md",
            [],
            id="import-package-document",
        ),
        pytest.param(
            "python/bulbul/notes/ARCHITECTURE.md",
            [RuleId("repository/documentation/placement")],
            id="arbitrary-nested-document",
        ),
    ],
)
def test_flat_layout_python_import_package_document_ownership(
    document: str, expected: list[RuleId]
) -> None:
    package = PackageEvidence(
        ecosystem="python",
        path="python/bulbul/pyproject.toml",
        name="bulbul",
        private=None,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="python",
        path="python/pyproject.toml",
        member_patterns=("bulbul",),
        exclude_patterns=(),
    )

    snapshot = _snapshot(
        "python/bulbul/bulbul/__init__.py",
        document,
        packages=(package,),
        workspaces=(workspace,),
    )
    snapshot = _with_insubstantive_path(snapshot, "python/bulbul/bulbul/__init__.py")

    assert _rule_ids(snapshot) == expected


@pytest.mark.parametrize(
    "workspace_path",
    [
        pytest.param("tools/platform/package.json", id="npm-workspace-root"),
        pytest.param("tools/platform/pnpm-workspace.yaml", id="pnpm-workspace-root"),
    ],
)
def test_named_nonempty_workspace_root_owns_tool_source_verifier(
    workspace_path: str,
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="tools/platform/package.json",
        name="@example/platform",
        private=True,
        workspace_root=workspace_path.endswith("package.json"),
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path=workspace_path,
        member_patterns=("packages/*",),
        exclude_patterns=(),
    )

    assert (
        _rule_ids(
            _snapshot(
                "tools/platform/src/verify-plan.cjs",
                packages=(package,),
                workspaces=(workspace,),
            )
        )
        == []
    )


@pytest.mark.parametrize(
    ("members", "excludes", "expected"),
    [
        pytest.param(("packages/**",), (), [], id="recursive-member"),
        pytest.param(
            ("packages/*",),
            (),
            [RuleId("repository/artifacts/bespoke-iac-verifiers")],
            id="immediate-member-does-not-overmatch",
        ),
        pytest.param(
            ("packages/**",),
            ("packages/team/**",),
            [RuleId("repository/artifacts/bespoke-iac-verifiers")],
            id="recursive-exclusion",
        ),
    ],
)
def test_workspace_globstar_membership(
    members: tuple[str, ...], excludes: tuple[str, ...], expected: list[RuleId]
) -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="packages/team/app/package.json",
        name="app",
        private=True,
        workspace_root=False,
    )
    workspace = WorkspaceEvidence(
        ecosystem="npm",
        path="pnpm-workspace.yaml",
        member_patterns=members,
        exclude_patterns=excludes,
    )

    assert (
        _rule_ids(
            _snapshot(
                "packages/team/app/src/verify-plan.cjs",
                packages=(package,),
                workspaces=(workspace,),
            )
        )
        == expected
    )


def test_workflow_markdown_is_rejected() -> None:
    assert _rule_ids(_snapshot(".github/workflows/SANDBOX.md")) == [
        RuleId("repository/documentation/placement")
    ]


def test_declared_tool_cannot_own_workflow_markdown() -> None:
    component = Component(
        ComponentId("workflow.tool"),
        "tool",
        ".github/workflows/tool",
        "@example/workflow-tool",
        capability="workflow-tool",
    )
    package = PackageEvidence(
        ecosystem="npm",
        path=".github/workflows/tool/package.json",
        name="@example/workflow-tool",
        private=True,
        workspace_root=False,
    )
    assert _rule_ids(
        _snapshot(
            ".github/workflows/tool/README.md",
            components=(component,),
            packages=(package,),
        )
    ) == [RuleId("repository/documentation/placement")]


def test_generated_client_markdown_is_clean() -> None:
    generated = Component(
        ComponentId("alpha.client"),
        "generated-client",
        "clients/generated/alpha/platform/python",
        "@example/alpha",
        product="alpha",
        capability="platform",
    )
    snapshot = _snapshot(
        "clients/generated/alpha/platform/python/docs/models/call.md",
        components=(generated,),
    )
    assert _rule_ids(snapshot) == []


def test_declared_application_root_readme_is_clean() -> None:
    application = Component(
        ComponentId("alpha.api"),
        "application",
        "applications/alpha/api",
        "@example/alpha",
        product="alpha",
    )
    snapshot = _snapshot("applications/alpha/api/README.md", components=(application,))
    assert _rule_ids(snapshot) == []


def test_declared_operational_root_readme_is_rejected() -> None:
    terraform = Component(
        ComponentId("alpha.terraform"),
        "terraform-root",
        "deployments/alpha/terraform",
        "@example/alpha",
        product="alpha",
    )
    snapshot = _snapshot("deployments/alpha/terraform/README.md", components=(terraform,))
    assert _rule_ids(snapshot) == [RuleId("repository/documentation/placement")]


def test_terraform_module_named_package_cannot_own_documentation() -> None:
    package = PackageEvidence(
        ecosystem="npm",
        path="services/release/package.json",
        name="@example/release",
        private=True,
        workspace_root=False,
    )
    snapshot = _snapshot(
        "services/release/docs/operations.md",
        packages=(package,),
        terraform_modules=("services/release",),
    )
    assert _rule_ids(snapshot) == [RuleId("repository/documentation/placement")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("iac/delivery/README.md", id="terraform-root"),
        pytest.param("deploy/cloudflare-target/README.md", id="deployment-root"),
        pytest.param("scripts/release/NOTES.md", id="script-root"),
        pytest.param("applications/alpha/api/internal/README.md", id="nested-readme"),
        pytest.param("notes/implementation-plan.md", id="floating-document"),
        pytest.param(".claude/docs/handoff.md", id="agent-document-dump"),
        pytest.param("IMPLEMENTATION_SUMMARY.md", id="root-implementation-summary"),
        pytest.param("QA_HANDOFF.md", id="root-qa-handoff"),
        pytest.param("PLAN.md", id="root-plan"),
        pytest.param("RELEASE_PROCESS.md", id="root-release-process"),
    ],
)
def test_ad_hoc_markdown_is_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/documentation/placement")]


def test_rejected_artifact_uses_nearest_component_owner() -> None:
    component = Component(
        ComponentId("alpha.api"),
        "application",
        "applications/alpha/api",
        "@example/alpha",
        product="alpha",
    )
    diagnostic = SarjPolicy.evaluate_repository(
        _snapshot("applications/alpha/api/internal/README.md", components=(component,))
    )[0]
    assert diagnostic.component_id == ComponentId("alpha.api")
    assert diagnostic.path == "applications/alpha/api/internal/README.md"
    assert diagnostic.evidence_level == "verified"


def test_one_diagnostic_is_emitted_per_rejected_path() -> None:
    diagnostics = SarjPolicy.evaluate_repository(
        _snapshot("iac/delivery/README.md", "iac/delivery/terraform.tfvars.example")
    )
    assert [(item.path, item.rule_id) for item in diagnostics] == [
        ("iac/delivery/README.md", RuleId("repository/documentation/placement")),
        (
            "iac/delivery/terraform.tfvars.example",
            RuleId("repository/artifacts/terraform-examples"),
        ),
    ]
