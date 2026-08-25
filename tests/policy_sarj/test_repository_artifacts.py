from __future__ import annotations

import pytest

from repo_standards.core.models import (
    Component,
    ComponentId,
    GitObjectId,
    InputProvenance,
    Manifest,
    PackageEvidence,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedFileEvidence,
)
from repo_standards.policy_sarj import SarjPolicy


def _snapshot(
    *paths: str,
    components: tuple[Component, ...] = (),
    packages: tuple[PackageEvidence, ...] = (),
) -> RepositorySnapshot:
    tracked = tuple(
        TrackedFileEvidence(path=path, object_id=f"{index + 1:040x}")
        for index, path in enumerate(sorted(paths))
    )
    return RepositorySnapshot(
        manifest=Manifest(
            repository_id=RepositoryId("example-repository"),
            components=components,
        ),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            tracked_file_count=len(tracked),
            packages=packages,
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
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


def _rule_ids(snapshot: RepositorySnapshot) -> list[RuleId]:
    return [item.rule_id for item in SarjPolicy.evaluate_repository(snapshot)]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("terraform.tfvars.example", id="root"),
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
    ],
)
def test_non_example_tfvars_paths_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("backend.conf.example", id="terraform-backend"),
        pytest.param("iac/dev/BACKEND.CONF.EXAMPLE", id="backend-case-insensitive"),
        pytest.param(".env.example", id="env-root"),
        pytest.param("services/api/.env.local.example", id="env-profile"),
        pytest.param("services/api/.ENV.DEV.EXAMPLE", id="env-case-insensitive"),
        pytest.param(".env.schema", id="env-schema"),
        pytest.param("services/api/.env.production.schema.json", id="env-schema-json"),
        pytest.param("services/api/.env.schema.yaml", id="env-schema-yaml"),
        pytest.param("services/api/.ENV.LOCAL.SCHEMA.YML", id="env-schema-yml-case-insensitive"),
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
        pytest.param(".env", id="runtime-env"),
        pytest.param(".env.local", id="runtime-env-profile"),
        pytest.param("env.example", id="missing-dot-prefix"),
        pytest.param(".envrc.example", id="different-basename"),
        pytest.param("docs/.env.example.md", id="env-documentation"),
        pytest.param(".env.schema.toml", id="unsupported-schema-suffix"),
        pytest.param("settings.schema.json", id="application-schema"),
    ],
)
def test_non_schema_derived_config_example_paths_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("verify.mjs", id="root-minimal-mjs"),
        pytest.param("verify-alert-policies.mjs", id="root-mjs"),
        pytest.param("verify-environment-boundary.test.mjs", id="root-mjs"),
        pytest.param("tools/VERIFY-PLAN.MJS", id="case-insensitive-mjs"),
        pytest.param("iac/bulbul/scripts/verify-dev-apply-plan.jq", id="nested-jq"),
        pytest.param("tools/VERIFY-DEV-APPLY-PLAN.JQ", id="case-insensitive"),
    ],
)
def test_bespoke_iac_verifier_files_are_rejected(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("preverify.mjs", id="prefix-mjs"),
        pytest.param("plan.test.mjs", id="ordinary-mjs-test"),
        pytest.param("verify-plan.js", id="different-mjs-extension"),
        pytest.param("verify-plan.mjs.bak", id="mjs-suffix"),
        pytest.param("verify-dev-apply-plan.jq.bak", id="suffix"),
        pytest.param("prefix-verify-dev-apply-plan.jq", id="prefix"),
        pytest.param("verify/plan.mjs", id="different-basename"),
    ],
)
def test_nearby_iac_verifier_names_are_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


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
        pytest.param("RELEASE_PROCESS.md", id="root-durable-doc"),
        pytest.param("docs/deployment/cloud-run.md", id="docs"),
        pytest.param("architecture/runtime.md", id="architecture"),
        pytest.param("adr/0001-runtime.md", id="adr"),
        pytest.param(".github/pull_request_template.md", id="github"),
        pytest.param(".agents/skills/review/SKILL.md", id="agent-skill"),
        pytest.param(".claude/commands/release.md", id="agent-command"),
        pytest.param("nested/AGENTS.md", id="agent-contract"),
    ],
)
def test_durable_and_tool_contract_markdown_is_clean(path: str) -> None:
    assert _rule_ids(_snapshot(path)) == []


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
    )
    assert _rule_ids(snapshot) == []


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


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("iac/delivery/README.md", id="terraform-root"),
        pytest.param("deploy/cloudflare-target/README.md", id="deployment-root"),
        pytest.param("scripts/release/NOTES.md", id="script-root"),
        pytest.param("applications/alpha/api/internal/README.md", id="nested-readme"),
        pytest.param("notes/implementation-plan.md", id="floating-document"),
        pytest.param(".claude/docs/handoff.md", id="agent-document-dump"),
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
