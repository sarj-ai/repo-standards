from __future__ import annotations

from repo_standards.core.models import (
    ActiveConfiguration,
    AuthorityId,
    Component,
    ComponentId,
    ConfigurationFormat,
    DeliveryConfig,
    DeploymentAuthority,
    DocumentationConfig,
    GitObjectId,
    InputProvenance,
    Manifest,
    PackageEvidence,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedContentEvidence,
    TrackedFileEvidence,
    WorkspaceEvidence,
)
from repo_standards.policy_sarj.policy import SarjPolicy


_REVISION = "a" * 40
_TREE = "b" * 40


def _component() -> Component:
    return Component(
        component_id=ComponentId("alpha.api"),
        kind="application",
        path="applications/alpha/api",
        owner="@example/alpha",
        product="alpha",
    )


def _snapshot(
    files: dict[str, bytes],
    *,
    documentation: DocumentationConfig | None = None,
    active: tuple[ActiveConfiguration, ...] = (),
    delivery: DeliveryConfig | None = None,
    package_owned: bool = False,
) -> RepositorySnapshot:
    component = _component()
    tracked = tuple(
        TrackedFileEvidence(path, f"{index + 1:040x}") for index, path in enumerate(sorted(files))
    )
    return RepositorySnapshot(
        manifest=Manifest(
            repository_id=RepositoryId("example-repository"),
            components=(component,),
            documentation=documentation,
            active_configuration=active,
            delivery=delivery,
        ),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision=_REVISION,
            tree_digest=_TREE,
            tracked_file_count=len(tracked),
            packages=(
                PackageEvidence(
                    ecosystem="npm",
                    path="packages/app/package.json",
                    name="@example/app",
                    private=True,
                    workspace_root=False,
                ),
            )
            if package_owned
            else (),
            workspaces=(
                WorkspaceEvidence(
                    ecosystem="npm",
                    path="package.json",
                    member_patterns=("packages/*",),
                    exclude_patterns=(),
                ),
            )
            if package_owned
            else (),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=tracked,
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision=_REVISION,
            tree_digest=_TREE,
            manifest_path=".repo-lint/repository.toml",
            manifest_object_id=GitObjectId("c" * 40),
            manifest_digest="d" * 64,
        ),
        content=tuple(
            TrackedContentEvidence(path, f"{index + 1:040x}", "e" * 64, content)
            for index, (path, content) in enumerate(sorted(files.items()))
        ),
    )


def _rule_ids(snapshot: RepositorySnapshot) -> list[RuleId]:
    return [item.rule_id for item in SarjPolicy.evaluate_repository(snapshot)]


def test_documentation_reachability_is_opt_in() -> None:
    snapshot = _snapshot({"README.md": b"# Root\n", "docs/orphan.md": b"# Orphan\n"})
    assert RuleId("repository/documentation/reachability") not in _rule_ids(snapshot)


def test_relative_reference_and_directory_links_make_docs_reachable() -> None:
    snapshot = _snapshot(
        {
            "README.md": b"[Docs][docs]\n\n[docs]: docs/\n",
            "docs/README.md": b"[Guide](guide.md#start)\n",
            "docs/guide.md": b"# Guide\n",
        },
        documentation=DocumentationConfig(("README.md",)),
    )
    assert RuleId("repository/documentation/reachability") not in _rule_ids(snapshot)


def test_conventional_root_documents_are_independent_entrypoints() -> None:
    snapshot = _snapshot(
        {
            "README.md": b"# Root\n",
            "CONTRIBUTING.md": b"# Contributing\n",
            "HISTORY.md": b"# History\n",
        },
        documentation=DocumentationConfig(("README.md",)),
    )
    assert RuleId("repository/documentation/reachability") not in _rule_ids(snapshot)


def test_owned_package_documents_are_outside_the_repository_documentation_graph() -> None:
    snapshot = _snapshot(
        {
            "README.md": b"# Root\n",
            "packages/app/docs/guide.md": b"# Package guide\n",
        },
        documentation=DocumentationConfig(("README.md",)),
        package_owned=True,
    )
    assert RuleId("repository/documentation/reachability") not in _rule_ids(snapshot)


def test_unreachable_cycle_reports_each_page_once() -> None:
    snapshot = _snapshot(
        {
            "README.md": b"# Root\n",
            "docs/a.md": b"[B](b.md)\n",
            "docs/b.md": b"[A](a.md)\n",
        },
        documentation=DocumentationConfig(("README.md",)),
    )
    findings = [
        item
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.rule_id == RuleId("repository/documentation/reachability")
    ]
    assert [item.path for item in findings] == ["docs/a.md", "docs/b.md"]


def test_images_and_external_links_do_not_create_reachability() -> None:
    snapshot = _snapshot(
        {
            "README.md": b"![Guide](docs/guide.md)\n[External](https://example.invalid)\n",
            "docs/guide.md": b"# Guide\n",
        },
        documentation=DocumentationConfig(("README.md",)),
    )
    assert _rule_ids(snapshot).count(RuleId("repository/documentation/reachability")) == 1


def test_exact_placeholder_is_reported_without_value_disclosure() -> None:
    component = _component()
    snapshot = _snapshot(
        {"config/active.yaml": b"nested:\n  endpoint: CHANGE_ME\n"},
        active=(
            ActiveConfiguration(
                component.component_id, "config/active.yaml", ConfigurationFormat.YAML
            ),
        ),
    )
    finding = next(
        item
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.rule_id == RuleId("repository/configuration/unresolved-placeholders")
    )
    assert finding.observed_value == {
        "category": "unresolved-placeholder",
        "pointer": "$/nested/endpoint",
    }
    assert "CHANGE_ME" not in finding.observed


def test_placeholder_near_misses_are_clean() -> None:
    component = _component()
    snapshot = _snapshot(
        {
            "config/active.json": (
                b'{"interpolation":"${SERVICE_URL}","domain":"example.com",'
                b'"name":"changeme-service","empty":""}'
            )
        },
        active=(
            ActiveConfiguration(
                component.component_id, "config/active.json", ConfigurationFormat.JSON
            ),
        ),
    )
    assert RuleId("repository/configuration/unresolved-placeholders") not in _rule_ids(snapshot)


def test_dotenv_quotes_comments_and_case_are_normalized() -> None:
    component = _component()
    snapshot = _snapshot(
        {"config/prod.env": b"export ENDPOINT='Replace-Me' # unresolved\n"},
        active=(
            ActiveConfiguration(
                component.component_id, "config/prod.env", ConfigurationFormat.DOTENV
            ),
        ),
    )
    assert (
        _rule_ids(snapshot).count(RuleId("repository/configuration/unresolved-placeholders")) == 1
    )


def _authority(
    authority_id: str,
    *,
    environment: str = "production",
    role: str = "primary",
) -> DeploymentAuthority:
    component = _component()
    return DeploymentAuthority(
        authority_id=AuthorityId(authority_id),
        component_id=component.component_id,
        environment=environment,
        mechanism="cloud-deploy",
        path=f"deploy/{authority_id}.yaml",
        authority="primary" if role == "primary" else "recovery",
    )


def test_duplicate_primary_authorities_emit_one_grouped_finding() -> None:
    authorities = (
        _authority("first"),
        _authority("second"),
        _authority("break-glass", role="recovery"),
    )
    snapshot = _snapshot(
        {item.path: b"deployment" for item in authorities},
        delivery=DeliveryConfig(authorities=authorities),
    )
    findings = [
        item
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.rule_id == RuleId("architecture/delivery/authority")
    ]
    assert len(findings) == 1
    assert findings[0].observed == "first, second"
    assert len(findings[0].related_locations) == 1


def test_different_environments_and_recovery_paths_do_not_compete() -> None:
    authorities = (
        _authority("production"),
        _authority("preview", environment="preview"),
        _authority("recovery", role="recovery"),
    )
    snapshot = _snapshot(
        {item.path: b"deployment" for item in authorities},
        delivery=DeliveryConfig(authorities=authorities),
    )
    assert RuleId("architecture/delivery/authority") not in _rule_ids(snapshot)
