from __future__ import annotations

from collections.abc import Callable
from datetime import date
import tomllib

from pydantic import TypeAdapter
import pytest

from repo_standards.core.catalog import core_rules
from repo_standards.core.engine import apply_exceptions, check_baseline, core_diagnostics
from repo_standards.core.inspection import parse_project_metadata, parse_workspace_metadata
from repo_standards.core.migration import migration_diagnostics
from repo_standards.core.models import (
    ComponentId,
    Diagnostic,
    ExceptionRecord,
    FixtureId,
    GitObjectId,
    InputProvenance,
    Manifest,
    Mode,
    PackageEvidence,
    PassedReport,
    Remediation,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleDefinition,
    RuleExamplePair,
    RuleId,
    TrackedFileEvidence,
    WorkspaceEvidence,
)
from repo_standards.core.parser import parse_baseline_bytes, parse_manifest_bytes
from repo_standards.core.schema_provenance import (
    SchemaObject,
    parse_postgresql_objects,
    unattributed_schema_objects,
)


type ExampleRunner = Callable[[bytes], tuple[str, ...]]
_STRING_MAPPING = TypeAdapter(dict[str, str])
_SINGLE_MIGRATION = b"""\
schema_version = 2
repository_id = "example-repository"
[[components]]
id = "api"
kind = "service"
path = "applications/alpha/api"
owner = "@example/alpha"

[[migration_paths]]
component_id = "api"
from = "apps/api"
to = "applications/alpha/api"
"""
_TARGET = "applications/alpha/api"
_FINGERPRINT = "f" * 64


def _inspection(
    paths: tuple[str, ...],
    *,
    packages: tuple[PackageEvidence, ...] = (),
    workspaces: tuple[WorkspaceEvidence, ...] = (),
) -> RepositoryInspection:
    tracked = tuple(
        TrackedFileEvidence(path=path, object_id=f"{index + 1:040x}")
        for index, path in enumerate(sorted(paths))
    )
    return RepositoryInspection(
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
        workspaces=workspaces,
    )


def _snapshot(
    manifest: Manifest,
    paths: tuple[str, ...],
    *,
    packages: tuple[PackageEvidence, ...] = (),
    workspaces: tuple[WorkspaceEvidence, ...] = (),
) -> RepositorySnapshot:
    return RepositorySnapshot(
        manifest=manifest,
        baseline=None,
        inspection=_inspection(paths, packages=packages, workspaces=workspaces),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            manifest_path=".repo-standards/repository.toml",
            manifest_object_id=GitObjectId("c" * 40),
            manifest_digest="d" * 64,
        ),
    )


def _paths(content: bytes) -> tuple[str, ...]:
    return tuple(line for line in content.decode("utf-8").splitlines() if line)


def _rule_ids(diagnostics: tuple[Diagnostic, ...]) -> tuple[str, ...]:
    return tuple(sorted(str(item.rule_id) for item in diagnostics))


def _run_layout(content: bytes) -> tuple[str, ...]:
    return _rule_ids(core_diagnostics(parse_manifest_bytes(content)))


def _run_batch(content: bytes) -> tuple[str, ...]:
    manifest = parse_manifest_bytes(content)
    tracked = tuple(f"{migration.new_path}/marker.txt" for migration in manifest.migration_paths)
    return _rule_ids(migration_diagnostics(_snapshot(manifest, tracked)))


def _run_target(content: bytes) -> tuple[str, ...]:
    manifest = parse_manifest_bytes(_SINGLE_MIGRATION)
    return _rule_ids(migration_diagnostics(_snapshot(manifest, _paths(content))))


def _run_install_artifacts(content: bytes) -> tuple[str, ...]:
    manifest = parse_manifest_bytes(_SINGLE_MIGRATION)
    return _rule_ids(migration_diagnostics(_snapshot(manifest, _paths(content))))


def _run_source(content: bytes) -> tuple[str, ...]:
    manifest = parse_manifest_bytes(_SINGLE_MIGRATION)
    return _rule_ids(migration_diagnostics(_snapshot(manifest, _paths(content))))


def _run_workspace(content: bytes) -> tuple[str, ...]:
    manifest = parse_manifest_bytes(_SINGLE_MIGRATION)
    package_path = f"{_TARGET}/package.json"
    project = parse_project_metadata(
        package_path,
        b'{"name":"@example/api","private":true}',
    )
    workspace = parse_workspace_metadata("package.json", content)
    assert workspace is not None
    snapshot = _snapshot(
        manifest,
        (package_path,),
        packages=(project,),
        workspaces=(workspace,),
    )
    return _rule_ids(migration_diagnostics(snapshot))


def _run_exception(content: bytes) -> tuple[str, ...]:
    fields = _STRING_MAPPING.validate_python(
        tomllib.loads(content.decode("utf-8")),
        strict=True,
    )
    exception = ExceptionRecord(
        rule_id=RuleId(fields["rule_id"]),
        component_id=ComponentId(fields["component_id"]),
        manifest_anchor=fields["manifest_anchor"],
        fingerprint=fields["fingerprint"],
        owner=fields["owner"],
        reason=fields["reason"],
        issue=fields["issue"],
        created_on=fields["created_on"],
        expires_on=fields["expires_on"],
    )
    manifest = Manifest(
        repository_id=RepositoryId("example-repository"),
        components=(),
        exceptions=(exception,),
    )
    finding = Diagnostic(
        rule_id=exception.rule_id,
        rule_version=1,
        severity="error",
        evidence_level="verified",
        component_id=exception.component_id,
        subject_kind="component-root",
        observed="services/payments contains services/payments/worker",
        expected="component roots must be disjoint",
        message="component root overlaps payments",
        path="services/payments/worker",
        manifest_anchor=exception.manifest_anchor,
        remediation=Remediation(
            summary="Give each component one disjoint ownership root.",
            steps=("Move one component to a disjoint root.",),
            validation=("Run repo-standards check again.",),
        ),
        fingerprint=exception.fingerprint,
    )
    return _rule_ids(apply_exceptions((finding,), manifest, date(2029, 3, 2)))


def _run_baseline(content: bytes) -> tuple[str, ...]:
    baseline = parse_baseline_bytes(content)
    report = PassedReport(
        mode=Mode.RATCHET,
        repository_id=baseline.repository_id,
        policy_id=baseline.policy_id,
        policy_version=baseline.policy_version,
        scope_digest=baseline.scope_digest,
    )
    return _rule_ids(check_baseline(report, baseline))


def _run_schema_provenance(content: bytes) -> tuple[str, ...]:
    sql = b"\n".join(
        line for line in content.splitlines() if not line.strip().lower().endswith(b".sql")
    )
    generated = parse_postgresql_objects(sql)
    migrations: frozenset[SchemaObject] = (
        generated if b"/migrations/" in content else frozenset()
    )
    findings = unattributed_schema_objects(frozenset(), generated, migrations)
    return ("repository/database/generated-schema-provenance",) if findings else ()


_RUNNERS: dict[FixtureId, ExampleRunner] = {
    FixtureId("core.migration.target-missing.v2"): _run_target,
    FixtureId("core.migration.source-retained.v2"): _run_source,
    FixtureId("core.migration.workspace-membership-lost.v2"): _run_workspace,
    FixtureId("core.schema-provenance.dump-only-enum.v1"): _run_schema_provenance,
}

_EXPECTED_FLAGGED: dict[FixtureId, tuple[str, ...]] = {
    FixtureId("core.migration.target-missing.v2"): ("repository/migration/consistency",),
    FixtureId("core.migration.source-retained.v2"): ("repository/migration/consistency",),
    FixtureId("core.migration.workspace-membership-lost.v2"): ("repository/migration/consistency",),
    FixtureId("core.schema-provenance.dump-only-enum.v1"): (
        "repository/database/generated-schema-provenance",
    ),
}

_EXPECTED_PASSES: dict[FixtureId, tuple[str, ...]] = dict.fromkeys(_RUNNERS, ())

_EXAMPLES: tuple[tuple[RuleDefinition, RuleExamplePair], ...] = tuple(
    (rule, example) for rule in core_rules() for example in rule.examples
)


@pytest.mark.parametrize(
    ("rule", "example"),
    _EXAMPLES,
    ids=[str(example.example_id) for _, example in _EXAMPLES],
)
def test_core_rule_examples_execute_exact_catalog_bytes(
    rule: RuleDefinition,
    example: RuleExamplePair,
) -> None:
    runner = _RUNNERS[example.example_id]

    flagged = runner(example.before.encode("utf-8"))
    passes = runner(example.after.encode("utf-8"))

    assert flagged == _EXPECTED_FLAGGED[example.example_id]
    assert passes == _EXPECTED_PASSES[example.example_id]
    assert str(rule.rule_id) in flagged
    assert str(rule.rule_id) not in passes


def test_every_core_rule_has_one_registered_executable_example() -> None:
    rules = core_rules()
    fixture_ids = tuple(example.example_id for rule in rules for example in rule.examples)

    assert len(rules) == 2
    assert len(_RUNNERS) == len(set(fixture_ids)) == 4
    assert set(fixture_ids) == set(_RUNNERS) == set(_EXPECTED_FLAGGED) == set(_EXPECTED_PASSES)
