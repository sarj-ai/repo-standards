from __future__ import annotations

import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git fixture only
from typing import TYPE_CHECKING

import pytest

from repo_lint.core import (
    ConfigurationError,
    InventoryKind,
    core_rules,
    load_repository_snapshot,
    migration_diagnostics,
    parse_project_metadata,
    parse_workspace_metadata,
    read_tracked_blob_contents,
)


if TYPE_CHECKING:
    from pathlib import Path


_MANIFEST = b"""\
schema_version = 1
repository_id = "example-repository"
policy = "example"
policy_version = 1

[[components]]
id = "application"
kind = "service"
path = "apps/application"
owner = "@example/platform"
"""


def _git(repository: Path, *arguments: str) -> None:
    git_executable = shutil.which("git")
    assert git_executable is not None
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed local Git fixture only
        [git_executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )


def _committed_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".repo-lint").mkdir()
    (repository / ".repo-lint" / "repository.toml").write_bytes(_MANIFEST)
    (repository / "apps" / "application").mkdir(parents=True)
    (repository / "apps" / "application" / "package.json").write_text(
        '{"name":"@example/application","private":true}', encoding="utf-8"
    )
    (repository / "packages" / "shared").mkdir(parents=True)
    (repository / "package.json").write_text(
        '{"private":true,"workspaces":["apps/*","packages/*"]}', encoding="utf-8"
    )
    (repository / "iac").mkdir()
    (repository / "iac" / "main.tf").write_text("terraform {}\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return repository


def _manifest_with_migration(*, source: str, target: str) -> bytes:
    manifest = _MANIFEST.replace(b'path = "apps/application"', f'path = "{target}"'.encode())
    return (
        manifest
        + f"""\n[[migration_paths]]
component_id = "application"
from = "{source}"
to = "{target}"
""".encode()
    )


def test_deep_json_is_classified_without_crashing() -> None:
    content = b"[" * 2_000 + b"]" * 2_000
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_project_metadata("package.json", content)


@pytest.mark.parametrize(
    "content",
    [
        b'{"name": 42}',
        b'{"private": "yes"}',
        b'{"workspaces": false}',
    ],
)
def test_invalid_npm_metadata_types_are_classified(content: bytes) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_project_metadata("package.json", content)


def test_workspace_metadata_is_typed_without_expanding_globs() -> None:
    npm = parse_workspace_metadata(
        "package.json", b'{"workspaces":{"packages":["apps/*","packages/*"]}}'
    )
    python = parse_workspace_metadata(
        "pyproject.toml",
        b'[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = ["packages/old"]\n',
    )
    assert npm is not None
    assert npm.member_patterns == ("apps/*", "packages/*")
    assert python is not None
    assert python.member_patterns == ("packages/*",)
    assert python.exclude_patterns == ("packages/old",)


def test_workspace_metadata_rejects_unsafe_patterns() -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("package.json", b'{"workspaces":["../outside"]}')


def test_snapshot_joins_manifest_and_inventory_from_one_git_tree(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    snapshot = load_repository_snapshot(repository)

    assert snapshot.manifest.repository_id == "example-repository"
    assert snapshot.provenance.mode == "git-tree"
    assert len(snapshot.provenance.source_revision) in {40, 64}
    assert len(snapshot.provenance.tree_digest) in {40, 64}
    assert len(snapshot.provenance.manifest_digest) == 64
    assert snapshot.provenance.manifest_object_id is not None
    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.packages[0].object_id
    assert snapshot.inspection.workspaces[0].member_patterns == ("apps/*", "packages/*")
    assert snapshot.inspection.terraform_modules == ("iac",)
    assert InventoryKind.TERRAFORM_MODULE in {
        unit.kind for unit in snapshot.inspection.inventory_units
    }

    dirty_manifest = _MANIFEST.replace(b"example-repository", b"dirty-repository")
    (repository / ".repo-lint" / "repository.toml").write_bytes(dirty_manifest)
    repeated = load_repository_snapshot(repository)
    assert repeated.manifest.repository_id == "example-repository"
    assert repeated.provenance == snapshot.provenance
    assert repeated.inspection == snapshot.inspection


def test_selected_blob_reader_ignores_dirty_worktree_bytes(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    selected = read_tracked_blob_contents(repository, ("package.json",))
    assert selected[0].content == b'{"private":true,"workspaces":["apps/*","packages/*"]}'

    (repository / "package.json").write_text('{"private":false}', encoding="utf-8")
    repeated = read_tracked_blob_contents(repository, ("package.json",))
    assert repeated == selected


def test_selected_blob_reader_rejects_absent_and_duplicate_paths(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    with pytest.raises(ConfigurationError, match="absent"):
        read_tracked_blob_contents(repository, ("missing.json",))
    with pytest.raises(ConfigurationError, match="unique"):
        read_tracked_blob_contents(repository, ("package.json", "package.json"))


def test_core_catalog_is_stable_and_complete() -> None:
    assert tuple(rule.rule_id for rule in core_rules()) == (
        "core/layout/non-overlapping-root",
        "core/migration/batch-too-large",
        "core/migration/target-missing",
        "core/migration/tracked-install-artifacts",
        "core/migration/source-retained",
        "core/migration/workspace-membership-lost",
        "core/exception/expired",
        "core/baseline/stale-entry",
    )


def test_migration_diagnostics_verify_tree_and_workspace_state(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="apps/application", target="applications/platform/api"
    )
    (repository / ".repo-lint" / "repository.toml").write_bytes(manifest)
    (repository / "applications" / "platform" / "api").mkdir(parents=True)
    (repository / "applications" / "platform" / "api" / "package.json").write_text(
        '{"name":"@example/application","private":true}', encoding="utf-8"
    )
    for index in range(24):
        (repository / "apps" / "application" / f"legacy-{index:02d}.txt").write_text(
            "legacy\n", encoding="utf-8"
        )
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "move application",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))

    assert [item.rule_id for item in diagnostics] == [
        "core/migration/source-retained",
        "core/migration/workspace-membership-lost",
    ]
    assert diagnostics[0].observed_value == {
        "count": 25,
        "paths": [f"apps/application/legacy-{index:02d}.txt" for index in range(20)],
        "truncated": True,
    }


def test_migration_target_must_exist_in_selected_tree(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="apps/application", target="applications/platform/api"
    )
    (repository / ".repo-lint" / "repository.toml").write_bytes(manifest)
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "declare missing move",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))

    assert [item.rule_id for item in diagnostics] == [
        "core/migration/target-missing",
        "core/migration/source-retained",
    ]


def test_workspace_rule_ignores_packages_that_were_never_members(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="external/application", target="applications/platform/api"
    )
    (repository / ".repo-lint" / "repository.toml").write_bytes(manifest)
    (repository / "applications" / "platform" / "api").mkdir(parents=True)
    (repository / "applications" / "platform" / "api" / "package.json").write_text(
        '{"name":"@example/application","private":true}', encoding="utf-8"
    )
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "move external application",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))

    assert diagnostics == ()


def test_completed_move_has_no_migration_diagnostics(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    (repository / ".repo-lint" / "repository.toml").write_bytes(
        _manifest_with_migration(source="apps/application", target="applications/platform/api")
    )
    (repository / "apps" / "application" / "package.json").unlink()
    (repository / "applications" / "platform" / "api").mkdir(parents=True)
    (repository / "applications" / "platform" / "api" / "package.json").write_text(
        '{"name":"@example/application","private":true}', encoding="utf-8"
    )
    (repository / "package.json").write_text(
        '{"private":true,"workspaces":["applications/*/*","packages/*"]}',
        encoding="utf-8",
    )
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "complete application move",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))

    assert diagnostics == ()


def test_separately_owned_compatibility_source_is_not_retained_debt(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="apps/application", target="applications/platform/api"
    ).replace(
        b"\n[[migration_paths]]",
        b"""\n[[components]]
id = "compatibility"
kind = "service"
path = "apps/application"
owner = "@example/platform"

[[migration_paths]]""",
    )
    (repository / ".repo-lint" / "repository.toml").write_bytes(manifest)
    (repository / "applications" / "platform" / "api").mkdir(parents=True)
    (repository / "applications" / "platform" / "api" / "marker.txt").write_text(
        "moved\n", encoding="utf-8"
    )
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "declare compatibility source",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))

    assert diagnostics == ()


def test_migration_reports_tracked_install_artifacts_once_with_bounded_evidence(
    tmp_path: Path,
) -> None:
    repository = _committed_repository(tmp_path)
    (repository / ".repo-lint" / "repository.toml").write_bytes(
        _manifest_with_migration(source="apps/application", target="applications/platform/api")
    )
    (repository / "applications" / "platform" / "api").mkdir(parents=True)
    (repository / "applications" / "platform" / "api" / "marker.txt").write_text(
        "moved\n", encoding="utf-8"
    )
    (repository / ".yarn").mkdir()
    (repository / ".yarn" / "install-state.gz").write_bytes(b"generated")
    for index in range(24):
        generated = repository / "node_modules" / f"dependency-{index:02d}" / "index.js"
        generated.parent.mkdir(parents=True)
        generated.write_text("module.exports = {};\n", encoding="utf-8")
    _git(repository, "add", "-f", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "track generated install state",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))
    artifact = next(
        item for item in diagnostics if item.rule_id == "core/migration/tracked-install-artifacts"
    )

    assert artifact.observed_value == {
        "count": 25,
        "paths": [".yarn/install-state.gz"]
        + [f"node_modules/dependency-{index:02d}/index.js" for index in range(19)],
        "truncated": True,
    }
    assert (
        sum(item.rule_id == "core/migration/tracked-install-artifacts" for item in diagnostics) == 1
    )


def test_install_artifacts_are_out_of_scope_without_a_declared_migration(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    generated = repository / "node_modules" / "dependency" / "index.js"
    generated.parent.mkdir(parents=True)
    generated.write_text("module.exports = {};\n", encoding="utf-8")
    _git(repository, "add", "-f", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "track install state outside migration",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))

    assert diagnostics == ()


def test_multiple_declared_moves_produce_one_advisory_batch_finding(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="apps/application", target="applications/platform/api"
    ).replace(
        b"\n[[migration_paths]]",
        b"""\n[[components]]
id = "worker"
kind = "service"
path = "applications/platform/worker"
owner = "@example/platform"

[[migration_paths]]""",
    )
    manifest += b"""\n[[migration_paths]]
component_id = "worker"
from = "apps/worker"
to = "applications/platform/worker"
"""
    (repository / ".repo-lint" / "repository.toml").write_bytes(manifest)
    for component in ("api", "worker"):
        target = repository / "applications" / "platform" / component / "marker.txt"
        target.parent.mkdir(parents=True)
        target.write_text("moved\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "declare migration batch",
    )

    diagnostics = migration_diagnostics(load_repository_snapshot(repository))
    batch = next(item for item in diagnostics if item.rule_id == "core/migration/batch-too-large")

    assert batch.severity == "warning"
    assert batch.observed_value == {
        "count": 2,
        "component_ids": ["application", "worker"],
        "truncated": False,
    }
    assert sum(item.rule_id == "core/migration/batch-too-large" for item in diagnostics) == 1
