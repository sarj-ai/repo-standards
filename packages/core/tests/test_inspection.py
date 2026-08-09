"""Adversarial tests for inert Git metadata parsing."""

from __future__ import annotations

import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git fixture only
from typing import TYPE_CHECKING

import pytest
from repo_lint_core import (
    ConfigurationError,
    InventoryKind,
    core_rules,
    load_repository_snapshot,
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
        "core/exception/expired",
        "core/baseline/stale-entry",
    )
