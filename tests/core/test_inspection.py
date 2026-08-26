from __future__ import annotations

import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git fixture only
from typing import TYPE_CHECKING, Literal

import pytest

from repo_standards.core.catalog import core_rules
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    git_index_identity,
    load_repository_snapshot,
    parse_project_metadata,
    parse_workspace_metadata,
    read_tracked_blob_contents,
)
from repo_standards.core.migration import migration_diagnostics
from repo_standards.core.models import InventoryKind, RuleId
from repo_standards.policy_sarj import SarjPolicy


if TYPE_CHECKING:
    from pathlib import Path


_MANIFEST = b"""\
schema_version = 2
repository_id = "example-repository"
[[components]]
id = "application"
kind = "service"
path = "apps/application"
owner = "@example/alpha"
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
    (repository / ".repo-standards").mkdir()
    (repository / ".repo-standards" / "repository.toml").write_bytes(_MANIFEST)
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
    pnpm = parse_workspace_metadata(
        "pnpm-workspace.yaml",
        b"packages:\n  - packages/*\n  - '!packages/retired'\n",
    )
    assert npm is not None
    assert npm.member_patterns == ("apps/*", "packages/*")
    assert python is not None
    assert python.member_patterns == ("packages/*",)
    assert python.exclude_patterns == ("packages/old",)
    assert pnpm is not None
    assert pnpm.member_patterns == ("packages/*",)
    assert pnpm.exclude_patterns == ("packages/retired",)
    assert parse_workspace_metadata("pnpm-workspace.yaml", b"catalog:\n  react: 19.0.0\n") is None


def test_workspace_metadata_rejects_unsafe_patterns() -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("package.json", b'{"workspaces":["../outside"]}')
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("pnpm-workspace.yaml", b"packages:\n  - ../outside\n")


@pytest.mark.parametrize(
    "pattern",
    ["{apps,packages}/*", "@(apps|packages)/*", "!(packages/retired)"],
)
def test_workspace_metadata_rejects_unsupported_globs(pattern: str) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata(
            "pnpm-workspace.yaml", f"packages:\n  - '{pattern}'\n".encode()
        )


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
    (repository / ".repo-standards" / "repository.toml").write_bytes(dirty_manifest)
    repeated = load_repository_snapshot(repository)
    assert repeated.manifest.repository_id == "example-repository"
    assert repeated.provenance == snapshot.provenance
    assert repeated.inspection == snapshot.inspection


def test_snapshot_can_select_the_exact_staged_index(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = repository / ".repo-standards" / "repository.toml"
    manifest.write_bytes(_MANIFEST.replace(b"example-repository", b"staged-repository"))
    _git(repository, "add", str(manifest.relative_to(repository)))
    identity = git_index_identity(repository)
    manifest.write_bytes(_MANIFEST.replace(b"example-repository", b"unstaged-repository"))

    snapshot = load_repository_snapshot(repository, identity=identity)
    repeated = load_repository_snapshot(repository, identity=identity)

    assert snapshot.manifest.repository_id == "staged-repository"
    assert snapshot.provenance.mode == "git-index"
    assert (
        snapshot.provenance.source_revision
        == load_repository_snapshot(repository).provenance.source_revision
    )
    assert len(snapshot.provenance.tree_digest) == 64
    assert repeated.provenance == snapshot.provenance
    assert repeated.manifest == snapshot.manifest


def test_staged_index_rejects_symlinks(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "linked.py").symlink_to("apps/application/package.json")
    _git(repository, "add", "linked.py")

    with pytest.raises(ConfigurationError, match="symlink"):
        git_index_identity(repository)


def test_committed_tree_rejects_symlinks(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "linked.py").symlink_to("apps/application/package.json")
    _git(repository, "add", "linked.py")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "symlink",
    )

    with pytest.raises(ConfigurationError, match="symlink"):
        load_repository_snapshot(repository)


@pytest.mark.parametrize(
    ("evidence", "content"),
    [
        pytest.param("package-lock.json", "\n", id="newline-lock"),
        pytest.param("index.js", "// ownership decoy\n", id="line-comment-entrypoint"),
        pytest.param("index.mjs", "/* ownership decoy */\n", id="block-comment-entrypoint"),
        pytest.param("uv.lock", "# ownership decoy\n", id="hash-comment-lock"),
        pytest.param("main.py", "# ownership decoy\n", id="python-comment-entrypoint"),
    ],
)
def test_exact_tree_marks_comment_only_ownership_evidence_insubstantial(
    tmp_path: Path, evidence: str, content: str
) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "package.json").write_text('{"private":true}', encoding="utf-8")
    package = repository / "packages" / "fake"
    package.mkdir()
    manifest = "package.json" if evidence.endswith((".js", ".mjs", ".json")) else "pyproject.toml"
    manifest_content = (
        '{"name":"fake"}' if manifest == "package.json" else '[project]\nname="fake"\n'
    )
    (package / manifest).write_text(manifest_content, encoding="utf-8")
    (package / evidence).write_text(content, encoding="utf-8")
    verifier = "src/verify-plan.mjs" if manifest == "package.json" else "src/verify_plan.py"
    (package / "src").mkdir()
    (package / verifier).write_text("export {}\n", encoding="utf-8")
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
        "evidence",
    )

    snapshot = load_repository_snapshot(repository)
    tracked = next(
        item for item in snapshot.inspection.tracked_files if item.path.endswith(evidence)
    )

    assert not tracked.substantive
    assert [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.path == f"packages/fake/{verifier}"
    ] == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize(
    ("tree_mode", "evidence", "content"),
    [
        pytest.param("committed", "package-lock.json", " " * 1_048_577, id="committed-lock"),
        pytest.param(
            "staged",
            "index.mjs",
            f"/*{' ' * 1_048_573}*/",
            id="staged-entrypoint",
        ),
    ],
)
def test_oversized_ownership_decoys_fail_closed_in_the_exact_tree(
    tmp_path: Path,
    tree_mode: Literal["committed", "staged"],
    evidence: str,
    content: str,
) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "package.json").write_text('{"private":true}', encoding="utf-8")
    package = repository / "packages" / "fake"
    package.mkdir()
    (package / "package.json").write_text('{"name":"fake"}', encoding="utf-8")
    (package / evidence).write_text(content, encoding="utf-8")
    (package / "src").mkdir()
    verifier = package / "src" / "verify-plan.mjs"
    verifier.write_text("export {}\n", encoding="utf-8")
    _git(repository, "add", ".")
    identity = git_index_identity(repository) if tree_mode == "staged" else None
    if tree_mode == "committed":
        _git(
            repository,
            "-c",
            "user.name=Repository Lint",
            "-c",
            "user.email=repository-lint@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "oversized ownership decoy",
        )
    (package / evidence).write_text("substantive dirty bytes\n", encoding="utf-8")

    snapshot = load_repository_snapshot(repository, identity=identity)
    tracked = next(
        item for item in snapshot.inspection.tracked_files if item.path.endswith(evidence)
    )

    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.issues == ()
    assert not tracked.substantive
    assert [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.path == "packages/fake/src/verify-plan.mjs"
    ] == [RuleId("repository/artifacts/bespoke-iac-verifiers")]


@pytest.mark.parametrize("ownership", ["workspace", "entrypoint"])
def test_oversized_lock_does_not_brick_independently_owned_package(
    tmp_path: Path, ownership: Literal["workspace", "entrypoint"]
) -> None:
    repository = _committed_repository(tmp_path)
    if ownership == "entrypoint":
        (repository / "package.json").write_text('{"private":true}', encoding="utf-8")
    relative_package = "packages/owned" if ownership == "workspace" else "vendor/owned"
    package_root = repository / relative_package
    package_root.mkdir(parents=True)
    (package_root / "package.json").write_text('{"name":"owned"}', encoding="utf-8")
    oversized_lock = package_root / "package-lock.json"
    oversized_lock.write_text(" " * 1_048_577, encoding="utf-8")
    if ownership == "entrypoint":
        (package_root / "index.mjs").write_text("export {}\n", encoding="utf-8")
    (package_root / "src").mkdir()
    verifier = package_root / "src" / "verify-plan.mjs"
    verifier.write_text("export {}\n", encoding="utf-8")
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
        "large legitimate lockfile",
    )

    snapshot = load_repository_snapshot(repository)
    lock_evidence = next(
        item
        for item in snapshot.inspection.tracked_files
        if item.path == oversized_lock.relative_to(repository).as_posix()
    )

    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.issues == ()
    assert not lock_evidence.substantive
    assert [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.path == verifier.relative_to(repository).as_posix()
    ] == []


def test_unrelated_oversized_blob_does_not_affect_inspection(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    unrelated = repository / "assets" / "payload.txt"
    unrelated.parent.mkdir()
    unrelated.write_text("x" * 1_048_577, encoding="utf-8")
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
        "unrelated large blob",
    )

    snapshot = load_repository_snapshot(repository)

    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.issues == ()


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
    assert tuple(rule.rule_id for rule in core_rules()) == ("repository/migration/consistency",)


def test_migration_diagnostics_verify_tree_and_workspace_state(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(source="apps/application", target="applications/alpha/api")
    (repository / ".repo-standards" / "repository.toml").write_bytes(manifest)
    (repository / "applications" / "alpha" / "api").mkdir(parents=True)
    (repository / "applications" / "alpha" / "api" / "package.json").write_text(
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
        "repository/migration/consistency",
        "repository/migration/consistency",
    ]
    assert diagnostics[0].observed_value == {
        "count": 25,
        "paths": [f"apps/application/legacy-{index:02d}.txt" for index in range(20)],
        "truncated": True,
    }


def test_migration_target_must_exist_in_selected_tree(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(source="apps/application", target="applications/alpha/api")
    (repository / ".repo-standards" / "repository.toml").write_bytes(manifest)
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
        "repository/migration/consistency",
        "repository/migration/consistency",
    ]


def test_workspace_rule_ignores_packages_that_were_never_members(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="external/application", target="applications/alpha/api"
    )
    (repository / ".repo-standards" / "repository.toml").write_bytes(manifest)
    (repository / "applications" / "alpha" / "api").mkdir(parents=True)
    (repository / "applications" / "alpha" / "api" / "package.json").write_text(
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
    (repository / ".repo-standards" / "repository.toml").write_bytes(
        _manifest_with_migration(source="apps/application", target="applications/alpha/api")
    )
    (repository / "apps" / "application" / "package.json").unlink()
    (repository / "applications" / "alpha" / "api").mkdir(parents=True)
    (repository / "applications" / "alpha" / "api" / "package.json").write_text(
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
        source="apps/application", target="applications/alpha/api"
    ).replace(
        b"\n[[migration_paths]]",
        b"""\n[[components]]
id = "compatibility"
kind = "service"
path = "apps/application"
owner = "@example/alpha"

[[migration_paths]]""",
    )
    (repository / ".repo-standards" / "repository.toml").write_bytes(manifest)
    (repository / "applications" / "alpha" / "api").mkdir(parents=True)
    (repository / "applications" / "alpha" / "api" / "marker.txt").write_text(
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


def test_install_artifacts_are_not_a_migration_policy(
    tmp_path: Path,
) -> None:
    repository = _committed_repository(tmp_path)
    (repository / ".repo-standards" / "repository.toml").write_bytes(
        _manifest_with_migration(source="apps/application", target="applications/alpha/api")
    )
    (repository / "applications" / "alpha" / "api").mkdir(parents=True)
    (repository / "applications" / "alpha" / "api" / "marker.txt").write_text(
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
    assert all(item.subject_kind != "tracked-install-artifacts" for item in diagnostics)


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


def test_multiple_consistent_declared_moves_are_allowed(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = _manifest_with_migration(
        source="apps/application", target="applications/alpha/api"
    ).replace(
        b"\n[[migration_paths]]",
        b"""\n[[components]]
id = "worker"
kind = "service"
path = "applications/alpha/worker"
owner = "@example/alpha"

[[migration_paths]]""",
    )
    manifest += b"""\n[[migration_paths]]
component_id = "worker"
from = "apps/worker"
to = "applications/alpha/worker"
"""
    (repository / ".repo-standards" / "repository.toml").write_bytes(manifest)
    for component in ("api", "worker"):
        target = repository / "applications" / "alpha" / component / "marker.txt"
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
    assert all(item.subject_kind != "migration-batch" for item in diagnostics)
