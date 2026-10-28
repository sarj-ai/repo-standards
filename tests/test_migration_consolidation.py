from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE = "repository/artifacts/migration-consolidation"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(
        (executable, "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _write(root: Path, path: str, content: str = "SELECT 1;\n") -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def _commit(root: Path) -> str:
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    _write(tmp_path, ".repo-standards/repository.toml", _MANIFEST)
    _commit(tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (("db/migrations/001.sql", "db/migrations/002.sql"), 1),
        (("db/migrations/001.sql",), 0),
        (("db/migrations/001.up.sql", "db/migrations/001.down.sql"), 0),
        (("db/migrations/up/001.sql", "db/migrations/down/001.sql"), 0),
        (("db/migrations/001.up.sql", "db/migrations/002.up.sql"), 1),
        (("db/migrations/V001__add.sql", "db/migrations/U1__add.sql"), 0),
        (("db/migrations/V001__add.sql", "db/migrations/U1.0__add.sql"), 0),
        (("db/migrations/V1__add.sql", "db/migrations/V2__other.sql"), 1),
        (("db/migrations/R__first.sql", "db/migrations/R__second.sql"), 0),
        (("prisma/migrations/001/migration.sql", "prisma/migrations/002/migration.sql"), 1),
        (("a/migrations/001.sql", "b/migrations/002.sql"), 0),
        (("db/migrations-old/001.sql", "db/migrations-old/002.sql"), 0),
        (("db/migrations/001.py", "db/migrations/002.py"), 0),
        (("db/migrations/snapshots/001.sql", "db/migrations/snapshots/002.sql"), 0),
        (("db/migrations/001.sql", "db/migrations/002.json"), 0),
    ],
)
def test_counts_new_logical_sql_revisions_per_stream(
    repository: Path, paths: tuple[str, ...], expected: int
) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    for path in paths:
        _write(repository, path)
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == expected
    if expected:
        assert report.diagnostics[0].severity == "warning"
        assert report.diagnostics[0].observed_value == 2
        assert report.diagnostics[0].expected_value == 1


def test_pr_comparison_covers_all_commits_and_ignores_untracked_files(repository: Path) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    _write(repository, "migrations/001.sql")
    _commit(repository)
    _write(repository, "migrations/002.sql")
    _commit(repository)
    _write(repository, "migrations/003.sql")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].observed_value == 2
    assert {item.location.path for item in report.diagnostics[0].related_locations} == {
        "migrations/001.sql",
        "migrations/002.sql",
    }
    assert analyze_repository(RepositoryAnalysisRequest(root=repository)).diagnostics == ()
    result = CliRunner().invoke(app, ["report", str(repository), "--base", base])
    assert result.exit_code == 0, result.output
    assert _RULE in result.stdout


@pytest.mark.parametrize(
    "prefix",
    [
        "tests",
        "test",
        "testing",
        "__tests__",
        "fixtures",
        "fixture",
        "__fixtures__",
        "testdata",
        "examples",
        "example",
        "vendor",
        "node_modules",
        "generated",
    ],
)
def test_auto_discovery_ignores_nonproduction_migration_paths(
    repository: Path, prefix: str
) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    for name in ("001.sql", "002.sql"):
        _write(repository, f"{prefix}/migrations/{name}")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert report.diagnostics == ()


def test_explicit_migration_root_retains_ownership_in_a_nonproduction_path(
    repository: Path,
) -> None:
    manifest = _MANIFEST.replace("components = []", "") + (
        '\n[[components]]\nid = "db"\nkind = "migration-set"\n'
        'path = "tests/migrations"\nowner = "@example/database"\n'
    )
    _write(repository, ".repo-standards/repository.toml", manifest)
    base = _commit(repository)
    for name in ("001.sql", "002.sql"):
        _write(repository, f"tests/migrations/{name}")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == 1


def test_existing_revisions_and_added_rollback_are_not_new(repository: Path) -> None:
    _write(repository, "migrations/001.up.sql")
    base = _commit(repository)
    _write(repository, "migrations/001.up.sql", "SELECT 2;\n")
    _write(repository, "migrations/001.down.sql")
    _write(repository, "migrations/002.sql")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert report.diagnostics == ()


def test_exact_renames_are_not_new_but_copies_are(repository: Path) -> None:
    _write(repository, "migrations/001.sql")
    base = _commit(repository)
    _git(repository, "mv", "migrations/001.sql", "migrations/002.sql")
    _write(repository, "migrations/003.sql", "SELECT 3;\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.diagnostics == ()
    _write(repository, "migrations/004.sql", "SELECT 3;\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert len(report.diagnostics) == 1


def test_staged_uses_selected_index_and_cannot_be_hidden_by_unstaged_deletions(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected_index = repository / ".git/pending-index"
    monkeypatch.setenv("GIT_INDEX_FILE", str(selected_index))
    _git(repository, "read-tree", "HEAD")
    for path in ("migrations/001.sql", "migrations/002.sql"):
        _write(repository, path)
    _git(repository, "add", ".")
    selected_bytes = selected_index.read_bytes()
    (repository / "migrations/002.sql").unlink()
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert len(report.diagnostics) == 1
    assert selected_index.read_bytes() == selected_bytes


def test_declared_custom_root_is_retained_from_base_manifest(repository: Path) -> None:
    manifest = _MANIFEST.replace("components = []", "") + (
        '\n[[components]]\nid = "db"\nkind = "migration-set"\n'
        'path = "database/changes"\nowner = "@example/database"\n'
    )
    _write(repository, ".repo-standards/repository.toml", manifest)
    base = _commit(repository)
    _write(repository, ".repo-standards/repository.toml", _MANIFEST)
    for path in ("database/changes/001.sql", "database/changes/002.sql"):
        _write(repository, path)
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == 1


def test_missing_base_is_incomplete_only_when_rule_is_enabled(repository: Path) -> None:
    request = RepositoryAnalysisRequest(root=repository, base_revision="f" * 40)
    assert analyze_repository(request).completion == "incomplete"
    _write(
        repository,
        ".repo-standards/repository.toml",
        'repository_id = "example"\ncomponents = []\n',
    )
    _commit(repository)
    assert analyze_repository(request).completion == "complete"


def test_head_parent_root_cannot_hide_a_trusted_child_stream(repository: Path) -> None:
    component = (
        '\n[[components]]\nid = "db"\nkind = "migration-set"\n'
        'path = "database/changes"\nowner = "@example/database"\n'
    )
    manifest = _MANIFEST.replace("components = []", "") + component
    _write(repository, ".repo-standards/repository.toml", manifest)
    base = _commit(repository)
    _write(
        repository,
        ".repo-standards/repository.toml",
        manifest.replace('path = "database/changes"', 'path = "database"'),
    )
    for path in ("database/changes/001.sql", "database/changes/002.sql"):
        _write(repository, path)
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].manifest_anchor == "migration_streams.database/changes"


def test_head_child_roots_cannot_split_a_trusted_prisma_stream(repository: Path) -> None:
    _write(repository, "prisma/migrations/000/migration.sql")
    base = _commit(repository)
    manifest = _MANIFEST.replace("components = []", "")
    for revision in ("001", "002"):
        manifest += (
            f'\n[[components]]\nid = "db-{revision}"\nkind = "migration-set"\n'
            f'path = "prisma/migrations/{revision}"\nowner = "@example/database"\n'
        )
        _write(repository, f"prisma/migrations/{revision}/migration.sql")
    _write(repository, ".repo-standards/repository.toml", manifest)
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].manifest_anchor == "migration_streams.prisma/migrations"


def test_moving_an_existing_stream_does_not_reclassify_history(repository: Path) -> None:
    for path in ("old/migrations/001.sql", "old/migrations/002.sql"):
        _write(repository, path)
    base = _commit(repository)
    _git(repository, "mv", "old", "new")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert report.diagnostics == ()


def test_deleting_then_readding_base_revision_does_not_create_a_new_revision(
    repository: Path,
) -> None:
    _write(repository, "migrations/001.sql")
    base = _commit(repository)
    _git(repository, "rm", "migrations/001.sql")
    _commit(repository)
    _write(repository, "migrations/001.sql", "SELECT 2;\n")
    _write(repository, "migrations/002.sql")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert report.diagnostics == ()


def test_root_commit_and_unborn_index_use_an_empty_base(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    _write(tmp_path, ".repo-standards/repository.toml", _MANIFEST)
    _write(tmp_path, "migrations/001.sql")
    _write(tmp_path, "migrations/002.sql")
    _git(tmp_path, "add", ".")
    staged = analyze_repository(RepositoryAnalysisRequest(root=tmp_path, staged=True))
    assert staged.completion == "complete"
    assert len(staged.diagnostics) == 1
    _commit(tmp_path)
    committed = analyze_repository(RepositoryAnalysisRequest(root=tmp_path))
    assert committed.completion == "complete"
    assert len(committed.diagnostics) == 1
