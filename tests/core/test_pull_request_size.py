from __future__ import annotations

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - local Git fixture only
from typing import NamedTuple

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.pull_request_size import analyze_pull_request_size, is_test_path


class RepositoryFixture(NamedTuple):
    path: Path
    base_revision: str


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(repository: Path, message: str) -> str:
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
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> RepositoryFixture:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".gitattributes").write_text(
        "generated/** pr-size-excluded\n",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
    return RepositoryFixture(tmp_path, _commit(tmp_path, "base"))


@pytest.mark.parametrize(
    "path",
    [
        "python/worker/tests/test_worker.py",
        "python/bell/test/test_rpc.py",
        "typescript/app/__tests__/service.ts",
        "typescript/app/src/service.test.ts",
        "scripts/verify.spec.mjs",
        "python/unit_test.py",
        "python/test_unit.py",
        "typescript/app/__snapshots__/service.snap",
    ],
)
def test_test_conventions_are_excluded(path: str) -> None:
    assert is_test_path(path)


@pytest.mark.parametrize(
    "path",
    ["src/contest.py", "src/testimonials.ts", "vitest.config.ts", "migrations/test_data.sql"],
)
def test_test_near_misses_are_counted(path: str) -> None:
    assert not is_test_path(path)


def test_analysis_reports_counted_and_excluded_churn(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    (repository / "src" / "app.py").write_text("value = 2\nextra = 3\n", encoding="utf-8")
    (repository / "tests").mkdir()
    (repository / "tests" / "test_app.py").write_text("assert True\n" * 50, encoding="utf-8")
    (repository / "generated").mkdir()
    (repository / "generated" / "client.py").write_text("generated = True\n" * 40, encoding="utf-8")
    head = _commit(repository, "head")

    result = analyze_pull_request_size(repository, base=base, head=head)

    assert result.counted_lines == 3
    assert result.excluded_lines == 90
    assert result.category_lines() == {"generated": 40, "production": 3, "test": 50}


def test_policy_is_loaded_from_base_not_head(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    (repository / ".gitattributes").write_text("** pr-size-excluded\n", encoding="utf-8")
    (repository / "src" / "new.py").write_text("review_me = True\n", encoding="utf-8")
    head = _commit(repository, "attempt policy bypass")

    result = analyze_pull_request_size(repository, base=base, head=head)

    assert result.counted_lines == 3
    assert {item.path for item in result.files if item.category == "production"} == {
        ".gitattributes",
        "src/new.py",
    }


def test_production_to_test_move_counts_the_deleted_source(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    (repository / "tests").mkdir()
    (repository / "src" / "app.py").rename(repository / "tests" / "test_app.py")
    head = _commit(repository, "move")

    result = analyze_pull_request_size(repository, base=base, head=head)

    assert result.counted_lines == 1
    assert result.category_lines()["test"] == 1


def test_binary_changes_are_reported_but_count_zero(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    (repository / "asset.bin").write_bytes(b"\x00\x01")
    head = _commit(repository, "binary")

    result = analyze_pull_request_size(repository, base=base, head=head)

    assert any(item.category == "binary" for item in result.files)
    assert result.total_lines == 0


def test_invalid_revision_is_incomplete(tmp_path: Path) -> None:
    repository, _base = _repository(tmp_path)

    with pytest.raises(ConfigurationError, match="could not resolve"):
        analyze_pull_request_size(repository, base="missing", head="HEAD")
