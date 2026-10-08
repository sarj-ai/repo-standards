from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from test_selection import select_tests


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    for name in ["test_public_content", "test_test_selection", "test_alpha", "test_ci_artifacts"]:
        path = tmp_path / "tests" / f"{name}.py"
        path.parent.mkdir(exist_ok=True)
        path.write_text("pass\n")
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "add", ".")
    _git(
        tmp_path,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return tmp_path


def _git(root: Path, *args: str) -> None:
    subprocess.run((shutil.which("git") or "git", *args), cwd=root, check=True, capture_output=True)


def test_changed_test_cohort_includes_uncommitted_work_and_public_contracts(
    repository: Path,
) -> None:
    (repository / "tests/test_alpha.py").write_text("changed\n")
    plan = select_tests(repository, base="HEAD")
    assert plan.tests == (
        "tests/test_alpha.py",
        "tests/test_public_content.py",
        "tests/test_test_selection.py",
    )
    assert plan.total_files == 4


@pytest.mark.parametrize(
    "path",
    [
        "src/changed.py",
        "tests/conftest.py",
        "pyproject.toml",
        "README.md",
        "tests/test_test_selection.py",
    ],
)
def test_shared_and_unclassified_changes_fall_back_to_all_tests(
    repository: Path, path: str
) -> None:
    changed = repository / path
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("changed\n")
    plan = select_tests(repository, base="HEAD")
    assert len(plan.tests) == plan.total_files
    assert "unclassified" in plan.reason


@pytest.mark.parametrize("base", ["", "missing-ref", "--help", "HEAD;false"])
def test_missing_or_invalid_git_evidence_runs_every_test(repository: Path, base: str) -> None:
    plan = select_tests(repository, base=base)
    assert len(plan.tests) == plan.total_files


def test_deletions_run_every_test(repository: Path) -> None:
    (repository / "tests/test_alpha.py").unlink()
    plan = select_tests(repository, base="HEAD")
    assert len(plan.tests) == plan.total_files
    assert "deletion" in plan.reason


def test_release_tool_cohort_is_selected_and_new_test_is_not_lost(repository: Path) -> None:
    (repository / "ci_artifacts.py").write_text("changed\n")
    (repository / "tests/test_new.py").write_text("new\n")
    plan = select_tests(repository, base="HEAD")
    assert plan.tests == (
        "tests/test_ci_artifacts.py",
        "tests/test_new.py",
        "tests/test_public_content.py",
        "tests/test_test_selection.py",
    )


def test_missing_required_documentation_contract_falls_back_to_full(repository: Path) -> None:
    path = repository / "apps/docs/new.ts"
    path.parent.mkdir(parents=True)
    path.write_text("changed\n")
    plan = select_tests(repository, base="HEAD")
    assert len(plan.tests) == plan.total_files
    assert "missing" in plan.reason
