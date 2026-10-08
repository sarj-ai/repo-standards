from __future__ import annotations

import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

import test_selection
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


def test_distribution_verifier_uses_its_complete_delivery_cohort(repository: Path) -> None:
    expected = {
        "tests/test_release_distributions.py",
        "tests/test_release_site_contract.py",
        "tests/test_distribution_fast_paths.py",
        "tests/test_public_api.py",
        "tests/test_public_content.py",
        "tests/test_test_selection.py",
    }
    for name in expected:
        (repository / name).write_text("pass\n")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "contracts",
    )
    source = repository / "src/repo_standards/verify_release_artifacts.py"
    source.parent.mkdir(parents=True)
    source.write_text("changed\n")
    plan = select_tests(repository, base="HEAD")
    assert set(plan.tests) == expected
    assert len(plan.tests) < plan.total_files


@pytest.mark.parametrize("dependency_change", [False, True])
def test_version_only_release_retains_cohort_but_dependency_changes_run_full(
    repository: Path, dependency_change: bool
) -> None:
    required = {
        "tests/test_public_api.py",
        "tests/test_release_distributions.py",
        "tests/test_catalog.py",
        "tests/test_cli.py",
    }
    for path in required:
        (repository / path).write_text("pass\n")
    project = repository / "pyproject.toml"
    lock = repository / "uv.lock"
    project.write_text(
        '[project]\nname="repo-standards"\nversion="1.0.0"\ndependencies=["example==1"]\n'
    )
    lock.write_text('[[package]]\nname="repo-standards"\nversion="1.0.0"\nsource={editable="."}\n')
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "release",
    )
    project.write_text(project.read_text().replace("1.0.0", "1.0.1"))
    lock.write_text(lock.read_text().replace("1.0.0", "1.0.1"))
    (repository / "ci_artifacts.py").write_text("changed\n")
    if dependency_change:
        project.write_text(project.read_text().replace("example==1", "example==2"))
    plan = select_tests(repository, base="HEAD")
    if dependency_change:
        assert len(plan.tests) == plan.total_files
    else:
        assert set(plan.tests) == required | {
            "tests/test_ci_artifacts.py",
            "tests/test_public_content.py",
            "tests/test_test_selection.py",
        }
        assert len(plan.tests) < plan.total_files


@pytest.mark.parametrize(
    "source",
    [
        "broken TOML",
        '[[package]]\nname="repo-standards"\nversion="1"\nsource={registry="https://pypi.org/simple"}\n',
    ],
)
def test_bad_version_evidence_runs_full(repository: Path, source: str) -> None:
    (repository / "uv.lock").write_text(source)
    plan = select_tests(repository, base="HEAD")
    assert len(plan.tests) == plan.total_files


@pytest.mark.parametrize(
    ("files", "jobs", "parallel"), [(6, 2, False), (8, 2, True), (8, 1, False)]
)
def test_worker_startup_is_avoided_for_small_or_serial_plans(
    monkeypatch: pytest.MonkeyPatch, files: int, jobs: int, parallel: bool
) -> None:
    plan = test_selection.TestPlan(
        tuple(f"tests/test_{i}.py" for i in range(files)), "fixture", files
    )

    def select(_root: Path, *, base: str = "") -> test_selection.TestPlan:
        assert not base
        return plan

    monkeypatch.setattr(test_selection, "select_tests", select)
    calls: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["test_selection.py", "--run", "--jobs", str(jobs)])
    assert test_selection.main() == 0
    assert ("-n" in calls[0]) is parallel
