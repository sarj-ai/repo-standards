from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.models import FindingsReport, FixtureId
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE = "repository/documentation/added-markdown"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    return subprocess.run(
        (executable, "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


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
    (tmp_path / ".repo-standards").mkdir()
    (tmp_path / ".repo-standards/repository.toml").write_text(_MANIFEST)
    (tmp_path / "README.md").write_text("Canonical guide\n")
    _commit(tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    "path", ["notes.md", "nested/GUIDE.MD", "guide.mdx", "empty.md", "vendor/doc.md", ".hidden.md"]
)
@pytest.mark.parametrize("staged", [False, True])
def test_new_paths_warn_with_exact_comparison(repository: Path, path: str, *, staged: bool) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    target = repository / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("")
    if staged:
        _git(repository, "add", ".")
        target.unlink()
    else:
        _commit(repository)
    report = analyze_repository(
        RepositoryAnalysisRequest(root=repository, base_revision=base, staged=staged)
    )
    assert isinstance(report, FindingsReport)
    assert [(item.rule_id, item.path, item.severity) for item in report.diagnostics] == [
        (_RULE, path, "warning")
    ]
    assert not report.diagnostics[0].baselineable
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_base_revision == base
    assert report.input_provenance.comparison_basis == ("staged" if staged else "explicit")


@pytest.mark.parametrize("change", ["edit", "delete", "untracked", "source", "extension-near-miss"])
def test_existing_edits_and_non_additions_pass(repository: Path, change: str) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    match change:
        case "edit":
            (repository / "README.md").write_text("A materially updated guide\n")
        case "delete":
            (repository / "README.md").unlink()
        case _:
            path = {
                "untracked": "notes.md",
                "source": "module.py",
                "extension-near-miss": "guide.md.py",
            }[change]
            (repository / path).write_text("content\n")
    if change != "untracked":
        _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert report.diagnostics == ()


@pytest.mark.parametrize("operation", ["rename", "copy"])
def test_new_destinations_need_review(repository: Path, operation: str) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "guide.md").write_bytes((repository / "README.md").read_bytes())
    if operation == "rename":
        (repository / "README.md").unlink()
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert [item.path for item in report.diagnostics] == ["guide.md"]


@pytest.mark.parametrize("trusted", [False, True])
def test_only_base_budget_and_exact_exemptions_apply(repository: Path, *, trusted: bool) -> None:
    manifest = repository / ".repo-standards/repository.toml"
    policy = (
        '\n[documentation]\nentrypoints = ["README.md"]\n'
        'maximum_added_pages = 1\naddition_exemptions = ["required.md"]\n'
    )
    if trusted:
        manifest.write_text(_MANIFEST + policy)
        _commit(repository)
    base = _git(repository, "rev-parse", "HEAD")
    manifest.write_text(_MANIFEST + policy)
    for path in ("required.md", "other.md"):
        (repository / path).write_text("Required content\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == (0 if trusted else 1)
    if not trusted:
        assert report.diagnostics[0].observed_value == 2


def test_one_budget_finding_and_branch_base_cover_multiple_commits(repository: Path) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    for path in ("b.md", "a.md"):
        (repository / path).write_text("content\n")
        _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].path == "a.md"
    assert report.diagnostics[0].observed_value == 2


def test_missing_comparison_evidence_is_incomplete(repository: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision="f" * 40))
    assert report.completion == "incomplete"


def test_public_example_executes_the_warning_contract() -> None:
    fixture = FixtureId("sarj-documentation-added-markdown")
    assert run_rule_example(fixture, '{"base":[],"head":["docs/notes.md"]}') == (_RULE,)
    assert run_rule_example(fixture, '{"base":["README.md"],"head":["README.md"]}') == ()
