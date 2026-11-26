from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.models import FixtureId
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path

    from repo_standards.core.outcome import JSONValue


_RULE = "repository/documentation/markdown-word-growth"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'
_BUDGET = '\n[documentation]\nentrypoints = ["README.md"]\nmaximum_added_words = 10\n'


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
    _git(root, "add", "--all")
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


def _words(count: int) -> str:
    return " ".join(f"word{index}" for index in range(count)) + "\n"


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".repo-standards").mkdir()
    (tmp_path / ".repo-standards/repository.toml").write_text(_MANIFEST)
    (tmp_path / "README.md").write_text(_words(40))
    _commit(tmp_path)
    return tmp_path


def _growth(repository: Path, base: str) -> list[JSONValue]:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert all(item.severity == "warning" and not item.baselineable for item in report.diagnostics)
    return [item.observed_value for item in report.diagnostics]


@pytest.mark.parametrize(
    ("readme", "pages", "expected"),
    [
        (190, {}, []),
        (191, {}, [151]),
        (40, {"docs/guide.mdx": 151, "notes.txt": 500}, [151]),
        (40, {"notes.txt": 500, "guide.md.py": 500}, []),
        (0, {"docs/GUIDE.MD": 190}, []),
        (0, {"docs/GUIDE.MD": 191}, [151]),
    ],
)
def test_net_markdown_words_are_compared_with_the_default_budget(
    repository: Path, readme: int, pages: dict[str, int], expected: list[int]
) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "README.md").write_text(_words(readme))
    for path, count in pages.items():
        (repository / path).parent.mkdir(exist_ok=True)
        (repository / path).write_text(_words(count))
    _commit(repository)
    assert _growth(repository, base) == expected


def test_moved_and_duplicated_content_counts_only_new_copies(repository: Path) -> None:
    (repository / "copy.md").write_text(_words(40))
    base = _commit(repository)
    (repository / "README.md").rename(repository / "docs.md")
    for name in ("a.md", "b.md", "c.md", "d.md"):
        (repository / name).write_text(_words(40))
    _commit(repository)
    assert _growth(repository, base) == [160]


@pytest.mark.parametrize("trusted", [False, True])
def test_only_the_base_manifest_sets_the_budget(repository: Path, *, trusted: bool) -> None:
    manifest = repository / ".repo-standards/repository.toml"
    if trusted:
        manifest.write_text(_MANIFEST + _BUDGET)
        _commit(repository)
    base = _git(repository, "rev-parse", "HEAD")
    manifest.write_text(_MANIFEST + _BUDGET.replace("10", "1000"))
    (repository / "README.md").write_text(_words(51))
    _commit(repository)
    assert _growth(repository, base) == ([11] if trusted else [])


def test_public_example_executes_the_word_budget_contract() -> None:
    fixture = FixtureId("sarj-documentation-markdown-word-growth")
    assert run_rule_example(fixture, '{"added_words":151}') == (_RULE,)
    assert run_rule_example(fixture, '{"added_words":150}') == ()


@pytest.mark.parametrize("trusted", [False, True])
def test_base_declared_generated_documentation_is_outside_both_budgets(
    repository: Path, *, trusted: bool
) -> None:
    manifest = repository / ".repo-standards/repository.toml"
    rules = f'"{_RULE}", "repository/documentation/added-markdown"'
    declared = _MANIFEST.replace(f'"{_RULE}"', rules) + (
        '\n[documentation]\nentrypoints = ["README.md"]\n\n[[documentation.generated]]\n'
        'path = "docs/sdk"\nsource = "openapi.json"\ncommand = "make sdk"\n'
    )
    if trusted:
        manifest.write_text(declared)
        _commit(repository)
    base = _git(repository, "rev-parse", "HEAD")
    manifest.write_text(declared)
    (repository / "docs/sdk").mkdir(parents=True)
    (repository / "docs/sdk/models.md").write_text(_words(500))
    (repository / "docs/sdk-notes.md").write_text(_words(5))
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert [(item.rule_id, item.observed_value) for item in report.diagnostics] == (
        [("repository/documentation/added-markdown", 1)]
        if trusted
        else [(_RULE, 505), ("repository/documentation/added-markdown", 2)]
    )
