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


_RULE = "repository/documentation/local-links"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'


def _git(root: Path, *arguments: str) -> None:
    executable = shutil.which("git")
    assert executable is not None
    subprocess.run((executable, "-C", str(root), *arguments), check=True, timeout=10)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".repo-standards").mkdir()
    (tmp_path / ".repo-standards/repository.toml").write_text(_MANIFEST)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/my guide.md").write_text("[Home](../README.md)\n[Self](#top)\n")
    (tmp_path / "untracked.md").write_text("on disk only\n")
    return tmp_path


def _broken(repository: Path, readme: str) -> list[tuple[str, str, int | None]]:
    (repository / "README.md").write_text(readme)
    _git(repository, "add", ".repo-standards", "docs", "README.md")
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    report = analyze_repository(RepositoryAnalysisRequest(root=repository))
    assert report.completion == "complete"
    assert all(item.severity == "warning" for item in report.diagnostics)
    return [
        (item.path, item.observed, item.location.line if item.location else None)
        for item in report.diagnostics
    ]


@pytest.mark.parametrize(
    ("readme", "expected"),
    [
        (
            "[a](docs/my%20guide.md#x) [b](<docs/my guide.md>) [c](docs/) [d](./) [e](?q)\n",
            [],
        ),
        (
            "[a](https://example.com) [b](mailto:x@example.invalid) [c](#top) [d](/abs.md)\n",
            [],
        ),
        ("```md\n[a](gone.md)\n```\n`[b](gone.md)`\n~~~~\n```\n[c](gone.md)\n~~~~\n", []),
        ("[^1]: a footnote\n", []),
        ("[a](gone.md)\n[b](gone.md)\n", [("README.md", "gone.md", 1)]),
        ('intro\n[ref]: old/page.md "Title"\n', [("README.md", "old/page.md", 2)]),
        ("![logo](logo.png)\n", [("README.md", "logo.png", 1)]),
        ("[a](untracked.md)\n", [("README.md", "untracked.md", 1)]),
        ("[a](../outside.md)\n", [("README.md", "../outside.md", 1)]),
    ],
)
def test_relative_links_resolve_against_the_tracked_tree(
    repository: Path, readme: str, expected: list[tuple[str, str, int]]
) -> None:
    assert _broken(repository, readme) == expected


def test_public_example_executes_the_link_contract() -> None:
    fixture = FixtureId("sarj-documentation-local-links")
    tracked = '{"tracked":["docs/guide.md"],"readme":"[Guide](docs/%s.md)"}'
    assert run_rule_example(fixture, tracked % "old") == (_RULE,)
    assert run_rule_example(fixture, tracked % "guide") == ()
