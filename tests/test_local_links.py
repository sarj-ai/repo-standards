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
    (tmp_path / "docs/my guide.md").write_text(
        "[Home](../README.md)\n[Self](#top)\n# Set `up` & [run](../README.md) #\n"
        '## Set up\n## Set up\nCafé_Notes\n---\n```\n# Fenced\n```\n<a name="legacy"></a>\n'
    )
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
            "[a](docs/my%20guide.md#set-up) [b](<docs/my guide.md>) [c](docs/) [d](./) [e](?q)\n",
            [],
        ),
        (
            "[a](https://example.com) [b](mailto:x@example.invalid) [c](#top) [d](/abs.md)\n",
            [],
        ),
        ("```md\n[a](gone.md)\n```\n`[b](gone.md)`\n~~~~\n```\n[c](gone.md)\n~~~~\n", []),
        ("[^1]: a footnote\n", []),
        ("`[b.md](README.md)`\n", []),
        ("[a](gone.md)\n[b](gone.md)\n", [("README.md", "gone.md", 1)]),
        ('intro\n[ref]: old/page.md "Title"\n', [("README.md", "old/page.md", 2)]),
        ("![logo](logo.png)\n", [("README.md", "logo.png", 1)]),
        ("[a](untracked.md)\n", [("README.md", "untracked.md", 1)]),
        ("[a](../outside.md)\n", [("README.md", "../outside.md", 1)]),
        (
            (
                "[a](docs/my%20guide.md#set-up--run) [b](<docs/my guide.md#Set-Up-1>) "
                "[c](docs/my%20guide.md#café_notes) [d](docs/my%20guide.md#legacy) "
                "[e](docs/my%20guide.md#L3) [f](docs/my%20guide.md?plain=1#x) [g](docs#x)\n"
            ),
            [],
        ),
        (
            "[`ARCH.md`](docs/my%20guide.md#set-up) [README.md](./README.md)\n[y.md](gone.md)\n",
            [("README.md", "docs/my%20guide.md", 1), ("README.md", "gone.md", 2)],
        ),
        (
            "[a](docs/my%20guide.md#fenced)\n[b](README.md#gone)\n",
            [("README.md", "README.md#gone", 2), ("README.md", "docs/my%20guide.md#fenced", 1)],
        ),
    ],
)
def test_relative_links_resolve_against_the_tracked_tree(
    repository: Path, readme: str, expected: list[tuple[str, str, int]]
) -> None:
    assert _broken(repository, readme) == expected


def test_code_spans_naming_a_removed_path_are_reported_on_unchanged_pages(
    repository: Path,
) -> None:
    for path in ("src/app/old.py", "src/app/twin.py", "lib/app/twin.py"):
        (repository / path).parent.mkdir(parents=True, exist_ok=True)
        (repository / path).write_text("")
    _git(repository, "add", "src", "lib")
    readme = (
        "`old.py` `app/twin.py` `run app/old.py`\n```\napp/old.py\n```\n`app/old.py` `app/old.py`\n"
    )
    assert _broken(repository, readme) == []
    _git(repository, "rm", "--quiet", "src/app/old.py", "src/app/twin.py")
    (repository / "docs/my guide.md").write_text("`src/app/old.py` was removed\n")
    assert _broken(repository, readme) == [("README.md", "app/old.py", 5)]


def test_public_example_executes_the_link_contract() -> None:
    fixture = FixtureId("sarj-documentation-local-links")
    tracked = '{"tracked":["docs/guide.md"],"readme":"[Guide](docs/%s.md)"}'
    assert run_rule_example(fixture, tracked % "old") == (_RULE,)
    assert run_rule_example(fixture, tracked % "guide") == ()
