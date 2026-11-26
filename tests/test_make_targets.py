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


_RULE = "repository/documentation/make-targets"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'
_FILES = {
    "Makefile": "STAMPS := .stamps\ninclude Makedev\n-include .env\n$(STAMPS):\n\tmkdir $@\n",
    "Makedev": "up: | $(STAMPS)\n\t@true\nplan-%:\n\t@true\n",
    "ops/Makefile": (
        "define HELP\nghost: x\nendef\nifeq ($(ENV),prod)\ndeploy:\nendif\n"
        "include $(dir $(lastword $(MAKEFILE_LIST)))Makefile.tf\n"
    ),
    "ops/Makefile.tf": "init \\\n  apply::\n\t@true\n",
    "ops/tests/case.txt": "",
}


def _git(root: Path, *arguments: str) -> None:
    executable = shutil.which("git")
    assert executable is not None
    subprocess.run((executable, "-C", str(root), *arguments), check=True, timeout=10)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".repo-standards").mkdir()
    (tmp_path / ".repo-standards/repository.toml").write_text(_MANIFEST)
    for path, content in _FILES.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text(content)
    return tmp_path


def _missing(repository: Path, **files: str) -> list[tuple[str, str, int | None]]:
    for path, content in files.items():
        (repository / path).parent.mkdir(parents=True, exist_ok=True)
        (repository / path).write_text(content)
    _git(repository, "add", ".")
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
    ("page", "readme", "expected"),
    [
        (
            "README.md",
            (
                "`make up` `ENV=x make plan-prod` `mise exec -- make -j4 up` `make -C ops deploy`\n"
                "```bash\n$ make -C ops init apply && make -Cops tests\n```\n"
            ),
            [],
        ),
        ("ops/README.md", "`make -C . apply` `make apply`\n", []),
        (
            "README.md",
            (
                "`make plan-<env>` `make -f x.mk gone` `make -C $DIR gone`\n"
                "`make -C missing gone` `Native make gone` make gone\n"
                "```text\nmake gone\n```\n```bash\n# make gone\n```\n"
            ),
            [],
        ),
        (
            "docs/run.md",
            "`make -C ops sync`\n```sh\nmake sync\nmake -C ops sync\n```\n",
            [("docs/run.md", "make -C ops sync", 1), ("docs/run.md", "make sync", 3)],
        ),
        ("README.md", "`make ghost`\n", [("README.md", "make ghost", 1)]),
    ],
)
def test_make_commands_name_tracked_targets(
    repository: Path, page: str, readme: str, expected: list[tuple[str, str, int]]
) -> None:
    assert _missing(repository, **{page: readme}) == expected


def test_unresolvable_makefiles_skip_their_commands(repository: Path) -> None:
    readme = "`make -C gen gone` `make gone` `make -C ops gone`\n"
    generated = {"gen/Makefile": "$(eval $(call rules))\n", "README.md": readme}
    assert _missing(repository, **generated) == [("README.md", "make -C ops gone", 1)]


def test_public_example_executes_the_make_target_contract() -> None:
    fixture = FixtureId("sarj-documentation-make-targets")
    source = '{"makefile":"check:\\n","readme":"`make %s`"}'
    assert run_rule_example(fixture, source % "lint") == (_RULE,)
    assert run_rule_example(fixture, source % "check") == ()
