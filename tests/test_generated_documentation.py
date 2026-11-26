from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import FixtureId
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE = "repository/documentation/generated-sources"
_MANIFEST = f"""repository_id = "example"
components = []
enabled_rules = ["{_RULE}"]

[documentation]
entrypoints = ["README.md"]

[[documentation.generated]]
path = "docs/api"
source = "src"
command = "make api-docs"
"""


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


def _write(root: Path, files: dict[str, str | None]) -> None:
    for path, content in files.items():
        target = root / path
        if content is None:
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    _write(
        tmp_path,
        {
            ".repo-standards/repository.toml": _MANIFEST,
            "README.md": "readme\n",
            "src/api.py": "v1\n",
            "docs/api/index.md": "v1\n",
            "docs/api/models.md": "v1\n",
        },
    )
    _commit(tmp_path)
    return tmp_path


def _findings(repository: Path, base: str) -> list[str]:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert all(item.severity == "warning" for item in report.diagnostics)
    return [item.observed for item in report.diagnostics]


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        pytest.param(
            {"docs/api/models.md": "edit\n", "docs/api/index.md": "edit\n"},
            ["docs/api/index.md"],
            id="hand-edit-reports-first-output",
        ),
        pytest.param(
            {"docs/api/models.md": "edit\n", "README.md": "edit\n"},
            ["docs/api/models.md"],
            id="unrelated-change-is-not-source",
        ),
        pytest.param(
            {"docs/api/models.md": "edit\n", "src/api.py": "v2\n"}, [], id="regenerated-with-source"
        ),
        pytest.param(
            {"docs/api/models.md": "edit\n", "src/new.py": "v1\n"}, [], id="added-source-file"
        ),
        pytest.param({"docs/api/models.md": None}, [], id="deleted-output-is-not-an-edit"),
        pytest.param({"src/api.py": "v2\n"}, [], id="source-only-change"),
        pytest.param({"docs/apis.md": "near miss\n"}, [], id="sibling-prefix-near-miss"),
        pytest.param({"src/api.py": None}, ["src"], id="untracked-source"),
        pytest.param(
            {"docs/api/index.md": None, "docs/api/models.md": None},
            ["docs/api"],
            id="untracked-output",
        ),
    ],
)
def test_generated_output_changes_only_with_its_source(
    repository: Path, change: dict[str, str | None], expected: list[str]
) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    _write(repository, change)
    _commit(repository)
    assert _findings(repository, base) == expected


def test_another_generated_output_is_not_a_source_change(repository: Path) -> None:
    _write(
        repository,
        {
            ".repo-standards/repository.toml": _MANIFEST
            + '\n[[documentation.generated]]\npath = "src/generated.md"\n'
            + 'source = "schema.json"\ncommand = "make docs"\n',
            "src/generated.md": "v1\n",
            "schema.json": "{}\n",
        },
    )
    base = _commit(repository)
    _write(repository, {"docs/api/index.md": "edit\n", "src/generated.md": "edit\n"})
    _commit(repository)
    assert _findings(repository, base) == ["docs/api/index.md", "src/generated.md"]


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        pytest.param(
            'path = "docs"\nsource = "docs/src"\ncommand = "x"',
            "must be outside path",
            id="source-inside-path",
        ),
        pytest.param(
            'path = "docs"\nsource = "docs"\ncommand = "x"',
            "must be outside path",
            id="source-equals-path",
        ),
        pytest.param(
            'path = "docs"\nsource = "src"', "missing fields: command", id="missing-command"
        ),
        pytest.param(
            'path = "./docs"\nsource = "src"\ncommand = "x"',
            "exact canonical Git path",
            id="non-canonical-path",
        ),
        pytest.param(
            'path = "docs/api"\nsource = "lib"\ncommand = "x"',
            "duplicate paths",
            id="duplicate-path",
        ),
    ],
)
def test_invalid_declarations_are_rejected(entry: str, error: str) -> None:
    manifest = f"{_MANIFEST}\n[[documentation.generated]]\n{entry}\n"
    with pytest.raises(ConfigurationError, match=error):
        parse_manifest_bytes(manifest.encode())


def test_public_example_executes_the_generated_source_contract() -> None:
    fixture = FixtureId("sarj-documentation-generated-sources")
    assert run_rule_example(fixture, '{"changed":["docs/api.md"]}') == (_RULE,)
    assert run_rule_example(fixture, '{"changed":["docs/api.md","openapi.json"]}') == ()
