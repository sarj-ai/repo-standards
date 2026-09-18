from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from repo_standards.cli import app


if TYPE_CHECKING:
    from pathlib import Path


runner = CliRunner()


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )
    return completed.stdout.decode().strip()


def _commit(repository: Path) -> str:
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path, *, maximum: int = 1, exemptions: tuple[str, ...] = ()) -> str:
    _git(tmp_path, "init", "--quiet")
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.parent.mkdir()
    exempt_line = (
        "addition_exemptions = [" + ", ".join(f'"{path}"' for path in exemptions) + "]\n"
        if exemptions
        else ""
    )
    manifest.write_text(
        'schema_version = 6\nrepository_id = "fixture"\ncomponents = []\n'
        '[documentation]\nentrypoints = ["README.md"]\n'
        f"maximum_added_pages = {maximum}\n{exempt_line}",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    return _commit(tmp_path)


def test_documentation_budget_rejects_multiple_new_pages(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "one.md").write_text("# One\n", encoding="utf-8")
    (docs / "two.mdx").write_text("# Two\n", encoding="utf-8")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", "json"],
    )

    assert result.exit_code == 1
    assert '"added_pages":2' in result.stdout
    assert '"docs/one.md"' in result.stdout
    assert '"docs/two.mdx"' in result.stdout


def test_documentation_budget_uses_trusted_base_policy_and_exact_exemptions(
    tmp_path: Path,
) -> None:
    base = _repository(tmp_path, maximum=0, exemptions=("docs/contract.md",))
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "contract.md").write_text("# Contract\n", encoding="utf-8")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", "json"],
    )

    assert result.exit_code == 0
    assert '"added_pages":0' in result.stdout
    assert '"exempt_pages":1' in result.stdout


def test_documentation_budget_does_not_count_pure_renames(tmp_path: Path) -> None:
    base = _repository(tmp_path, maximum=0)
    _git(tmp_path, "mv", "README.md", "GUIDE.md")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", "json"],
    )

    assert result.exit_code == 0
    assert '"added_pages":0' in result.stdout
