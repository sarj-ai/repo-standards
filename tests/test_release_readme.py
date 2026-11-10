from __future__ import annotations

from importlib.metadata import version
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from release_readme import app, render_package_readme
from release_reconciliation import ReleaseStateError


SOURCE_SHA = "b" * 40
VERSION = "3.0.0"


def test_short_readme_gets_one_exact_release_pin_without_repeating_it() -> None:
    source = "# Repo Standards\n\nUse the site for setup.\n"
    rendered = render_package_readme(source, source_sha=SOURCE_SHA, version=VERSION)
    assert rendered.startswith(source)
    assert rendered.count(f"uses: sarj-ai/repo-standards@{SOURCE_SHA} # v{VERSION}") == 1
    assert render_package_readme(rendered, source_sha=SOURCE_SHA, version=VERSION) == rendered


@pytest.mark.parametrize(
    "source",
    [
        "- uses: sarj-ai/repo-standards@main\n",
        "- uses: SARJ-AI/REPO-STANDARDS@main\n",
        "- uses: sarj-ai/repo-standards@main # v2.0.0\n" * 2,
    ],
)
def test_malformed_and_duplicate_existing_pins_are_rejected(source: str) -> None:
    with pytest.raises(ReleaseStateError, match="exactly one"):
        render_package_readme(source, source_sha=SOURCE_SHA, version=VERSION)


@pytest.mark.parametrize(
    ("source_sha", "release_version"), [("main", VERSION), (SOURCE_SHA, "latest")]
)
def test_generated_pins_require_an_exact_commit_and_version(
    source_sha: str, release_version: str
) -> None:
    with pytest.raises(ReleaseStateError):
        render_package_readme("# Repo Standards\n", source_sha=source_sha, version=release_version)


def test_workflow_command_renders_the_tracked_readme_with_the_project_version(
    tmp_path: Path,
) -> None:
    readme = tmp_path / "README.md"
    source = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    readme.write_text(source, encoding="utf-8")
    result = CliRunner().invoke(app, ["--readme", str(readme), "--source-sha", SOURCE_SHA])
    assert result.exit_code == 0, result.output
    assert (
        readme.read_text(encoding="utf-8").count(
            f"uses: sarj-ai/repo-standards@{SOURCE_SHA} # v{version('repo-standards')}"
        )
        == 1
    )


def test_saved_tooling_can_render_an_older_checkout_without_the_new_helper(tmp_path: Path) -> None:
    tooling = tmp_path / "tooling"
    tooling.mkdir()
    root = Path(__file__).parents[1]
    for name in ("release_readme.py", "release_reconciliation.py"):
        shutil.copyfile(root / name, tooling / name)
    checkout = tmp_path / "release"
    checkout.mkdir()
    readme = checkout / "README.md"
    readme.write_text("- uses: sarj-ai/repo-standards@main # v2.0.0\n", encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(tooling / "release_readme.py"),
            "--readme",
            str(readme),
            "--source-sha",
            SOURCE_SHA,
            "--version",
            VERSION,
        ],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert (
        readme.read_text(encoding="utf-8").count(
            f"uses: sarj-ai/repo-standards@{SOURCE_SHA} # v{VERSION}"
        )
        == 1
    )
