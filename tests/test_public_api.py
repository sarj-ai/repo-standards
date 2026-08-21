from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess  # ruff: ignore[suspicious-subprocess-import] - isolated import smoke test
import sys

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.pull_request import analyze_pull_request_size
from repo_standards.repository import inspect_repository


def test_root_import_is_lightweight() -> None:
    command = (
        "import sys; import repo_standards; "
        "assert 'typer' not in sys.modules; assert 'pydantic' not in sys.modules"
    )
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed interpreter smoke test
        [
            sys.executable,
            "-c",
            command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr


def test_removed_import_names_and_commands_are_absent() -> None:
    assert importlib.util.find_spec("repo_lint") is None
    assert importlib.util.find_spec("repo_standards.github") is None
    assert importlib.util.find_spec("repo_standards.core.registry") is None

    runner = CliRunner()
    root_help = runner.invoke(app, ["--help"])
    check_help = runner.invoke(app, ["check", "--help"])

    assert root_help.exit_code == check_help.exit_code == 0
    assert "github" not in {command.name for command in app.registered_commands}
    assert "--policy" not in check_help.stdout
    assert "--github-repository" not in check_help.stdout
    assert "--require-github-evidence" not in check_help.stdout


def test_feature_apis_are_explicit() -> None:
    assert callable(analyze_pull_request_size)
    assert callable(inspect_repository)


def test_manifest_rejects_removed_delivery_configuration() -> None:
    manifest = b"""
schema_version = 2
repository_id = "example"
policy = "sarj"
policy_version = 5
components = []

[delivery]
provider = "github"
"""

    with pytest.raises(ValueError, match="unknown fields: delivery"):
        parse_manifest_bytes(manifest)


def test_action_keeps_the_stable_executable() -> None:
    action = Path(__file__).parents[1] / "action.yml"
    assert "repo-standards pull-request size" in action.read_text(encoding="utf-8")
