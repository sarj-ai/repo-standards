from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import NotRequired, TypedDict

from pydantic import TypeAdapter
import pytest
from typer.testing import CliRunner
import yaml

from repo_standards.cli import app
from repo_standards.core.models import Mode
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.pull_request import analyze_pull_request_commits, analyze_pull_request_size
from repo_standards.repository import (
    RepositoryAnalysisRequest,
    analyze_repository,
    inspect_repository,
)


class _ActionStep(TypedDict):
    run: NotRequired[str]


class _ActionRuns(TypedDict):
    steps: list[_ActionStep]


class _ActionDocument(TypedDict):
    runs: _ActionRuns


def test_root_import_is_lightweight() -> None:
    command = (
        "import sys; import repo_standards; "
        "assert 'typer' not in sys.modules; assert 'pydantic' not in sys.modules"
    )
    completed = subprocess.run(
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


@pytest.mark.parametrize(
    "module_name",
    ["repo_lint", "repo_standards.github", "repo_standards.core.registry"],
)
def test_removed_import_name_is_absent(module_name: str) -> None:
    assert importlib.util.find_spec(module_name) is None


def test_removed_commands_are_absent() -> None:

    runner = CliRunner()
    root_help = runner.invoke(app, ["--help"])
    check_help = runner.invoke(app, ["check", "--help"])

    assert root_help.exit_code == check_help.exit_code == 0
    assert "github" not in {command.name for command in app.registered_commands}
    assert "list-rules" not in {command.name for command in app.registered_commands}
    assert "--policy" not in check_help.stdout
    assert "--github-repository" not in check_help.stdout
    assert "--require-github-evidence" not in check_help.stdout


def test_feature_apis_are_explicit() -> None:
    assert callable(analyze_pull_request_commits)
    assert callable(analyze_pull_request_size)
    assert callable(inspect_repository)
    assert callable(analyze_repository)


def test_repository_analysis_api_reports_configuration_failures(tmp_path: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=tmp_path))

    assert report.completion == "incomplete"
    assert report.execution_issues[0].code == "analysis.configuration"


def test_repository_analysis_api_distinguishes_an_absent_selected_manifest(tmp_path: Path) -> None:
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Repository Standards",
            "-c",
            "user.email=repository-standards@example.invalid",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "test: initialize fixture",
        ),
        cwd=tmp_path,
        check=True,
    )

    report = analyze_repository(RepositoryAnalysisRequest(root=tmp_path, staged=True))

    assert report.completion == "incomplete"
    assert report.execution_issues[0].code == "analysis.manifest-absent"


def test_repository_analysis_api_selects_committed_or_staged_tree(tmp_path: Path) -> None:
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.parent.mkdir()
    manifest.write_text(
        'repository_id = "committed"\ncomponents = []\n',
        encoding="utf-8",
    )
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    subprocess.run(("git", "add", "."), cwd=tmp_path, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Repository Standards",
            "-c",
            "user.email=repository-standards@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test: initialize fixture",
        ),
        cwd=tmp_path,
        check=True,
    )
    manifest.write_text(
        'repository_id = "staged"\ncomponents = []\n',
        encoding="utf-8",
    )
    subprocess.run(("git", "add", str(manifest)), cwd=tmp_path, check=True)
    manifest.write_text(
        'repository_id = "unstaged"\ncomponents = []\n',
        encoding="utf-8",
    )

    committed = analyze_repository(RepositoryAnalysisRequest(root=tmp_path))
    staged = analyze_repository(RepositoryAnalysisRequest(root=tmp_path, staged=True))

    assert committed.repository_id == "committed"
    assert staged.repository_id == "staged"
    assert staged.input_provenance is not None
    assert staged.input_provenance.mode == "git-index"


def test_repository_analysis_api_classifies_a_selected_ratchet_baseline(tmp_path: Path) -> None:
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.parent.mkdir()
    manifest.write_text(
        'repository_id = "ratcheted"\ncomponents = []\n',
        encoding="utf-8",
    )
    subprocess.run(("git", "init", "--quiet"), cwd=tmp_path, check=True)
    subprocess.run(("git", "add", "."), cwd=tmp_path, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Repository Standards",
            "-c",
            "user.email=repository-standards@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test: initialize fixture",
        ),
        cwd=tmp_path,
        check=True,
    )
    initial = analyze_repository(RepositoryAnalysisRequest(root=tmp_path))
    baseline = manifest.with_name("baseline.json")
    baseline.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "repository_id": initial.repository_id,
                "policy": initial.policy_id,
                "policy_version": initial.policy_version,
                "scope_digest": initial.scope_digest,
                "fingerprints": [],
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(("git", "add", str(baseline)), cwd=tmp_path, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Repository Standards",
            "-c",
            "user.email=repository-standards@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "test: add baseline",
        ),
        cwd=tmp_path,
        check=True,
    )

    report = analyze_repository(
        RepositoryAnalysisRequest(
            root=tmp_path,
            baseline_path=".repo-standards/baseline.json",
            mode=Mode.RATCHET,
        )
    )

    assert report.completion == "complete"
    assert report.ratchet is not None
    assert report.ratchet.entries == ()


def test_repository_analysis_api_requires_a_ratchet_baseline_path(tmp_path: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=tmp_path, mode=Mode.RATCHET))

    assert report.completion == "incomplete"
    assert "baseline_path" in report.execution_issues[0].message


def test_manifest_rejects_removed_delivery_configuration() -> None:
    manifest = b"""
repository_id = "example"
components = []

[delivery]
provider = "github"
"""

    with pytest.raises(ValueError, match="manifest has unknown fields: delivery"):
        parse_manifest_bytes(manifest)


def test_action_keeps_the_stable_executable() -> None:
    action = Path(__file__).parents[1] / "action.yml"
    document = TypeAdapter(_ActionDocument).validate_python(
        yaml.safe_load(action.read_text(encoding="utf-8"))
    )
    steps = document["runs"]["steps"]
    commands = [step["run"] for step in steps if "run" in step]
    assert sum("repo-standards pull-request size" in command for command in commands) == 1
