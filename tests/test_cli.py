"""CLI contract tests."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate
import pytest
from typer.testing import CliRunner

from repo_lint_cli.main import app


runner = CliRunner()


def _manifest(root: Path, text: str) -> None:
    policy_directory = root / ".repo-lint"
    policy_directory.mkdir()
    (policy_directory / "repository.toml").write_text(text, encoding="utf-8")


def _json_object(value: str) -> dict[str, object]:
    parsed: object = json.loads(value)  # pyright: ignore[reportAny]
    assert isinstance(parsed, dict)
    return {
        key: item
        for key, item in parsed.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _object_list(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    return [
        _object(item)  # pyright: ignore[reportUnknownArgumentType]
        for item in value  # pyright: ignore[reportUnknownVariableType]
    ]


GOOD_MANIFEST = """
schema_version = 1
repository_id = "example-repository"
policy = "sarj"
policy_version = 2

[[components]]
id = "platform.agent"
kind = "application"
product = "platform"
path = "applications/platform/agent"
owner = "@example/platform"
"""


def test_report_json_is_one_deterministic_value(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    first = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    second = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert _json_object(first.stdout)["conclusion"] == "passed"


def test_report_findings_are_nonblocking(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/platform/agent", "python/agent"))
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    assert report["conclusion"] == "findings"
    diagnostics = _object_list(report["diagnostics"])
    assert diagnostics[0]["rule_id"] == "sarj/layout/component-path"
    remediation = _object(diagnostics[0]["remediation"])
    assert remediation["steps"]
    assert remediation["validation"]


def test_text_diagnostics_do_not_invent_source_coordinates(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/platform/agent", "python/agent"))
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "text"])
    assert result.exit_code == 0
    assert ":1:1:" not in result.stdout
    assert "anchor=components.platform.agent.path" in result.stdout


def test_strict_errors_block(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("applications/platform/agent", "python/agent"))
    result = runner.invoke(
        app, ["check", str(tmp_path), "--policy", "sarj", "--mode", "strict", "--format", "json"]
    )
    assert result.exit_code == 1


def test_strict_operational_layout_guidance_is_nonblocking(tmp_path: Path) -> None:
    operational_manifest = GOOD_MANIFEST.replace(
        '''id = "platform.agent"
kind = "application"
product = "platform"
path = "applications/platform/agent"''',
        '''id = "platform.terraform"
kind = "terraform-root"
product = "platform"
path = "iac/platform"''',
    )
    _manifest(tmp_path, operational_manifest)
    result = runner.invoke(
        app, ["check", str(tmp_path), "--policy", "sarj", "--mode", "strict", "--format", "json"]
    )
    report = _json_object(result.stdout)
    assert result.exit_code == 0
    diagnostics = _object_list(report["diagnostics"])
    assert diagnostics[0]["rule_id"] == "sarj/layout/operational-path"
    assert diagnostics[0]["severity"] == "warning"


def test_malformed_manifest_is_incomplete(tmp_path: Path) -> None:
    _manifest(tmp_path, "schema_version = 1\nunknown = true\n")
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 2
    assert report["completion"] == "incomplete"
    assert report["conclusion"] == "inconclusive"


def test_schema_is_machine_discoverable() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    schema = _json_object(result.stdout)
    properties = _object(schema["properties"])
    schema_version = _object(properties["schema_version"])
    assert schema_version["const"] == 1


def test_report_validates_against_published_schema(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    checked = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert checked.exit_code == 0
    report = _json_object(checked.stdout)
    schema_result = runner.invoke(app, ["schema"])
    assert schema_result.exit_code == 0
    schema = _json_object(schema_result.stdout)
    validate(instance=report, schema=schema)


def test_incomplete_report_and_anchor_locations_validate_against_schema(tmp_path: Path) -> None:
    _manifest(tmp_path, "schema_version = 1\nunknown = true\n")
    incomplete = runner.invoke(
        app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"]
    )
    schema_result = runner.invoke(app, ["schema"])
    validate(instance=_json_object(incomplete.stdout), schema=_json_object(schema_result.stdout))

    policy_directory = tmp_path / ".repo-lint"
    (policy_directory / "repository.toml").write_text(
        GOOD_MANIFEST.replace("applications/platform/agent", "python/agent"),
        encoding="utf-8",
    )
    findings = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    diagnostic = _object_list(_json_object(findings.stdout)["diagnostics"])[0]
    location = _object(diagnostic["location"])
    assert location["path"] == "python/agent"
    assert location["manifest_anchor"] == "components.platform.agent.path"
    assert "start" not in location


def test_neutral_core_contains_no_sarj_policy_vocabulary() -> None:
    core = Path(__file__).parents[1] / "packages" / "core" / "src" / "repo_lint_core"
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(core.glob("*.py"))
    ).casefold()
    assert "sarj" not in source
    assert "najm" not in source
    assert '"platform"' not in source


def test_manifest_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text(GOOD_MANIFEST, encoding="utf-8")
    policy_directory = tmp_path / ".repo-lint"
    policy_directory.mkdir()
    Path(policy_directory / "repository.toml").symlink_to(outside)
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = _json_object(result.stdout)
    assert result.exit_code == 2
    issues = _object_list(report["execution_issues"])
    assert issues[0]["code"] == "analysis.configuration"
    assert "symlink" in str(issues[0]["message"])


def test_repository_code_is_not_executed(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    marker = tmp_path / "must-not-exist"
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": f"touch {marker}"}}), encoding="utf-8"
    )
    result = runner.invoke(app, ["report", str(tmp_path), "--policy", "sarj", "--format", "json"])
    assert result.exit_code == 0
    assert not marker.exists()


def test_inspect_bootstraps_without_a_repository_manifest() -> None:
    repository = Path(__file__).parents[1]
    result = runner.invoke(app, ["inspect", str(repository)])
    assert result.exit_code == 0
    inspection = _json_object(result.stdout)
    assert inspection["command"] == "inspect"
    assert inspection["completion"] == "complete"
    summary = _object(inspection["summary"])
    assert isinstance(summary["tracked_files"], int)
    assert summary["tracked_files"] > 0


def test_capabilities_are_machine_discoverable() -> None:
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    capabilities = _json_object(result.stdout)
    assert capabilities["schema_version"] == 1
    safety = _object(capabilities["safety"])
    assert safety["repository_code_execution"] is False
    assert safety["mutation"] is False


def test_unknown_policy_is_structured_incomplete(tmp_path: Path) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    result = runner.invoke(
        app,
        ["report", str(tmp_path), "--policy", "missing", "--format", "json"],
    )
    assert result.exit_code == 2
    report = _json_object(result.stdout)
    assert report["completion"] == "incomplete"
    assert report["conclusion"] == "inconclusive"


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(("rules",), id="rules"),
        pytest.param(("explain", "example/rule"), id="explain"),
    ],
)
def test_unknown_policy_is_structured_for_rule_commands(arguments: tuple[str, ...]) -> None:
    result = runner.invoke(app, [*arguments, "--policy", "missing"])
    assert result.exit_code == 2
    payload = _json_object(result.stdout)
    assert payload["completion"] == "incomplete"
