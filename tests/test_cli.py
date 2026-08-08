"""CLI contract tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import validate

from repo_lint_cli.main import main


def _manifest(root: Path, text: str) -> None:
    policy_directory = root / ".repo-lint"
    policy_directory.mkdir()
    (policy_directory / "repository.toml").write_text(text, encoding="utf-8")


def _run(arguments: list[str]) -> int:
    with pytest.raises(SystemExit) as caught:
        main(arguments)
    code = caught.value.code
    assert isinstance(code, int)
    return code


GOOD_MANIFEST = """
schema_version = 1
repository_id = "example-repository"
policy = "sarj"
policy_version = 1

[[components]]
id = "platform.agent"
kind = "application"
product = "platform"
path = "products/platform/components/agent"
owner = "@example/platform"
"""


def test_report_json_is_one_deterministic_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    first_code = _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"])
    first = capsys.readouterr().out
    second_code = _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"])
    second = capsys.readouterr().out
    assert first_code == second_code == 0
    assert first == second
    assert json.loads(first)["conclusion"] == "passed"


def test_report_findings_are_nonblocking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("products/platform/components/agent", "python/agent"))
    code = _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["conclusion"] == "findings"
    assert report["diagnostics"][0]["rule_id"] == "sarj/layout/component-path"
    assert report["diagnostics"][0]["remediation"]["auto_applicable"] is False


def test_strict_errors_block(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _manifest(tmp_path, GOOD_MANIFEST.replace("products/platform/components/agent", "python/agent"))
    code = _run(
        ["check", str(tmp_path), "--policy", "sarj", "--mode", "strict", "--format", "json"]
    )
    capsys.readouterr()
    assert code == 1


def test_malformed_manifest_is_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _manifest(tmp_path, "schema_version = 1\nunknown = true\n")
    code = _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["completion"] == "incomplete"
    assert report["conclusion"] == "inconclusive"


def test_schema_is_machine_discoverable(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["properties"]["schema_version"]["const"] == 1


def test_report_validates_against_published_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    assert _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert _run(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    validate(instance=report, schema=schema)


def test_neutral_core_contains_no_sarj_policy_vocabulary() -> None:
    core = Path(__file__).parents[1] / "packages" / "core" / "src" / "repo_lint_core"
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(core.glob("*.py"))
    ).casefold()
    assert "sarj" not in source
    assert "najm" not in source
    assert '"platform"' not in source


def test_manifest_symlink_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text(GOOD_MANIFEST, encoding="utf-8")
    policy_directory = tmp_path / ".repo-lint"
    policy_directory.mkdir()
    os.symlink(outside, policy_directory / "repository.toml")
    code = _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert "symlink" in report["execution_issues"][0]


def test_repository_code_is_not_executed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _manifest(tmp_path, GOOD_MANIFEST)
    marker = tmp_path / "must-not-exist"
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": f"touch {marker}"}}), encoding="utf-8"
    )
    assert _run(["check", str(tmp_path), "--policy", "sarj", "--format", "json"]) == 0
    capsys.readouterr()
    assert not marker.exists()
