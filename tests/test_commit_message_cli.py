from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic schema codecs preserve the tested wire representation without adding a model envelope.
from typer.testing import CliRunner

from repo_standards.cli import app


if TYPE_CHECKING:
    from pathlib import Path


runner = CliRunner()
OBJECT_MAP = TypeAdapter(dict[str, object])
OBJECT_MAPS = TypeAdapter(list[dict[str, object]])


def test_clean_commit_message_is_silent(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text("feat(api): add search\n\nBody\n")
    result = runner.invoke(app, ["commit-message", str(path)])
    assert result.exit_code == 0
    assert not result.stdout


def test_safe_fix_is_transparent_and_preserves_body(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_bytes(b"FIX : repair cache\r\n\r\nRefs: SARJ-1\r\n")
    result = runner.invoke(app, ["commit-message", "--fix-safe", str(path)])
    content = path.read_bytes()
    assert result.exit_code == 0
    assert "safely normalized" in result.stdout
    assert content == b"fix: repair cache\r\n\r\nRefs: SARJ-1\r\n"


def test_semantic_failure_is_machine_readable_and_blocking(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text("WIP\n")
    result = runner.invoke(app, ["commit-message", str(path), "--format", "json"])
    assert result.exit_code == 1
    payload = OBJECT_MAP.validate_json(result.stdout)
    assert payload["conclusion"] == "findings"
    findings = OBJECT_MAPS.validate_python(payload["findings"])
    summary = OBJECT_MAP.validate_python(payload["summary"])
    assert findings[0]["code"] == "commit-message.invalid-header"
    policy = OBJECT_MAP.validate_python(payload["policy"])
    assert summary["replacement_header"] is None
    assert summary["replacement_message"] is None
    assert policy["safe_fix"] is True
    assert policy["safe_fix_enabled"] is False


def test_invalid_file_is_incomplete() -> None:
    result = runner.invoke(app, ["commit-message", "missing", "--format", "json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["completion"] == "incomplete"


def test_subject_advice_is_explicit_and_preserves_strict_success_and_message_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    original = "[SARJ-1] fix(api): " + "x" * 73 + "\n\nReason.\n\nRefs: SARJ-1\n"
    path.write_text(original)

    ordinary = runner.invoke(app, ["commit-message", str(path)])
    ordinary_json = runner.invoke(app, ["commit-message", str(path), "--format", "json"])
    advised = runner.invoke(app, ["commit-message", str(path), "--advise", "--format", "json"])

    assert ordinary.exit_code == advised.exit_code == 0
    assert not ordinary.stdout
    assert ordinary_json.exit_code == 0
    assert "advisories" not in OBJECT_MAP.validate_json(ordinary_json.stdout)
    payload = OBJECT_MAP.validate_json(advised.stdout)
    assert payload["conclusion"] == "passed"
    assert OBJECT_MAP.validate_python(payload["summary"])["satisfied"] is True
    assert payload["findings"] == []
    assert [item["code"] for item in OBJECT_MAPS.validate_python(payload["advisories"])] == [
        "subject.too-long"
    ]
    assert path.read_text() == original


def test_subject_advice_does_not_replace_a_strict_syntax_failure(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text("feature: " + "x" * 100)

    result = runner.invoke(app, ["commit-message", str(path), "--advise", "--format", "json"])

    assert result.exit_code == 1
    payload = OBJECT_MAP.validate_json(result.stdout)
    assert payload["advisories"] == []
    findings = OBJECT_MAPS.validate_python(payload["findings"])
    assert findings[0]["code"] == "commit-message.invalid-header"
