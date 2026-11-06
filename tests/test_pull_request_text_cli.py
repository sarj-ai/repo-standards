from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- test the generic CLI wire representation without a second report model.
import pytest
from typer.testing import CliRunner

from repo_standards.cli import app


if TYPE_CHECKING:
    from pathlib import Path


runner = CliRunner()
OBJECT_MAP = TypeAdapter(dict[str, object])
OBJECT_MAPS = TypeAdapter(list[dict[str, object]])


@pytest.mark.parametrize(
    ("body", "warnings"),
    [
        pytest.param("", [], id="self-evident-empty-body"),
        pytest.param("x" * 500, [], id="prose-at-budget"),
        pytest.param("x" * 501, ["body_prose_too_long"], id="prose-over-budget"),
        pytest.param(
            "```text\n" + "x" * 1989 + "\n```",
            ["body_too_long"],
            id="raw-budget-includes-code",
        ),
        pytest.param(
            "```\nvalue = 1\n```",
            ["body_code_example_invalid"],
            id="untyped-example",
        ),
        pytest.param(
            "Fix retry exhaustion.\n\n```diff\n-retries = 0\n+retries = 2\n```",
            [],
            id="compact-typed-example",
        ),
        pytest.param(
            "<!--" + "x" * 2000 + "-->",
            ["body_too_long"],
            id="hidden-instructions-retain-raw-bound",
        ),
    ],
)
def test_text_preflight_uses_existing_budgets_without_a_git_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, warnings: list[str]
) -> None:
    body_file = tmp_path / "body.txt"
    body_file.write_text(body)
    before = body_file.read_bytes()

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["pull-request", "text", str(body_file), "--format", "json"])

    assert result.exit_code == 0
    payload = OBJECT_MAP.validate_json(result.stdout)
    assert payload["command"] == "pull-request text"
    assert payload["completion"] == "complete"
    assert payload["conclusion"] == ("findings" if warnings else "passed")
    findings = OBJECT_MAPS.validate_python(payload["warnings"])
    assert [finding["code"] for finding in findings] == warnings
    assert all(finding["severity"] == "warning" for finding in findings)
    summary = OBJECT_MAP.validate_python(payload["summary"])
    assert summary["body_characters"] == len(body)
    assert body_file.read_bytes() == before
    assert not (tmp_path / ".git").exists()


@pytest.mark.parametrize("output_format", ["text", "pretty-json"])
def test_text_preflight_explains_how_to_shorten_a_body(tmp_path: Path, output_format: str) -> None:
    body_file = tmp_path / "body.txt"
    body_file.write_text("x" * 501)

    result = runner.invoke(app, ["pull-request", "text", str(body_file), "--format", output_format])

    assert result.exit_code == 0
    assert "body_prose_too_long" in result.stdout
    assert "Link detailed evidence" in result.stdout


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"invalid \xff", id="invalid-utf8"),
        pytest.param(b"x" * 1_048_577, id="oversized-input"),
    ],
)
def test_text_preflight_reports_incomplete_input(tmp_path: Path, content: bytes) -> None:
    body_file = tmp_path / "body.txt"
    body_file.write_bytes(content)

    result = runner.invoke(app, ["pull-request", "text", str(body_file), "--format", "json"])

    assert result.exit_code == 2
    payload = OBJECT_MAP.validate_json(result.stdout)
    assert payload["completion"] == "incomplete"
    assert payload["conclusion"] == "inconclusive"


def test_text_preflight_rejects_a_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["pull-request", "text", str(tmp_path), "--format", "json"])

    assert result.exit_code == 2
    assert OBJECT_MAP.validate_json(result.stdout)["completion"] == "incomplete"


@pytest.mark.parametrize(
    ("title", "warning_codes"),
    [
        pytest.param("[SARJ-123] fix(api): " + "x" * 72, [], id="structural-prefixes"),
        pytest.param("fix(api: v1): " + "x" * 73, ["subject.too-long"], id="colon-in-scope"),
        pytest.param("x" * 73, ["subject.too-long"], id="plain-title"),
        pytest.param("x" * 72 + " (GH-123)", [], id="plain-title-reference"),
        pytest.param(
            "fix: " + "x" * 73 + " (#123)",
            ["subject.too-long"],
            id="long-description-with-reference",
        ),
    ],
)
def test_text_preflight_can_advise_on_a_proposed_title(
    tmp_path: Path, title: str, warning_codes: list[str]
) -> None:
    body_file = tmp_path / "body.txt"
    body_file.write_text("Fix retry exhaustion.")

    result = runner.invoke(
        app, ["pull-request", "text", str(body_file), "--title", title, "--format", "json"]
    )

    assert result.exit_code == 0
    payload = OBJECT_MAP.validate_json(result.stdout)
    warnings = OBJECT_MAPS.validate_python(payload["warnings"])
    assert [finding["code"] for finding in warnings] == warning_codes


@pytest.mark.parametrize("separator", ["\n", "\r"])
def test_text_preflight_rejects_a_title_with_physical_line_separators(
    tmp_path: Path, separator: str
) -> None:
    body_file = tmp_path / "body.txt"
    body_file.write_text("Fix retry exhaustion.")

    result = runner.invoke(
        app,
        [
            "pull-request",
            "text",
            str(body_file),
            "--title",
            f"First{separator}second",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert OBJECT_MAP.validate_json(result.stdout)["completion"] == "incomplete"
