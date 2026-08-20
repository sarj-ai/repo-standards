from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).parents[1]
INPUT_KEY = re.compile(r"^  ([a-z][a-z-]+):$", re.MULTILINE)


def _action_source() -> str:
    return (ROOT / "action.yml").read_text(encoding="utf-8")


def test_public_action_is_pull_request_size_only() -> None:
    source = _action_source()
    inputs_block = source.split("inputs:\n", 1)[1].split("outputs:\n", 1)[0]
    assert set(INPUT_KEY.findall(inputs_block)) == {
        "root",
        "base",
        "head",
        "generated-attribute",
        "operation",
        "policy",
        "mode",
        "format",
    }
    assert source.count("repo-standards pull-request size") == 1
    assert "repo-lint check" not in source
    assert "Repository lint rules are disabled pending review" in source
    assert "github.event.pull_request.base.sha" in source
    assert "github.event.pull_request.head.sha" in source


def test_action_uses_locked_non_mutating_environment() -> None:
    serialized = _action_source()
    assert "--locked --no-dev --python 3.12" in serialized
    assert "setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9" in serialized
