from __future__ import annotations

from pathlib import Path

from pydantic import TypeAdapter
import yaml


ROOT = Path(__file__).parents[1]
ACTION_PATH = ROOT / "documentation" / "action.yml"
OBJECT_MAP = TypeAdapter(dict[str, object])


def test_documentation_action_has_only_revision_and_root_inputs() -> None:
    document = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    inputs = OBJECT_MAP.validate_python(document["inputs"])

    assert set(inputs) == {"root", "base", "head"}


def test_documentation_action_uses_trusted_revisions_and_locked_package() -> None:
    source = ACTION_PATH.read_text(encoding="utf-8")

    assert "github.event.pull_request.base.sha" in source
    assert "github.event.pull_request.head.sha" in source
    assert "pull-request documentation" in source
    assert '--project "$GITHUB_ACTION_PATH/.." --locked --no-dev --python 3.14' in source
    assert "uvx" not in source
