from __future__ import annotations

from pathlib import Path

from pydantic import TypeAdapter
import yaml


ROOT = Path(__file__).parents[1]
HOOKS_PATH = ROOT / ".pre-commit-hooks.yaml"
ACTION_PATH = ROOT / "pull-request-commits" / "action.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
OBJECT_MAP = TypeAdapter(dict[str, object])
OBJECT_MAPS = TypeAdapter(list[dict[str, object]])


def test_pull_request_commits_hook_is_quiet_advisory_and_history_scoped() -> None:
    document = OBJECT_MAPS.validate_python(yaml.safe_load(HOOKS_PATH.read_text(encoding="utf-8")))

    assert document == [
        {
            "id": "repo-standards-pull-request-commits",
            "name": "Repo Standards - concise pull-request history",
            "description": (
                "Advises when pull-request history should be squashed or explicitly numbered."
            ),
            "entry": "repo-standards pull-request commits . --advisory --quiet",
            "language": "python",
            "always_run": True,
            "pass_filenames": False,
            "verbose": True,
            "stages": ["pre-commit", "pre-push"],
        }
    ]


def test_pull_request_commits_action_has_one_safe_consumer_input() -> None:
    document = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    inputs = OBJECT_MAP.validate_python(document["inputs"])
    runs = OBJECT_MAP.validate_python(document["runs"])

    assert inputs == {
        "root": {
            "description": "Repository root to inspect",
            "required": False,
            "default": ".",
        }
    }
    assert runs["using"] == "composite"


def test_pull_request_commits_action_uses_runner_event_file_and_locked_package() -> None:
    source = ACTION_PATH.read_text(encoding="utf-8")

    assert "${{ github.event" not in source
    assert "${{ inputs.root }}" in source
    assert '--github-event "$GITHUB_EVENT_PATH"' in source
    assert 'pull-request commits "$INPUT_ROOT"' in source
    assert '--project "$GITHUB_ACTION_PATH/.." --locked --no-dev --python 3.12' in source
    assert '--project "$GITHUB_ACTION_PATH/.." --no-sync repo-standards' in source
    assert "uvx" not in source


def test_ci_self_tests_action_hook_manifest_and_installed_cli() -> None:
    source = CI_PATH.read_text(encoding="utf-8")

    assert "types: [opened, synchronize, reopened, edited]" in source
    assert "types: [checks_requested]" in source
    assert "uses: ./pull-request-commits" in source
    assert "fetch-depth: 0" in source
    assert "pre-commit validate-manifest .pre-commit-hooks.yaml" in source
    assert 'repo-standards" pull-request commits --help' in source
