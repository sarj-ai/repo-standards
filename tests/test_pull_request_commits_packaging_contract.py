from __future__ import annotations

import json
from pathlib import Path
import subprocess

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic schema codecs preserve the tested wire representation without adding a model envelope.
import pytest
import yaml


ROOT = Path(__file__).parents[1]
HOOKS_PATH = ROOT / ".pre-commit-hooks.yaml"
ACTION_PATH = ROOT / "pull-request-commits" / "action.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
OBJECT_MAP = TypeAdapter(dict[str, object])
OBJECT_MAPS = TypeAdapter(list[dict[str, object]])


def test_pull_request_commits_hook_is_quiet_advisory_and_history_scoped() -> None:
    document = OBJECT_MAPS.validate_python(yaml.safe_load(HOOKS_PATH.read_text(encoding="utf-8")))
    hooks = [
        {key: value for key, value in hook.items() if key not in {"name", "description"}}
        for hook in document
    ]

    assert hooks == [
        {
            "id": "repo-standards-pull-request-commits",
            "entry": "repo-standards pull-request commits . --advisory --quiet",
            "language": "python",
            "language_version": "python3.15",
            "always_run": True,
            "pass_filenames": False,
            "verbose": True,
            "stages": ["pre-commit", "pre-push"],
        },
        {
            "id": "repo-standards-commit-message",
            "entry": "repo-standards commit-message --fix-safe --advise",
            "language": "python",
            "language_version": "python3.15",
            "always_run": True,
            "pass_filenames": True,
            "require_serial": True,
            "verbose": True,
            "stages": ["commit-msg"],
        },
        {
            "id": "repo-standards-check",
            "entry": "repo-standards check . --staged",
            "language": "python",
            "language_version": "python3.15",
            "always_run": True,
            "pass_filenames": False,
            "require_serial": True,
            "stages": ["pre-commit"],
        },
    ]


def test_pull_request_commits_action_inputs_default_to_owning_the_check() -> None:
    document = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    inputs = OBJECT_MAP.validate_python(document["inputs"])
    specs = {name: OBJECT_MAP.validate_python(value) for name, value in inputs.items()}
    runs = OBJECT_MAP.validate_python(document["runs"])

    assert {name: spec["default"] for name, spec in specs.items()} == {
        "root": ".",
        "status-context": "",
        "github-token": "",
    }
    assert all(spec["required"] is False for spec in specs.values())
    assert runs["using"] == "composite"


def test_pull_request_commits_action_reports_the_verdict_it_exits_with() -> None:
    document = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    runs = OBJECT_MAP.validate_python(document["runs"])
    steps = {str(step.get("name")): step for step in OBJECT_MAPS.validate_python(runs["steps"])}

    assert steps["Enforce pull-request commit history"]["continue-on-error"] is True
    assert steps["Report the verdict as a commit status"]["if"] == (
        "${{ !cancelled() && inputs.status-context != '' }}"
    )
    assert steps["Fail on a failing verdict"] == {
        "name": "Fail on a failing verdict",
        "if": "${{ steps.enforce.outcome != 'success' }}",
        "shell": "bash",
        "run": "exit 1",
    }


def test_pull_request_commits_action_uses_runner_event_file_and_locked_package() -> None:
    source = ACTION_PATH.read_text(encoding="utf-8")
    document = OBJECT_MAP.validate_python(yaml.safe_load(source))
    steps = OBJECT_MAPS.validate_python(OBJECT_MAP.validate_python(document["runs"])["steps"])

    assert all("${{" not in str(step.get("run", "")) for step in steps)
    assert "${{ inputs.root }}" in source
    assert '--github-event "$GITHUB_EVENT_PATH"' in source
    assert 'pull-request commits "$INPUT_ROOT"' in source
    assert '--project "$GITHUB_ACTION_PATH/.." --locked --no-dev --python 3.15' in source
    assert '--project "$GITHUB_ACTION_PATH/.." --no-sync repo-standards' in source
    assert "uvx" not in source


def test_ci_self_tests_action_hook_manifest_and_installed_cli() -> None:
    source = CI_PATH.read_text(encoding="utf-8")

    assert "types: [opened, synchronize, reopened]" in source
    # Title edits still need commit-policy validation; they do not change the
    # package tree or require its lint, types, tests and docs to run again.
    policy = (ROOT / ".github/workflows/commit-policy.yml").read_text(encoding="utf-8")
    assert "edited" in policy
    assert "types: [checks_requested]" in source
    assert "uses: ./pull-request-commits" in source
    assert "fetch-depth: 0" in source
    assert "pre-commit validate-manifest .pre-commit-hooks.yaml" in source
    assert "bash .github/scripts/ci-workflow.sh smoke" in source
    smoke = (ROOT / ".github/scripts/smoke-interfaces.sh").read_text(encoding="utf-8")
    assert '"$cli" pull-request commits --help' in smoke


@pytest.mark.parametrize(
    ("title", "body", "codes"),
    [
        pytest.param("fix: repair retries", None, [], id="null-body"),
        pytest.param("fix: " + "x" * 72 + " (#123)", "x" * 500, [], id="boundaries"),
        pytest.param(
            "fix: " + "x" * 73,
            "x" * 501,
            ["body_prose_too_long", "subject.too-long"],
            id="automatic-advice",
        ),
        pytest.param("fix: repair retries", "x" * 2001, ["body_too_long"], id="raw-budget"),
        pytest.param(
            "fix: repair retries", "~~~text\n" + "x" * 1988 + "\n~~~", [], id="raw-boundary"
        ),
        pytest.param(
            "fix: repair retries",
            "~~~\nprivate payload\n~~~",
            ["body_code_example_invalid"],
            id="untyped-code",
        ),
        pytest.param(
            "fix: $(touch INJECTED) %0A::error::PRIVATE",
            "::error::PRIVATE\n$(touch INJECTED)\n" + "x" * 501,
            ["body_prose_too_long"],
            id="untrusted-metadata",
        ),
        pytest.param(
            "fix: first\n::error::PRIVATE", "Retain facts.", None, id="unavailable-advice"
        ),
        pytest.param("fix: repair retries\n", "Retain facts.", None, id="trailing-title-newline"),
    ],
)
def test_action_advises_on_event_metadata_without_mutation_or_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    title: str,
    body: str | None,
    codes: list[str] | None,
) -> None:
    document = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    steps = OBJECT_MAPS.validate_python(OBJECT_MAP.validate_python(document["runs"])["steps"])
    step = next(step for step in steps if step.get("name") == "Advise on pull-request text")
    assert step["if"] == "${{ !cancelled() && github.event_name == 'pull_request' }}"
    assert step["continue-on-error"] is True
    event = tmp_path / "event.json"
    original = json.dumps({"pull_request": {"title": title, "body": body}}).encode()
    event.write_bytes(original)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_ACTION_PATH", str(ACTION_PATH.parent))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    result = subprocess.run(
        ("bash", "-e", "-o", "pipefail", "-c", str(step["run"])),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert (result.returncode == 0) is (codes is not None), result.stderr
    annotations = result.stdout.splitlines()
    expected_codes = codes or []
    assert len(annotations) == len(expected_codes)
    assert all(line.startswith("::warning title=PR text::") for line in annotations)
    assert all(f"::{code}:" in line for code, line in zip(expected_codes, annotations, strict=True))
    assert "PRIVATE" not in result.stdout + result.stderr
    assert "private payload" not in result.stdout + result.stderr
    assert not (tmp_path / "INJECTED").exists()
    assert event.read_bytes() == original
    assert sorted(path.name for path in tmp_path.iterdir()) == ["event.json"]
