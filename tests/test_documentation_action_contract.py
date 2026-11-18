from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic schema codecs preserve the tested wire representation without adding a model envelope.
import pytest
import yaml


ROOT = Path(__file__).parents[1]
ACTION_PATH = ROOT / "documentation" / "action.yml"
OBJECT_MAP = TypeAdapter(dict[str, object])


def test_documentation_action_has_only_revision_and_root_inputs() -> None:
    document = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    inputs = OBJECT_MAP.validate_python(document["inputs"])

    assert set(inputs) == {"root", "base", "head"}


@pytest.mark.parametrize(("explicit", "status"), [(False, 0), (True, 0), (False, 3)])
def test_documentation_action_uses_trusted_revisions_and_locked_package(
    tmp_path: Path, *, explicit: bool, status: int
) -> None:
    action = OBJECT_MAP.validate_python(yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8")))
    steps = TypeAdapter(list[dict[str, object]]).validate_python(
        OBJECT_MAP.validate_python(action["runs"])["steps"]
    )
    installer, runner = (step for step in steps if "run" in step)
    assert OBJECT_MAP.validate_python(runner["env"]) == {
        "INPUT_BASE": "${{ inputs.base }}",
        "INPUT_HEAD": "${{ inputs.head }}",
        "INPUT_ROOT": "${{ inputs.root }}",
        "PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
    }
    executable = shutil.which("python3")
    shell = shutil.which("bash")
    assert executable is not None
    assert shell is not None
    stub = tmp_path / "uv"
    stub.write_text(
        f"#!{executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['CALLS'], 'a') as calls:\n"
        "    calls.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "sys.exit(int(os.environ['STATUS']) if sys.argv[1] == 'run' else 0)\n"
    )
    stub.chmod(0o755)
    calls = tmp_path / "calls.jsonl"
    result = subprocess.run(
        (shell, "-eu", "-o", "pipefail", "-c", f"{installer['run']}\n{runner['run']}"),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "CALLS": str(calls),
            "STATUS": str(status),
            "GITHUB_ACTION_PATH": str(ROOT / "documentation"),
            "INPUT_ROOT": ".",
            "INPUT_BASE": "explicit-base" if explicit else "",
            "INPUT_HEAD": "explicit-head" if explicit else "",
            "PR_BASE_SHA": "trusted-base",
            "PR_HEAD_SHA": "trusted-head",
        },
    )
    assert result.returncode == status, result.stderr
    assert [json.loads(line) for line in calls.read_text().splitlines()] == [
        [
            "sync",
            "--project",
            str(ROOT / "documentation/.."),
            "--locked",
            "--no-dev",
            "--python",
            "3.15",
        ],
        [
            "run",
            "--project",
            str(ROOT / "documentation/.."),
            "--no-sync",
            "repo-standards",
            "pull-request",
            "documentation",
            ".",
            "--base",
            "explicit-base" if explicit else "trusted-base",
            "--head",
            "explicit-head" if explicit else "trusted-head",
        ],
    ]
