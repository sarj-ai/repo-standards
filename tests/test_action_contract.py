from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from pydantic import TypeAdapter
import pytest
import yaml


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
    }
    assert source.count("repo-standards pull-request size") == 1
    assert "repo-lint check" not in source
    assert "Validate compatibility inputs" not in source
    assert "github.event.pull_request.base.sha" in source
    assert "github.event.pull_request.head.sha" in source
    assert "report-path" in source


def test_action_keeps_complete_report_out_of_github_output() -> None:
    source = _action_source()
    assert '--report-path "$report_path"' in source
    assert 'key not in {"categories", "directories", "files"}' in source
    assert 'echo "report-path=$report_path" >> "$GITHUB_OUTPUT"' in source


def test_action_uses_locked_non_mutating_environment() -> None:
    serialized = _action_source()
    assert "--locked --no-dev --python 3.14" in serialized
    assert "setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7" in serialized


@pytest.mark.parametrize("valid", [True, False])
def test_action_decodes_once_and_keeps_full_report_separate(tmp_path: Path, valid: bool) -> None:
    mapping = TypeAdapter(dict[str, object])
    rows = TypeAdapter(list[dict[str, object]])
    document = mapping.validate_python(yaml.safe_load(_action_source()))
    runs = mapping.validate_python(document["runs"])
    script = rows.validate_python(runs["steps"])[-1]["run"]
    assert isinstance(script, str)
    payload = {
        "summary": {"counted_lines": 3, "excluded_lines": 7, "total_lines": 10},
        "files": ["complete report"],
        "categories": [],
        "directories": [],
    }
    if not valid:
        payload.pop("summary")
    source = tmp_path / "source.json"
    source.write_text(json.dumps(payload))
    executable = shutil.which("python3")
    shell = shutil.which("bash")
    assert executable is not None
    assert shell is not None
    stub = tmp_path / "uv"
    stub.write_text(
        f"#!{executable}\n"
        """import os, sys, shutil
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as stream:
    stream.write("decode\\n" if "python" in args else "analyze\\n")
if "python" in args:
    os.execv(sys.executable, [sys.executable, *args[args.index("python") + 1:]])
shutil.copyfile(os.environ["SOURCE"], args[args.index("--report-path") + 1])
"""
    )
    stub.chmod(0o755)
    output = tmp_path / "outputs"
    result = subprocess.run(
        (shell, "-eu", "-o", "pipefail", "-c", script),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "CALLS": str(tmp_path / "calls"),
            "SOURCE": str(source),
            "INPUT_BASE": "base",
            "INPUT_HEAD": "head",
            "INPUT_ROOT": ".",
            "INPUT_GENERATED_ATTRIBUTE": "pr-size-excluded",
            "GITHUB_ACTION_PATH": str(tmp_path),
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        },
    )
    assert (result.returncode == 0) == valid, result.stderr
    assert (tmp_path / "calls").read_text().splitlines() == ["analyze", "decode"]
    if valid:
        lines = output.read_text().splitlines()
        assert lines[:3] == ["counted-lines=3", "excluded-lines=7", "total-lines=10"]
        assert json.loads(lines[3].split("=", 1)[1]) == {"summary": payload["summary"]}
        assert json.loads(Path(lines[4].split("=", 1)[1]).read_text(encoding="utf-8")) == payload
