from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- decode the native workflow without a second schema.
import pytest
import yaml

from ci_artifacts import JsonValue


ROOT = Path(__file__).parents[1]
SHA = "a" * 40


@pytest.mark.parametrize("failed_lane", ["none", "validate", "compatibility", "package"])
def test_native_package_gate_requires_every_runtime_lane(tmp_path: Path, failed_lane: str) -> None:
    objects = TypeAdapter(dict[str, JsonValue])
    workflow = objects.validate_python(
        yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader),
        strict=True,
    )
    jobs = objects.validate_python(workflow["jobs"], strict=True)
    gate = objects.validate_python(jobs["packages_gate"], strict=True)
    assert gate["if"] == "always()"
    assert gate["needs"] == ["validate", "compatibility", "package"]
    steps = TypeAdapter(list[dict[str, JsonValue]]).validate_python(gate["steps"], strict=True)
    command = steps[0]["run"]
    assert isinstance(command, str)
    executable = shutil.which("bash")
    assert executable is not None
    process = subprocess.run(
        (executable, "-euo", "pipefail", "-c", command),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            f"{lane.upper()}_RESULT": "failure" if lane == failed_lane else "success"
            for lane in ("validate", "compatibility", "package")
        },
    )
    assert (process.returncode == 0) == (failed_lane == "none"), process.stderr


@pytest.mark.parametrize(
    "case",
    [
        "docs-failed",
        "package-failed",
        "missing-gate",
        "duplicate-gate",
        "cancelled",
        "rerun",
        "standards-failed",
        "missing-gate-success",
        "pending-gate-success",
        "missing-conclusion",
        "legacy-success",
        "legacy-success-lost",
    ],
)
def test_publisher_uses_exact_attempt_package_and_standards_qualification(
    tmp_path: Path, case: str
) -> None:
    run: dict[str, JsonValue] = {
        "id": 7,
        "run_attempt": 1,
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "path": ".github/workflows/ci.yml",
        "head_repository": {"full_name": "owner/repo"},
        "status": "completed",
        "conclusion": "success"
        if case.endswith("-success")
        else "cancelled"
        if case == "cancelled"
        else "failure",
    }
    latest = {**run, "run_attempt": 2 if case == "rerun" else 1}
    if case == "legacy-success-lost":
        run["conclusion"] = "success"
    if case == "missing-conclusion":
        latest = {key: value for key, value in latest.items() if key != "conclusion"}
    gate: dict[str, JsonValue] = {
        "name": "CI / gate" if case.startswith("legacy-") else "CI / packages",
        "status": "in_progress" if case == "pending-gate-success" else "completed",
        "conclusion": None
        if case == "pending-gate-success"
        else "failure"
        if case == "package-failed"
        else "success",
    }
    jobs: list[JsonValue] = [] if case.startswith("missing-gate") else [gate]
    if case == "duplicate-gate":
        jobs.append(gate)
    standard = {
        **run,
        "id": 8,
        "path": ".github/workflows/standards.yml",
        "conclusion": "failure" if case == "standards-failed" else "success",
    }
    fixtures: dict[str, JsonValue] = {
        "ci": {"workflow_runs": [run]},
        "latest": latest,
        "jobs": {"total_count": len(jobs), "jobs": jobs},
        "standards": {"workflow_runs": [standard]},
    }
    for name, value in fixtures.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(value))
    stub = tmp_path / "gh"
    stub.write_text(
        '#!/bin/sh\ncase "$*" in\n'
        '*"/runs/7/attempts/1/jobs?per_page=100") fixture=jobs;;\n'
        '*"/runs/7") fixture=latest;;\n'
        '*"workflows/ci.yml/runs"*) fixture=ci;;\n'
        '*"workflows/standards.yml/runs"*) fixture=standards;;\n'
        '*) exit 99;;\nesac\ncat "$FIXTURE_ROOT/$fixture.json"\n'
    )
    stub.chmod(0o755)
    executable = shutil.which("bash")
    assert executable is not None
    process = subprocess.run(
        (executable, str(ROOT / ".github/scripts/ci-workflow.sh"), "wait-main"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- preserve native jq and shell resolution; GitHub is replaced by a private fixture.
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],  # ruff: ignore[banned-api] -- explicit PATH injection for the isolated GitHub fixture.
            "FIXTURE_ROOT": str(tmp_path),
            "GITHUB_REPOSITORY": "owner/repo",
            "TARGET_SHA": SHA,
        },
    )
    assert (process.returncode == 0) == (case in {"docs-failed", "legacy-success"}), (
        process.stdout + process.stderr
    )
