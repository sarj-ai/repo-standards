from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

from pydantic import TypeAdapter
import pytest
import yaml

from tests.test_public_content import OBJECT_LIST, OBJECT_MAP, REPOSITORY_ROOT


if TYPE_CHECKING:
    from pathlib import Path


def test_parallel_build_preserves_the_immutable_anchor_publication_barrier() -> None:
    workflow = OBJECT_MAP.validate_python(
        yaml.load(
            (REPOSITORY_ROOT / ".github/workflows/publish.yml").read_text(), Loader=yaml.BaseLoader
        ),
        strict=True,
    )
    jobs = OBJECT_MAP.validate_python(workflow["jobs"], strict=True)
    build = OBJECT_MAP.validate_python(jobs["build"], strict=True)
    assert build["needs"] == ["detect"]
    for name in ["publish_primary", "release"]:
        job = OBJECT_MAP.validate_python(jobs[name], strict=True)
        needs = TypeAdapter(list[str]).validate_python(job["needs"], strict=True)
        condition = job["if"]
        assert isinstance(condition, str)
        assert "anchor" in needs
        assert "needs.anchor.result == 'success' || needs.anchor.result == 'skipped'" in condition


@pytest.mark.parametrize("failed_tool", ["none", "uv", "npm"])
def test_documentation_installs_overlap_and_either_failure_blocks_build(
    tmp_path: Path, failed_tool: str
) -> None:
    workflow = OBJECT_MAP.validate_python(
        yaml.load(
            (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
        ),
        strict=True,
    )
    jobs = OBJECT_MAP.validate_python(workflow["jobs"], strict=True)
    docs = OBJECT_MAP.validate_python(jobs["docs"], strict=True)
    steps = OBJECT_LIST.validate_python(docs["steps"], strict=True)
    script = next(step["run"] for step in steps if step.get("name") == "Install locked toolchains")
    assert isinstance(script, str)
    shell = shutil.which("bash")
    assert shell is not None
    signals = tmp_path / "signals"
    signals.mkdir()
    for tool in ["uv", "npm"]:
        other = "npm" if tool == "uv" else "uv"
        stub = tmp_path / tool
        stub.write_text(
            f'#!/bin/sh\ntouch "$SIGNALS/{tool}"\n'
            f'until test -f "$SIGNALS/{other}"; do sleep 0.01; done\n'
            f'[ "$FAIL_TOOL" != "{tool}" ]\n'
        )
        stub.chmod(0o755)
    process = subprocess.run(
        (shell, "-eu", "-o", "pipefail", "-c", script),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- execute the actual workflow shell with stubbed package managers.
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "SIGNALS": str(signals),
            "FAIL_TOOL": failed_tool,
        },
    )
    assert (process.returncode == 0) == (failed_tool == "none"), process.stderr
    assert sorted(path.name for path in signals.iterdir()) == ["npm", "uv"]


@pytest.mark.parametrize("failed_check", ["none", "eslint", "test", "typecheck"])
def test_reference_checks_overlap_and_all_must_pass_before_build(
    tmp_path: Path, failed_check: str
) -> None:
    script = (REPOSITORY_ROOT / ".github/scripts/verify-reference.sh").read_text()
    commands = script[script.index("npm run catalog") :]
    stub = tmp_path / "npm"
    stub.write_text(
        '#!/bin/sh\ncase "$*" in *catalog*) exit 0;; *eslint*) name=eslint;; '
        "*typecheck*) name=typecheck;; *test*) name=test;; *) "
        'test -f "$SIGNALS/eslint.done" && test -f "$SIGNALS/test.done" '
        '&& test -f "$SIGNALS/typecheck.done" || exit 9; '
        'touch "$SIGNALS/build"; exit 0;; esac\n'
        'touch "$SIGNALS/$name.started"\n'
        'until test -f "$SIGNALS/eslint.started" && test -f "$SIGNALS/test.started" '
        '&& test -f "$SIGNALS/typecheck.started"; do sleep 0.01; done\n'
        'touch "$SIGNALS/$name.done"\n'
        '[ "$name" != "$FAIL_CHECK" ]\n'
    )
    stub.chmod(0o755)
    node = tmp_path / "node"
    node.write_text("#!/bin/sh\nexit 0\n")
    node.chmod(0o755)
    process = subprocess.run(
        (shutil.which("bash") or "/bin/bash", "-eu", "-o", "pipefail", "-c", commands),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- preserve the real verification shell environment.
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "SIGNALS": str(tmp_path),
            "FAIL_CHECK": failed_check,
        },
    )
    assert (process.returncode == 0) == (failed_check == "none"), process.stderr
    assert (tmp_path / "build").exists() is (failed_check == "none")
    assert all((tmp_path / f"{name}.done").exists() for name in ["eslint", "test", "typecheck"])
