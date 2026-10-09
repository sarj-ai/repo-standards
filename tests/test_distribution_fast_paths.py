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


@pytest.mark.parametrize("failed_check", ["none", "ruff", "basedpyright", "python"])
@pytest.mark.parametrize("base_option", [False, True])
def test_local_gate_runs_all_checks_and_preserves_test_base(
    tmp_path: Path, failed_check: str, *, base_option: bool
) -> None:
    stub = tmp_path / "uv"
    stub.write_text(
        '#!/bin/sh\nif [ "$1" = sync ]; then exit 0; fi\nname="$3"\n'
        'if [ "$name" = python ]; then test "$*" = '
        '"run --no-sync python test_selection.py --run --base origin/main --jobs 4" || exit 8; fi\n'
        'touch "$SIGNALS/$name.started"\n'
        'until test -f "$SIGNALS/ruff.started" && test -f "$SIGNALS/basedpyright.started" '
        '&& test -f "$SIGNALS/python.started"; do sleep 0.01; done\n'
        'touch "$SIGNALS/$name.done"\n[ "$name" != "$FAIL_CHECK" ]\n'
    )
    stub.chmod(0o755)
    result = subprocess.run(
        (
            shutil.which("bash") or "/bin/bash",
            "-eu",
            "-o",
            "pipefail",
            str(REPOSITORY_ROOT / ".github/scripts/verify-python.sh"),
            *(("--base", "origin/main") if base_option else ("origin/main",)),
            "--jobs",
            "4",
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- real shell with controlled tool path
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "SIGNALS": str(tmp_path),
            "FAIL_CHECK": failed_check,
        },
    )
    assert (result.returncode == 0) is (failed_check == "none"), result.stderr
    assert all((tmp_path / f"{name}.done").exists() for name in ["ruff", "basedpyright", "python"])


@pytest.mark.parametrize("failed_check", ["none", "capabilities", "schema", "rest"])
def test_installed_smoke_overlaps_groups_and_propagates_failure(
    tmp_path: Path, failed_check: str
) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    cli = binaries / "repo-standards"
    cli.write_text(
        '#!/bin/sh\nname="$1"\n'
        'if [ "$name" = capabilities ] || [ "$name" = schema ]; then\n'
        'touch "$SIGNALS/$name.started"\n'
        'until test -f "$SIGNALS/capabilities.started" && test -f "$SIGNALS/schema.started"; '
        "do sleep 0.01; done\nfi\n"
        'echo "$*" >> "$SIGNALS/commands"\n'
        '[ "$name" != "$FAIL_CHECK" ]\n'
    )
    cli.chmod(0o755)
    python = binaries / "python"
    python.write_text("#!/bin/sh\nexit 0\n")
    python.chmod(0o755)
    result = subprocess.run(
        (
            shutil.which("bash") or "/bin/bash",
            str(REPOSITORY_ROOT / ".github/scripts/smoke-interfaces.sh"),
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- exercise the actual installed smoke helper
            "SMOKE_ENV": str(tmp_path),
            "SIGNALS": str(tmp_path),
            "FAIL_CHECK": failed_check,
            "RUNNER_TEMP": str(tmp_path),
        },
    )
    assert (result.returncode == 0) is (failed_check == "none"), result.stderr
    commands = (tmp_path / "commands").read_text().splitlines()
    assert "capabilities" in commands
    assert "schema" in commands
    if failed_check == "none":
        assert len(commands) == 8


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(["--jobs"], id="missing-jobs"),
        pytest.param(["--jobs", "0"], id="zero-jobs"),
        pytest.param(["--jobs", "17"], id="unbounded-jobs"),
        pytest.param(["--base"], id="missing-base"),
        pytest.param(["--base", "--help"], id="option-as-base"),
        pytest.param(["first", "second"], id="duplicate-positionals"),
        pytest.param(["first", "--base", "second"], id="duplicate-base"),
        pytest.param(["--unknown"], id="unknown-flag"),
    ],
)
def test_local_gate_rejects_invalid_options_before_installing(
    tmp_path: Path, arguments: list[str]
) -> None:
    stub = tmp_path / "uv"
    stub.write_text('#!/bin/sh\ntouch "$SIGNALS/installed"\n')
    stub.chmod(0o755)

    result = subprocess.run(
        (
            shutil.which("bash") or "/bin/bash",
            str(REPOSITORY_ROOT / ".github/scripts/verify-python.sh"),
            *arguments,
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- real argument parser with an observable installer.
            "PATH": str(tmp_path) + os.pathsep + os.defpath,
            "SIGNALS": str(tmp_path),
        },
    )

    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert not (tmp_path / "installed").exists()


def test_reused_validation_skips_only_the_test_environment_and_retains_a_fresh_audit() -> None:
    workflow = OBJECT_MAP.validate_python(
        yaml.load(
            (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader
        ),
        strict=True,
    )
    jobs = OBJECT_MAP.validate_python(workflow["jobs"], strict=True)
    validate = OBJECT_MAP.validate_python(jobs["validate"], strict=True)
    steps = OBJECT_LIST.validate_python(validate["steps"], strict=True)
    proof = next(index for index, step in enumerate(steps) if step.get("id") == "reviewed")
    install = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Install locked environment"
    )
    assert proof < install
    assert steps[install]["if"] == "steps.reviewed.outputs.reused != 'true'"
    audit = next(step for step in steps if step.get("name") == "Audit locked dependencies")
    assert audit["run"] == "uv audit --locked"
    assert "if" not in audit
