from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import NamedTuple

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.models import RepositoryId
from repo_standards.core.pull_request_commits import (
    PullRequestCommits,
    TransitionExemption,
    TransitionExemptionId,
    analyze_pull_request_commits,
)


_IDENTITY = (
    "-c",
    "user.name=Repository Standards",
    "-c",
    "user.email=repository-standards@example.invalid",
)


class Resolution(NamedTuple):
    repository: Path
    snapshot: str
    base: str
    head: str


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(repository), *_IDENTITY, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _write_commit(repository: Path, files: dict[str, str], message: str) -> str:
    for name, content in files.items():
        (repository / name).write_text(content, encoding="utf-8")
    _git(repository, "add", *files)
    _git(repository, "commit", "--quiet", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _resolution(
    tmp_path: Path, *, extra_files: dict[str, str] | None = None, conflict: str = "conflict.txt"
) -> Resolution:
    """Preview (source) and dev (base) both edit conflict.txt; head resolves it by merge."""
    _git(tmp_path, "init", "--quiet")
    root = _write_commit(tmp_path, {conflict: "root\n", "shared.txt": "root\n"}, "root")
    snapshot = root
    for index in range(6):
        snapshot = _write_commit(
            tmp_path,
            {conflict: f"preview {index}\n", f"preview{index}.txt": "p\n"},
            f"preview {index}",
        )
    _git(tmp_path, "branch", "preview", snapshot)
    _git(tmp_path, "checkout", "--quiet", "--detach", root)
    base = _write_commit(tmp_path, {conflict: "dev\n", "dev.txt": "d\n"}, "dev")
    _git(tmp_path, "checkout", "--quiet", "--detach", snapshot)
    _git(tmp_path, "merge", "--quiet", "--no-ff", "--no-commit", base)
    head = _write_commit(
        tmp_path,
        {conflict: "resolved\n", **(extra_files or {})},
        "Merge dev into preview snapshot",
    )
    return Resolution(tmp_path, snapshot, base, head)


def _exemption(
    *, allow: bool = True, head_prefix: str = "automation/sync-preview-"
) -> TransitionExemption:
    return TransitionExemption(
        exemption_id=TransitionExemptionId("preview-dev"),
        repository_id=RepositoryId("sarj-ai/platform"),
        source_ref="preview",
        base_ref="dev",
        head_prefix=head_prefix,
        allow_reviewed_resolution=allow,
    )


def _analyze(  # ruff: ignore[too-many-arguments] - each identity input is varied independently
    resolution: Resolution,
    *,
    head: str | None = None,
    base: str | None = None,
    head_ref: str | None = None,
    repository_id: str = "sarj-ai/platform",
    exemption: TransitionExemption | None = None,
) -> PullRequestCommits:
    return analyze_pull_request_commits(
        resolution.repository,
        base=base or resolution.base,
        head=head or resolution.head,
        base_ref="dev",
        head_ref=head_ref or f"automation/sync-preview-{resolution.snapshot[:12]}",
        repository_id=repository_id,
        transition_exemptions=(exemption or _exemption(),),
    )


def test_reviewed_resolution_confined_to_conflicts_is_reported(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path)

    result = _analyze(resolution)

    assert result.satisfied
    assert result.disposition == "transition-resolution"
    assert result.exemption_id == "preview-dev"
    assert result.resolved_paths == ("conflict.txt",)


def test_reviewed_resolution_requires_the_opt_in(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path)

    result = _analyze(resolution, exemption=_exemption(allow=False))

    assert not result.satisfied
    assert result.exemption_id is None
    assert result.resolved_paths == ()


def test_resolution_editing_a_non_conflicted_path_is_rejected(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path, extra_files={"shared.txt": "smuggled\n"})

    result = _analyze(resolution)

    assert not result.satisfied
    assert result.exemption_id is None


def test_resolution_against_a_stale_base_is_rejected(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path)
    _git(tmp_path, "checkout", "--quiet", "--detach", resolution.base)
    current_base = _write_commit(tmp_path, {"later.txt": "l\n"}, "dev advanced")

    result = _analyze(resolution, base=current_base)

    assert result.exemption_id is None


def test_resolution_snapshot_outside_source_is_rejected(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path)
    _git(tmp_path, "branch", "--force", "preview", resolution.base)

    result = _analyze(resolution)

    assert result.exemption_id is None


@pytest.mark.parametrize("forgery", ["fork", "prefix", "length", "snapshot"])
def test_resolution_identity_lookalikes_are_rejected(tmp_path: Path, forgery: str) -> None:
    resolution = _resolution(tmp_path)
    head_ref = {
        "prefix": f"automation/other-{resolution.snapshot[:12]}",
        "length": f"automation/sync-preview-{resolution.snapshot[:11]}",
        "snapshot": f"automation/sync-preview-{resolution.base[:12]}",
    }.get(forgery)

    result = _analyze(
        resolution,
        head_ref=head_ref,
        repository_id="fork/platform" if forgery == "fork" else "sarj-ai/platform",
    )

    assert result.exemption_id is None


def test_commit_on_top_of_a_resolution_is_rejected(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path)
    _git(tmp_path, "checkout", "--quiet", "--detach", resolution.head)
    head = _write_commit(tmp_path, {"conflict.txt": "edited after merge\n"}, "follow-up")

    result = _analyze(resolution, head=head)

    assert result.exemption_id is None


def test_octopus_resolution_is_rejected(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path)
    tree = _git(tmp_path, "rev-parse", f"{resolution.head}^{{tree}}")
    other = _git(tmp_path, "rev-parse", f"{resolution.snapshot}^")
    head = _git(
        tmp_path,
        "commit-tree",
        tree,
        "-p",
        resolution.snapshot,
        "-p",
        resolution.base,
        "-p",
        other,
        "-m",
        "Octopus",
    )

    result = _analyze(resolution, head=head)

    assert result.exemption_id is None


def test_opt_in_does_not_accept_a_changed_clean_merge(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    root = _write_commit(tmp_path, {"a.txt": "root\n"}, "root")
    snapshot = root
    for index in range(6):
        snapshot = _write_commit(tmp_path, {f"p{index}.txt": "p\n"}, f"preview {index}")
    _git(tmp_path, "branch", "preview", snapshot)
    _git(tmp_path, "checkout", "--quiet", "--detach", root)
    base = _write_commit(tmp_path, {"d.txt": "d\n"}, "dev")
    _git(tmp_path, "checkout", "--quiet", "--detach", snapshot)
    _git(tmp_path, "merge", "--quiet", "--no-ff", "--no-commit", base)
    head = _write_commit(tmp_path, {"a.txt": "changed\n"}, "Merge with edit")

    result = _analyze(Resolution(tmp_path, snapshot, base, head))

    assert result.exemption_id is None


def test_resolution_receipt_lists_sanitized_conflicted_paths(tmp_path: Path) -> None:
    resolution = _resolution(tmp_path, conflict="con\tflict.txt")
    exemption = json.dumps(
        {
            "id": "preview-dev",
            "repository_id": "sarj-ai/platform",
            "source_ref": "preview",
            "base_ref": "dev",
            "head_prefix": "automation/sync-preview-",
            "allow_reviewed_resolution": True,
        }
    )
    arguments = [
        "pull-request",
        "commits",
        str(tmp_path),
        "--base",
        resolution.base,
        "--head",
        resolution.head,
        "--base-ref",
        "dev",
        "--head-ref",
        f"automation/sync-preview-{resolution.snapshot[:12]}",
        "--repository-id",
        "sarj-ai/platform",
        "--transition-exemption",
        exemption,
    ]

    text = CliRunner().invoke(app, arguments)
    receipt = CliRunner().invoke(app, [*arguments, "--format", "json"])

    assert text.exit_code == 0, text.stdout
    assert "Disposition: transition-resolution" in text.stdout
    assert "  con\\x09flict.txt\n" in text.stdout
    assert "\t" not in text.stdout
    summary = json.loads(receipt.stdout)["summary"]  # pyright: ignore[reportAny] - JSON boundary
    assert summary["disposition"] == "transition-resolution"
    assert summary["resolved_paths"] == ["con\\x09flict.txt"]
