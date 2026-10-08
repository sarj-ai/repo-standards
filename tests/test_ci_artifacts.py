from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile

from pydantic import TypeAdapter
import pytest
import yaml

from ci_artifacts import extract, reuse


SHA = "a" * 40
OTHER = "b" * 40


def _run(**changes: object) -> dict[str, object]:
    return {
        "id": 7,
        "run_attempt": 1,
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": "success",
        "head_repository": {"id": 3, "full_name": "owner/repo"},
        **changes,
    }


@dataclass(frozen=True)
class Archive:
    path: Path
    digest: str


def _archive(root: Path, *, sha: str = SHA, extra: str | None = None) -> Archive:
    archive = root / "payload.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("SOURCE_COMMIT", sha)
        bundle.writestr("repo_standards-1.0.0-py3-none-any.whl", b"tested wheel")
        bundle.writestr("repo_standards-1.0.0.tar.gz", b"tested sdist")
        if extra:
            bundle.writestr(extra, b"unexpected")
    return Archive(archive, "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest())


@dataclass
class Gateway:
    responses: list[object]
    archive: Path

    def get(self, endpoint: str) -> object:
        assert endpoint.startswith("repos/owner/repo/actions/")
        return self.responses.pop(0)

    def download(self, endpoint: str, destination: Path) -> None:
        assert endpoint == "repos/owner/repo/actions/artifacts/9/zip"
        destination.write_bytes(self.archive.read_bytes())


def _responses(digest: str, *, latest_attempt: int = 1) -> list[object]:
    return [
        {"total_count": 1, "workflow_runs": [_run()]},
        {
            "total_count": 1,
            "jobs": [
                {
                    "name": "Build and install artifacts",
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        },
        {
            "total_count": 1,
            "artifacts": [
                {
                    "id": 9,
                    "name": "tested-packages-1",
                    "expired": False,
                    "digest": digest,
                    "workflow_run": {
                        "id": 7,
                        "head_sha": SHA,
                        "head_branch": "main",
                        "repository_id": 3,
                        "head_repository_id": 3,
                    },
                }
            ],
        },
        _run(run_attempt=latest_attempt),
    ]


def test_reuse_preserves_tested_bytes_and_excludes_source_marker(tmp_path: Path) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(_responses(digest), archive)
    )
    assert result.reused
    assert (destination / "repo_standards-1.0.0-py3-none-any.whl").read_bytes() == b"tested wheel"
    assert not (destination / "SOURCE_COMMIT").exists()


def test_rerun_race_leaves_no_reusable_files(tmp_path: Path) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo",
        SHA,
        "packages",
        destination,
        transport=Gateway(_responses(digest, latest_attempt=2), archive),
    )
    assert not result.reused
    assert not destination.exists()


@pytest.mark.parametrize(
    "case",
    ["fork", "pr", "other-sha", "other-path", "failure", "pending", "truncated", "newer-failure"],
)
def test_wrong_failed_or_incomplete_main_runs_do_not_reuse(tmp_path: Path, case: str) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    run = _run()
    if case == "fork":
        run["head_repository"] = {"id": 4, "full_name": "fork/repo"}
    elif case == "pr":
        run["event"] = "pull_request"
    elif case == "other-sha":
        run["head_sha"] = OTHER
    elif case == "other-path":
        run["path"] = ".github/workflows/other.yml"
    elif case == "failure":
        run["conclusion"] = "failure"
    elif case == "pending":
        run.update(status="in_progress", conclusion=None)
    responses = _responses(digest)
    rows = [run, _run(id=8, conclusion="failure")] if case == "newer-failure" else [run]
    responses[0] = {"total_count": 2 if case == "truncated" else len(rows), "workflow_runs": rows}
    if case == "pending":
        responses[1] = {
            "total_count": 1,
            "jobs": [
                {"name": "Build and install artifacts", "status": "in_progress", "conclusion": None}
            ],
        }
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, archive)
    )
    assert not result.reused
    assert not destination.exists()


@pytest.mark.parametrize(
    "extra", ["../escape.whl", "/absolute.whl", "deps\\evil.whl", "execute.py"]
)
def test_unsafe_archives_fail_before_extraction(tmp_path: Path, extra: str) -> None:
    bundle = _archive(tmp_path, extra=extra)
    archive, digest = bundle.path, bundle.digest
    with pytest.raises(ValueError, match="unsafe"):
        extract(archive, tmp_path / "out", digest=digest, sha=SHA, kind="packages")
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("case", ["digest", "source"])
def test_digest_and_source_are_required_before_extraction(tmp_path: Path, case: str) -> None:
    bundle = _archive(tmp_path, sha=OTHER if case == "source" else SHA)
    archive, digest = bundle.path, bundle.digest
    if case == "digest":
        archive.write_bytes(archive.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="mismatch"):
        extract(archive, tmp_path / "out", digest=digest, sha=SHA, kind="packages")
    assert not (tmp_path / "out").exists()


def test_site_artifact_keeps_nested_files_without_exposing_marker(tmp_path: Path) -> None:
    archive = tmp_path / "site.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("SOURCE_COMMIT", SHA)
        bundle.writestr("api/v1/catalog.json", b"public catalog")
    digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    extract(archive, tmp_path / "site", digest=digest, sha=SHA, kind="site")
    assert (tmp_path / "site/api/v1/catalog.json").read_bytes() == b"public catalog"
    assert not (tmp_path / "site/SOURCE_COMMIT").exists()


@pytest.mark.parametrize(
    "case",
    [
        "expired",
        "attempt",
        "fork-id",
        "repository-id",
        "source-sha",
        "run-id",
        "branch",
        "digest",
        "failed-job",
    ],
)
def test_artifact_provenance_and_success_are_required(tmp_path: Path, case: str) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    responses = _responses(digest)
    artifacts: dict[str, object] = {
        "id": 9,
        "name": "tested-packages-1",
        "expired": False,
        "digest": digest,
    }
    identity: dict[str, object] = {
        "id": 7,
        "head_sha": SHA,
        "head_branch": "main",
        "repository_id": 3,
        "head_repository_id": 3,
    }
    if case == "expired":
        artifacts["expired"] = True
    elif case == "attempt":
        artifacts["name"] = "tested-packages-2"
    elif case == "digest":
        artifacts["digest"] = "missing"
    elif case == "failed-job":
        responses[1] = {
            "total_count": 1,
            "jobs": [
                {
                    "name": "Build and install artifacts",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ],
        }
    else:
        field, value = {
            "fork-id": ("head_repository_id", 4),
            "repository-id": ("repository_id", 4),
            "source-sha": ("head_sha", OTHER),
            "run-id": ("id", 8),
            "branch": ("head_branch", "topic"),
        }[case]
        identity[field] = value
    artifacts["workflow_run"] = identity
    responses[2] = {"total_count": 1, "artifacts": [artifacts]}
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, archive)
    )
    assert not result.reused
    assert not destination.exists()


def test_main_can_complete_successfully_during_download(tmp_path: Path) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    responses = _responses(digest)
    responses[0] = {
        "total_count": 1,
        "workflow_runs": [_run(status="in_progress", conclusion=None)],
    }
    result = reuse(
        "owner/repo", SHA, "packages", tmp_path / "out", transport=Gateway(responses, archive)
    )
    assert result.reused


@pytest.mark.parametrize("case", ["failure", "changed-source", "malformed"])
def test_failed_or_changed_main_cannot_supply_artifacts(tmp_path: Path, case: str) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    responses = _responses(digest)
    responses[-1] = {
        "failure": _run(conclusion="failure"),
        "changed-source": _run(head_sha=OTHER),
        "malformed": _run(conclusion={"unexpected": True}),
    }[case]
    destination = tmp_path / "out"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, archive)
    )
    assert not result.reused
    assert not destination.exists()


@pytest.mark.parametrize("failed_check", ["none", "ruff", "basedpyright", "pytest"])
def test_parallel_ci_waits_for_all_checks_and_propagates_failure(
    tmp_path: Path, failed_check: str
) -> None:
    object_map = TypeAdapter(dict[str, object])
    objects = TypeAdapter(list[dict[str, object]])
    root = Path(__file__).parents[1]
    document = object_map.validate_python(
        yaml.load((root / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader),
        strict=True,
    )
    jobs = object_map.validate_python(document["jobs"], strict=True)
    job = object_map.validate_python(jobs["validate"], strict=True)
    steps = objects.validate_python(job["steps"], strict=True)
    script = next(
        step["run"]
        for step in steps
        if step.get("name") == "Lint, typecheck and test independently"
    )
    assert isinstance(script, str)
    executable = shutil.which("bash")
    assert executable is not None
    stub = tmp_path / "uv"
    stub.write_text(
        '#!/bin/sh\ncase "$*" in *ruff*) name=ruff;; *basedpyright*) name=basedpyright;; '
        "*) name=pytest;; esac\n"
        'printf "%s\\n" "$name" >> "$RESULTS"\n'
        '[ "$name" != "$FAIL_CHECK" ]\n'
    )
    stub.chmod(0o755)
    process = subprocess.run(
        (executable, "-eu", "-o", "pipefail", "-c", script),
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,  # ruff: ignore[banned-api] -- preserve shell process environment in the real workflow test.
            "PATH": str(tmp_path) + os.pathsep + str(Path(shutil.which("sh") or "/bin/sh").parent),
            "FAIL_CHECK": failed_check,
            "RESULTS": str(tmp_path / "results"),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "RUNNER_TEMP": str(tmp_path),
            "TEST_BASE": "",
        },
    )
    assert (process.returncode == 0) == (failed_check == "none"), process.stderr
    assert sorted((tmp_path / "results").read_text().splitlines()) == [
        "basedpyright",
        "pytest",
        "ruff",
    ]
    assert len((tmp_path / "summary").read_text().splitlines()) == 3
