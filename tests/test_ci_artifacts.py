from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic schema codecs preserve the tested wire representation without adding a model envelope.
import pytest
import yaml

from ci_artifacts import (
    AwaitingArtifact,
    FreshValidationRequired,
    JsonValue,
    VerifiedArtifact,
    extract,
    reuse,
)


SHA = "a" * 40
OTHER = "b" * 40


def _run(**changes: JsonValue) -> dict[str, JsonValue]:
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
    responses: list[JsonValue]
    archive: Path

    def get(self, endpoint: str) -> JsonValue:
        assert endpoint.startswith("repos/owner/repo/actions/")
        if "/jobs?" in endpoint:
            assert endpoint.endswith("/attempts/1/jobs?per_page=100")
        return self.responses.pop(0)

    def download(self, endpoint: str, destination: Path) -> None:
        assert endpoint == "repos/owner/repo/actions/artifacts/9/zip"
        destination.write_bytes(self.archive.read_bytes())


def _successful_jobs() -> dict[str, JsonValue]:
    return {
        "total_count": 2,
        "jobs": [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in ("Build and install artifacts", "CI / packages")
        ],
    }


def _responses(digest: str, *, latest_attempt: int = 1) -> list[JsonValue]:
    return [
        {"total_count": 1, "workflow_runs": [_run()]},
        _successful_jobs(),
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
        _successful_jobs(),
        _run(run_attempt=latest_attempt),
    ]


def test_reuse_preserves_tested_bytes_and_excludes_source_marker(tmp_path: Path) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(_responses(digest), archive)
    )
    assert isinstance(result, VerifiedArtifact)
    assert result.source == SHA
    assert result.run.identifier == 7
    assert result.run.attempt == 1
    assert result.artifact.identifier == 9
    assert result.artifact.digest == digest
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
    assert isinstance(result, FreshValidationRequired)
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
    if case in {"failure", "newer-failure"}:
        responses[1] = {
            "total_count": 1,
            "jobs": [{"name": "CI / packages", "status": "completed", "conclusion": "failure"}],
        }
    rows: list[JsonValue] = (
        [run, _run(id=8, conclusion="failure")] if case == "newer-failure" else [run]
    )
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
    if case in {"fork", "pr", "other-sha", "other-path", "pending"}:
        assert isinstance(result, AwaitingArtifact)
    else:
        assert isinstance(result, FreshValidationRequired)
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
    artifacts: dict[str, JsonValue] = {
        "id": 9,
        "name": "tested-packages-1",
        "expired": False,
        "digest": digest,
    }
    identity: dict[str, JsonValue] = {
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
    assert isinstance(result, FreshValidationRequired)
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
    assert isinstance(result, VerifiedArtifact)


@pytest.mark.parametrize("case", ["cancelled", "changed-source", "malformed"])
def test_failed_or_changed_main_cannot_supply_artifacts(tmp_path: Path, case: str) -> None:
    bundle = _archive(tmp_path)
    archive, digest = bundle.path, bundle.digest
    responses = _responses(digest)
    responses[4] = {
        "cancelled": _run(conclusion="cancelled"),
        "changed-source": _run(head_sha=OTHER),
        "malformed": _run(conclusion={"unexpected": True}),
    }[case]
    destination = tmp_path / "out"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, archive)
    )
    assert isinstance(result, FreshValidationRequired)
    assert not destination.exists()


@pytest.mark.parametrize("conclusion", [None, "failure"])
def test_packages_remain_qualified_when_only_docs_fail_or_are_pending(
    tmp_path: Path, conclusion: str | None
) -> None:
    bundle = _archive(tmp_path)
    responses = _responses(bundle.digest)
    run = _run(conclusion=conclusion, status="in_progress" if conclusion is None else "completed")
    responses[0] = {"total_count": 1, "workflow_runs": [run]}
    responses[4] = run
    gateway = Gateway(responses, bundle.path)
    assert isinstance(
        reuse("owner/repo", SHA, "packages", tmp_path / "out", transport=gateway),
        VerifiedArtifact,
    )
    assert not gateway.responses


@pytest.mark.parametrize("final_conclusion", ["success", "failure"])
def test_legacy_artifacts_require_successful_full_ci_through_final_snapshot(
    tmp_path: Path, final_conclusion: str
) -> None:
    bundle = _archive(tmp_path)
    responses = _responses(bundle.digest)
    legacy: dict[str, JsonValue] = {
        "total_count": 2,
        "jobs": [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in ("Build and install artifacts", "CI / gate")
        ],
    }
    responses[1] = legacy
    responses[3] = legacy
    responses[4] = _run(conclusion=final_conclusion)
    destination = tmp_path / "out"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, bundle.path)
    )
    expected = VerifiedArtifact if final_conclusion == "success" else FreshValidationRequired
    assert isinstance(result, expected)
    assert destination.exists() == (final_conclusion == "success")


@pytest.mark.parametrize("index", [1, 3])
@pytest.mark.parametrize(
    "state", ["failure", "skipped", "cancelled", "pending", "missing", "duplicate"]
)
def test_package_gate_must_succeed_before_and_after_download(
    tmp_path: Path, index: int, state: str
) -> None:
    bundle = _archive(tmp_path)
    responses = _responses(bundle.digest)
    jobs: list[JsonValue] = [
        {"name": "Build and install artifacts", "status": "completed", "conclusion": "success"}
    ]
    gate: dict[str, JsonValue] = {
        "name": "CI / packages",
        "status": "in_progress" if state == "pending" else "completed",
        "conclusion": None if state == "pending" else state,
    }
    if state != "missing":
        jobs.append(gate)
    if state == "duplicate":
        gate["conclusion"] = "success"
        jobs.append(gate)
    responses[index] = {"total_count": len(jobs), "jobs": jobs}
    destination = tmp_path / "out"
    assert isinstance(
        reuse(
            "owner/repo", SHA, "packages", destination, transport=Gateway(responses, bundle.path)
        ),
        FreshValidationRequired,
    )
    assert not destination.exists()


@pytest.mark.parametrize("conclusion", [None, "failure"])
def test_site_requires_successful_whole_ci(tmp_path: Path, conclusion: str | None) -> None:
    bundle = _archive(tmp_path)
    run = _run(conclusion=conclusion, status="in_progress" if conclusion is None else "completed")
    destination = tmp_path / "site"
    result = reuse(
        "owner/repo",
        SHA,
        "site",
        destination,
        transport=Gateway([{"total_count": 1, "workflow_runs": [run]}], bundle.path),
    )
    expected = AwaitingArtifact if conclusion is None else FreshValidationRequired
    assert isinstance(result, expected)
    assert not destination.exists()


@pytest.mark.parametrize("test_jobs", ["2", "4"])
@pytest.mark.parametrize("failed_check", ["none", "ruff", "basedpyright", "pytest"])
def test_parallel_ci_waits_for_all_checks_and_propagates_failure(
    tmp_path: Path, failed_check: str, test_jobs: str
) -> None:
    object_map = TypeAdapter(dict[str, JsonValue])
    objects = TypeAdapter(list[dict[str, JsonValue]])
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
        '*) name=pytest; printf "%s\\n" "$@" > "$ARGUMENTS";; esac\n'
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
            "ARGUMENTS": str(tmp_path / "arguments"),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
            "RUNNER_TEMP": str(tmp_path),
            "TEST_BASE": "",
            "TEST_JOBS": test_jobs,
        },
    )
    assert (process.returncode == 0) == (failed_check == "none"), process.stderr
    assert sorted((tmp_path / "results").read_text().splitlines()) == [
        "basedpyright",
        "pytest",
        "ruff",
    ]
    assert len((tmp_path / "summary").read_text().splitlines()) == 3
    arguments = (tmp_path / "arguments").read_text().splitlines()
    assert arguments.count("--jobs") == 1
    assert arguments[arguments.index("--jobs") + 1] == test_jobs


@pytest.mark.parametrize("index", [0, 1, 2])
def test_boolean_collection_counts_cannot_qualify_artifacts(tmp_path: Path, index: int) -> None:
    bundle = _archive(tmp_path)
    responses = _responses(bundle.digest)
    response = responses[index]
    assert isinstance(response, dict)
    response["total_count"] = True
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, bundle.path)
    )
    assert isinstance(result, FreshValidationRequired)
    assert not destination.exists()


@pytest.mark.parametrize("field", ["id", "repository_id", "head_repository_id"])
def test_boolean_artifact_identity_cannot_match_an_integer(tmp_path: Path, field: str) -> None:
    bundle = _archive(tmp_path)
    responses = _responses(bundle.digest)
    responses[0] = {
        "total_count": 1,
        "workflow_runs": [_run(id=1, head_repository={"id": 1, "full_name": "owner/repo"})],
    }
    identity: dict[str, JsonValue] = {
        "id": 1,
        "head_sha": SHA,
        "head_branch": "main",
        "repository_id": 1,
        "head_repository_id": 1,
    }
    identity[field] = True
    responses[2] = {
        "total_count": 1,
        "artifacts": [
            {
                "id": 9,
                "name": "tested-packages-1",
                "expired": False,
                "digest": bundle.digest,
                "workflow_run": identity,
            }
        ],
    }
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo", SHA, "packages", destination, transport=Gateway(responses, bundle.path)
    )
    assert isinstance(result, FreshValidationRequired)
    assert not destination.exists()


@pytest.mark.parametrize("nonfinite", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_provider_json_cannot_qualify_artifacts(tmp_path: Path, nonfinite: float) -> None:
    bundle = _archive(tmp_path)
    destination = tmp_path / "verified"
    result = reuse(
        "owner/repo",
        SHA,
        "packages",
        destination,
        transport=Gateway([nonfinite], bundle.path),
    )
    assert isinstance(result, FreshValidationRequired)
    assert not destination.exists()
