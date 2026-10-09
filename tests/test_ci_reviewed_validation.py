from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile

import pytest

from ci_reviewed_validation import record, reuse
from tests.test_public_content import OBJECT_MAP


REPOSITORY = "owner/repo"
BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40


def _git(root: Path, *argv: str) -> str:
    return subprocess.run(
        (shutil.which("git") or "git", *argv), cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


@dataclass(frozen=True)
class RepositoryFixture:
    root: Path
    base: str
    sha: str
    tree: str


@pytest.fixture
def repository(tmp_path: Path) -> RepositoryFixture:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "config", "user.email", "fixture@example.invalid")
    (root / "tests").mkdir()
    (root / "tests/test_one.py").write_text("assert True\n")
    _git(root, "add", ".")
    _git(root, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "source.py").write_text("value = 1\n")
    _git(root, "add", ".")
    _git(root, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "merge")
    return RepositoryFixture(
        root, base, _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")
    )


def _run(*, run_id: int = 7, conclusion: str | None = "success") -> dict[str, object]:
    return {
        "id": run_id,
        "run_attempt": 1,
        "head_sha": HEAD,
        "event": "pull_request",
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": conclusion,
        "head_repository": {"id": 3, "full_name": REPOSITORY},
        "updated_at": datetime.now(UTC).isoformat(),
    }


@dataclass
class Gateway:
    responses: list[object]
    archive: Path
    downloads: int = 0

    def get(self, endpoint: str) -> object:
        assert endpoint.startswith(f"repos/{REPOSITORY}/")
        return self.responses.pop(0)

    def download(self, endpoint: str, destination: Path) -> None:
        assert endpoint == f"repos/{REPOSITORY}/actions/artifacts/9/zip"
        self.downloads += 1
        destination.write_bytes(self.archive.read_bytes())


def _gateway(  # ruff: ignore[too-many-branches] -- independent negative provider fixtures.
    tmp_path: Path, base: str, sha: str, tree: str, *, case: str = "valid"
) -> Gateway:
    proof: dict[str, object] = {
        "schema_version": 1,
        "repository": REPOSITORY,
        "source_commit": HEAD,
        "tree": tree,
        "comparison_base": base,
        "run_id": 7,
        "run_attempt": 1,
        "full_validation": True,
    }
    if case in {"tree", "comparison_base", "repository", "source_commit"}:
        proof[case] = "wrong"
    if case == "partial":
        proof["full_validation"] = False
    if case == "boolean-id":
        proof["run_attempt"] = True
    if case == "integer-full":
        proof["full_validation"] = 1
    archive = tmp_path / "proof.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("proof.json", json.dumps(proof))
        if case == "unsafe":
            bundle.writestr("../escape", "bad")
        if case == "duplicate":
            with pytest.warns(UserWarning, match="Duplicate name"):
                bundle.writestr("proof.json", json.dumps(proof))
    digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    if case == "digest":
        digest = "sha256:" + "0" * 64
    run = _run()
    if case == "old":
        run["updated_at"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    if case == "failed":
        run["conclusion"] = "failure"
    if case == "pending":
        run.update(status="in_progress", conclusion=None)
    if case == "wrong-workflow":
        run["path"] = ".github/workflows/other.yml"
    branch = {"ref": "main", "sha": base, "repo": {"id": 3, "full_name": REPOSITORY}}
    pull: dict[str, object] = {
        "merge_commit_sha": sha,
        "merged_at": "now",
        "base": branch,
        "head": {**branch, "sha": HEAD},
    }
    if case == "fork":
        pull["head"] = {**branch, "sha": HEAD, "repo": {"id": 4, "full_name": "fork/repo"}}
    if case == "unmerged":
        pull["merged_at"] = None
    artifact = {
        "id": 9,
        "name": "reviewed-validation-1",
        "expired": False,
        "digest": digest,
        "workflow_run": {"id": 7, "head_sha": HEAD, "repository_id": 3, "head_repository_id": 3},
    }
    if case == "expired":
        artifact["expired"] = True
    if case == "wrong-attempt":
        artifact["name"] = "reviewed-validation-2"
    if case == "artifact-fork":
        artifact["workflow_run"] = {
            "id": 7,
            "head_sha": HEAD,
            "repository_id": 3,
            "head_repository_id": 4,
        }
    latest = {**run, "run_attempt": 2} if case == "race" else run
    jobs = [{"name": "Validate / Python 3.15", "status": "completed", "conclusion": "success"}]
    if case == "job-failed":
        jobs[0]["conclusion"] = "failure"
    rows = [run, _run(run_id=8, conclusion="failure")] if case == "newer-failed" else [run]
    return Gateway(
        [
            [pull],
            {"total_count": len(rows) + (case == "truncated"), "workflow_runs": rows},
            {"total_count": len(jobs), "jobs": jobs},
            {"total_count": 1, "artifacts": [artifact]},
            latest,
        ],
        archive,
    )


def test_full_exact_tree_proof_reuses_validation(
    repository: RepositoryFixture, tmp_path: Path
) -> None:
    root, base, sha, tree = repository.root, repository.base, repository.sha, repository.tree
    gateway = _gateway(tmp_path, base, sha, tree)
    result = reuse(root, REPOSITORY, sha, base, client=gateway)
    assert result.reused
    assert "identical tree" in result.reason
    assert gateway.downloads == 1
    assert not gateway.responses


@pytest.mark.parametrize(
    "case",
    [
        "tree",
        "comparison_base",
        "repository",
        "source_commit",
        "partial",
        "boolean-id",
        "integer-full",
        "unsafe",
        "duplicate",
        "digest",
        "old",
        "failed",
        "pending",
        "wrong-workflow",
        "fork",
        "unmerged",
        "expired",
        "wrong-attempt",
        "artifact-fork",
        "race",
        "job-failed",
        "truncated",
        "newer-failed",
    ],
)
def test_wrong_or_unavailable_proof_requires_fresh_validation(
    repository: RepositoryFixture, tmp_path: Path, case: str
) -> None:
    root, base, sha, tree = repository.root, repository.base, repository.sha, repository.tree
    assert not reuse(
        root, REPOSITORY, sha, base, client=_gateway(tmp_path, base, sha, tree, case=case)
    ).reused


@pytest.mark.parametrize("changed", ["base", "sha"])
def test_local_checkout_and_push_parent_must_match(
    repository: RepositoryFixture, tmp_path: Path, changed: str
) -> None:
    root, base, sha, tree = repository.root, repository.base, repository.sha, repository.tree
    gateway = _gateway(tmp_path, base, sha, tree)
    result = reuse(
        root,
        REPOSITORY,
        BASE if changed == "sha" else sha,
        BASE if changed == "base" else base,
        client=gateway,
    )
    assert not result.reused
    assert gateway.downloads == 0


@pytest.mark.parametrize("full", [False, True])
def test_record_requires_every_actual_test_file(
    repository: RepositoryFixture, tmp_path: Path, full: bool
) -> None:
    root, base, sha, tree = repository.root, repository.base, repository.sha, repository.tree
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"base": {"sha": base}}}))
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {"tests": ["tests/test_one.py"] if full else ["tests/test_fake.py"], "total_files": 1}
        )
    )
    destination = tmp_path / "recorded"
    record(
        root,
        plan,
        destination,
        {
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_RUN_ID": "7",
            "GITHUB_RUN_ATTEMPT": "1",
        },
    )
    if full:
        proof = OBJECT_MAP.validate_json((destination / "proof.json").read_text(), strict=True)
        assert proof["source_commit"] == sha
        assert proof["tree"] == tree
        assert proof["full_validation"] is True
    else:
        assert not destination.exists()
