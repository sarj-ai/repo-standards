"""Reuse full validation of an identical, recently merged, own-repository PR tree."""

from __future__ import annotations

import argparse  # ruff: ignore[banned-api] -- dependency-free CI bootstrap.
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] -- fixed read-only Git argv.
import tempfile
from zipfile import BadZipFile, ZipFile

from ci_artifacts import GitHub, Result, Transport, _object, _positive, _rows  # ruff: ignore[import-private-name] # pyright: ignore[reportPrivateUsage] -- shared validated provider boundaries in sibling CI bootstraps.


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_AGE = timedelta(hours=24)
_MAX_PROOF_BYTES = 4096
_MAX_PROVIDER_ROWS = 100
_JOB = "Validate / Python 3.14"


def _git(root: Path, revision: str) -> str:
    value = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- fixed read-only Git command.
        (shutil.which("git") or "git", "rev-parse", revision),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if _SHA.fullmatch(value) is None:
        message = "invalid checked Git identity"
        raise ValueError(message)
    return value


def record(root: Path, plan_path: Path, destination: Path, environment: dict[str, str]) -> None:
    plan = _object(json.loads(plan_path.read_text(encoding="utf-8")))
    tests = plan.get("tests")
    all_tests = sorted(
        path.relative_to(root).as_posix() for path in (root / "tests").rglob("test_*.py")
    )
    if (
        not all_tests
        or tests != all_tests
        or type(plan.get("total_files")) is not int
        or len(tests) != plan["total_files"]
    ):
        return
    event = _object(json.loads(Path(environment["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8")))
    base = _object(_object(event["pull_request"])["base"])["sha"]
    if not isinstance(base, str) or _SHA.fullmatch(base) is None:
        message = "invalid reviewed comparison base"
        raise ValueError(message)
    destination.mkdir(parents=True, exist_ok=True)
    proof = {
        "schema_version": 1,
        "repository": environment["GITHUB_REPOSITORY"],
        "source_commit": _git(root, "HEAD"),
        "tree": _git(root, "HEAD^{tree}"),
        "comparison_base": base,
        "run_id": _positive(int(environment["GITHUB_RUN_ID"])),
        "run_attempt": _positive(int(environment["GITHUB_RUN_ATTEMPT"])),
        "full_validation": True,
    }
    (destination / "proof.json").write_text(json.dumps(proof, sort_keys=True) + "\n")


def reuse(
    root: Path, repository: str, sha: str, base: str, *, client: Transport | None = None
) -> Result:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None or any(
        _SHA.fullmatch(value) is None for value in (sha, base)
    ):
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: invalid repository or commit identity",
        )
    try:
        return _lookup(root, repository, sha, base, client or GitHub(shutil.which("gh") or "gh"))
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        BadZipFile,
        subprocess.SubprocessError,
    ) as error:
        return Result(
            reused=False,
            waiting=False,
            reason=f"fresh validation: reviewed evidence unavailable ({type(error).__name__})",
        )


def _lookup(  # ruff: ignore[too-many-return-statements] -- independent proof gates fall back to fresh checks.
    root: Path, repository: str, sha: str, base: str, client: Transport
) -> Result:
    if _git(root, "HEAD") != sha or _git(root, f"{sha}^") != base:
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: push base differs from checked merge parent",
        )
    run = _find_run(repository, sha, client)
    if run is None:
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: no recent successful own-repository merged PR",
        )
    run_id, attempt = _positive(run["id"]), _positive(run["run_attempt"])
    jobs = _rows(client.get(f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100"), "jobs")
    selected_jobs = [job for job in jobs if job.get("name") == _JOB]
    if len(selected_jobs) != 1 or (
        selected_jobs[0].get("status"),
        selected_jobs[0].get("conclusion"),
    ) != ("completed", "success"):
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: full validation job did not succeed",
        )
    artifacts = _rows(
        client.get(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"), "artifacts"
    )
    selected = [
        item
        for item in artifacts
        if item.get("name") == f"reviewed-validation-{attempt}" and item.get("expired") is False
    ]
    if len(selected) != 1:
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: current-attempt full-test proof is missing",
        )
    artifact = selected[0]
    identity = _object(artifact.get("workflow_run"))
    repository_id = _positive(_object(run["head_repository"])["id"])
    if tuple(
        identity.get(key) for key in ("id", "head_sha", "repository_id", "head_repository_id")
    ) != (run_id, run["head_sha"], repository_id, repository_id):
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: reviewed artifact ownership mismatch",
        )
    digest = artifact.get("digest")
    if not isinstance(digest, str):
        return Result(
            reused=False, waiting=False, reason="fresh validation: reviewed digest is absent"
        )
    expected = {
        "schema_version": 1,
        "repository": repository,
        "tree": _git(root, f"{sha}^{{tree}}"),
        "comparison_base": base,
        "run_id": run_id,
        "run_attempt": attempt,
        "full_validation": True,
    }
    with tempfile.TemporaryDirectory(prefix="repo-reviewed-validation-") as temporary:
        archive = Path(temporary) / "proof.zip"
        client.download(
            f"repos/{repository}/actions/artifacts/{_positive(artifact['id'])}/zip", archive
        )
        _verify_proof(archive, digest, expected)
    latest = _object(client.get(f"repos/{repository}/actions/runs/{run_id}"))
    if latest != run:
        return Result(
            reused=False,
            waiting=False,
            reason="fresh validation: reviewed CI changed during proof verification",
        )
    return Result(
        reused=True,
        waiting=False,
        reason=f"identical tree and base fully validated in CI {run_id}, attempt {attempt}",
    )


def _find_run(  # ruff: ignore[too-many-return-statements] -- conservative evidence gates.
    repository: str, sha: str, client: Transport
) -> dict[str, object] | None:
    raw = client.get(f"repos/{repository}/commits/{sha}/pulls?per_page=100")
    if not isinstance(raw, list) or len(raw) >= _MAX_PROVIDER_ROWS:
        return None
    matching: list[dict[str, object]] = []
    for value in raw:
        pull = _object(value)
        base, head = _object(pull["base"]), _object(pull["head"])
        base_repo, head_repo = _object(base.get("repo")), _object(head.get("repo"))
        if (
            pull.get("merge_commit_sha") == sha
            and pull.get("merged_at") is not None
            and base.get("ref") == "main"
            and base_repo.get("full_name") == head_repo.get("full_name") == repository
            and _positive(base_repo.get("id")) == _positive(head_repo.get("id"))
        ):
            matching.append(pull)
    if len(matching) != 1:
        return None
    head = _object(matching[0]["head"])
    head_sha = head.get("sha")
    repository_id = _positive(_object(head["repo"])["id"])
    if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
        return None
    runs = _rows(
        client.get(
            f"repos/{repository}/actions/workflows/ci.yml/runs?head_sha={head_sha}&event=pull_request&per_page=100"
        ),
        "workflow_runs",
    )
    candidates = [
        run
        for run in runs
        if run.get("head_sha") == head_sha
        and run.get("event") == "pull_request"
        and run.get("path") == ".github/workflows/ci.yml"
        and _object(run.get("head_repository")).get("full_name") == repository
        and _object(run.get("head_repository")).get("id") == repository_id
    ]
    if not candidates:
        return None
    run = max(candidates, key=lambda row: _positive(row.get("id")))
    updated = run.get("updated_at")
    if not isinstance(updated, str):
        return None
    stamp = datetime.fromisoformat(updated)
    if (
        run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or stamp.tzinfo is None
        or not timedelta(0) <= datetime.now(UTC) - stamp <= _MAX_AGE
    ):
        return None
    return run


def _verify_proof(archive: Path, digest: str, expected: dict[str, object]) -> None:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        message = "invalid reviewed artifact digest"
        raise ValueError(message)
    with archive.open("rb") as stream:
        if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            message = "reviewed artifact digest mismatch"
            raise ValueError(message)
    with ZipFile(archive) as bundle:
        members = bundle.infolist()
        if (
            len(members) != 1
            or members[0].filename != "proof.json"
            or members[0].file_size > _MAX_PROOF_BYTES
        ):
            message = "unexpected reviewed proof archive"
            raise ValueError(message)
        proof = _object(json.loads(bundle.read("proof.json")))
    source = proof.pop("source_commit", None)
    if (
        not isinstance(source, str)
        or _SHA.fullmatch(source) is None
        or any(type(proof.get(key)) is not type(value) for key, value in expected.items())
        or proof != expected
    ):
        message = "reviewed proof does not match full validation of this tree and base"
        raise ValueError(message)


class Arguments(argparse.Namespace):
    command: str
    plan: Path
    destination: Path
    repository: str
    sha: str
    base: str
    github_output: Path
    summary: Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record_parser = commands.add_parser("record")
    record_parser.add_argument("--plan", type=Path, required=True)
    record_parser.add_argument("--destination", type=Path, required=True)
    reuse_parser = commands.add_parser("reuse")
    for name in ("repository", "sha", "base"):
        reuse_parser.add_argument(f"--{name}", required=True)
    for name in ("github-output", "summary"):
        reuse_parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args(namespace=Arguments())
    root = Path(__file__).resolve().parent
    if args.command == "record":
        import os  # ruff: ignore[import-outside-top-level] -- environment read only for certificate creation.

        record(root, args.plan, args.destination, dict(os.environ))  # ruff: ignore[banned-api] -- only named CI metadata is read.
        return
    result = reuse(root, args.repository, args.sha, args.base)
    with args.github_output.open("a") as stream:
        stream.write(f"reused={str(result.reused).lower()}\n")
    with args.summary.open("a") as stream:
        stream.write(f"Reviewed validation: {result.reason}\n")


if __name__ == "__main__":
    main()
