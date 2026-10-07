"""Reuse only immutable artifacts from this repository's exact main CI revision."""

from __future__ import annotations

import argparse  # ruff: ignore[banned-api] -- dependency-free artifact bootstrap runs before uv installs the project.
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] -- fixed GitHub API argv only
import tempfile
import time
from typing import Protocol, cast  # ruff: ignore[banned-api] -- one validated JSON mapping boundary.
from zipfile import BadZipFile, ZipFile


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_JOBS = {"packages": "Build and install artifacts", "site": "Build documentation"}
_MAX_BYTES = 100_000_000
_MAX_FILES = 10_000
_MAX_WAIT = 300


class Transport(Protocol):
    def get(self, endpoint: str) -> object: ...
    def download(self, endpoint: str, destination: Path) -> None: ...


@dataclass(frozen=True)
class GitHub:
    executable: str

    def get(self, endpoint: str) -> object:
        process = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- fixed argv, never a shell.
            (self.executable, "api", "--method", "GET", endpoint),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        result: object = json.loads(process.stdout)
        return result

    def download(self, endpoint: str, destination: Path) -> None:
        with destination.open("wb") as stream:
            subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- binary response goes directly to a bounded archive verifier.
                (self.executable, "api", endpoint),
                check=True,
                stdout=stream,
                timeout=60,
            )


@dataclass(frozen=True)
class Result:
    reused: bool
    waiting: bool
    reason: str


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        message = "invalid GitHub object"
        raise ValueError(message)
    return cast("dict[str, object]", value)


def _rows(value: object, name: str) -> list[dict[str, object]]:
    response = _object(value)
    rows = response.get(name)
    if not isinstance(rows, list) or response.get("total_count") != len(rows):
        message = "incomplete GitHub response"
        raise ValueError(message)
    return [_object(row) for row in rows]


def _positive(value: object) -> int:
    if type(value) is not int or value <= 0:
        message = "invalid GitHub identifier or attempt"
        raise ValueError(message)
    return value


def extract(archive: Path, destination: Path, *, digest: str, sha: str, kind: str) -> None:
    with archive.open("rb") as stream:
        if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            message = "CI archive digest mismatch"
            raise ValueError(message)
    with ZipFile(archive) as bundle:
        members = bundle.infolist()
        paths = [PurePosixPath(member.filename) for member in members]
        if len(members) > _MAX_FILES or sum(member.file_size for member in members) > _MAX_BYTES:
            message = "CI archive exceeds size or file limits"
            raise ValueError(message)
        if len(paths) != len(set(paths)) or any(
            path.is_absolute()
            or ".." in path.parts
            or "\\" in str(path)
            or (
                kind == "packages"
                and (
                    len(path.parts) != 1
                    or (str(path) != "SOURCE_COMMIT" and path.suffix not in {".whl", ".gz"})
                )
            )
            for path in paths
        ):
            message = "unsafe or unexpected CI archive member"
            raise ValueError(message)
        if bundle.read("SOURCE_COMMIT").decode("ascii").strip() != sha:
            message = "CI archive source commit mismatch"
            raise ValueError(message)
        if kind == "packages" and not any(path.suffix == ".whl" for path in paths):
            message = "CI package archive has no wheel"
            raise ValueError(message)
        destination.mkdir(parents=True, exist_ok=True)
        for member, path in zip(members, paths, strict=True):
            if member.is_dir() or str(path) == "SOURCE_COMMIT":
                continue
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))


def lookup(repository: str, sha: str, kind: str, destination: Path, transport: Transport) -> Result:
    if (
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
        or _SHA.fullmatch(sha) is None
        or kind not in _JOBS
    ):
        message = "CI reuse requires repository, full commit SHA and artifact kind"
        raise ValueError(message)
    runs = _rows(
        transport.get(
            f"repos/{repository}/actions/workflows/ci.yml/runs?head_sha={sha}&event=push&per_page=100"
        ),
        "workflow_runs",
    )
    owned = [
        run
        for run in runs
        if run.get("head_sha") == sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("path") == ".github/workflows/ci.yml"
        and _object(run.get("head_repository")).get("full_name") == repository
    ]
    if not owned:
        return Result(reused=False, waiting=True, reason="waiting for exact main CI")
    run = max(owned, key=lambda row: _positive(row.get("id")))
    identity = _identity(run)
    artifact = _find_artifact(run, repository, sha, kind, transport)
    if isinstance(artifact, Result):
        return artifact
    with tempfile.TemporaryDirectory(prefix="repo-standards-ci-") as temporary:
        archive = Path(temporary) / "artifact.zip"
        transport.download(
            f"repos/{repository}/actions/artifacts/{artifact.identifier}/zip", archive
        )
        staged = Path(temporary) / "verified"
        extract(archive, staged, digest=artifact.digest, sha=sha, kind=kind)
        latest = _object(transport.get(f"repos/{repository}/actions/runs/{identity.identifier}"))
        if (
            _identity(latest) != identity
            or latest.get("head_sha") != sha
            or (latest.get("conclusion") is not None and latest.get("conclusion") != "success")
        ):
            return Result(
                reused=False, waiting=False, reason="CI changed while verifying its artifact"
            )
        shutil.copytree(staged, destination, dirs_exist_ok=True)
    return Result(
        reused=True,
        waiting=False,
        reason=f"verified exact main CI {identity.identifier}, attempt {identity.attempt}",
    )


@dataclass(frozen=True)
class RunIdentity:
    identifier: int
    attempt: int


@dataclass(frozen=True)
class Artifact:
    identifier: int
    digest: str


def _identity(run: dict[str, object]) -> RunIdentity:
    return RunIdentity(_positive(run.get("id")), _positive(run.get("run_attempt")))


def _find_artifact(
    run: dict[str, object], repository: str, sha: str, kind: str, transport: Transport
) -> Artifact | Result:
    identity = _identity(run)
    run_id, attempt = identity.identifier, identity.attempt
    conclusion = run.get("conclusion")
    if conclusion is not None and conclusion != "success":
        return Result(
            reused=False, waiting=False, reason="exact main CI failed; fresh validation required"
        )
    jobs = _rows(
        transport.get(f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100"), "jobs"
    )
    selected = [job for job in jobs if job.get("name") == _JOBS[kind]]
    if len(selected) != 1 or selected[0].get("status") != "completed":
        return Result(
            reused=False, waiting=conclusion is None, reason="waiting for successful artifact job"
        )
    if selected[0].get("conclusion") != "success":
        return Result(reused=False, waiting=False, reason="artifact job did not succeed")
    artifacts = _rows(
        transport.get(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"),
        "artifacts",
    )
    selected = [
        item
        for item in artifacts
        if item.get("name") == f"tested-{kind}-{attempt}" and item.get("expired") is False
    ]
    if len(selected) != 1:
        return Result(
            reused=False, waiting=False, reason="current-attempt artifact missing or expired"
        )
    artifact = selected[0]
    identity = _object(artifact.get("workflow_run"))
    repository_id = _positive(_object(run.get("head_repository")).get("id"))
    digest = artifact.get("digest")
    actual = tuple(
        identity.get(key)
        for key in ("id", "head_sha", "head_branch", "repository_id", "head_repository_id")
    )
    expected = (run_id, sha, "main", repository_id, repository_id)
    if actual != expected or not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        return Result(
            reused=False,
            waiting=False,
            reason="artifact identity or digest does not match exact main CI",
        )
    return Artifact(_positive(artifact.get("id")), digest)


def reuse(  # ruff: ignore[too-many-arguments] -- explicit artifact identity plus bounded wait and injected transport.
    repository: str,
    sha: str,
    kind: str,
    destination: Path,
    *,
    wait: int = 0,
    transport: Transport | None = None,
) -> Result:
    if not 0 <= wait <= _MAX_WAIT:
        return Result(reused=False, waiting=False, reason="fresh validation: invalid wait bound")
    client = GitHub(shutil.which("gh") or "gh") if transport is None else transport
    deadline = time.monotonic() + wait
    while True:
        try:
            result = lookup(repository, sha, kind, destination, client)
        except (OSError, ValueError, KeyError, BadZipFile, subprocess.SubprocessError) as error:
            return Result(
                reused=False,
                waiting=False,
                reason=f"fresh validation: CI proof unavailable ({type(error).__name__})",
            )
        if not result.waiting or time.monotonic() >= deadline:
            return result
        time.sleep(min(3, max(0, deadline - time.monotonic())))


class Arguments(argparse.Namespace):
    repository: str
    sha: str
    kind: str
    destination: Path
    github_output: Path
    summary: Path
    wait: int


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--kind", choices=tuple(_JOBS), required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--wait", type=int, default=180)
    args = parser.parse_args(namespace=Arguments())
    started = time.monotonic()
    result = reuse(args.repository, args.sha, args.kind, args.destination, wait=args.wait)
    with args.github_output.open("a") as stream:
        stream.write(f"reused={str(result.reused).lower()}\n")
    with args.summary.open("a") as stream:
        stream.write(
            f"CI artifact ({args.kind}): {result.reason}; {time.monotonic() - started:.2f}s\n"
        )
    print(result.reason)  # ruff: ignore[print] -- command-line reuse/fallback explanation.


if __name__ == "__main__":
    main()
