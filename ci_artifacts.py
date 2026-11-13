"""Reuse only immutable artifacts from this repository's exact main CI revision."""

from __future__ import annotations

import argparse  # ruff: ignore[banned-api] -- dependency-free artifact bootstrap runs before uv installs the project.
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] -- fixed GitHub API argv only
import tempfile
import time
from typing import ClassVar, Final, Literal, NewType, Protocol, TypeGuard
from zipfile import BadZipFile, ZipFile, ZipInfo


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ArtifactKind = Literal["packages", "site"]
type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None
_JOBS: Final[dict[ArtifactKind, str]] = {
    "packages": "Build and install artifacts",
    "site": "Build documentation",
}
_MAX_BYTES = 100_000_000
_MAX_FILES = 10_000
_MAX_WAIT = 300
WorkflowRunId = NewType("WorkflowRunId", int)
WorkflowRunAttempt = NewType("WorkflowRunAttempt", int)
CIArtifactId = NewType("CIArtifactId", int)
CIArtifactDigest = NewType("CIArtifactDigest", str)
SourceCommit = NewType("SourceCommit", str)


class Transport(Protocol):
    def get(self, endpoint: str) -> JsonValue: ...
    def download(self, endpoint: str, destination: Path) -> None: ...


@dataclass(frozen=True)
class GitHub:
    executable: str

    def get(self, endpoint: str) -> JsonValue:
        process = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- fixed argv, never a shell.
            (self.executable, "api", "--method", "GET", endpoint),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        result: object = json.loads(process.stdout)  # pyright: ignore[reportAny] -- stdlib decoder boundary; recursively validated before returning.
        return json_value(result)

    def download(self, endpoint: str, destination: Path) -> None:
        with destination.open("wb") as stream:
            subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- binary response goes directly to a bounded archive verifier.
                (self.executable, "api", endpoint),
                check=True,
                stdout=stream,
                timeout=60,
            )


@dataclass(frozen=True)
class VerifiedArtifact:
    kind: ClassVar[Literal["verified"]] = "verified"
    source: SourceCommit
    run: RunIdentity
    artifact: Artifact

    @property
    def reason(self) -> str:
        return f"verified exact main CI {self.run.identifier}, attempt {self.run.attempt}"


@dataclass(frozen=True)
class AwaitingArtifact:
    kind: ClassVar[Literal["awaiting"]] = "awaiting"
    reason: str


@dataclass(frozen=True)
class FreshValidationRequired:
    kind: ClassVar[Literal["fresh-validation-required"]] = "fresh-validation-required"
    reason: str


type Result = VerifiedArtifact | AwaitingArtifact | FreshValidationRequired


def json_object(value: object) -> dict[str, JsonValue]:
    result = json_value(value)
    match result:
        case dict():
            return result
        case _:
            message = "invalid GitHub object"
            raise ValueError(message)


def json_value(value: object) -> JsonValue:
    match value:
        case None | str() | bool() | int():
            return value
        case float() if math.isfinite(value):
            return value
        case _:
            if _is_array(value):
                return [json_value(item) for item in value]
            if _is_object(value):
                result: dict[str, JsonValue] = {}
                for key, item in value.items():
                    if not isinstance(key, str):
                        message = "invalid JSON object key"
                        raise TypeError(message)
                    result[key] = json_value(item)
                return result
            message = "invalid JSON value"
            raise ValueError(message)


def _is_array(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_object(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def collection_rows(value: object, name: str) -> list[dict[str, JsonValue]]:
    response = json_object(value)
    rows = response.get(name)
    count = response.get("total_count")
    if not isinstance(rows, list) or type(count) is not int or count != len(rows):
        message = "incomplete GitHub response"
        raise ValueError(message)
    return [json_object(row) for row in rows]


def positive_integer(value: object) -> int:
    if type(value) is not int or value <= 0:
        message = "invalid GitHub identifier or attempt"
        raise ValueError(message)
    return value


def extract(archive: Path, destination: Path, *, digest: str, sha: str, kind: ArtifactKind) -> None:
    if kind not in _JOBS:
        message = "invalid CI artifact kind"
        raise ValueError(message)
    with archive.open("rb") as stream:
        if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            message = "CI archive digest mismatch"
            raise ValueError(message)
    with ZipFile(archive) as bundle:
        members = bundle.infolist()
        paths = _archive_paths(members, kind)
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


def _archive_paths(members: list[ZipInfo], kind: ArtifactKind) -> list[PurePosixPath]:
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
    return paths


def lookup(
    repository: str, sha: str, kind: ArtifactKind, destination: Path, transport: Transport
) -> Result:
    if (
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
        or _SHA.fullmatch(sha) is None
        or kind not in _JOBS
    ):
        message = "CI reuse requires repository, full commit SHA and artifact kind"
        raise ValueError(message)
    runs = collection_rows(
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
        and json_object(run.get("head_repository")).get("full_name") == repository
    ]
    if not owned:
        return AwaitingArtifact("waiting for exact main CI")
    run = max(owned, key=lambda row: positive_integer(row.get("id")))
    identity = _identity(run)
    artifact = _find_artifact(run, repository, sha, kind, transport)
    if isinstance(artifact, AwaitingArtifact | FreshValidationRequired):
        return artifact
    with tempfile.TemporaryDirectory(prefix="repo-standards-ci-") as temporary:
        archive = Path(temporary) / "artifact.zip"
        transport.download(
            f"repos/{repository}/actions/artifacts/{artifact.identifier}/zip", archive
        )
        staged = Path(temporary) / "verified"
        extract(archive, staged, digest=artifact.digest, sha=sha, kind=kind)
        latest = json_object(
            transport.get(f"repos/{repository}/actions/runs/{identity.identifier}")
        )
        if (
            _identity(latest) != identity
            or latest.get("head_sha") != sha
            or (latest.get("conclusion") is not None and latest.get("conclusion") != "success")
        ):
            return FreshValidationRequired("CI changed while verifying its artifact")
        shutil.copytree(staged, destination, dirs_exist_ok=True)
    return VerifiedArtifact(SourceCommit(sha), identity, artifact)


@dataclass(frozen=True)
class RunIdentity:
    identifier: WorkflowRunId
    attempt: WorkflowRunAttempt


@dataclass(frozen=True)
class Artifact:
    kind: ClassVar[Literal["artifact"]] = "artifact"
    identifier: CIArtifactId
    digest: CIArtifactDigest


def _identity(run: dict[str, JsonValue]) -> RunIdentity:
    return RunIdentity(
        WorkflowRunId(positive_integer(run.get("id"))),
        WorkflowRunAttempt(positive_integer(run.get("run_attempt"))),
    )


def _find_artifact(
    run: dict[str, JsonValue], repository: str, sha: str, kind: ArtifactKind, transport: Transport
) -> Artifact | AwaitingArtifact | FreshValidationRequired:
    identity = _identity(run)
    run_id, attempt = identity.identifier, identity.attempt
    conclusion = run.get("conclusion")
    if conclusion is not None and conclusion != "success":
        return FreshValidationRequired("exact main CI failed; fresh validation required")
    jobs = collection_rows(
        transport.get(f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100"), "jobs"
    )
    selected = [job for job in jobs if job.get("name") == _JOBS[kind]]
    if len(selected) != 1 or selected[0].get("status") != "completed":
        return (
            AwaitingArtifact("waiting for successful artifact job")
            if conclusion is None
            else FreshValidationRequired("waiting for successful artifact job")
        )
    if selected[0].get("conclusion") != "success":
        return FreshValidationRequired("artifact job did not succeed")
    artifacts = collection_rows(
        transport.get(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"),
        "artifacts",
    )
    selected = [
        item
        for item in artifacts
        if item.get("name") == f"tested-{kind}-{attempt}" and item.get("expired") is False
    ]
    if len(selected) != 1:
        return FreshValidationRequired("current-attempt artifact missing or expired")
    artifact = selected[0]
    artifact_identity = json_object(artifact.get("workflow_run"))
    repository_id = positive_integer(json_object(run.get("head_repository")).get("id"))
    digest = artifact.get("digest")
    actual = (
        positive_integer(artifact_identity.get("id")),
        artifact_identity.get("head_sha"),
        artifact_identity.get("head_branch"),
        positive_integer(artifact_identity.get("repository_id")),
        positive_integer(artifact_identity.get("head_repository_id")),
    )
    expected = (run_id, sha, "main", repository_id, repository_id)
    if actual != expected or not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        return FreshValidationRequired(
            "artifact identity or digest does not match exact main CI",
        )
    return Artifact(CIArtifactId(positive_integer(artifact.get("id"))), CIArtifactDigest(digest))


def reuse(  # ruff: ignore[too-many-arguments] -- explicit artifact identity plus bounded wait and injected transport.
    repository: str,
    sha: str,
    kind: ArtifactKind,
    destination: Path,
    *,
    wait: int = 0,
    transport: Transport | None = None,
) -> Result:
    if type(wait) is not int or not 0 <= wait <= _MAX_WAIT:
        return FreshValidationRequired("fresh validation: invalid wait bound")
    client = GitHub(shutil.which("gh") or "gh") if transport is None else transport
    deadline = time.monotonic() + wait
    while True:
        try:
            result = lookup(repository, sha, kind, destination, client)
        except (
            OSError,
            TypeError,
            ValueError,
            KeyError,
            BadZipFile,
            subprocess.SubprocessError,
        ) as error:
            return FreshValidationRequired(
                f"fresh validation: CI proof unavailable ({type(error).__name__})",
            )
        if not isinstance(result, AwaitingArtifact) or time.monotonic() >= deadline:
            return result
        time.sleep(min(3, max(0, deadline - time.monotonic())))


class Arguments(argparse.Namespace):
    repository: str = ""
    sha: str = ""
    kind: ArtifactKind = "packages"
    destination: Path = Path()
    github_output: Path = Path()
    summary: Path = Path()
    wait: int = 0


def main() -> None:
    parser = argparse.ArgumentParser(  # sarj-noqa: SARJ533 -- pre-install CLI; typed decode.
        description=__doc__
    )
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
        stream.write(f"reused={str(isinstance(result, VerifiedArtifact)).lower()}\n")
    with args.summary.open("a") as stream:
        stream.write(
            f"CI artifact ({args.kind}): {result.reason}; {time.monotonic() - started:.2f}s\n"
        )
    print(result.reason)  # ruff: ignore[print] -- command-line reuse/fallback explanation.


if __name__ == "__main__":
    main()
