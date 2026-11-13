"""Reuse full validation of an identical, recently merged, own-repository PR tree.

Only successful full-suite CI within 24 hours can qualify. Partial cohorts,
changed bases, forks, expired artifacts or unavailable proof require fresh checks.
Dependency audits and exact-main package/documentation builds remain fresh.
Manual and scheduled CI always run all tests.
"""

from __future__ import annotations

import argparse  # ruff: ignore[banned-api] -- dependency-free CI bootstrap.
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] -- fixed read-only Git argv.
import tempfile
from typing import ClassVar, Literal, NewType, assert_never
from zipfile import BadZipFile, ZipFile

from ci_artifacts import (
    Artifact,
    CIArtifactDigest,
    CIArtifactId,
    FreshValidationRequired,
    GitHub,
    JsonValue,
    RunIdentity,
    SourceCommit,
    Transport,
    WorkflowRunAttempt,
    WorkflowRunId,
    collection_rows,
    json_object,
    positive_integer,
)
from test_selection import discover_test_files


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_AGE = timedelta(hours=24)
_MAX_PROOF_BYTES = 4096
_MAX_PROVIDER_ROWS = 100
_JOB = "Validate / Python 3.15"
GitTreeId = NewType("GitTreeId", str)


@dataclass(frozen=True)
class VerifiedReviewedValidation:
    kind: ClassVar[Literal["reviewed-validation"]] = "reviewed-validation"
    source: SourceCommit
    comparison_base: SourceCommit
    tree: GitTreeId
    reviewed_source: SourceCommit
    run: RunIdentity
    artifact: Artifact

    @property
    def reason(self) -> str:
        return (
            f"identical tree and base fully validated in CI {self.run.identifier}, "
            f"attempt {self.run.attempt}"
        )


type ReviewedValidation = VerifiedReviewedValidation | FreshValidationRequired


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
    decoded_plan: object = json.loads(plan_path.read_text(encoding="utf-8"))  # pyright: ignore[reportAny] -- stdlib JSON boundary; json_object recursively validates all fields.
    plan = json_object(decoded_plan)
    tests = plan.get("tests")
    all_tests = list(discover_test_files(root))
    if (
        not all_tests
        or not isinstance(tests, list)
        or tests != all_tests
        or type(plan.get("total_files")) is not int
        or len(tests) != plan["total_files"]
    ):
        return
    decoded_event: object = json.loads(  # pyright: ignore[reportAny] -- decoder output is recursively validated below.
        Path(environment["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8")
    )
    event = json_object(decoded_event)
    base = json_object(json_object(event["pull_request"])["base"])["sha"]
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
        "run_id": positive_integer(int(environment["GITHUB_RUN_ID"])),
        "run_attempt": positive_integer(int(environment["GITHUB_RUN_ATTEMPT"])),
        "full_validation": True,
    }
    (destination / "proof.json").write_text(json.dumps(proof, sort_keys=True) + "\n")


def reuse(
    root: Path, repository: str, sha: str, base: str, *, client: Transport | None = None
) -> ReviewedValidation:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None or any(
        _SHA.fullmatch(value) is None for value in (sha, base)
    ):
        return FreshValidationRequired(
            "fresh validation: invalid repository or commit identity",
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
        return FreshValidationRequired(
            f"fresh validation: reviewed evidence unavailable ({type(error).__name__})",
        )


def _lookup(  # ruff: ignore[too-many-return-statements] -- independent proof gates fall back to fresh checks.
    root: Path, repository: str, sha: str, base: str, client: Transport
) -> ReviewedValidation:
    if _git(root, "HEAD") != sha or _git(root, f"{sha}^") != base:
        return FreshValidationRequired(
            "fresh validation: push base differs from checked merge parent",
        )
    run = _find_run(repository, sha, client)
    if run is None:
        return FreshValidationRequired(
            "fresh validation: no recent successful own-repository merged PR",
        )
    run_id, attempt = positive_integer(run["id"]), positive_integer(run["run_attempt"])
    selected_jobs = [
        job
        for job in collection_rows(
            client.get(f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100"), "jobs"
        )
        if job.get("name") == _JOB
    ]
    if len(selected_jobs) != 1 or (
        selected_jobs[0].get("status"),
        selected_jobs[0].get("conclusion"),
    ) != ("completed", "success"):
        return FreshValidationRequired(
            "fresh validation: full validation job did not succeed",
        )
    artifacts = collection_rows(
        client.get(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"), "artifacts"
    )
    selected = [
        item
        for item in artifacts
        if item.get("name") == f"reviewed-validation-{attempt}" and item.get("expired") is False
    ]
    if len(selected) != 1:
        return FreshValidationRequired(
            "fresh validation: current-attempt full-test proof is missing",
        )
    artifact = selected[0]
    identity = json_object(artifact.get("workflow_run"))
    repository_id = positive_integer(json_object(run["head_repository"])["id"])
    if (
        positive_integer(identity.get("id")),
        identity.get("head_sha"),
        positive_integer(identity.get("repository_id")),
        positive_integer(identity.get("head_repository_id")),
    ) != (run_id, run["head_sha"], repository_id, repository_id):
        return FreshValidationRequired(
            "fresh validation: reviewed artifact ownership mismatch",
        )
    digest = artifact.get("digest")
    if not isinstance(digest, str):
        return FreshValidationRequired("fresh validation: reviewed digest is absent")
    checked_tree = _git(root, f"{sha}^{{tree}}")
    expected: dict[str, JsonValue] = {
        "schema_version": 1,
        "repository": repository,
        "tree": checked_tree,
        "comparison_base": base,
        "run_id": run_id,
        "run_attempt": attempt,
        "full_validation": True,
    }
    artifact_id = positive_integer(artifact["id"])
    with tempfile.TemporaryDirectory(prefix="repo-reviewed-validation-") as temporary:
        archive = Path(temporary) / "proof.zip"
        client.download(f"repos/{repository}/actions/artifacts/{artifact_id}/zip", archive)
        reviewed_source = _verify_proof(archive, digest, expected)
    if json_object(client.get(f"repos/{repository}/actions/runs/{run_id}")) != run:
        return FreshValidationRequired(
            "fresh validation: reviewed CI changed during proof verification",
        )
    return VerifiedReviewedValidation(
        source=SourceCommit(sha),
        comparison_base=SourceCommit(base),
        tree=GitTreeId(checked_tree),
        reviewed_source=reviewed_source,
        run=RunIdentity(WorkflowRunId(run_id), WorkflowRunAttempt(attempt)),
        artifact=Artifact(CIArtifactId(artifact_id), CIArtifactDigest(digest)),
    )


def _find_run(  # ruff: ignore[too-many-return-statements] -- conservative evidence gates.
    repository: str, sha: str, client: Transport
) -> dict[str, JsonValue] | None:
    raw = client.get(f"repos/{repository}/commits/{sha}/pulls?per_page=100")
    if not isinstance(raw, list) or len(raw) >= _MAX_PROVIDER_ROWS:
        return None
    matching: list[dict[str, JsonValue]] = []
    for value in raw:
        pull = json_object(value)
        base, head = json_object(pull["base"]), json_object(pull["head"])
        base_repo, head_repo = json_object(base.get("repo")), json_object(head.get("repo"))
        if (
            pull.get("merge_commit_sha") == sha
            and pull.get("merged_at") is not None
            and base.get("ref") == "main"
            and base_repo.get("full_name") == head_repo.get("full_name") == repository
            and positive_integer(base_repo.get("id")) == positive_integer(head_repo.get("id"))
        ):
            matching.append(pull)
    if len(matching) != 1:
        return None
    head = json_object(matching[0]["head"])
    head_sha = head.get("sha")
    repository_id = positive_integer(json_object(head["repo"])["id"])
    if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
        return None
    runs = collection_rows(
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
        and json_object(run.get("head_repository")).get("full_name") == repository
        and positive_integer(json_object(run.get("head_repository")).get("id")) == repository_id
    ]
    if not candidates:
        return None
    run = max(candidates, key=lambda row: positive_integer(row.get("id")))
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


def _verify_proof(archive: Path, digest: str, expected: dict[str, JsonValue]) -> SourceCommit:
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
        decoded_proof: object = json.loads(bundle.read("proof.json"))  # pyright: ignore[reportAny] -- digest-bound JSON is recursively checked before proof comparison.
        proof = json_object(decoded_proof)
    source = proof.pop("source_commit", None)
    if (
        not isinstance(source, str)
        or _SHA.fullmatch(source) is None
        or any(type(proof.get(key)) is not type(value) for key, value in expected.items())
        or proof != expected
    ):
        message = "reviewed proof does not match full validation of this tree and base"
        raise ValueError(message)
    return SourceCommit(source)


@dataclass(frozen=True)
class RecordValidation:
    kind: ClassVar[Literal["record"]] = "record"
    plan: Path
    destination: Path


@dataclass(frozen=True)
class ReuseValidation:
    kind: ClassVar[Literal["reuse"]] = "reuse"
    repository: str
    sha: str
    base: str
    github_output: Path
    summary: Path


type ValidationCommand = RecordValidation | ReuseValidation


class Arguments(argparse.Namespace):
    command: str = ""
    plan: Path | None = None
    destination: Path | None = None
    repository: str | None = None
    sha: str | None = None
    base: str | None = None
    github_output: Path | None = None
    summary: Path | None = None


def main() -> None:
    parser = argparse.ArgumentParser(  # sarj-noqa: SARJ533 -- pre-install CLI; typed decode.
        description=__doc__
    )
    commands = parser.add_subparsers(dest="command", required=True)
    record_parser = commands.add_parser("record")
    record_parser.add_argument("--plan", type=Path, required=True)
    record_parser.add_argument("--destination", type=Path, required=True)
    reuse_parser = commands.add_parser("reuse")
    for name in ("repository", "sha", "base"):
        reuse_parser.add_argument(f"--{name}", required=True)
    for name in ("github-output", "summary"):
        reuse_parser.add_argument(f"--{name}", type=Path, required=True)
    _run(Path(__file__).resolve().parent, _command(parser.parse_args(namespace=Arguments())))


def _command(arguments: Arguments) -> ValidationCommand:
    match arguments.command:
        case "record":
            if not isinstance(arguments.plan, Path) or not isinstance(arguments.destination, Path):
                message = "record requires plan and destination paths"
                raise TypeError(message)
            return RecordValidation(arguments.plan, arguments.destination)
        case "reuse":
            if not arguments.repository or not arguments.sha or not arguments.base:
                message = "reuse requires repository, source and comparison base"
                raise ValueError(message)
            if not isinstance(arguments.github_output, Path) or not isinstance(
                arguments.summary, Path
            ):
                message = "reuse requires output and summary paths"
                raise TypeError(message)
            return ReuseValidation(
                arguments.repository,
                arguments.sha,
                arguments.base,
                arguments.github_output,
                arguments.summary,
            )
        case _:
            message = "unknown validation command"
            raise ValueError(message)


def _run(root: Path, command: ValidationCommand) -> None:
    match command:
        case RecordValidation():
            import os  # ruff: ignore[import-outside-top-level] -- environment read only for certificate creation.

            record(root, command.plan, command.destination, dict(os.environ))  # ruff: ignore[banned-api] -- only named CI metadata is read.
        case ReuseValidation():
            result = reuse(root, command.repository, command.sha, command.base)
            match result:
                case VerifiedReviewedValidation():
                    reused = True
                case FreshValidationRequired():
                    reused = False
                case _:
                    assert_never(result)
            with command.github_output.open("a") as stream:
                stream.write(f"reused={str(reused).lower()}\n")
            with command.summary.open("a") as stream:
                stream.write(f"Reviewed validation: {result.reason}\n")
        case _:
            assert_never(command)


if __name__ == "__main__":
    main()
