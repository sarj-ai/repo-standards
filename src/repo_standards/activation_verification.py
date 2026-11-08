from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
from io import BytesIO
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import TYPE_CHECKING, Literal, Protocol, TypeGuard
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile
import zlib

from repo_standards.core.activation_policy import ActivationEdit, ActivationPolicy
from repo_standards.core.activation_receipt import (
    ActivationBinding,
    ActivationChange,
    exact_registered_activation,
    exact_registered_append,
    matches_activation_payload,
)


if TYPE_CHECKING:
    from collections.abc import Mapping

MAX_ARCHIVE_BYTES = 1_048_576
MAX_RECEIPT_FILES = 128
MAX_RECEIPT_BYTES = 16_384
MAX_BLOB_BYTES = 1_048_576
MAX_TREE_ENTRIES = 10_000


class ActivationClient(Protocol):
    repository: str

    def request(
        self, method: str, path: str, *, payload: Mapping[str, object] | None = None
    ) -> object: ...
    def rest_pages(self, path: str, *, collection_key: str | None = None) -> list[object]: ...
    def artifact_bytes(self, artifact_id: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class VerifiedActivation:
    binding: ActivationBinding
    run_id: int
    run_attempt: int
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class ProducerReceipt:
    run_id: int
    attempt: int
    source: str
    digest: str
    raw: bytes


class InvalidActivationError(ValueError):
    def __init__(self) -> None:
        super().__init__("activation evidence mismatch")


def _object(value: object) -> Mapping[str, object]:
    if not _is_object(value):
        raise InvalidActivationError
    return value


def _integer(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise InvalidActivationError
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise InvalidActivationError
    return value


def _require(condition: object) -> None:
    if not condition:
        raise InvalidActivationError


def _blob(client: ActivationClient, sha: str, path: str) -> bytes:
    pure = PurePosixPath(path)
    _require(not pure.is_absolute() and ".." not in pure.parts and pure.as_posix() == path)
    prefix = f"/repos/{client.repository}/git"
    commit = _object(client.request("GET", f"{prefix}/commits/{sha}"))
    tree_sha = _text(_object(commit.get("tree")).get("sha"))
    _require(commit.get("sha") == sha)
    entry: Mapping[str, object] = {}
    for index, part in enumerate(pure.parts):
        tree = _object(client.request("GET", f"{prefix}/trees/{tree_sha}"))
        _require(tree.get("sha") == tree_sha and tree.get("truncated") is False)
        entries = _array(tree.get("tree"))
        _require(len(entries) <= MAX_TREE_ENTRIES)
        matches = [_object(item) for item in entries if _object(item).get("path") == part]
        _require(len(matches) == 1)
        entry = matches[0]
        if index < len(pure.parts) - 1:
            _require(entry.get("mode") == "040000" and entry.get("type") == "tree")
            tree_sha = _text(entry.get("sha"))
    _require(entry.get("mode") == "100644" and entry.get("type") == "blob")
    blob_sha = _text(entry.get("sha"))
    response = _object(client.request("GET", f"{prefix}/blobs/{blob_sha}"))
    _require(response.get("sha") == blob_sha and response.get("encoding") == "base64")
    size = _integer(response.get("size"))
    _require(size <= MAX_BLOB_BYTES)
    raw = base64.b64decode(_text(response.get("content")).replace("\n", ""), validate=True)
    _require(len(raw) == size)
    _require(
        hashlib.sha1(b"blob " + str(size).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
        == blob_sha
    )
    return raw


def receipt_bytes(archive: bytes, digest: str, *, expected_name: str) -> bytes:
    _require(
        len(archive) <= MAX_ARCHIVE_BYTES
        and re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None
    )
    _require("sha256:" + hashlib.sha256(archive).hexdigest() == digest)
    with ZipFile(BytesIO(archive)) as zipped:
        entries = zipped.infolist()
        _require(0 < len(entries) <= MAX_RECEIPT_FILES)
        _require(len({entry.filename for entry in entries}) == len(entries))
        _require(sum(entry.file_size for entry in entries) <= MAX_ARCHIVE_BYTES)
        for entry in entries:
            _require(re.fullmatch(r"[1-9][0-9]*-[0-9a-f]{40}\.json", entry.filename) is not None)
            _require(
                entry.file_size <= MAX_RECEIPT_BYTES and entry.compress_size <= MAX_ARCHIVE_BYTES
            )
            _require(entry.flag_bits & 1 == 0 and entry.compress_type in {ZIP_STORED, ZIP_DEFLATED})
        _require(expected_name in {entry.filename for entry in entries})
        with zipped.open(expected_name) as stream:
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
        _require(len(raw) <= MAX_RECEIPT_BYTES)
        return raw


def policy_at_base(client: ActivationClient, base_sha: str) -> ActivationPolicy:
    trusted = _object(
        tomllib.loads(_blob(client, base_sha, ".repo-standards/repository.toml").decode())
    )
    configured = _object(_object(trusted.get("pull_request")).get("review_policy"))
    return ActivationPolicy.model_validate(configured.get("nonproduction_activation"))


def authenticate_activation(
    client: ActivationClient,
    *,
    policy: ActivationPolicy,
    number: int,
    base_sha: str,
    head_sha: str,
) -> VerifiedActivation | None:
    try:
        return _authenticate(
            client, policy=policy, number=number, base_sha=base_sha, head_sha=head_sha
        )
    except ValueError, KeyError, TypeError, OSError, RuntimeError, BadZipFile, zlib.error:
        return None


def _authenticate(  # ruff: ignore[too-many-locals] -- binding fields remain individually inspectable
    client: ActivationClient,
    *,
    policy: ActivationPolicy,
    number: int,
    base_sha: str,
    head_sha: str,
) -> VerifiedActivation:
    _require(policy.author == "sarj-bulbul[bot]")
    _require(policy_at_base(client, base_sha) == policy)
    pr = _snapshot(client, number)
    base, head, user = (_object(pr.get(key)) for key in ("base", "head", "user"))
    env = base.get("ref")
    if not _is_environment(env):
        raise InvalidActivationError
    _require(pr.get("state") == "open" and pr.get("draft") is False)
    _require(base.get("sha") == base_sha and head.get("sha") == head_sha)
    _require(_object(base.get("repo")).get("full_name") == client.repository)
    _require(
        _integer(_object(head.get("repo")).get("id"))
        == _integer(_object(base.get("repo")).get("id"))
    )
    _require(user.get("login") == policy.author and user.get("type") == "Bot")
    _require_protected_base(client, env, base_sha)
    producer = _producer_receipt(
        client, policy, base_sha, environment=env, expected_name=f"{number}-{head_sha}.json"
    )
    parsed: object = json.loads(producer.raw)  # pyright: ignore[reportAny] -- untrusted JSON is narrowed immediately
    payload = _object(parsed)
    feature_id = _text(payload.get("feature_id"))
    features = [item for item in policy.features if item.feature_id == feature_id]
    _require(len(features) == 1)
    feature = features[0]
    edits = [item for item in feature.edits if item.environment == env]
    _require(bool(edits) and len({item.path for item in edits}) == len(edits))
    changes = _activation_changes(client, edits, number, base_sha, head_sha)
    activation_source = _text(payload.get("activation_source_sha"))
    _require(re.fullmatch(r"[0-9a-f]{40}", activation_source) is not None)
    _require(
        head.get("ref")
        == f"automation/activate-{env}-{feature.ticket.lower()}-{activation_source[:12]}"
    )
    binding = ActivationBinding(
        client.repository,
        number,
        env,
        base_sha,
        _text(head.get("ref")),
        head_sha,
        env,
        producer.source,
        activation_source,
        feature_id,
        tuple(changes),
    )
    _require(matches_activation_payload(producer.raw, binding))
    proof = VerifiedActivation(binding, producer.run_id, producer.attempt, producer.digest)
    _require_current_producer(client, policy, proof)
    _require_protected_base(client, env, base_sha)
    _require(_identity(_snapshot(client, number)) == _identity(pr))
    return proof


def _activation_changes(
    client: ActivationClient,
    edits: list[ActivationEdit],
    number: int,
    base_sha: str,
    head_sha: str,
) -> list[ActivationChange]:
    changed = [
        _object(item)
        for item in client.rest_pages(f"/repos/{client.repository}/pulls/{number}/files")
    ]
    changed_paths = {_text(item.get("filename")) for item in changed}
    _require(
        bool(changed_paths)
        and len(changed_paths) == len(changed)
        and changed_paths <= {item.path for item in edits}
    )
    _require(
        all(
            item.get("status") == "modified" and not item.get("previous_filename")
            for item in changed
        )
    )
    changes: list[ActivationChange] = []
    for edit in sorted(edits, key=lambda item: item.path):
        # Producer/config/policy changes cannot ride in an activation receipt.
        _require(not edit.path.startswith((".github/", ".repo-standards/")))
        before, after = _blob(client, base_sha, edit.path), _blob(client, head_sha, edit.path)
        _require(after.count(edit.after.encode()) == 1)
        _require(not edit.before or edit.before.encode() not in after)
        if edit.path not in changed_paths:
            _require(before == after)
            continue
        _require(edit.after.encode() not in before)
        after_hash = hashlib.sha256(after).hexdigest()
        _require(
            exact_registered_append(
                base_content=before,
                head_content=after,
                registered_true=edit.after.encode(),
                expected_content_sha256=after_hash,
            )
            if edit.operation == "append_line"
            else exact_registered_activation(
                base_content=before,
                head_content=after,
                registered_false=edit.before.encode(),
                registered_true=edit.after.encode(),
                expected_content_sha256=after_hash,
            )
        )
        changes.append(ActivationChange(edit.path, hashlib.sha256(before).hexdigest(), after_hash))
    return changes


def _is_environment(value: object) -> TypeGuard[Literal["dev", "preview"]]:
    return value in {"dev", "preview"} if isinstance(value, str) else False


def _is_object(value: object) -> TypeGuard[Mapping[str, object]]:
    return isinstance(value, dict)


def _array(value: object) -> list[object]:
    if not _is_array(value):
        raise InvalidActivationError
    return value


def _is_array(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _snapshot(client: ActivationClient, number: int) -> Mapping[str, object]:
    return _object(client.request("GET", f"/repos/{client.repository}/pulls/{number}"))


def _identity(pr: Mapping[str, object]) -> tuple[object, ...]:
    base, head, user = (_object(pr.get(key)) for key in ("base", "head", "user"))
    return (
        pr.get("state"),
        pr.get("draft"),
        base.get("sha"),
        base.get("ref"),
        head.get("sha"),
        head.get("ref"),
        _object(base.get("repo")).get("id"),
        _object(head.get("repo")).get("id"),
        user.get("login"),
        user.get("type"),
    )


def _producer_receipt(  # ruff: ignore[too-many-locals] -- each authenticated provider identity stays explicit
    client: ActivationClient,
    policy: ActivationPolicy,
    base_sha: str,
    *,
    environment: Literal["dev", "preview"],
    expected_name: str,
) -> ProducerReceipt:
    prefix = f"/repos/{client.repository}"
    workflow = _object(
        client.request("GET", f"{prefix}/actions/workflows/{quote(policy.workflow_path, safe='')}")
    )
    _require(workflow.get("path") == policy.workflow_path and workflow.get("state") == "active")
    workflow_id = _integer(workflow.get("id"))
    branch = policy.workflow_ref.removeprefix("refs/heads/")
    runs = [
        _object(item)
        for item in client.rest_pages(
            f"{prefix}/actions/workflows/{workflow_id}/runs?branch={branch}",
            collection_key="workflow_runs",
        )
    ]
    _require(bool(runs))
    # Select latest before looking at outcome or source, so a newer failure invalidates old proof.
    run = max(runs, key=lambda item: _integer(item.get("id")))
    run_id, attempt = _integer(run.get("id")), _integer(run.get("run_attempt"))
    run = _object(client.request("GET", f"{prefix}/actions/runs/{run_id}/attempts/{attempt}"))
    source = _text(run.get("head_sha"))
    _require(re.fullmatch(r"[0-9a-f]{40}", source) is not None)
    _require(run.get("id") == run_id and run.get("run_attempt") == attempt)
    _require(run.get("workflow_id") == workflow_id and run.get("head_branch") == branch)
    _require(
        run.get("event") == policy.event
        and run.get("path")
        in {policy.workflow_path, f"{policy.workflow_path}@{policy.workflow_ref}"}
    )
    _require(run.get("status") == "completed" and run.get("conclusion") == "success")
    protected = _object(client.request("GET", f"{prefix}/branches/{branch}"))
    _require(
        protected.get("protected") is True and _object(protected.get("commit")).get("sha") == source
    )
    _require(_object(run.get("repository")).get("full_name") == client.repository)
    _require(_object(run.get("head_repository")).get("full_name") == client.repository)
    suite_id = _integer(run.get("check_suite_id"))
    suite = _object(client.request("GET", f"{prefix}/check-suites/{suite_id}"))
    _require(suite.get("id") == suite_id and suite.get("head_sha") == source)
    _require(_object(suite.get("app")).get("id") == policy.app_id)
    _require(suite.get("status") == "completed" and suite.get("conclusion") == "success")
    # A run of modified producer code cannot mint an exemption using its old workflow name.
    _require(
        _blob(client, source, policy.workflow_path) == _blob(client, base_sha, policy.workflow_path)
    )
    artifacts = [
        _object(item)
        for item in client.rest_pages(
            f"{prefix}/actions/runs/{run_id}/artifacts", collection_key="artifacts"
        )
    ]
    artifacts = [
        item for item in artifacts if item.get("name") == f"{policy.artifact_name}-{environment}"
    ]
    _require(len(artifacts) == 1)
    artifact = artifacts[0]
    _require(artifact.get("expired") is False)
    _require(
        datetime.fromisoformat(_text(artifact.get("created_at")))
        >= datetime.fromisoformat(_text(run.get("run_started_at")))
    )
    _require(
        datetime.fromisoformat(_text(artifact.get("updated_at")))
        <= datetime.fromisoformat(_text(run.get("updated_at")))
    )
    artifact_run = _object(artifact.get("workflow_run"))
    _require(artifact_run.get("id") == run_id and artifact_run.get("head_sha") == source)
    size = _integer(artifact.get("size_in_bytes"))
    _require(size <= MAX_ARCHIVE_BYTES)
    digest = _text(artifact.get("digest"))
    archive = client.artifact_bytes(_integer(artifact.get("id")))
    _require(len(archive) == size)
    return ProducerReceipt(
        run_id,
        attempt,
        source,
        digest,
        receipt_bytes(archive, digest, expected_name=expected_name),
    )


def _require_protected_base(
    client: ActivationClient,
    environment: Literal["dev", "preview"],
    base_sha: str,
) -> None:
    branch = _object(client.request("GET", f"/repos/{client.repository}/branches/{environment}"))
    _require(
        branch.get("protected") is True and _object(branch.get("commit")).get("sha") == base_sha
    )


def _require_current_producer(
    client: ActivationClient,
    policy: ActivationPolicy,
    proof: VerifiedActivation,
) -> None:
    prefix = f"/repos/{client.repository}"
    workflow = _object(
        client.request("GET", f"{prefix}/actions/workflows/{quote(policy.workflow_path, safe='')}")
    )
    workflow_id = _integer(workflow.get("id"))
    _require(workflow.get("path") == policy.workflow_path and workflow.get("state") == "active")
    branch = policy.workflow_ref.removeprefix("refs/heads/")
    runs = [
        _object(item)
        for item in client.rest_pages(
            f"{prefix}/actions/workflows/{workflow_id}/runs?branch={branch}",
            collection_key="workflow_runs",
        )
    ]
    _require(bool(runs))
    latest = max(runs, key=lambda item: _integer(item.get("id")))
    _require(latest.get("id") == proof.run_id and latest.get("run_attempt") == proof.run_attempt)
    current = _object(client.request("GET", f"{prefix}/actions/runs/{proof.run_id}"))
    _require(current.get("id") == proof.run_id and current.get("run_attempt") == proof.run_attempt)
    _require(current.get("status") == "completed" and current.get("conclusion") == "success")
    _require(
        current.get("head_sha") == proof.binding.producer_source_sha
        and current.get("workflow_id") == workflow_id
    )
    protected = _object(client.request("GET", f"{prefix}/branches/{branch}"))
    _require(
        protected.get("protected") is True
        and _object(protected.get("commit")).get("sha") == proof.binding.producer_source_sha
    )
