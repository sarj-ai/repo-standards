from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
from io import BytesIO
import json
import tomllib
from typing import TYPE_CHECKING, TypeGuard
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile


if TYPE_CHECKING:
    from collections.abc import Mapping

from pydantic import ValidationError
import pytest

from repo_standards.activation_verification import VerifiedActivation, authenticate_activation
from repo_standards.core.activation_policy import ActivationEdit, ActivationPolicy
from repo_standards.core.activation_receipt import ActivationBinding, ActivationChange
from repo_standards.core.models import GitObjectId
from repo_standards.core.pull_request_body import missing_required_body_sections
from repo_standards.core.review_policy import (
    CheckConclusion,
    RequiredCheckEvidence,
    ReviewPolicyConfig,
    ReviewPolicyEvidence,
    evaluate_review_policy,
)
from repo_standards.github_review_policy import final_policy_decision


BASE, HEAD, SOURCE, ACTIVATION = (letter * 40 for letter in "abad")
REPOSITORY = "sarj-ai/platform"
WORKFLOW = ".github/workflows/activate-flags.yml"
MANIFEST = """[pull_request.review_policy.nonproduction_activation]
author = "sarj-bulbul[bot]"
app_id = 15368
workflow_path = ".github/workflows/activate-flags.yml"
workflow_ref = "refs/heads/dev"
event = "workflow_dispatch"
artifact_name = "activation-receipt"
[[pull_request.review_policy.nonproduction_activation.features]]
feature_id = "example"
ticket = "PLT-4803"
kind = "rollout"
[[pull_request.review_policy.nonproduction_activation.features.edits]]
environment = "dev"
path = "domain/api.tf"
before = "example_enabled = false"
after = "example_enabled = true"
[[pull_request.review_policy.nonproduction_activation.features.edits]]
environment = "dev"
path = "domain/worker.tf"
before = "example_enabled = false"
after = "example_enabled = true"
"""
POLICY = ActivationPolicy.model_validate(
    tomllib.loads(MANIFEST)["pull_request"]["review_policy"]["nonproduction_activation"]
)
BEFORE = b"example_enabled = false\noperational = false\n"
AFTER = b"example_enabled = true\noperational = false\n"


def archive(raw: bytes, name: str = f"123-{HEAD}.json") -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w") as zipped:
        zipped.writestr(name, raw)
    return stream.getvalue()


def _is_mapping(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _set(target: object, path: tuple[str, ...], value: object) -> None:
    assert _is_mapping(target)
    for key in path[:-1]:
        nested = target[key]
        assert _is_mapping(nested)
        target = nested
    target[path[-1]] = value


class Provider:
    repository = REPOSITORY

    def __init__(self) -> None:
        self.policy = POLICY
        self.base_sha = BASE
        self.target_protected = True
        self.target_advanced = False
        self.pr: dict[str, object] = {
            "state": "open",
            "draft": False,
            "user": {"login": "sarj-bulbul[bot]", "type": "Bot"},
            "base": {"sha": BASE, "ref": "dev", "repo": {"id": 1, "full_name": REPOSITORY}},
            "head": {
                "sha": HEAD,
                "ref": f"automation/activate-dev-plt-4803-{ACTIVATION[:12]}",
                "repo": {"id": 1, "full_name": REPOSITORY},
            },
        }
        self.run: dict[str, object] = {
            "id": 7,
            "run_attempt": 2,
            "workflow_id": 9,
            "head_branch": "dev",
            "head_sha": SOURCE,
            "event": "workflow_dispatch",
            "path": WORKFLOW,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": 8,
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "run_started_at": "2026-11-08T10:00:00Z",
            "updated_at": "2026-11-08T10:05:00Z",
        }
        self.runs = [self.run]
        self.suite: dict[str, object] = {
            "id": 8,
            "head_sha": SOURCE,
            "app": {"id": 15368},
            "status": "completed",
            "conclusion": "success",
        }
        self.files = [
            {"filename": path, "status": "modified"}
            for path in ("domain/api.tf", "domain/worker.tf")
        ]
        self.binding = ActivationBinding(
            REPOSITORY,
            123,
            "dev",
            BASE,
            f"automation/activate-dev-plt-4803-{ACTIVATION[:12]}",
            HEAD,
            "dev",
            SOURCE,
            ACTIVATION,
            "example",
            tuple(
                ActivationChange(
                    path, hashlib.sha256(BEFORE).hexdigest(), hashlib.sha256(AFTER).hexdigest()
                )
                for path in ("domain/api.tf", "domain/worker.tf")
            ),
        )
        self.raw = json.dumps(self.binding.payload()).encode()
        self.artifact: dict[str, object] = {
            "id": 6,
            "name": "activation-receipt-dev",
            "expired": False,
            "workflow_run": {"id": 7, "head_sha": SOURCE},
            "created_at": "2026-11-08T10:01:00Z",
            "updated_at": "2026-11-08T10:01:00Z",
        }
        self.set_archive(archive(self.raw))
        self.contents = {(sha, WORKFLOW): b"name: activation\n" for sha in (BASE, SOURCE)}
        self.contents[BASE, ".repo-standards/repository.toml"] = MANIFEST.encode()
        for path in ("domain/api.tf", "domain/worker.tf"):
            self.contents[BASE, path] = BEFORE
            self.contents[HEAD, path] = AFTER
        self.blobs: dict[str, bytes] = {}
        self.trees: dict[str, tuple[str, str]] = {}
        self.pr_reads = 0
        self.changed_on_refresh = False
        self.producer_race = ""
        self.run_queries: list[dict[str, list[str]]] = []

    def set_archive(self, zipped: bytes) -> None:
        self.zipped = zipped
        self.artifact.update(
            size_in_bytes=len(zipped), digest="sha256:" + hashlib.sha256(zipped).hexdigest()
        )

    def tree(self, sha: str, directory: str = "") -> list[dict[str, object]]:
        entries: dict[str, dict[str, object]] = {}
        for (commit, path), content in self.contents.items():
            if commit != sha or not path.startswith(directory):
                continue
            relative = path.removeprefix(directory)
            part = relative.split("/")[0]
            if "/" in relative:
                tree_id = f"{sha}:{directory}{part}/"
                entries[part] = {"path": part, "sha": tree_id, "type": "tree", "mode": "040000"}
                self.trees[tree_id] = (sha, directory + part + "/")
            else:
                blob_id = hashlib.sha1(
                    b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False
                ).hexdigest()
                entries[part] = {"path": part, "sha": blob_id, "type": "blob", "mode": "100644"}
                self.blobs[blob_id] = content
        return list(entries.values())

    def request(  # ruff: ignore[too-many-return-statements] -- explicit fake API routes
        self, method: str, path: str, *, payload: Mapping[str, object] | None = None
    ) -> object:
        assert method == "GET"
        assert payload is None
        suffix = path.removeprefix(f"/repos/{REPOSITORY}")
        if suffix == "/pulls/123":
            self.pr_reads += 1
            result = deepcopy(self.pr)
            if self.changed_on_refresh and self.pr_reads > 1:
                _set(result, ("head", "sha"), "e" * 40)
            return result
        if suffix.startswith("/actions/workflows/"):
            return {"id": 9, "path": WORKFLOW, "state": "active"}
        if suffix == "/actions/runs/7":
            return self.run
        if suffix.startswith("/actions/runs/"):
            return self.run_attempt(suffix)
        if suffix == "/branches/dev":
            return {
                "protected": self.target_protected,
                "commit": {"sha": "f" * 40 if self.target_advanced else SOURCE},
            }
        if suffix == "/branches/preview":
            return {
                "protected": self.target_protected,
                "commit": {"sha": "f" * 40 if self.target_advanced else self.base_sha},
            }
        if suffix == "/check-suites/8":
            return self.suite
        if suffix.startswith("/git/commits/"):
            sha = suffix.split("/")[-1]
            self.trees[sha] = (sha, "")
            return {"sha": sha, "tree": {"sha": sha}}
        if suffix.startswith("/git/trees/"):
            tree_id = suffix.removeprefix("/git/trees/")
            sha, directory = self.trees[tree_id]
            return {"sha": tree_id, "truncated": False, "tree": self.tree(sha, directory)}
        if suffix.startswith("/git/blobs/"):
            blob_id = suffix.split("/")[-1]
            content = self.blobs[blob_id]
            return {
                "sha": blob_id,
                "size": len(content),
                "encoding": "base64",
                "content": base64.b64encode(content).decode(),
            }
        raise AssertionError(path)

    def run_attempt(self, suffix: str) -> dict[str, object]:
        return next(
            run
            for run in self.runs
            if f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}" == suffix
        )

    def rest_pages(self, path: str, *, collection_key: str | None = None) -> list[object]:
        assert path.startswith("/repos/")
        if collection_key == "workflow_runs":
            # Mirror the provider's server-side filters so selection sees what GitHub returns.
            query = parse_qs(urlsplit(path).query, strict_parsing=True)
            self.run_queries.append(query)
            return [
                run
                for run in self.runs
                if [run["head_branch"]] == query["branch"] and [run["event"]] == query["event"]
            ]
        if collection_key == "artifacts":
            return [self.artifact]
        return list(self.files)

    def artifact_bytes(self, artifact_id: int) -> bytes:
        assert artifact_id == 6
        if self.producer_race == "new_run":
            self.runs.append(self.run | {"id": 99, "status": "in_progress", "conclusion": None})
        elif self.producer_race == "other_event":
            self.runs.append(self.run | {"id": 99, "event": "check_run", "head_sha": "d" * 40})
        elif self.producer_race == "rerun":
            self.run.update(run_attempt=3, status="in_progress", conclusion=None)
        return self.zipped

    def verify(self) -> VerifiedActivation | None:
        return authenticate_activation(
            self, policy=self.policy, number=123, base_sha=self.base_sha, head_sha=HEAD
        )


def _mixed_provider() -> Provider:
    provider = Provider()
    provider.contents[BASE, "domain/api.tf"] = AFTER
    provider.files = [{"filename": "domain/worker.tf", "status": "modified"}]
    provider.binding = replace(provider.binding, changes=provider.binding.changes[1:])
    provider.set_archive(archive(json.dumps(provider.binding.payload()).encode()))
    return provider


def test_mixed_activation_proves_unchanged_consumer_is_already_enabled() -> None:
    provider = _mixed_provider()
    proof = provider.verify()
    assert proof is not None
    assert proof.binding.changes == provider.binding.changes


@pytest.mark.parametrize("commit", [BASE, HEAD])
def test_mixed_activation_rejects_unchanged_consumer_symlink(commit: str) -> None:
    class SymlinkProvider(Provider):
        def tree(self, sha: str, directory: str = "") -> list[dict[str, object]]:
            entries = super().tree(sha, directory)
            for entry in entries:
                if sha == commit and directory == "domain/" and entry["path"] == "api.tf":
                    entry["mode"] = "120000"
            return entries

    provider = SymlinkProvider()
    provider.contents[BASE, "domain/api.tf"] = AFTER
    provider.files = [{"filename": "domain/worker.tf", "status": "modified"}]
    provider.binding = replace(provider.binding, changes=provider.binding.changes[1:])
    provider.set_archive(archive(json.dumps(provider.binding.payload()).encode()))
    assert provider.verify() is None


def test_mixed_activation_rejects_consumer_left_off_at_both_commits() -> None:
    provider = _mixed_provider()
    provider.contents[BASE, "domain/api.tf"] = BEFORE
    provider.contents[HEAD, "domain/api.tf"] = BEFORE
    assert provider.verify() is None


def test_mixed_activation_authenticates_actual_tfvar_and_worker_fragments() -> None:
    provider = _mixed_provider()
    tfvar_before = "transfer_multiple_routes_enabled     = false"
    worker_before = (
        '        "TRANSFER_MULTIPLE_ROUTES": "false",\n'
        '        "MODEL_CATALOG_ENABLED": "true",\n'
        '        "ENVIRONMENT": "dev",'
    )
    manifest = MANIFEST
    for before in (tfvar_before, worker_before):
        manifest = manifest.replace(
            'before = "example_enabled = false"\nafter = "example_enabled = true"',
            f"before = {json.dumps(before)}\nafter = {json.dumps(before.replace('false', 'true'))}",
            1,
        )
    provider.contents[BASE, ".repo-standards/repository.toml"] = manifest.encode()
    provider.policy = ActivationPolicy.model_validate(
        tomllib.loads(manifest)["pull_request"]["review_policy"]["nonproduction_activation"]
    )
    edits = provider.policy.features[0].edits
    for edit in edits:
        provider.contents[BASE, edit.path] = (
            edit.after if edit.path == "domain/api.tf" else edit.before
        ).encode()
        provider.contents[HEAD, edit.path] = edit.after.encode()
    worker = edits[1]
    provider.binding = replace(
        provider.binding,
        changes=(
            ActivationChange(
                worker.path,
                hashlib.sha256(worker.before.encode()).hexdigest(),
                hashlib.sha256(worker.after.encode()).hexdigest(),
            ),
        ),
    )
    provider.set_archive(archive(json.dumps(provider.binding.payload()).encode()))
    assert provider.verify() is not None


@pytest.mark.parametrize(
    "unchanged", [BEFORE, AFTER + AFTER, AFTER + BEFORE, AFTER + b"unexpected = true\n"]
)
def test_mixed_activation_rejects_off_ambiguous_or_modified_unchanged_consumer(
    unchanged: bytes,
) -> None:
    provider = _mixed_provider()
    provider.contents[HEAD, "domain/api.tf"] = unchanged
    assert provider.verify() is None


@pytest.mark.parametrize("status", ["added", "removed", "renamed"])
def test_mixed_activation_rejects_nonmodified_scope(status: str) -> None:
    provider = _mixed_provider()
    provider.files[0]["status"] = status
    assert provider.verify() is None


def test_mixed_activation_rejects_unrelated_or_duplicate_or_empty_scope() -> None:
    provider = _mixed_provider()
    for files in (
        [*provider.files, {"filename": "unrelated.tf", "status": "modified"}],
        provider.files * 2,
        [],
    ):
        provider.files = files
        assert provider.verify() is None


def test_authenticated_multifile_activation_waives_only_review_floors():

    provider = Provider()
    proof = provider.verify()
    assert proof is not None
    evidence = _activation_evidence()
    config = ReviewPolicyConfig(author_review_floor=1, verified_activation=proof)
    result = evaluate_review_policy(evidence, config)
    assert result.required_human_reviews == 0
    assert "sensitive_approval_missing" not in result.reasons
    for policy_passed in (True, False):
        decision = final_policy_decision(
            policy_passed=policy_passed,
            tier=0,
            lane_enabled=False,
            same_repository=True,
            author_is_bot=True,
            draft=False,
            verified_activation=proof,
        )
        assert decision.passed == policy_passed
    ordinary = evaluate_review_policy(evidence, ReviewPolicyConfig(author_review_floor=1))
    assert ordinary.required_human_reviews == 1
    assert "sensitive_approval_missing" in ordinary.reasons


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_bot",
        "fork",
        "production",
        "draft",
        "stale_base",
        "stale_head",
        "wrong_workflow",
        "wrong_suite",
        "wrong_app",
        "newer_failed",
        "pending",
        "extra_file",
        "extra_byte",
        "producer_modified",
        "policy_modified",
        "unregistered",
        "wrong_attempt",
        "digest",
        "changed_pr",
        "traversal",
    ],
)
def test_adversarial_provider_evidence_never_grants_exception(mutation: str) -> None:  # ruff: ignore[too-many-branches] -- independent adversarial cases
    provider = Provider()
    if mutation == "wrong_bot":
        _set(provider.pr, ("user", "login"), "another[bot]")
    elif mutation == "fork":
        _set(provider.pr, ("head", "repo", "id"), 2)
    elif mutation == "production":
        _set(provider.pr, ("base", "ref"), "production")
    elif mutation == "draft":
        provider.pr["draft"] = True
    elif mutation == "stale_base":
        _set(provider.pr, ("base", "sha"), "e" * 40)
    elif mutation == "stale_head":
        _set(provider.pr, ("head", "sha"), "e" * 40)
    elif mutation == "wrong_workflow":
        provider.run["path"] = ".github/workflows/other.yml"
    elif mutation == "wrong_suite":
        provider.suite["id"] = 99
    elif mutation == "wrong_app":
        _set(provider.suite, ("app", "id"), 99)
    elif mutation == "newer_failed":
        provider.runs.append(provider.run | {"id": 99, "conclusion": "failure"})
    elif mutation == "pending":
        provider.run["status"] = "in_progress"
    elif mutation == "extra_file":
        provider.files.append({"filename": "secrets.tf", "status": "modified"})
    elif mutation == "extra_byte":
        provider.contents[HEAD, "domain/api.tf"] += b" "
    elif mutation == "producer_modified":
        provider.files.append({"filename": WORKFLOW, "status": "modified"})
    elif mutation == "policy_modified":
        provider.contents[BASE, ".repo-standards/repository.toml"] = MANIFEST.replace(
            "15368", "12345"
        ).encode()
    elif mutation == "unregistered":
        provider.set_archive(
            archive(json.dumps(provider.binding.payload() | {"feature_id": "unknown"}).encode())
        )
    elif mutation == "wrong_attempt":
        provider.artifact["created_at"] = "2026-11-08T09:00:00Z"
    elif mutation == "digest":
        provider.artifact["digest"] = "sha256:" + "0" * 64
    elif mutation == "changed_pr":
        provider.changed_on_refresh = True
    elif mutation == "traversal":
        provider.set_archive(archive(provider.raw, "../activation-receipt.json"))
    assert provider.verify() is None


def test_archive_rejects_duplicates_and_oversize():
    provider = Provider()
    stream = BytesIO()
    with ZipFile(stream, "w") as zipped:
        zipped.writestr(f"123-{HEAD}.json", provider.raw)
        zipped.writestr("extra.json", b"{}")
    provider.set_archive(stream.getvalue())
    assert provider.verify() is None
    provider.set_archive(archive(b"x" * 16_385))
    assert provider.verify() is None


def test_bundle_selects_only_exact_pr_head_receipt() -> None:
    provider = Provider()
    stream = BytesIO()
    with ZipFile(stream, "w") as zipped:
        zipped.writestr(f"999-{'f' * 40}.json", b"{}")
        zipped.writestr(f"123-{HEAD}.json", provider.raw)
    provider.set_archive(stream.getvalue())
    assert provider.verify() is not None
    provider.pr["head"] = {
        "sha": "f" * 40,
        "ref": provider.binding.head_ref,
        "repo": {"id": 1, "full_name": REPOSITORY},
    }
    assert provider.verify() is None


def test_preview_uses_same_authenticated_producer_with_distinct_sources() -> None:
    provider = Provider()
    preview_manifest = MANIFEST.replace('environment = "dev"', 'environment = "preview"')
    provider.policy = ActivationPolicy.model_validate(
        tomllib.loads(preview_manifest)["pull_request"]["review_policy"]["nonproduction_activation"]
    )
    provider.base_sha = "e" * 40
    for (commit, path), content in list(provider.contents.items()):
        if commit == BASE:
            provider.contents[provider.base_sha, path] = content
    provider.contents[provider.base_sha, ".repo-standards/repository.toml"] = (
        preview_manifest.encode()
    )
    _set(provider.pr, ("base", "sha"), provider.base_sha)
    _set(provider.pr, ("base", "ref"), "preview")
    head_ref = f"automation/activate-preview-plt-4803-{ACTIVATION[:12]}"
    _set(provider.pr, ("head", "ref"), head_ref)
    provider.binding = replace(
        provider.binding,
        base_ref="preview",
        base_sha=provider.base_sha,
        environment="preview",
        head_ref=head_ref,
    )
    provider.artifact["name"] = "activation-receipt-preview"
    provider.set_archive(archive(json.dumps(provider.binding.payload()).encode()))
    proof = provider.verify()
    assert proof is not None
    assert (
        proof.binding.base_sha
        != proof.binding.producer_source_sha
        != proof.binding.activation_source_sha
    )


@pytest.mark.parametrize("race", ["new_run", "rerun"])
def test_new_producer_during_artifact_acquisition_revokes_proof(race: str) -> None:
    provider = Provider()
    provider.producer_race = race
    assert provider.verify() is None


def test_newer_run_from_another_event_does_not_displace_configured_event_run() -> None:
    provider = Provider()
    provider.runs.append(
        provider.run | {"id": 10, "run_attempt": 1, "event": "check_run", "head_sha": "d" * 40}
    )
    proof = provider.verify()
    assert proof is not None
    assert proof.run_id == 7
    assert provider.run_queries
    assert all(
        query == {"branch": ["dev"], "event": ["workflow_dispatch"]}
        for query in provider.run_queries
    )


def test_run_from_another_event_during_acquisition_keeps_proof() -> None:
    provider = Provider()
    provider.producer_race = "other_event"
    assert provider.verify() is not None


def test_newer_configured_event_run_on_other_head_is_rejected() -> None:
    provider = Provider()
    provider.runs.append(provider.run | {"id": 10, "run_attempt": 1, "head_sha": "d" * 40})
    assert provider.verify() is None


def test_policy_without_event_fails_closed() -> None:
    raw = POLICY.model_dump(mode="json")
    del raw["event"]
    with pytest.raises(ValidationError):
        ActivationPolicy.model_validate(raw)


@pytest.mark.parametrize("violation", ["unprotected", "advanced"])
def test_target_base_must_remain_protected_and_current(violation: str) -> None:
    provider = Provider()
    provider.target_protected = violation != "unprotected"
    provider.target_advanced = violation == "advanced"
    assert provider.verify() is None


@pytest.mark.parametrize("failure", ["none", "ci", "body", "threads"])
def test_authenticated_activation_keeps_technical_and_body_policy(failure: str) -> None:
    proof = Provider().verify()
    assert proof is not None
    body = (
        ""
        if failure == "body"
        else "## What & why\nScoped flag.\n## QA impact / blast radius\nDev only.\n"
    )
    evidence = replace(
        _activation_evidence(),
        required_checks=(
            RequiredCheckEvidence(
                "CI", CheckConclusion.FAILURE if failure == "ci" else CheckConclusion.SUCCESS
            ),
        ),
        threads_resolved=failure != "threads",
        body=body,
    )
    result = evaluate_review_policy(
        evidence, ReviewPolicyConfig(author_review_floor=1, verified_activation=proof)
    )
    missing_sections = missing_required_body_sections(
        body, ("What & why", "QA impact / blast radius")
    )
    assert (result.merge_ready and not missing_sections) == (failure == "none")
    assert result.required_human_reviews == 0
    assert "sensitive_approval_missing" not in result.reasons


def _activation_evidence() -> ReviewPolicyEvidence:
    return ReviewPolicyEvidence(
        counted_lines=30,
        changed_paths=("domain/api.tf", "domain/worker.tf"),
        evaluated_head_sha=GitObjectId(HEAD),
        current_head_sha=GitObjectId(HEAD),
        required_checks=(),
        latest_human_reviews=(),
        threads_resolved=True,
        author_is_bot=True,
        body="",
    )


def _append_provider() -> Provider:
    provider = _mixed_provider()
    manifest = MANIFEST.replace(
        'before = "example_enabled = false"\nafter = "example_enabled = true"',
        'operation = "append_line"\nbefore = ""\nafter = "model_catalog_enabled = true"',
        1,
    )
    provider.contents[BASE, ".repo-standards/repository.toml"] = manifest.encode()
    provider.policy = ActivationPolicy.model_validate(
        tomllib.loads(manifest)["pull_request"]["review_policy"]["nonproduction_activation"]
    )
    before = b"operational = false\n\n"
    after = before.rstrip() + b"\nmodel_catalog_enabled = true\n"
    provider.files = [{"filename": "domain/api.tf", "status": "modified"}]
    provider.contents[BASE, "domain/api.tf"] = before
    provider.contents[HEAD, "domain/api.tf"] = after
    provider.contents[BASE, "domain/worker.tf"] = AFTER
    provider.contents[HEAD, "domain/worker.tf"] = AFTER
    provider.binding = replace(
        provider.binding,
        changes=(
            ActivationChange(
                "domain/api.tf",
                hashlib.sha256(before).hexdigest(),
                hashlib.sha256(after).hexdigest(),
            ),
        ),
    )
    provider.set_archive(archive(json.dumps(provider.binding.payload()).encode()))
    return provider


def test_registered_append_authenticates_missing_assignment_and_already_on_consumer() -> None:
    assert _append_provider().verify() is not None


@pytest.mark.parametrize("suffix", [b"model_catalog_enabled = true\n", b"other = true\n"])
def test_registered_append_rejects_extra_bytes(suffix: bytes) -> None:
    provider = _append_provider()
    provider.contents[HEAD, "domain/api.tf"] += suffix
    assert provider.verify() is None


@pytest.mark.parametrize(
    ("operation", "before"), [("replace", ""), ("append_line", "off"), ("other", "")]
)
def test_activation_edit_rejects_invalid_operation_contract(operation: str, before: str) -> None:
    with pytest.raises(ValidationError):
        ActivationEdit.model_validate(
            {
                "environment": "preview",
                "path": "existing.tfvars",
                "operation": operation,
                "before": before,
                "after": "model_catalog_enabled = true",
            }
        )


@pytest.mark.parametrize("after", ["flag = true\nother = true", "flag = true\r", ""])
def test_append_line_requires_one_nonempty_literal(after: str) -> None:
    with pytest.raises(ValidationError):
        ActivationEdit.model_validate(
            {
                "environment": "preview",
                "path": "existing.tfvars",
                "operation": "append_line",
                "before": "",
                "after": after,
            }
        )


def test_append_line_rejects_existing_on() -> None:
    provider = _append_provider()
    provider.contents[BASE, "domain/api.tf"] = provider.contents[HEAD, "domain/api.tf"]
    assert provider.verify() is None


@pytest.mark.parametrize("commit", [BASE, HEAD])
def test_append_line_rejects_symlink(commit: str) -> None:
    provider = _append_provider()
    original_tree = provider.tree

    def tree(sha: str, directory: str = "") -> list[dict[str, object]]:
        entries = original_tree(sha, directory)
        if sha == commit and directory == "domain/":
            for entry in entries:
                if entry["path"] == "api.tf":
                    entry["mode"] = "120000"
        return entries

    provider.tree = tree
    assert provider.verify() is None
