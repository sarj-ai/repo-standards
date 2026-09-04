from __future__ import annotations

import json
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git fixture
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import GitObjectId
from repo_standards.pull_request._context import NotApplicable  # ruff: ignore[import-private-name]
from repo_standards.pull_request._github import (  # ruff: ignore[import-private-name]
    MAXIMUM_EVENT_BYTES,
    load_github_pull_request_context,
)
from repo_standards.pull_request._inputs import (  # ruff: ignore[import-private-name]
    resolve_github_pull_request_inputs,
)
from repo_standards.pull_request._local import (  # ruff: ignore[import-private-name]
    resolve_local_advisory_context,
)
from repo_standards.pull_request._trusted_manifest import (  # ruff: ignore[import-private-name]
    load_trusted_base_manifest,
)


if TYPE_CHECKING:
    from pathlib import Path


BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40


def _event(
    *,
    base_repository_id: object = 1,
    head_repository_id: object = 1,
) -> dict[str, object]:
    return {
        "action": "synchronize",
        "pull_request": {
            "base": {
                "sha": BASE_SHA,
                "ref": "dev",
                "repo": {"id": base_repository_id, "ignored": "value"},
            },
            "head": {
                "sha": HEAD_SHA,
                "ref": "feature/concise-history",
                "repo": {"id": head_repository_id},
            },
            "stack": {"base": {"sha": "3" * 40, "ref": "main"}},
        },
        "ignored": {"token": "must not be interpreted"},
    }


def _write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=repository-standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _manifest(repository_id: str) -> str:
    return f"""schema_version = 4
repository_id = "{repository_id}"
enabled_rules = []
components = []
"""


def test_github_context_uses_direct_pr_objects_and_numeric_repository_ids(
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    _write_json(event_path, _event(base_repository_id=123, head_repository_id=123))

    context = load_github_pull_request_context(event_path, event_name="pull_request")

    assert not isinstance(context, NotApplicable)
    assert context.base_sha == BASE_SHA
    assert context.head_sha == HEAD_SHA
    assert context.base_ref == "dev"
    assert context.head_ref == "feature/concise-history"
    assert context.base_repository_id == context.head_repository_id == 123
    assert context.same_repository


def test_github_context_does_not_treat_fork_as_same_repository(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    _write_json(event_path, _event(base_repository_id=123, head_repository_id=456))

    context = load_github_pull_request_context(event_path, event_name="pull_request")

    assert not isinstance(context, NotApplicable)
    assert not context.same_repository


@pytest.mark.parametrize("repository_id", ["123", True, 0, -1, None])
def test_github_context_rejects_non_positive_strict_repository_ids(
    tmp_path: Path,
    repository_id: object,
) -> None:
    event_path = tmp_path / "event.json"
    _write_json(event_path, _event(head_repository_id=repository_id))

    with pytest.raises(ConfigurationError, match="malformed"):
        load_github_pull_request_context(event_path, event_name="pull_request")


def test_github_context_rejects_duplicate_security_field(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(
        '{"action":"opened","pull_request":{"base":{"sha":"'
        + BASE_SHA
        + '","sha":"'
        + HEAD_SHA
        + '","ref":"dev","repo":{"id":1}},"head":{"sha":"'
        + HEAD_SHA
        + '","ref":"feature","repo":{"id":1}}}}',
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="unique-key"):
        load_github_pull_request_context(event_path, event_name="pull_request")


def test_github_context_enforces_event_size_bound(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_bytes(b" " * (MAXIMUM_EVENT_BYTES + 1))

    with pytest.raises(ConfigurationError, match="1 MiB"):
        load_github_pull_request_context(event_path, event_name="pull_request")


def test_merge_group_is_explicitly_not_applicable(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    _write_json(event_path, {"action": "checks_requested", "merge_group": {"id": 1}})

    result = load_github_pull_request_context(event_path, event_name="merge_group")

    assert isinstance(result, NotApplicable)
    assert result.event_name == "merge_group"


def test_trusted_manifest_is_loaded_from_exact_base_not_worktree(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    manifest_path = tmp_path / ".repo-standards" / "repository.toml"
    manifest_path.parent.mkdir()
    manifest_path.write_text(_manifest("trusted-base"), encoding="utf-8")
    base = _commit(tmp_path, "base policy")
    manifest_path.write_text(_manifest("untrusted-head"), encoding="utf-8")
    _commit(tmp_path, "change policy in pull request")

    trusted = load_trusted_base_manifest(tmp_path, GitObjectId(base))

    assert trusted.base_sha == base
    assert trusted.manifest is not None
    assert trusted.manifest.repository_id == "trusted-base"


def test_github_input_orchestration_combines_event_with_base_manifest(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    manifest_path = tmp_path / ".repo-standards" / "repository.toml"
    manifest_path.parent.mkdir()
    manifest_path.write_text(_manifest("trusted-base"), encoding="utf-8")
    base = _commit(tmp_path, "base")
    (tmp_path / "change.txt").write_text("head\n", encoding="utf-8")
    head = _commit(tmp_path, "head")
    event_path = tmp_path / "event.json"
    event = _event(base_repository_id=77, head_repository_id=77)
    pull_request_document = _object(event["pull_request"])
    base_input = _object(pull_request_document["base"])
    head_input = _object(pull_request_document["head"])
    base_input["sha"] = base
    head_input["sha"] = head
    pull_request_document["base"] = base_input
    pull_request_document["head"] = head_input
    event["pull_request"] = pull_request_document
    _write_json(event_path, event)

    resolved = resolve_github_pull_request_inputs(
        tmp_path,
        event_path,
        event_name="pull_request",
    )

    assert not isinstance(resolved, NotApplicable)
    assert resolved.context.base_sha == base
    assert resolved.context.head_sha == head
    assert resolved.manifest is not None
    assert resolved.manifest.repository_id == "trusted-base"


def test_local_context_infers_standard_transition_destination(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    base = _commit(tmp_path, "base")
    _git(tmp_path, "branch", "preview", base)
    _git(tmp_path, "remote", "add", "origin", str(tmp_path))
    _git(tmp_path, "fetch", "--quiet", "origin", "preview:refs/remotes/origin/preview")
    (tmp_path / "change.txt").write_text("head\n", encoding="utf-8")
    head = _commit(tmp_path, "head")
    _git(tmp_path, "checkout", "-q", "-b", f"automation/promote-dev-{head[:12]}")

    context = resolve_local_advisory_context(
        tmp_path,
        default_base_ref="dev",
        transition_bases=(("automation/promote-dev-", "preview", 12),),
    )

    assert context.base_sha == base
    assert context.head_sha == head
    assert context.base_ref == "preview"
    assert context.head_ref.startswith("automation/promote-dev-")
    assert context.source == "local"
