from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import GitObjectId

from ._context import NotApplicable, PullRequestContext, RepositoryNumericId


if TYPE_CHECKING:
    from pathlib import Path


MAXIMUM_EVENT_BYTES = 1024 * 1024

_GitObjectIdInput = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
_RefInput = Annotated[
    str,
    Field(min_length=1, max_length=1024, pattern=r"^[^\x00-\x20\x7f]+$"),
]
LiteralChecksRequested = Annotated[str, Field(pattern=r"^checks_requested$")]


class _RepositoryInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True, strict=True)

    id: Annotated[int, Field(gt=0)]


class _BranchInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True, strict=True)

    sha: _GitObjectIdInput
    ref: _RefInput
    repo: _RepositoryInput


class _PullRequestInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True, strict=True)

    base: _BranchInput
    head: _BranchInput


class _PullRequestEventInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True, strict=True)

    action: _RefInput
    pull_request: _PullRequestInput


class _MergeGroupEventInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True, strict=True)

    action: LiteralChecksRequested
    merge_group: dict[str, object]


def load_github_pull_request_context(
    path: Path,
    *,
    event_name: str,
) -> PullRequestContext | NotApplicable:
    document = _load_event_document(path)
    if event_name == "merge_group":
        try:
            _MergeGroupEventInput.model_validate(document)
        except ValidationError:
            ConfigurationError.fail("GitHub merge-group event is malformed")
        return NotApplicable(
            event_name=event_name,
            reason="merge groups aggregate already-evaluated pull requests",
        )
    if event_name != "pull_request":
        ConfigurationError.fail("GitHub event is not a supported pull-request context")
    try:
        event = _PullRequestEventInput.model_validate(document)
    except ValidationError:
        ConfigurationError.fail("GitHub pull-request event is malformed")
    return PullRequestContext(
        base_sha=GitObjectId(event.pull_request.base.sha),
        head_sha=GitObjectId(event.pull_request.head.sha),
        base_ref=event.pull_request.base.ref,
        head_ref=event.pull_request.head.ref,
        base_repository_id=RepositoryNumericId(event.pull_request.base.repo.id),
        head_repository_id=RepositoryNumericId(event.pull_request.head.repo.id),
        source="github-event",
    )


def _load_event_document(path: Path) -> object:
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            ConfigurationError.fail("GitHub event path is not a regular file")
        with resolved.open("rb") as stream:
            content = stream.read(MAXIMUM_EVENT_BYTES + 1)
    except (OSError, RuntimeError):
        ConfigurationError.fail("GitHub event cannot be read")
    if len(content) > MAXIMUM_EVENT_BYTES:
        ConfigurationError.fail("GitHub event exceeds the 1 MiB safety limit")
    try:
        return json.loads(content, object_pairs_hook=_unique_object)  # pyright: ignore[reportAny]
    except (RecursionError, UnicodeError, ValueError):
        ConfigurationError.fail("GitHub event is not valid unique-key UTF-8 JSON")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            message = "duplicate JSON object key"
            raise ValueError(message)
        document[key] = value
    return document
