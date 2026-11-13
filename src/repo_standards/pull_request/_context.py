from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal, NewType

from repo_standards.core.models import GitObjectId


RepositoryNumericId = NewType("RepositoryNumericId", int)


@dataclass(frozen=True, slots=True)
class _PullRequestContext:
    base_sha: GitObjectId
    head_sha: GitObjectId
    base_ref: str
    head_ref: str


@dataclass(frozen=True, slots=True)
class GitHubPullRequestContext(_PullRequestContext):
    base_repository_id: RepositoryNumericId
    head_repository_id: RepositoryNumericId
    source: ClassVar[Literal["github-event"]] = "github-event"

    @property
    def same_repository(self) -> bool:
        return self.base_repository_id == self.head_repository_id

    def __post_init__(self) -> None:
        if (
            type(self.base_repository_id) is not int
            or type(self.head_repository_id) is not int
            or self.base_repository_id <= 0
            or self.head_repository_id <= 0
        ):
            message = "GitHub context requires positive repository identities"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class LocalPullRequestContext(_PullRequestContext):
    base_repository_id: ClassVar[None] = None
    head_repository_id: ClassVar[None] = None
    source: ClassVar[Literal["local"]] = "local"
    same_repository: ClassVar[Literal[False]] = False


type PullRequestContext = GitHubPullRequestContext | LocalPullRequestContext


@dataclass(frozen=True, slots=True)
class NotApplicable:
    event_name: str
    reason: str
