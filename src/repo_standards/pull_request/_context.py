from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, NewType

from repo_standards.core.models import GitObjectId


ContextSource = Literal["github-event", "local"]
RepositoryNumericId = NewType("RepositoryNumericId", int)


@dataclass(frozen=True, slots=True)
class PullRequestContext:
    base_sha: GitObjectId
    head_sha: GitObjectId
    base_ref: str
    head_ref: str
    base_repository_id: RepositoryNumericId | None
    head_repository_id: RepositoryNumericId | None
    source: ContextSource

    @property
    def same_repository(self) -> bool:
        return (
            self.base_repository_id is not None
            and self.head_repository_id is not None
            and self.base_repository_id == self.head_repository_id
        )


@dataclass(frozen=True, slots=True)
class NotApplicable:
    event_name: str
    reason: str
