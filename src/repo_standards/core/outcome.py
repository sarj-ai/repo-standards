from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
from enum import StrEnum
from typing import ClassVar, Literal, TypedDict


type JSONScalar = str | int | float | bool | None
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]


type ConfigValue = JSONScalar | date | datetime | time | list[ConfigValue] | dict[str, ConfigValue]

type ParsedValue = ConfigValue | JSONValue


@dataclass(frozen=True, slots=True)
class ExecutionIssue:
    code: str
    phase: str
    message: str
    retryable: bool
    remediation: tuple[str, ...]


class IssueDocument(TypedDict):
    code: str
    phase: str
    message: str
    retryable: bool
    remediation: list[str]


def issue_document(issue: ExecutionIssue) -> IssueDocument:
    return {
        "code": issue.code,
        "phase": issue.phase,
        "message": issue.message,
        "retryable": issue.retryable,
        "remediation": list(issue.remediation),
    }


class CompletedOutcome(StrEnum):
    PASSED = "passed"
    FINDINGS = "findings"
    ADVISORY = "inconclusive"


@dataclass(frozen=True, slots=True)
class IncompleteCommand:
    issues: tuple[ExecutionIssue, ...]
    kind: ClassVar[Literal["incomplete"]] = "incomplete"

    def __post_init__(self) -> None:
        if not self.issues:
            message = "incomplete commands require execution issue evidence"
            raise ValueError(message)


type CommandOutcome = CompletedOutcome | IncompleteCommand
