from __future__ import annotations

from importlib import metadata
from typing import TYPE_CHECKING, Literal, TypedDict, assert_never

from repo_standards.core.outcome import (
    CommandOutcome,
    CompletedOutcome,
    IncompleteCommand,
    IssueDocument,
    JSONValue,
    issue_document,
)


if TYPE_CHECKING:
    from collections.abc import Mapping


MAX_PAGE_SIZE = 500


class ToolIdentity(TypedDict):
    name: str
    version: str


class CommandEnvelope(TypedDict):
    schema_version: Literal[2, 3]
    tool: ToolIdentity
    command: str
    completion: Literal["complete", "incomplete"]
    conclusion: Literal["passed", "findings", "inconclusive"]
    provenance: dict[str, JSONValue]
    execution_issues: list[IssueDocument]


class CapabilitiesPayload(CommandEnvelope):
    commands: list[str]
    formats: list[str]
    modes: list[str]
    exit_codes: dict[str, str]
    safety: dict[str, JSONValue]
    domains: dict[str, JSONValue]
    schemas: list[str]
    pagination: dict[str, int]


def capabilities_payload() -> CapabilitiesPayload:
    return {
        **envelope("capabilities"),
        "commands": [
            "baseline",
            "capabilities",
            "catalog",
            "check",
            "commit-message",
            "explain",
            "inspect",
            "pull-request commits",
            "pull-request review-policy",
            "pull-request size",
            "pull-request text",
            "report",
            "rest discover",
            "rest doctor",
            "rules",
            "schema",
        ],
        "formats": ["json", "pretty-json", "text"],
        "modes": ["report", "ratchet", "strict"],
        "exit_codes": {"0": "satisfied", "1": "policy-findings", "2": "incomplete"},
        "safety": {
            "network": False,
            "network_default": False,
            "network_mode": "disabled",
            "repository_code_execution": False,
            "mutation": "commit-message --fix-safe only",
            "autofix": "bounded mechanical commit-header normalization only",
            "inspection_input": "exact-git-head-tree",
        },
        "domains": {
            "repository": {"status": "stable"},
            "rest": {
                "status": "preview",
                "input": "committed-openapi-json",
                "application_code_execution": False,
            },
        },
        "schemas": ["baseline", "catalog", "report"],
        "pagination": {"default_limit": 100, "maximum_limit": MAX_PAGE_SIZE},
    }


def envelope(
    command: str,
    *,
    outcome: CommandOutcome = CompletedOutcome.PASSED,
    provenance: Mapping[str, JSONValue] | None = None,
) -> CommandEnvelope:
    match outcome:
        case CompletedOutcome():
            completion: Literal["complete", "incomplete"] = "complete"
            conclusion: Literal["passed", "findings", "inconclusive"] = outcome.value
            issues: list[IssueDocument] = []
        case IncompleteCommand():
            completion, conclusion = "incomplete", "inconclusive"
            issues = [issue_document(issue) for issue in outcome.issues]
        case _:
            assert_never(outcome)
    return {
        "schema_version": 2,
        "tool": {"name": "repo-standards", "version": installed_version()},
        "command": command,
        "completion": completion,
        "conclusion": conclusion,
        "provenance": dict(provenance or {"kind": "installed-environment"}),
        "execution_issues": issues,
    }


def installed_version() -> str:
    try:
        return metadata.version("repo-standards")
    except metadata.PackageNotFoundError:
        return "unknown"
