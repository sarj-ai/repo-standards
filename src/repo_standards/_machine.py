from __future__ import annotations

from collections.abc import Mapping
from importlib import metadata
from typing import TYPE_CHECKING, TypedDict


if TYPE_CHECKING:
    from collections.abc import Sequence


MAX_PAGE_SIZE = 500


class ToolIdentity(TypedDict):
    name: str
    version: str


class CommandEnvelope(TypedDict):
    schema_version: int
    tool: ToolIdentity
    command: str
    completion: str
    conclusion: str
    provenance: dict[str, object]
    execution_issues: list[Mapping[str, object]]


def capabilities_payload() -> dict[str, object]:
    return {
        **envelope("capabilities"),
        "commands": [
            "capabilities",
            "catalog",
            "check",
            "commit-message",
            "explain",
            "inspect",
            "pull-request commits",
            "pull-request review-policy",
            "pull-request size",
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
        "schemas": ["catalog", "report"],
        "pagination": {"default_limit": 100, "maximum_limit": MAX_PAGE_SIZE},
    }


def envelope(
    command: str,
    *,
    completion: str = "complete",
    conclusion: str = "passed",
    provenance: Mapping[str, object] | None = None,
    issues: Sequence[Mapping[str, object]] = (),
) -> CommandEnvelope:
    return {
        "schema_version": 2,
        "tool": {"name": "repo-standards", "version": installed_version()},
        "command": command,
        "completion": completion,
        "conclusion": conclusion,
        "provenance": dict(provenance or {"kind": "installed-environment"}),
        "execution_issues": list(issues),
    }


def installed_version() -> str:
    try:
        return metadata.version("repo-standards")
    except metadata.PackageNotFoundError:
        return "unknown"
