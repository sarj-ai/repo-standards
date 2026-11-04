from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import json
import os
from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git query
import sys
from typing import Literal

from repo_standards._git_environment import GIT_NO_PAGER_ENVIRONMENT


_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
_GIT_TIMEOUT = timedelta(seconds=10)
_MERGE_PARENT_COUNT = 2
_METADATA_LINES = 3


class GitHubCheckoutError(ValueError):
    """The checkout cannot be bound to the GitHub event."""


@dataclass(frozen=True, slots=True)
class GitHubCheckout:
    comparison_base: str
    source_commit: str
    tree: str
    event_head: str
    mode: Literal["head", "merge"]


def resolve_github_checkout(
    root: Path, *, base_sha: str, head_sha: str, github_sha: str
) -> GitHubCheckout:
    if not _OBJECT_ID.fullmatch(base_sha) or not _OBJECT_ID.fullmatch(head_sha):
        message = "GitHub event base and head must be full commit SHAs"
        raise GitHubCheckoutError(message)
    executable = shutil.which("git")
    if executable is None:
        message = "Git is required to verify the GitHub merge checkout"
        raise GitHubCheckoutError(message)
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only Git query
            [executable, "-C", str(root), "show", "--no-patch", "--format=%H%n%P%n%T", "HEAD"],
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT.total_seconds(),
            env={**GIT_NO_PAGER_ENVIRONMENT, "GIT_GRAFT_FILE": os.devnull},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        message = "Git could not verify the GitHub merge checkout"
        raise GitHubCheckoutError(message) from error
    metadata = completed.stdout.splitlines()
    if completed.returncode != 0 or len(metadata) != _METADATA_LINES:
        message = "Git could not verify the GitHub merge checkout"
        raise GitHubCheckoutError(message)
    try:
        checkout, parent_line, tree = (line.decode("ascii") for line in metadata)
    except UnicodeDecodeError as error:
        message = "Git could not verify the GitHub merge checkout"
        raise GitHubCheckoutError(message) from error
    if not _OBJECT_ID.fullmatch(checkout) or not _OBJECT_ID.fullmatch(tree):
        message = "Git could not verify the GitHub merge checkout"
        raise GitHubCheckoutError(message)
    mode: Literal["head", "merge"] = "head"
    if checkout != head_sha:
        if checkout != github_sha:
            message = "checkout does not match the GitHub event head or GITHUB_SHA"
            raise GitHubCheckoutError(message)
        parents = parent_line.split()
        if (
            len(parents) != _MERGE_PARENT_COUNT
            or any(_OBJECT_ID.fullmatch(parent) is None for parent in parents)
            or parents[1] != head_sha
        ):
            message = "GitHub merge checkout must have the event head as its second parent"
            raise GitHubCheckoutError(message)
        base_sha = parents[0]
        mode = "merge"
    return GitHubCheckout(base_sha, checkout, tree, head_sha, mode)


def main() -> int:
    try:
        _write_github_context()
    except (KeyError, OSError, ValueError) as error:
        sys.stderr.write(f"{error}\n")
        return 1
    return 0


def _write_github_context() -> None:
    environment = os.environ  # ruff: ignore[banned-api] - GitHub runner boundary before package activation
    if environment.get("GITHUB_EVENT_NAME") != "pull_request":
        message = "GitHub checkout context requires a pull_request event"
        raise GitHubCheckoutError(message)
    workspace = environment.get("GITHUB_WORKSPACE", "")
    if not workspace:
        message = "GitHub checkout context requires GITHUB_WORKSPACE"
        raise GitHubCheckoutError(message)
    with Path(environment["GITHUB_EVENT_PATH"]).open(encoding="utf-8") as event:
        document: object = json.load(event)  # pyright: ignore[reportAny] -- JSON parser boundary; every field is narrowed below
    match document:
        case {"pull_request": {"base": {"sha": str(base)}, "head": {"sha": str(head)}}}:
            context = resolve_github_checkout(
                Path(workspace).resolve(),
                base_sha=base,
                head_sha=head,
                github_sha=environment.get("GITHUB_SHA", ""),
            )
        case _:
            message = "GitHub pull-request event must include base and head SHAs"
            raise GitHubCheckoutError(message)
    with Path(environment["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(
            f"comparison-base={context.comparison_base}\n"
            f"source-commit={context.source_commit}\n"
            f"tree={context.tree}\n"
            f"event-head={context.event_head}\n"
            f"mode={context.mode}\n"
        )


if __name__ == "__main__":
    raise SystemExit(main())
