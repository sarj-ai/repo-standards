# pyright: reportAny=false, reportExplicitAny=false, reportUnannotatedClassAttribute=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import Any, Final
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen


_COMMENT_MARKER: Final = "<!-- repo-standards-review-policy -->"
_STATUS_CONTEXT: Final = "Review Policy"
_MAX_PAGES: Final = 100
_MAX_ITEMS: Final = 10_000
_PER_PAGE: Final = 100
_INCOMPLETE_EXIT: Final = 2
# A reconcile run posts its final status a few seconds before the run completes,
# and the merge queue starts a merge group as soon as that status turns green.
_RUN_COMPLETION_TIMEOUT_SECONDS: Final = 300
_RUN_COMPLETION_POLL_SECONDS: Final = 5
_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
_MERGE_GROUP_REF = re.compile(
    r"refs/heads/gh-readonly-queue/(?P<base_ref>.+)/"
    r"pr-(?P<number>[1-9][0-9]*)-(?P<parent_sha>[0-9a-f]{40})\Z"
)


class ReconciliationError(RuntimeError):
    """Provider evidence could not be collected or reconciled completely."""


@dataclass(frozen=True, slots=True)
class PullRequestSnapshot:
    number: int
    base_sha: str
    head_sha: str
    base_ref: str
    head_ref: str
    body: str
    author: str
    author_id: int
    author_type: str
    head_repository: str
    base_repository_id: int
    head_repository_id: int
    draft: bool
    state: str


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    receipt: Mapping[str, Any]
    stdout: str


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    snapshot: PullRequestSnapshot
    checks: tuple[dict[str, str], ...]
    raw_reviews: tuple[Any, ...]
    reviews: tuple[dict[str, str | None], ...]
    threads_resolved: bool

    def fingerprint(self) -> str:
        snapshot = self.snapshot
        payload = {
            "pull_request": {
                "number": snapshot.number,
                "base_sha": snapshot.base_sha,
                "head_sha": snapshot.head_sha,
                "base_ref": snapshot.base_ref,
                "head_ref": snapshot.head_ref,
                "body": snapshot.body,
                "author": snapshot.author,
                "author_id": snapshot.author_id,
                "author_type": snapshot.author_type,
                "head_repository": snapshot.head_repository,
                "base_repository_id": snapshot.base_repository_id,
                "head_repository_id": snapshot.head_repository_id,
                "draft": snapshot.draft,
                "state": snapshot.state,
            },
            "checks": self.checks,
            "reviews": self.reviews,
            "threads_resolved": self.threads_resolved,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class GitHubClient:
    def __init__(self, *, token: str, repository: str, api_url: str) -> None:
        if not token:
            raise ReconciliationError("github-token is required")
        if not re.fullmatch(r"[^/]+/[^/]+", repository):
            raise ReconciliationError("GITHUB_REPOSITORY must be owner/name")
        self._token = token
        self.repository = repository
        self.api_url = api_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        url = path if path.startswith("https://") else f"{self.api_url}{path}"
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "repo-standards-review-policy",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as error:
            detail = error.read().decode(errors="replace")[:1000]
            raise ReconciliationError(
                f"GitHub API {method} {path} returned {error.code}: {detail}"
            ) from error
        except (TimeoutError, URLError) as error:
            raise ReconciliationError(f"GitHub API {method} {path} failed: {error}") from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise ReconciliationError(
                f"GitHub API {method} {path} returned invalid JSON"
            ) from error

    def rest_pages(self, path: str, *, collection_key: str | None = None) -> list[Any]:
        items: list[Any] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, _MAX_PAGES + 1):
            payload = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            if collection_key is not None:
                if not isinstance(payload, dict) or not isinstance(
                    payload.get(collection_key), list
                ):
                    raise ReconciliationError(
                        f"GitHub API pagination response is missing {collection_key!r}"
                    )
                batch = payload[collection_key]
            else:
                if not isinstance(payload, list):
                    raise ReconciliationError("GitHub API pagination response must be an array")
                batch = payload
            items.extend(batch)
            if len(items) > _MAX_ITEMS:
                raise ReconciliationError("GitHub API evidence exceeds 10000 items")
            if len(batch) < _PER_PAGE:
                return items
        raise ReconciliationError("GitHub API pagination exceeded 100 pages")

    def graphql(self, query: str, variables: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = self.request("POST", "/graphql", payload={"query": query, "variables": variables})
        if not isinstance(payload, dict):
            raise ReconciliationError("GitHub GraphQL response must be an object")
        errors = payload.get("errors")
        if errors:
            raise ReconciliationError(f"GitHub GraphQL returned errors: {errors!r}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ReconciliationError("GitHub GraphQL response is missing data")
        return data


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReconciliationError(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReconciliationError(f"{context} must be a non-empty string")
    return value


def _integer(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ReconciliationError(f"{context} must be a positive integer")
    return value


def pull_request_snapshot(client: GitHubClient, number: int) -> PullRequestSnapshot:
    value = _mapping(
        client.request("GET", f"/repos/{client.repository}/pulls/{number}"),
        "pull request",
    )
    base = _mapping(value.get("base"), "pull request base")
    head = _mapping(value.get("head"), "pull request head")
    user = _mapping(value.get("user"), "pull request user")
    head_repo = _mapping(head.get("repo"), "pull request head repository")
    base_repo = _mapping(base.get("repo"), "pull request base repository")
    base_sha = _string(base.get("sha"), "base SHA")
    head_sha = _string(head.get("sha"), "head SHA")
    if _OBJECT_ID.fullmatch(base_sha) is None or _OBJECT_ID.fullmatch(head_sha) is None:
        raise ReconciliationError("pull request revisions must be lowercase 40-character SHAs")
    body = value.get("body")
    return PullRequestSnapshot(
        number=number,
        base_sha=base_sha,
        head_sha=head_sha,
        base_ref=_string(base.get("ref"), "base ref"),
        head_ref=_string(head.get("ref"), "head ref"),
        body=body if isinstance(body, str) else "",
        author=_string(user.get("login"), "pull request author"),
        author_id=_integer(user.get("id"), "pull request author id"),
        author_type=_string(user.get("type"), "pull request author type"),
        head_repository=_string(head_repo.get("full_name"), "pull request head repository"),
        base_repository_id=_integer(base_repo.get("id"), "base repository id"),
        head_repository_id=_integer(head_repo.get("id"), "head repository id"),
        draft=_boolean(value.get("draft"), "pull request draft"),
        state=_string(value.get("state"), "pull request state"),
    )


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ReconciliationError(f"{context} must be a boolean")
    return value


def _run_git(root: Path, *arguments: str, text: bool = True) -> str | bytes:
    process = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed executable and controlled arguments
        ("git", "-C", str(root), *arguments),
        check=False,
        capture_output=True,
        text=text,
    )
    if process.returncode != 0:
        stderr = (
            process.stderr
            if isinstance(process.stderr, str)
            else process.stderr.decode(errors="replace")
        )
        raise ReconciliationError(f"git {' '.join(arguments[:2])} failed: {stderr.strip()}")
    return process.stdout


def ensure_git_objects(root: Path, snapshot: PullRequestSnapshot) -> None:
    missing = []
    for revision in (snapshot.base_sha, snapshot.head_sha):
        process = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed executable and exact provider SHA
            ("git", "-C", str(root), "cat-file", "-e", f"{revision}^{{commit}}"),
            check=False,
            capture_output=True,
        )
        if process.returncode != 0:
            missing.append(revision)
    if missing:
        process = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed executable and exact provider SHAs
            (
                "git",
                "-C",
                str(root),
                "fetch",
                "--no-tags",
                "--filter=blob:none",
                "origin",
                *missing,
            ),
            check=False,
            capture_output=True,
            text=True,
        )
        if process.returncode != 0:
            raise ReconciliationError(
                f"cannot fetch exact pull request revisions: {process.stderr.strip()}"
            )
    for revision in (snapshot.base_sha, snapshot.head_sha):
        _run_git(root, "cat-file", "-e", f"{revision}^{{commit}}")


def trusted_manifest(
    root: Path,
    base_sha: str,
    destination: Path,
    *,
    manifest_path: str = ".repo-standards/repository.toml",
) -> Mapping[str, Any]:
    pure_path = PurePosixPath(manifest_path)
    if (
        not manifest_path
        or pure_path.is_absolute()
        or ".." in pure_path.parts
        or pure_path.as_posix() != manifest_path
    ):
        raise ReconciliationError("manifest-path must be a normalized repository-relative path")
    content = _run_git(
        root,
        "show",
        f"{base_sha}:{manifest_path}",
        text=False,
    )
    if not isinstance(content, bytes):
        raise ReconciliationError("git returned text for a binary manifest request")
    try:
        parsed = tomllib.loads(content.decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ReconciliationError("trusted base manifest is not valid UTF-8 TOML") from error
    destination.write_bytes(content)
    return parsed


def required_check_names(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    pull_request = _mapping(manifest.get("pull_request"), "manifest pull_request")
    policy = _mapping(pull_request.get("review_policy"), "manifest pull_request.review_policy")
    raw = policy.get("required_checks")
    if (
        not isinstance(raw, list)
        or not raw
        or not all(isinstance(item, str) and item for item in raw)
    ):
        raise ReconciliationError("trusted review policy required_checks must be a non-empty array")
    names = tuple(raw)
    if len(names) != len(set(names)):
        raise ReconciliationError("trusted review policy required_checks must be unique")
    return names


def check_conclusion(check: Mapping[str, Any]) -> str:
    if check.get("status") != "completed":
        return "pending"
    conclusion = check.get("conclusion")
    known = {
        "success",
        "neutral",
        "skipped",
        "failure",
        "cancelled",
        "timed_out",
        "action_required",
    }
    return conclusion if isinstance(conclusion, str) and conclusion in known else "failure"


def collect_required_checks(
    client: GitHubClient,
    *,
    head_sha: str,
    names: Sequence[str],
    required_app_id: int,
) -> tuple[dict[str, str], ...]:
    encoded_sha = urlencode({"ref": head_sha})[4:]
    runs = client.rest_pages(
        f"/repos/{client.repository}/commits/{encoded_sha}/check-runs?filter=all",
        collection_key="check_runs",
    )
    # Statuses are collected and fully paginated as independent provider evidence. The
    # configured producer is a GitHub App, so classic statuses cannot satisfy a check.
    client.rest_pages(f"/repos/{client.repository}/commits/{encoded_sha}/statuses")
    result: list[dict[str, str]] = []
    for name in names:
        candidates = []
        for raw in runs:
            check = _mapping(raw, "check run")
            if check.get("name") != name:
                continue
            app = _mapping(check.get("app"), "configured check run app")
            if app.get("id") == required_app_id:
                candidates.append(check)
        if not candidates:
            result.append({"name": name, "conclusion": "missing", "head_sha": head_sha})
            continue
        latest = max(candidates, key=lambda item: int(item.get("id", 0)))
        actual_head_sha = _string(latest.get("head_sha"), "configured check run head SHA")
        if actual_head_sha != head_sha:
            raise ReconciliationError(f"configured check {name!r} reported a different head SHA")
        _actions_run_id(
            _string(latest.get("details_url"), "configured check run details URL"),
            repository=client.repository,
        )
        result.append(
            {
                "name": name,
                "conclusion": check_conclusion(latest),
                "head_sha": actual_head_sha,
            }
        )
    return tuple(result)


def _actions_run_id(target_url: str, *, repository: str) -> int:
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    expected = urlsplit(server_url)
    observed = urlsplit(target_url)
    prefix = f"/{repository}/actions/runs/"
    if (
        observed.scheme != expected.scheme
        or observed.netloc != expected.netloc
        or not observed.path.startswith(prefix)
    ):
        raise ReconciliationError("workflow evidence does not point to this repository's Actions")
    run_id = observed.path.removeprefix(prefix).split("/", 1)[0]
    if not run_id.isdigit() or int(run_id) <= 0:
        raise ReconciliationError("workflow evidence has an invalid Actions run ID")
    return int(run_id)


def eligible_reviewer_ids(
    client: GitHubClient,
    reviews: Sequence[Any],
    *,
    author_id: int,
) -> frozenset[int]:
    actors: dict[int, str] = {}
    for raw in reviews:
        review = _mapping(raw, "review")
        state = review.get("state")
        if not isinstance(state, str) or state.casefold() not in {
            "approved",
            "changes_requested",
            "dismissed",
        }:
            continue
        user = _mapping(review.get("user"), "review user")
        login = _string(user.get("login"), "review user login")
        user_id = _integer(user.get("id"), "review user id")
        user_type = _string(user.get("type"), "review user type")
        if (
            user_id == author_id
            or user_type.casefold() == "bot"
            or login.casefold().endswith("[bot]")
        ):
            continue
        existing = actors.get(user_id)
        if existing is not None and existing.casefold() != login.casefold():
            raise ReconciliationError("one reviewer ID was returned with multiple logins")
        actors[user_id] = login

    eligible: set[int] = set()
    for user_id, login in actors.items():
        encoded_login = quote(login, safe="")
        permission = _mapping(
            client.request(
                "GET",
                f"/repos/{client.repository}/collaborators/{encoded_login}/permission",
            ),
            "collaborator permission",
        )
        resolved_user = _mapping(permission.get("user"), "collaborator permission user")
        if _integer(resolved_user.get("id"), "collaborator permission user id") != user_id:
            raise ReconciliationError("collaborator permission resolved a different user ID")
        base_permission = permission.get("permission")
        role_name = permission.get("role_name")
        if base_permission in {"write", "admin"} or role_name in {"write", "maintain", "admin"}:
            eligible.add(user_id)
    return frozenset(eligible)


def latest_human_reviews(
    reviews: Sequence[Any],
    *,
    author_id: int,
    eligible_ids: frozenset[int],
) -> tuple[dict[str, str | None], ...]:
    latest: dict[int, tuple[tuple[str, int], dict[str, str | None]]] = {}
    for raw in reviews:
        review = _mapping(raw, "review")
        user = _mapping(review.get("user"), "review user")
        login = _string(user.get("login"), "review user login")
        user_id = _integer(user.get("id"), "review user id")
        user_type = _string(user.get("type"), "review user type")
        reviewer_is_bot = user_type.casefold() == "bot" or login.casefold().endswith("[bot]")
        if user_id == author_id or reviewer_is_bot or user_id not in eligible_ids:
            continue
        state_value = review.get("state")
        if not isinstance(state_value, str):
            raise ReconciliationError("review state must be a string")
        state = state_value.casefold()
        if state not in {"approved", "changes_requested", "dismissed"}:
            continue
        submitted = review.get("submitted_at")
        submitted_key = submitted if isinstance(submitted, str) else ""
        review_id = review.get("id")
        if not isinstance(review_id, int):
            raise ReconciliationError("review id must be an integer")
        commit_sha = review.get("commit_id")
        if commit_sha is not None and (
            not isinstance(commit_sha, str) or _OBJECT_ID.fullmatch(commit_sha) is None
        ):
            raise ReconciliationError("review commit_id must be an exact SHA or null")
        value = {"reviewer": f"{user_id}:{login}", "state": state, "commit_sha": commit_sha}
        key = user_id
        ordering = (submitted_key, review_id)
        if key not in latest or ordering > latest[key][0]:
            latest[key] = (ordering, value)
    return tuple(latest[key][1] for key in sorted(latest))


def collect_threads_resolved(client: GitHubClient, number: int) -> bool:
    owner, name = client.repository.split("/", 1)
    query = """
      query($owner:String!,$name:String!,$number:Int!,$after:String) {
        repository(owner:$owner,name:$name) {
          pullRequest(number:$number) {
            reviewThreads(first:100,after:$after) {
              nodes { isResolved }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
      }
    """
    cursor: str | None = None
    resolved = True
    count = 0
    for _page in range(_MAX_PAGES):
        data = client.graphql(
            query,
            {"owner": owner, "name": name, "number": number, "after": cursor},
        )
        repository = _mapping(data.get("repository"), "GraphQL repository")
        pull_request = _mapping(repository.get("pullRequest"), "GraphQL pull request")
        threads = _mapping(pull_request.get("reviewThreads"), "GraphQL review threads")
        nodes = threads.get("nodes")
        if not isinstance(nodes, list):
            raise ReconciliationError("GraphQL review thread nodes must be an array")
        for raw in nodes:
            node = _mapping(raw, "GraphQL review thread")
            if not isinstance(node.get("isResolved"), bool):
                raise ReconciliationError("GraphQL review thread resolution must be boolean")
            resolved = resolved and bool(node["isResolved"])
        count += len(nodes)
        if count > _MAX_ITEMS:
            raise ReconciliationError("review thread evidence exceeds 10000 items")
        page_info = _mapping(threads.get("pageInfo"), "GraphQL review thread pageInfo")
        has_next = page_info.get("hasNextPage")
        if not isinstance(has_next, bool):
            raise ReconciliationError("GraphQL hasNextPage must be boolean")
        if not has_next:
            return resolved
        cursor_value = page_info.get("endCursor")
        cursor = _string(cursor_value, "GraphQL endCursor")
    raise ReconciliationError("review thread pagination exceeded 100 pages")


def collect_evidence(
    client: GitHubClient,
    *,
    number: int,
    check_names: Sequence[str],
    required_check_app_id: int,
) -> CollectedEvidence:
    snapshot = pull_request_snapshot(client, number)
    checks = collect_required_checks(
        client,
        head_sha=snapshot.head_sha,
        names=check_names,
        required_app_id=required_check_app_id,
    )
    raw_reviews = tuple(client.rest_pages(f"/repos/{client.repository}/pulls/{number}/reviews"))
    eligible_ids = eligible_reviewer_ids(client, raw_reviews, author_id=snapshot.author_id)
    reviews = latest_human_reviews(
        raw_reviews,
        author_id=snapshot.author_id,
        eligible_ids=eligible_ids,
    )
    return CollectedEvidence(
        snapshot=snapshot,
        checks=checks,
        raw_reviews=raw_reviews,
        reviews=reviews,
        threads_resolved=collect_threads_resolved(client, number),
    )


def require_unchanged_evidence(
    expected: CollectedEvidence,
    observed: CollectedEvidence,
    *,
    phase: str,
) -> None:
    if observed.fingerprint() != expected.fingerprint():
        raise ReconciliationError(f"pull request evidence changed {phase}; retry reconciliation")


def run_policy_cli(
    root: Path,
    *,
    base_sha: str,
    head_sha: str,
    evidence_path: Path,
    manifest_path: Path,
    project_root: Path,
) -> CommandResult:
    process = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed uv invocation and exact evidence paths
        (
            "uv",
            "run",
            "--project",
            str(project_root),
            "--no-sync",
            "repo-standards",
            "pull-request",
            "review-policy",
            str(root),
            "--base",
            base_sha,
            "--head",
            head_sha,
            "--evidence",
            str(evidence_path),
            "--manifest",
            str(manifest_path),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        receipt = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise ReconciliationError(
            f"review policy CLI returned invalid JSON (exit {process.returncode}): "
            f"{process.stderr[:1000]}"
        ) from error
    if not isinstance(receipt, dict) or process.returncode not in {0, 1, 2}:
        raise ReconciliationError(
            f"review policy CLI failed unexpectedly with exit {process.returncode}: "
            f"{process.stderr[:1000]}"
        )
    return CommandResult(process.returncode, receipt, process.stdout)


def _summary(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(receipt.get("summary"), "review policy receipt summary")


def render_comment(
    receipt: Mapping[str, Any],
    *,
    final_passed: bool,
    lane_enabled: bool,
    operational_reason: str | None,
) -> str:
    summary = _summary(receipt)
    size = _mapping(receipt.get("size"), "review policy receipt size")
    tier = summary.get("tier", "?")
    reasons = summary.get("reasons")
    reason_items = [str(item) for item in reasons] if isinstance(reasons, list) else ["unknown"]
    if operational_reason is not None:
        reason_items.append(operational_reason)
    reason_text = ", ".join(reason_items)
    lane = "enabled" if lane_enabled else "disabled"
    return (
        f"{_COMMENT_MARKER}\n"
        "### Review policy\n\n"
        f"- Decision: **{'pass' if final_passed else 'blocked'}**\n"
        f"- Tier: **{tier}** human review(s) required\n"
        f"- Approvals: **{summary.get('current_human_approvals', '?')}** "
        "current human approval(s)\n"
        f"- Counted size: **{size.get('counted_lines', '?')}** lines "
        f"({size.get('excluded_lines', '?')} excluded)\n"
        f"- Migration: **{'yes' if summary.get('touches_migration') else 'no'}**\n"
        f"- Review-optional lane: **{lane}**\n"
        f"- Reasons: `{reason_text}`\n\n"
        f"Evaluated head `{receipt.get('provenance', {}).get('evaluated_head', 'unknown')}`.\n"
    )


def render_incomplete_comment(receipt: Mapping[str, Any]) -> str:
    issue_count = len(receipt.get("issues", ())) if isinstance(receipt.get("issues"), list) else 0
    return (
        f"{_COMMENT_MARKER}\n"
        "### Review policy\n\n"
        "- Decision: **incomplete**\n"
        "- The evidence transaction failed closed.\n"
        f"- Receipt issues: **{issue_count}**\n"
    )


def upsert_comment(client: GitHubClient, number: int, body: str) -> None:
    comments = client.rest_pages(f"/repos/{client.repository}/issues/{number}/comments")
    matching = [
        _mapping(item, "issue comment")
        for item in comments
        if isinstance(item, dict)
        and isinstance(item.get("body"), str)
        and _COMMENT_MARKER in item["body"]
    ]
    if len(matching) > 1:
        raise ReconciliationError("multiple review-policy marker comments exist")
    if matching:
        comment_id = matching[0].get("id")
        if not isinstance(comment_id, int):
            raise ReconciliationError("review-policy comment id must be an integer")
        client.request(
            "PATCH",
            f"/repos/{client.repository}/issues/comments/{comment_id}",
            payload={"body": body},
        )
    else:
        client.request(
            "POST",
            f"/repos/{client.repository}/issues/{number}/comments",
            payload={"body": body},
        )


def post_status(
    client: GitHubClient,
    *,
    head_sha: str,
    state: str,
    description: str,
    target_url: str | None,
) -> None:
    payload: dict[str, Any] = {
        "state": state,
        "context": _STATUS_CONTEXT,
        "description": description[:140],
    }
    if target_url:
        payload["target_url"] = target_url
    client.request(
        "POST",
        f"/repos/{client.repository}/statuses/{head_sha}",
        payload=payload,
    )


def review_policy_status_passed(
    client: GitHubClient,
    statuses: Sequence[Any],
    *,
    head_sha: str,
    workflow_path: str,
) -> bool:
    matching: list[Mapping[str, Any]] = []
    for raw in statuses:
        status = _mapping(raw, "commit status")
        if status.get("context") == _STATUS_CONTEXT and status.get("sha") == head_sha:
            matching.append(status)
    if not matching:
        return False
    latest = max(matching, key=lambda item: _integer(item.get("id"), "commit status id"))
    creator = _mapping(latest.get("creator"), "commit status creator")
    if not (
        latest.get("state") == "success"
        and creator.get("login") == "github-actions[bot]"
        and creator.get("type") == "Bot"
    ):
        return False
    run_id = _actions_run_id(
        _string(latest.get("target_url"), "review policy status target URL"),
        repository=client.repository,
    )
    run = _completed_run(client, run_id)
    run_path = _string(run.get("path"), "review policy workflow path").split("@", 1)[0]
    return (
        run_path == workflow_path
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("event")
        in {"pull_request_target", "workflow_run", "schedule", "workflow_dispatch"}
    )


def _completed_run(client: GitHubClient, run_id: int) -> Mapping[str, Any]:
    deadline = time.monotonic() + _RUN_COMPLETION_TIMEOUT_SECONDS
    while True:
        run = _mapping(
            client.request("GET", f"/repos/{client.repository}/actions/runs/{run_id}"),
            "review policy workflow run",
        )
        if run.get("status") == "completed" or time.monotonic() >= deadline:
            return run
        time.sleep(_RUN_COMPLETION_POLL_SECONDS)


def merge_group_pull_request(head_ref: str) -> tuple[str, int, str]:
    match = _MERGE_GROUP_REF.fullmatch(head_ref)
    if match is None:
        raise ReconciliationError("merge-group-head-ref must be an exact merge-queue ref")
    return (
        match.group("base_ref"),
        int(match.group("number")),
        match.group("parent_sha"),
    )


def merge_queue_head_sha(client: GitHubClient, number: int) -> str:
    owner, repository = client.repository.split("/", 1)
    data = client.graphql(
        """query($owner: String!, $repository: String!, $number: Int!) {
          repository(owner: $owner, name: $repository) {
            pullRequest(number: $number) {
              mergeQueueEntry { headCommit { oid } }
            }
          }
        }""",
        {"owner": owner, "repository": repository, "number": number},
    )
    repo = _mapping(data.get("repository"), "merge queue repository")
    pull_request = _mapping(repo.get("pullRequest"), "merge queue pull request")
    entry = _mapping(pull_request.get("mergeQueueEntry"), "merge queue entry")
    head_commit = _mapping(entry.get("headCommit"), "merge queue head commit")
    sha = _string(head_commit.get("oid"), "merge queue head SHA")
    if _OBJECT_ID.fullmatch(sha) is None:
        raise ReconciliationError("merge queue head SHA must be an exact lowercase SHA")
    return sha


def reconcile_merge_group(
    *,
    client: GitHubClient,
    head_sha: str,
    head_ref: str,
    workflow_path: str,
) -> int:
    if _OBJECT_ID.fullmatch(head_sha) is None:
        raise ReconciliationError("merge-group-head-sha must be an exact lowercase SHA")
    base_ref, number, queue_parent_sha = merge_group_pull_request(head_ref)
    commit = _mapping(
        client.request("GET", f"/repos/{client.repository}/commits/{head_sha}"),
        "merge group commit",
    )
    if commit.get("sha") != head_sha:
        raise ReconciliationError("merge group commit lookup returned a different SHA")
    parents = commit.get("parents")
    if not isinstance(parents, list) or not parents:
        raise ReconciliationError("merge group commit must have at least one parent")
    parent_shas = {
        _string(_mapping(parent, "merge group parent").get("sha"), "merge group parent SHA")
        for parent in parents
    }
    if queue_parent_sha not in parent_shas:
        raise ReconciliationError("merge-group-head-ref parent does not match the merge group")
    post_status(
        client,
        head_sha=head_sha,
        state="pending",
        description=f"Checking pull request {number} review policy receipt",
        target_url=_workflow_url(),
    )
    snapshot = pull_request_snapshot(client, number)
    if snapshot.base_ref != base_ref:
        raise ReconciliationError(
            f"pull request {number} targets {snapshot.base_ref!r}, not merge-group base {base_ref!r}"
        )
    if snapshot.state != "open":
        raise ReconciliationError(f"merge-group pull request {number} is not open")
    if merge_queue_head_sha(client, number) != head_sha:
        raise ReconciliationError(f"pull request {number} queue entry changed during reconciliation")
    statuses = client.rest_pages(
        f"/repos/{client.repository}/commits/{snapshot.head_sha}/statuses"
    )
    passed = review_policy_status_passed(
        client,
        statuses,
        head_sha=snapshot.head_sha,
        workflow_path=workflow_path,
    )
    refreshed = pull_request_snapshot(client, snapshot.number)
    if refreshed.head_sha != snapshot.head_sha:
        raise ReconciliationError(
            f"pull request {snapshot.number} changed during merge-group reconciliation"
        )
    if merge_queue_head_sha(client, number) != head_sha:
        raise ReconciliationError(f"pull request {number} queue entry changed during reconciliation")
    refreshed_commit = _mapping(
        client.request("GET", f"/repos/{client.repository}/commits/{head_sha}"),
        "refreshed merge group commit",
    )
    if refreshed_commit.get("sha") != head_sha:
        raise ReconciliationError("merge group changed during reconciliation")
    description = (
        f"Pull request {number} review policy receipt passed"
        if passed
        else f"Pull request {number} review policy receipt blocked"
    )
    post_status(
        client,
        head_sha=head_sha,
        state="success" if passed else "failure",
        description=description,
        target_url=_workflow_url(),
    )
    _write_output("receipt-path", "")
    _write_output("tier", "merge-group")
    _write_output("merge-ready", str(passed).lower())
    return 0 if passed else 1


def _write_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with Path(path).open("a", encoding="utf-8") as output:
            output.write(f"{name}={value}\n")


def _workflow_url() -> str | None:
    server = os.environ.get("GITHUB_SERVER_URL")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repository and run_id:
        return f"{server}/{repository}/actions/runs/{run_id}"
    return None


def final_policy_decision(
    *,
    policy_passed: bool,
    tier: object,
    lane_enabled: bool,
    same_repository: bool,
    author_is_bot: bool,
    draft: bool,
) -> tuple[bool, str | None]:
    if not policy_passed or tier != 0:
        return policy_passed, None
    if not lane_enabled:
        return False, "review_optional_lane_disabled"
    if not same_repository:
        return False, "review_optional_fork_blocked"
    if author_is_bot:
        return False, "review_optional_bot_author_blocked"
    if draft:
        return False, "review_optional_draft_blocked"
    return True, None


def reconcile(args: argparse.Namespace) -> int:  # ruff: ignore[too-many-statements] - orchestration stays linear and auditable
    root = Path(args.root).resolve(strict=True)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    client = GitHubClient(token=github_token, repository=repository, api_url=api_url)
    if args.merge_group_head_sha:
        if args.pr_number is not None:
            raise ReconciliationError("pr-number and merge-group-head-sha are mutually exclusive")
        if args.merge_group_head_ref is None:
            raise ReconciliationError("merge-group-head-ref is required in merge-group mode")
        return reconcile_merge_group(
            client=client,
            head_sha=args.merge_group_head_sha,
            head_ref=args.merge_group_head_ref,
            workflow_path=args.policy_workflow_path,
        )
    if args.merge_group_head_ref is not None:
        raise ReconciliationError("merge-group-head-ref requires merge-group-head-sha")
    if args.pr_number is None:
        raise ReconciliationError("pr-number is required outside merge-group mode")
    snapshot = pull_request_snapshot(client, args.pr_number)
    post_status(
        client,
        head_sha=snapshot.head_sha,
        state="pending",
        description="Review policy reconciliation in progress",
        target_url=_workflow_url(),
    )
    if snapshot.state != "open":
        raise ReconciliationError("review policy only evaluates open pull requests")
    author_is_bot = snapshot.author_type.casefold() == "bot" or snapshot.author.casefold().endswith(
        "[bot]"
    )
    ensure_git_objects(root, snapshot)

    with tempfile.TemporaryDirectory(prefix="repo-standards-review-policy-") as raw_temp:
        temporary = Path(raw_temp)
        manifest_path = temporary / "repository.toml"
        manifest = trusted_manifest(
            root,
            snapshot.base_sha,
            manifest_path,
            manifest_path=args.manifest_path,
        )
        check_names = required_check_names(manifest)
        collected = collect_evidence(
            client,
            number=args.pr_number,
            check_names=check_names,
            required_check_app_id=args.required_check_app_id,
        )
        if collected.snapshot != snapshot:
            raise ReconciliationError("pull request changed before evidence collection completed")
        evidence = {
            "schema_version": 1,
            "evaluated_head_sha": snapshot.head_sha,
            "current_head_sha": snapshot.head_sha,
            "base_ref": snapshot.base_ref,
            "head_ref": snapshot.head_ref,
            "base_repository_id": snapshot.base_repository_id,
            "head_repository_id": snapshot.head_repository_id,
            "is_draft": snapshot.draft,
            "author_is_bot": (
                snapshot.author_type.casefold() == "bot"
                or snapshot.author.casefold().endswith("[bot]")
            ),
            "author_login": snapshot.author,
            "required_checks_complete": True,
            "required_checks": collected.checks,
            "reviews_complete": True,
            "latest_human_reviews": collected.reviews,
            "threads_complete": True,
            "threads_resolved": collected.threads_resolved,
            "body": snapshot.body,
        }
        evidence_path = temporary / "evidence.json"
        evidence_path.write_text(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        project_root = Path(__file__).resolve().parents[2]
        command = run_policy_cli(
            root,
            base_sha=snapshot.base_sha,
            head_sha=snapshot.head_sha,
            evidence_path=evidence_path,
            manifest_path=manifest_path,
            project_root=project_root,
        )
        receipt = command.receipt
        receipt_path = Path(os.environ.get("RUNNER_TEMP", raw_temp)) / (
            f"repo-standards-review-policy-pr-{args.pr_number}.json"
        )
        receipt_path.write_text(command.stdout, encoding="utf-8")

    if command.returncode == _INCOMPLETE_EXIT:
        comment = render_incomplete_comment(receipt)
        upsert_comment(client, args.pr_number, comment)
        _write_step_summary(comment)
        refreshed = pull_request_snapshot(client, args.pr_number)
        if refreshed.head_sha != snapshot.head_sha:
            raise ReconciliationError(
                "pull request head changed during reconciliation; no final status was posted"
            )
        post_status(
            client,
            head_sha=snapshot.head_sha,
            state="error",
            description="Review policy evidence is incomplete",
            target_url=_workflow_url(),
        )
        _write_output("receipt-path", str(receipt_path))
        _write_output("tier", "unknown")
        _write_output("merge-ready", "false")
        return _INCOMPLETE_EXIT

    summary = _summary(receipt)
    tier = summary.get("tier")
    policy_passed = command.returncode == 0 and summary.get("merge_ready") is True
    same_repository = snapshot.head_repository_id == snapshot.base_repository_id
    final_passed, operational_reason = final_policy_decision(
        policy_passed=policy_passed,
        tier=tier,
        lane_enabled=args.review_optional_enabled,
        same_repository=same_repository,
        author_is_bot=author_is_bot,
        draft=snapshot.draft,
    )
    comment = render_comment(
        receipt,
        final_passed=final_passed,
        lane_enabled=args.review_optional_enabled,
        operational_reason=operational_reason,
    )
    upsert_comment(client, args.pr_number, comment)
    _write_step_summary(comment)

    if final_passed:
        before_success = collect_evidence(
            client,
            number=args.pr_number,
            check_names=check_names,
            required_check_app_id=args.required_check_app_id,
        )
        require_unchanged_evidence(
            collected,
            before_success,
            phase="before final success",
        )
    else:
        refreshed = pull_request_snapshot(client, args.pr_number)
        if refreshed.head_sha != snapshot.head_sha:
            raise ReconciliationError(
                "pull request head changed during reconciliation; no final status was posted"
            )
    state = "success" if final_passed else "failure"
    description = (
        f"Tier {tier}: review policy passed"
        if final_passed
        else f"Tier {tier}: review policy blocked"
    )
    post_status(
        client,
        head_sha=snapshot.head_sha,
        state=state,
        description=description,
        target_url=_workflow_url(),
    )
    _write_output("receipt-path", str(receipt_path))
    _write_output("tier", str(tier))
    _write_output("merge-ready", str(final_passed).lower())
    return 0 if final_passed else 1


def _write_step_summary(comment: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with Path(path).open("a", encoding="utf-8") as output:
            output.write(comment.replace(_COMMENT_MARKER, "").lstrip())


def main() -> None:
    try:
        raise SystemExit(reconcile(_parser().parse_args()))
    except ReconciliationError as error:
        print(f"review policy reconciliation incomplete: {error}", file=sys.stderr)
        raise SystemExit(2) from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest-path", default=".repo-standards/repository.toml")
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--merge-group-head-sha")
    parser.add_argument("--merge-group-head-ref")
    parser.add_argument("--required-check-app-id", type=int, default=15368)
    parser.add_argument("--policy-workflow-path", default=".github/workflows/review-policy.yml")
    parser.add_argument("--review-optional-enabled", action="store_true")
    return parser


if __name__ == "__main__":
    main()
