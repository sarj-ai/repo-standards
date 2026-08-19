from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from http.client import HTTPMessage, HTTPResponse
import json
import re
from typing import NamedTuple, NoReturn, cast  # ruff: ignore[banned-api] - checked before narrowing
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from repo_lint.core import ExecutionIssue, JSONValue

from .models import BranchEvidence, RepositoryEvidence, RulesetEvidence


type JsonObject = dict[str, JSONValue]


class GitHubResponse(NamedTuple):
    status: int
    body: bytes


class RulesetDetails(NamedTuple):
    items: list[JsonObject]
    complete: bool


class RepositorySlug(NamedTuple):
    owner: str
    name: str


type Transport = Callable[[Request, timedelta], GitHubResponse]
_MAX_BODY_BYTES = 4 * 1024 * 1024
_MAX_PAGES = 10
_PER_PAGE = 100
_MAX_TIMEOUT = timedelta(minutes=1)
_DEFAULT_TIMEOUT = timedelta(seconds=10)
_ZERO_DURATION = timedelta(0)
_SUCCESS_START = 200
_SUCCESS_END = 300
_SERVER_ERROR_START = 500
_REPOSITORY_PARTS = 2
_MAX_RULESET_DETAILS = 100
_PUBLIC_API_URL = "https://api.github.com"
_ASCII_CONTROL_LIMIT = 32
_ASCII_DELETE = 127


class GitHubClientError(ValueError):
    @classmethod
    def fail(cls, message: str) -> NoReturn:
        raise cls(message)


class GitHubResponseTypeError(TypeError):
    @classmethod
    def fail(cls, message: str) -> NoReturn:
        raise cls(message)


class _SameOriginRedirectHandler(HTTPRedirectHandler):
    def redirect_request(  # ruff: ignore[too-many-arguments,too-many-positional-arguments]
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> Request | None:
        old = urlsplit(req.full_url)
        new = urlsplit(newurl)
        if (
            new.scheme != "https"
            or new.hostname != old.hostname
            or new.port != old.port
            or new.username is not None
            or new.password is not None
        ):
            GitHubClientError.fail("GitHub redirected the request to an untrusted origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)  # type: ignore[arg-type]


def _stdlib_transport(request: Request, timeout: timedelta) -> GitHubResponse:
    opener = build_opener(_SameOriginRedirectHandler())
    response = cast(
        "HTTPResponse",
        opener.open(request, timeout=timeout.total_seconds()),
    )
    with response:
        body = response.read(_MAX_BODY_BYTES + 1)
        if len(body) > _MAX_BODY_BYTES:
            GitHubClientError.fail("GitHub response exceeds the 4 MiB limit")
        return GitHubResponse(response.status, body)


class GitHubClient:
    _token: str | None
    _api_url: str
    _timeout: timedelta
    _max_pages: int
    _transport: Transport

    def __init__(
        self,
        token: str | None,
        *,
        api_url: str = "https://api.github.com",
        timeout: timedelta = _DEFAULT_TIMEOUT,
        max_pages: int = _MAX_PAGES,
        transport: Transport = _stdlib_transport,
    ) -> None:
        super().__init__()
        parsed = urlsplit(api_url)
        if not _valid_api_url(parsed):
            GitHubClientError.fail(
                f"api_url must be {_PUBLIC_API_URL}; custom GitHub Enterprise hosts are unsupported"
            )
        if token is not None and _invalid_token(token):
            GitHubClientError.fail("token must be non-empty and contain no whitespace or controls")
        if timeout <= _ZERO_DURATION or timeout > _MAX_TIMEOUT:
            GitHubClientError.fail("timeout must be greater than zero and at most 60 seconds")
        if max_pages < 1 or max_pages > _MAX_PAGES:
            GitHubClientError.fail(f"max_pages must be between 1 and {_MAX_PAGES}")
        self._token = token
        self._api_url = _PUBLIC_API_URL
        self._timeout = timeout
        self._max_pages = max_pages
        self._transport = transport

    def collect(  # ruff: ignore[too-many-locals] - explicit evidence completeness by phase
        self, repository: str
    ) -> RepositoryEvidence:
        owner, name = _split_repository(repository)
        slug = f"{owner}/{name}"
        issues: list[ExecutionIssue] = []
        issue_count = len(issues)
        repo = self._object(f"/repos/{_segment(owner)}/{_segment(name)}", "repository", issues)
        repository_available = len(issues) == issue_count and _validate_repository(repo, issues)
        issue_count = len(issues)
        branches_payload = self._pages(
            f"/repos/{_segment(owner)}/{_segment(name)}/branches", "branches", issues
        )
        branches_complete = len(issues) == issue_count
        issue_count = len(issues)
        ruleset_summaries = self._pages(
            f"/repos/{_segment(owner)}/{_segment(name)}/rulesets",
            "rulesets",
            issues,
            {"includes_parents": "true"},
        )
        rulesets_complete = len(issues) == issue_count
        rulesets_payload, details_complete = self._ruleset_details(
            owner, name, ruleset_summaries, issues
        )
        rulesets_complete = rulesets_complete and details_complete
        issue_count = len(issues)
        permissions = self._object(
            f"/repos/{_segment(owner)}/{_segment(name)}/actions/permissions/workflow",
            "actions-permissions",
            issues,
        )
        actions_permissions_available = len(issues) == issue_count and _validate_permissions(
            permissions, issues
        )
        branches: list[BranchEvidence] = []
        for item in branches_payload:
            try:
                branches.append(_branch(item))
            except GitHubResponseTypeError as error:
                branches_complete = False
                issues.append(_invalid_issue("branches", str(error)))
        parsed_rulesets: list[RulesetEvidence] = []
        for item in rulesets_payload:
            try:
                parsed_rulesets.append(_ruleset(item))
            except GitHubResponseTypeError as error:
                rulesets_complete = False
                issues.append(_invalid_issue("ruleset-details", str(error)))
        default_branch = repo.get("default_branch")
        canonical_repository = repo.get("full_name")
        allow_auto_merge = repo.get("allow_auto_merge")
        default_permissions = permissions.get("default_workflow_permissions")
        can_approve = permissions.get("can_approve_pull_request_reviews")
        return RepositoryEvidence(
            repository=(
                canonical_repository
                if repository_available and isinstance(canonical_repository, str)
                else slug
            ),
            default_branch=(
                default_branch if repository_available and isinstance(default_branch, str) else None
            ),
            branches=tuple(sorted(branches, key=lambda branch: branch.name)),
            rulesets=tuple(
                sorted(
                    parsed_rulesets,
                    key=lambda ruleset: (ruleset.name, ruleset.ruleset_id or 0),
                )
            ),
            allow_auto_merge=(
                allow_auto_merge
                if repository_available and isinstance(allow_auto_merge, bool)
                else None
            ),
            actions_default_workflow_permissions=(
                default_permissions
                if actions_permissions_available and isinstance(default_permissions, str)
                else None
            ),
            actions_can_approve_pull_requests=(
                can_approve
                if actions_permissions_available and isinstance(can_approve, bool)
                else None
            ),
            repository_metadata_available=repository_available,
            branches_complete=branches_complete,
            rulesets_complete=rulesets_complete,
            actions_permissions_available=actions_permissions_available,
            issues=tuple(issues),
            requested_repository=slug,
        )

    def _ruleset_details(
        self,
        owner: str,
        name: str,
        summaries: list[JsonObject],
        issues: list[ExecutionIssue],
    ) -> RulesetDetails:
        ids: set[int] = set()
        complete = True
        for summary in summaries:
            ruleset_id = summary.get("id")
            if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
                issues.append(
                    _invalid_issue("rulesets", "ruleset summary has no valid positive id")
                )
                complete = False
                continue
            ids.add(ruleset_id)
        ordered_ids = sorted(ids)
        if len(ordered_ids) > _MAX_RULESET_DETAILS:
            issues.append(
                ExecutionIssue(
                    code="github.ruleset-detail-limit",
                    phase="ruleset-details",
                    message=(
                        f"GitHub ruleset evidence exceeds the {_MAX_RULESET_DETAILS} detail limit"
                    ),
                    retryable=False,
                    remediation=(
                        "Reduce applicable rulesets before collecting complete evidence.",
                    ),
                )
            )
            ordered_ids = ordered_ids[:_MAX_RULESET_DETAILS]
            complete = False
        output: list[JsonObject] = []
        for ruleset_id in ordered_ids:
            issue_count = len(issues)
            detail = self._object(
                f"/repos/{_segment(owner)}/{_segment(name)}/rulesets/{ruleset_id}",
                "ruleset-details",
                issues,
            )
            if len(issues) != issue_count:
                complete = False
                continue
            detail_id = detail.get("id")
            if detail_id != ruleset_id:
                issues.append(
                    _invalid_issue("ruleset-details", "ruleset detail id does not match summary")
                )
                complete = False
                continue
            output.append(detail)
        return RulesetDetails(output, complete)

    def _request(self, path: str, params: dict[str, str] | None = None) -> bytes:
        query = f"?{urlencode(params)}" if params else ""
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "sarj-repo-lint",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = Request(  # ruff: ignore[suspicious-url-open-usage] - validated HTTPS
            f"{self._api_url}{path}{query}", headers=headers, method="GET"
        )
        status, body = self._transport(request, self._timeout)
        if status < _SUCCESS_START or status >= _SUCCESS_END:
            raise HTTPError(
                request.full_url,
                status,
                "unexpected GitHub response",
                HTTPMessage(),
                None,
            )
        if len(body) > _MAX_BODY_BYTES:
            GitHubClientError.fail("GitHub response exceeds the 4 MiB limit")
        return body

    def _object(
        self,
        path: str,
        phase: str,
        issues: list[ExecutionIssue],
    ) -> JsonObject:
        try:
            return _decode_object(self._request(path))
        except (
            GitHubClientError,
            GitHubResponseTypeError,
            HTTPError,
            URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as error:
            issues.append(_issue(phase, error))
            return {}

    def _pages(
        self,
        path: str,
        phase: str,
        issues: list[ExecutionIssue],
        params: dict[str, str] | None = None,
    ) -> list[JsonObject]:
        output: list[JsonObject] = []
        for page in range(1, self._max_pages + 1):
            query = {**(params or {}), "page": str(page), "per_page": str(_PER_PAGE)}
            try:  # ruff: ignore[too-many-statements-in-try-clause] - one bounded page transaction
                value = _decode_array(self._request(path, query))
                items = [cast("JsonObject", item) for item in value if isinstance(item, dict)]
                if len(items) != len(value):
                    issues.append(_invalid_issue(phase, "collection contains a non-object item"))
                    return output
                output.extend(items)
                if len(value) < _PER_PAGE:
                    return output
            except (
                GitHubClientError,
                GitHubResponseTypeError,
                HTTPError,
                URLError,
                TimeoutError,
                json.JSONDecodeError,
            ) as error:
                issues.append(_issue(phase, error))
                return output
        issues.append(
            ExecutionIssue(
                code="github.pagination-limit",
                phase=phase,
                message=f"GitHub {phase} evidence exceeded {self._max_pages} pages",
                retryable=False,
                remediation=(
                    "Narrow the repository evidence or raise the client bound explicitly.",
                ),
            )
        )
        return output


def _split_repository(repository: str) -> RepositorySlug:
    parts = repository.split("/")
    if len(parts) != _REPOSITORY_PARTS or not all(
        part and part not in {".", ".."} for part in parts
    ):
        GitHubClientError.fail("repository must use owner/name form")
    return RepositorySlug(parts[0], parts[1])


def _valid_api_url(value: SplitResult) -> bool:
    return bool(
        value.scheme == "https"
        and value.hostname == "api.github.com"
        and value.username is None
        and value.password is None
        and value.port is None
        and value.path in {"", "/"}
        and not value.query
        and not value.fragment
    )


def _invalid_token(token: str) -> bool:
    return (
        not token
        or any(char.isspace() for char in token)
        or any(ord(char) < _ASCII_CONTROL_LIMIT or ord(char) == _ASCII_DELETE for char in token)
    )


def _segment(value: str) -> str:
    return quote(value, safe="")


def _issue(phase: str, error: Exception) -> ExecutionIssue:
    status = error.code if isinstance(error, HTTPError) else None
    retryable = (
        status in {408, 429}
        or (status is not None and status >= _SERVER_ERROR_START)
        or isinstance(error, TimeoutError)
        or (isinstance(error, URLError) and not isinstance(error, HTTPError))
    )
    detail = f"HTTP {status}" if status is not None else type(error).__name__
    return ExecutionIssue(
        code="github.evidence-unavailable",
        phase=phase,
        message=f"GitHub {phase} evidence is unavailable: {detail}",
        retryable=retryable,
        remediation=("Check token access and retry the read-only evidence request.",),
    )


def _invalid_issue(phase: str, detail: str) -> ExecutionIssue:
    return ExecutionIssue(
        code="github.evidence-invalid",
        phase=phase,
        message=f"GitHub {phase} evidence is invalid: {detail}",
        retryable=False,
        remediation=(
            "Retry with a supported GitHub API version and report persistent schema drift.",
        ),
    )


def _validate_repository(item: JsonObject, issues: list[ExecutionIssue]) -> bool:
    if not isinstance(item.get("default_branch"), str) or not item.get("default_branch"):
        issues.append(_invalid_issue("repository", "default_branch is missing or invalid"))
        return False
    if not isinstance(item.get("allow_auto_merge"), bool):
        issues.append(_invalid_issue("repository", "allow_auto_merge is missing or invalid"))
        return False
    full_name = item.get("full_name")
    try:
        _split_repository(full_name if isinstance(full_name, str) else "")
    except GitHubClientError:
        issues.append(_invalid_issue("repository", "full_name is missing or invalid"))
        return False
    return True


def _validate_permissions(item: JsonObject, issues: list[ExecutionIssue]) -> bool:
    if item.get("default_workflow_permissions") not in {"read", "write"}:
        issues.append(
            _invalid_issue(
                "actions-permissions",
                "default_workflow_permissions is missing or invalid",
            )
        )
        return False
    if not isinstance(item.get("can_approve_pull_request_reviews"), bool):
        issues.append(
            _invalid_issue(
                "actions-permissions", "can_approve_pull_request_reviews is missing or invalid"
            )
        )
        return False
    return True


def _branch(item: JsonObject) -> BranchEvidence:
    name = item.get("name")
    protected = item.get("protected")
    if not isinstance(name, str) or not name or not isinstance(protected, bool):
        GitHubResponseTypeError.fail("branch name or protected state is missing or invalid")
    commit = item.get("commit")
    head_sha: str | None = None
    if commit is not None:
        if not isinstance(commit, dict):
            GitHubResponseTypeError.fail("branch commit is invalid")
        candidate = commit.get("sha")
        if not isinstance(candidate, str) or re.fullmatch(r"[0-9a-f]{40}", candidate) is None:
            GitHubResponseTypeError.fail("branch head SHA is missing or invalid")
        head_sha = candidate
    protection = item.get("protection")
    context_names: set[str] = set()
    if isinstance(protection, dict):
        checks = protection.get("required_status_checks")
        if isinstance(checks, dict):
            context_values = checks.get("contexts", [])
            check_values = checks.get("checks", [])
            if not isinstance(context_values, list) or not isinstance(check_values, list):
                GitHubResponseTypeError.fail("branch required status checks are invalid")
            if any(not isinstance(value, str) for value in context_values):
                GitHubResponseTypeError.fail("branch status-check context is invalid")
            context_names.update(cast("list[str]", context_values))
            for value in check_values:
                if not isinstance(value, dict) or not isinstance(value.get("context"), str):
                    GitHubResponseTypeError.fail("branch app-bound status check is invalid")
                context_names.add(cast("str", value["context"]))
    return BranchEvidence(
        name=name,
        protected=protected,
        required_status_checks=tuple(sorted(context_names)),
        head_sha=head_sha,
    )


def _ruleset(item: JsonObject) -> RulesetEvidence:
    rules = item.get("rules")
    ruleset_id = item.get("id")
    name = item.get("name")
    enforcement = item.get("enforcement")
    target = item.get("target")
    if isinstance(ruleset_id, bool) or not isinstance(ruleset_id, int) or ruleset_id <= 0:
        GitHubResponseTypeError.fail("ruleset detail id is missing or invalid")
    if not isinstance(name, str) or not name:
        GitHubResponseTypeError.fail("ruleset detail name is missing or invalid")
    if not isinstance(enforcement, str) or not enforcement:
        GitHubResponseTypeError.fail("ruleset detail enforcement is missing or invalid")
    if not isinstance(target, str) or not target:
        GitHubResponseTypeError.fail("ruleset detail target is missing or invalid")
    if not isinstance(rules, list):
        GitHubResponseTypeError.fail("ruleset detail has missing or invalid required fields")
    rule_type_values: list[str] = []
    for value in rules:
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            GitHubResponseTypeError.fail("ruleset rule type is missing or invalid")
        rule_type_values.append(cast("str", value["type"]))
    return RulesetEvidence(
        name=name,
        enforcement=enforcement,
        target=target,
        rule_types=tuple(sorted(set(rule_type_values))),
        ruleset_id=ruleset_id,
        details_complete=True,
    )


def _decode_object(body: bytes) -> JsonObject:
    value: object = json.loads(body)  # pyright: ignore[reportAny]
    if not isinstance(value, dict):
        GitHubResponseTypeError.fail("response is not a JSON object")
    return cast("JsonObject", value)


def _decode_array(body: bytes) -> list[object]:
    value: object = json.loads(body)  # pyright: ignore[reportAny]
    if not isinstance(value, list):
        GitHubResponseTypeError.fail("response is not a JSON array")
    return cast("list[object]", value)
