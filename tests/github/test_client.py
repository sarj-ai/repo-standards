from __future__ import annotations

from datetime import timedelta
from http.client import HTTPMessage
import json
from typing import TYPE_CHECKING
from urllib.error import HTTPError

import pytest

from repo_lint.github import GitHubClient
from repo_lint.github.client import GitHubResponse


if TYPE_CHECKING:
    from urllib.request import Request


def _response(body: bytes) -> GitHubResponse:
    return GitHubResponse(200, body)


def _json_response(value: object) -> GitHubResponse:
    return _response(json.dumps(value).encode())


class FakeTransport:
    def __init__(self) -> None:
        self.requests: list[Request] = []

    def __call__(self, request: Request, timeout: timedelta) -> GitHubResponse:
        self.requests.append(request)
        assert timeout == timedelta(seconds=3)
        url = request.full_url
        if "/branches?" in url:
            return _json_response(
                [
                    {
                        "name": "main",
                        "protected": True,
                        "commit": {"sha": "a" * 40},
                        "protection": {"required_status_checks": {"contexts": ["gate"]}},
                    }
                ]
            )
        if "/rulesets?" in url:
            return _json_response(
                [
                    {
                        "id": 42,
                        "name": "protected",
                        "enforcement": "active",
                    }
                ]
            )
        if url.endswith("/rulesets/42"):
            return _json_response(
                {
                    "id": 42,
                    "name": "protected",
                    "enforcement": "active",
                    "target": "branch",
                    "rules": [{"type": "pull_request"}],
                }
            )
        if url.endswith("/actions/permissions/workflow"):
            return _json_response(
                {
                    "default_workflow_permissions": "read",
                    "can_approve_pull_request_reviews": False,
                }
            )
        return _json_response(
            {
                "default_branch": "main",
                "allow_auto_merge": True,
                "full_name": "acme/widgets-renamed",
            }
        )


def test_collects_typed_read_only_evidence() -> None:
    transport = FakeTransport()
    evidence = GitHubClient("secret", timeout=timedelta(seconds=3), transport=transport).collect(
        "acme/widgets"
    )

    assert evidence.repository == "acme/widgets-renamed"
    assert evidence.requested_repository == "acme/widgets"
    assert evidence.default_branch == "main"
    assert evidence.allow_auto_merge
    assert evidence.branches[0].required_status_checks == ("gate",)
    assert evidence.branches[0].head_sha == "a" * 40
    assert evidence.rulesets[0].rule_types == ("pull_request",)
    assert evidence.rulesets[0].ruleset_id == 42
    assert evidence.actions_default_workflow_permissions == "read"
    assert not evidence.issues
    assert all(request.method == "GET" for request in transport.requests)
    assert all(
        request.get_header("Authorization") == "Bearer secret" for request in transport.requests
    )


def test_missing_canonical_repository_identity_is_incomplete() -> None:
    class MissingFullNameTransport(FakeTransport):
        def __call__(self, request: Request, timeout: timedelta) -> GitHubResponse:
            if request.full_url.endswith("/repos/acme/widgets"):
                self.requests.append(request)
                return _response(b'{"default_branch":"main","allow_auto_merge":true}')
            return super().__call__(request, timeout)

    evidence = GitHubClient(
        None, timeout=timedelta(seconds=3), transport=MissingFullNameTransport()
    ).collect("acme/widgets")

    assert not evidence.repository_metadata_available
    assert evidence.repository == "acme/widgets"
    assert any("full_name" in issue.message for issue in evidence.issues)


def test_network_failures_become_execution_issues_without_leaking_details() -> None:
    def fail(request: Request, timeout: timedelta) -> GitHubResponse:
        del timeout
        raise HTTPError(request.full_url, 503, "secret upstream message", HTTPMessage(), None)

    evidence = GitHubClient(None, transport=fail).collect("acme/widgets")
    assert evidence.issues
    assert all(issue.retryable for issue in evidence.issues)
    assert "secret upstream message" not in repr(evidence.issues)


def test_permissions_403_marks_evidence_incomplete() -> None:
    def transport(request: Request, timeout: timedelta) -> GitHubResponse:
        del timeout
        if request.full_url.endswith("/actions/permissions/workflow"):
            raise HTTPError(request.full_url, 403, "forbidden", HTTPMessage(), None)
        if "/branches?" in request.full_url or "/rulesets?" in request.full_url:
            return _response(b"[]")
        return _response(
            b'{"default_branch":"main","allow_auto_merge":false,"full_name":"acme/widgets"}'
        )

    evidence = GitHubClient(None, transport=transport).collect("acme/widgets")
    assert [issue.phase for issue in evidence.issues] == ["actions-permissions"]
    assert not evidence.actions_permissions_available
    assert evidence.actions_default_workflow_permissions is None
    assert evidence.actions_can_approve_pull_requests is None


@pytest.mark.parametrize("repository", ["owner", "a/b/c", "/repo", "owner/"])
def test_rejects_invalid_repository_slug(repository: str) -> None:
    with pytest.raises(ValueError, match="owner/name"):
        GitHubClient(None, transport=FakeTransport()).collect(repository)


def test_client_configuration_is_bounded_and_https_only() -> None:
    with pytest.raises(ValueError, match="https"):
        GitHubClient(None, api_url="http://api.example.test")
    with pytest.raises(ValueError, match="at most 60"):
        GitHubClient(None, timeout=timedelta(seconds=61))
    with pytest.raises(ValueError, match="between"):
        GitHubClient(None, max_pages=11)


@pytest.mark.parametrize(
    "api_url",
    [
        "https://api.github.com@evil.example",
        "https://evil.example",
        "https://api.github.com:443",
        "https://api.github.com/api/v3",
    ],
)
def test_rejects_untrusted_api_urls(api_url: str) -> None:
    with pytest.raises(ValueError, match=r"api\.github\.com"):
        GitHubClient("secret", api_url=api_url)


@pytest.mark.parametrize("token", ["", " secret", "secret ", "sec ret", "secret\r\nInjected: yes"])
def test_rejects_empty_or_control_bearing_tokens(token: str) -> None:
    with pytest.raises(ValueError, match="token"):
        GitHubClient(token)


def test_pagination_limit_is_visible() -> None:
    def transport(request: Request, timeout: timedelta) -> GitHubResponse:
        del timeout
        if "/branches?" in request.full_url:
            return _json_response(
                [{"name": str(index), "protected": False} for index in range(100)]
            )
        if "/rulesets?" in request.full_url:
            return _json_response(
                [
                    {"id": index + 1, "name": str(index), "enforcement": "active"}
                    for index in range(100)
                ]
            )
        if "/rulesets/" in request.full_url:
            ruleset_id = int(request.full_url.rsplit("/", maxsplit=1)[1])
            return _json_response(
                {
                    "id": ruleset_id,
                    "name": str(ruleset_id),
                    "enforcement": "active",
                    "target": "branch",
                    "rules": [],
                }
            )
        if request.full_url.endswith("/actions/permissions/workflow"):
            return _response(
                b'{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}',
            )
        return _response(
            b'{"default_branch":"main","allow_auto_merge":false,"full_name":"acme/widgets"}'
        )

    evidence = GitHubClient(None, max_pages=1, transport=transport).collect("acme/widgets")
    assert [issue.code for issue in evidence.issues] == [
        "github.pagination-limit",
        "github.pagination-limit",
    ]


def test_realistic_ruleset_summaries_are_resolved_in_stable_id_order() -> None:
    requests: list[str] = []

    def transport(request: Request, timeout: timedelta) -> GitHubResponse:
        del timeout
        requests.append(request.full_url)
        if "/branches?" in request.full_url:
            return _response(b"[]")
        if "/rulesets?" in request.full_url:
            return _response(
                b'[{"id":9,"name":"z","enforcement":"active"},{"id":2,"name":"a","enforcement":"active"}]',
            )
        if request.full_url.endswith("/rulesets/2"):
            return _response(
                b'{"id":2,"name":"a","enforcement":"active","target":"branch","rules":[{"type":"merge_queue"}]}',
            )
        if request.full_url.endswith("/rulesets/9"):
            return _response(
                b'{"id":9,"name":"z","enforcement":"disabled","target":"branch","rules":[{"type":"pull_request"}]}',
            )
        if request.full_url.endswith("/actions/permissions/workflow"):
            return _response(
                b'{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}',
            )
        return _response(
            b'{"default_branch":"main","allow_auto_merge":true,"full_name":"acme/widgets"}'
        )

    evidence = GitHubClient(None, transport=transport).collect("acme/widgets")

    detail_requests = [url for url in requests if "/rulesets/" in url]
    assert detail_requests[0].endswith("/rulesets/2")
    assert detail_requests[1].endswith("/rulesets/9")
    assert [(item.name, item.enforcement, item.rule_types) for item in evidence.rulesets] == [
        ("a", "active", ("merge_queue",)),
        ("z", "disabled", ("pull_request",)),
    ]
    assert evidence.rulesets_complete
    assert not evidence.issues


def test_malformed_decision_fields_are_unknown_and_incomplete() -> None:
    def transport(request: Request, timeout: timedelta) -> GitHubResponse:
        del timeout
        if "/branches?" in request.full_url:
            return _response(b'[{"name":"main","protected":"yes"}]')
        if "/rulesets?" in request.full_url:
            return _response(b'[{"name":"missing-id"}]')
        if request.full_url.endswith("/actions/permissions/workflow"):
            return _response(b'{"default_workflow_permissions":"owner"}')
        return _response(
            b'{"default_branch":7,"allow_auto_merge":"yes","full_name":"acme/widgets"}'
        )

    evidence = GitHubClient(None, transport=transport).collect("acme/widgets")

    assert evidence.default_branch is None
    assert evidence.allow_auto_merge is None
    assert not evidence.repository_metadata_available
    assert not evidence.branches_complete
    assert not evidence.rulesets_complete
    assert not evidence.actions_permissions_available
    assert evidence.branches == ()
    assert evidence.rulesets == ()
    assert {issue.code for issue in evidence.issues} == {"github.evidence-invalid"}


def test_ruleset_detail_failure_is_partial_not_an_empty_success() -> None:
    def transport(request: Request, timeout: timedelta) -> GitHubResponse:
        del timeout
        if "/branches?" in request.full_url:
            return _response(b"[]")
        if "/rulesets?" in request.full_url:
            return _response(b'[{"id":42,"name":"protected","enforcement":"active"}]')
        if request.full_url.endswith("/rulesets/42"):
            raise HTTPError(request.full_url, 403, "forbidden", HTTPMessage(), None)
        if request.full_url.endswith("/actions/permissions/workflow"):
            return _response(
                b'{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}',
            )
        return _response(
            b'{"default_branch":"main","allow_auto_merge":true,"full_name":"acme/widgets"}'
        )

    evidence = GitHubClient(None, transport=transport).collect("acme/widgets")

    assert not evidence.rulesets_complete
    assert evidence.rulesets == ()
    assert [(issue.phase, issue.retryable) for issue in evidence.issues] == [
        ("ruleset-details", False)
    ]
