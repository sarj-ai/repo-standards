from __future__ import annotations

from dataclasses import dataclass, field
from email.message import Message
from io import BytesIO
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError

import pytest

import repo_standards.github_review_policy as policy


if TYPE_CHECKING:
    from urllib.request import Request


@dataclass
class _Clock:
    now: float = 0.0
    sleeps: list[float] = field(default_factory=list)

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def client(self, monkeypatch: pytest.MonkeyPatch) -> policy.GitHubClient:
        monkeypatch.setattr(  # sarj-noqa: SARJ445 -- control time without patching global state.
            policy, "time", self
        )
        return policy.GitHubClient(
            token="test-token",
            repository="owner/repo",
            api_url="https://api.test",
        )


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_transient_get_recovers_without_changing_request(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    clock = _Clock()
    timeouts: list[float] = []
    error_body = BytesIO(b"Service unavailable")

    def open_url(request: Request, *, timeout: float) -> BytesIO:
        timeouts.append(timeout)
        assert request.get_method() == "GET"
        assert request.data is None
        assert request.full_url == "https://api.test/repos/owner/repo/pulls/1"
        if len(timeouts) == 1:
            raise HTTPError(request.full_url, status, "Unavailable", Message(), error_body)
        assert error_body.closed
        return BytesIO(b'{"head": {"sha": "current"}}')

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- HTTP transport is the failure boundary under test.
        policy, "urlopen", open_url
    )

    assert clock.client(monkeypatch).request("GET", "/repos/owner/repo/pulls/1") == {
        "head": {"sha": "current"}
    }
    assert timeouts == [30, 29]
    assert clock.sleeps == [1]


def test_persistent_transient_get_fails_after_bounded_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    timeouts: list[float] = []
    bodies: list[BytesIO] = []

    def open_url(request: Request, *, timeout: float) -> BytesIO:
        timeouts.append(timeout)
        body = BytesIO(b"Service unavailable")
        bodies.append(body)
        raise HTTPError(request.full_url, 503, "Unavailable", Message(), body)

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- HTTP transport is the failure boundary under test.
        policy, "urlopen", open_url
    )

    with pytest.raises(policy.ReconciliationError, match="returned 503: Service unavailable"):
        clock.client(monkeypatch).request("GET", "/pulls/1")
    assert timeouts == [30, 29, 27]
    assert clock.sleeps == [1, 2]
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize(
    ("method", "status"),
    [("GET", 401), ("GET", 403), ("GET", 404), ("GET", 429), ("POST", 503), ("PATCH", 502)],
)
def test_permanent_errors_and_mutations_are_not_retried(
    monkeypatch: pytest.MonkeyPatch, method: str, status: int
) -> None:
    clock = _Clock()
    calls: list[str] = []

    def open_url(request: Request, *, timeout: float) -> BytesIO:
        assert timeout == 30
        calls.append(request.get_method())
        raise HTTPError(request.full_url, status, "Rejected", Message(), BytesIO(b"rejected"))

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- prove policy failures and writes get one attempt.
        policy, "urlopen", open_url
    )

    with pytest.raises(policy.ReconciliationError, match=f"returned {status}: rejected"):
        clock.client(monkeypatch).request(
            method, "/statuses/head", payload=None if method == "GET" else {}
        )
    assert calls == [method]
    assert clock.sleeps == []


@pytest.mark.parametrize("elapsed", [29.5, 30.0])
def test_retry_does_not_extend_request_budget(
    monkeypatch: pytest.MonkeyPatch, elapsed: float
) -> None:
    clock = _Clock()
    calls: list[float] = []

    def open_url(request: Request, *, timeout: float) -> BytesIO:
        calls.append(timeout)
        clock.now += elapsed
        raise HTTPError(request.full_url, 503, "Unavailable", Message(), BytesIO())

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- transport time consumes the request budget.
        policy, "urlopen", open_url
    )

    with pytest.raises(policy.ReconciliationError, match="returned 503"):
        clock.client(monkeypatch).request("GET", "/pulls/1")
    assert calls == [30]
    assert clock.sleeps == []


@pytest.mark.parametrize("failure", ["timeout", "network", "invalid-json"])
def test_other_failures_remain_fail_closed(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    clock = _Clock()
    calls: list[float] = []

    def open_url(_request: Request, *, timeout: float) -> BytesIO:
        calls.append(timeout)
        if failure == "timeout":
            raise TimeoutError
        if failure == "network":
            reason = "unavailable"
            raise URLError(reason)
        return BytesIO(b"invalid")

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- HTTP/JSON failures must remain failures.
        policy, "urlopen", open_url
    )

    with pytest.raises(policy.ReconciliationError):
        clock.client(monkeypatch).request("GET", "/pulls/1")
    assert calls == [30]
    assert clock.sleeps == []


def test_artifact_redirect_drops_token_and_bounds_read(monkeypatch: pytest.MonkeyPatch) -> None:
    class ArtifactOpener:
        def __init__(self) -> None:
            self.requests: list[Request] = []

        def open(self, request: Request, *, timeout: float) -> BytesIO:
            assert timeout > 0
            self.requests.append(request)
            if len(self.requests) == 1:
                assert request.get_header("Authorization") == "Bearer test-token"
                headers = Message()
                headers["Location"] = "https://storage.example/artifact?signature=private"
                raise HTTPError(request.full_url, 302, "Found", headers, BytesIO())
            assert request.get_header("Authorization") is None
            return BytesIO(b"artifact")

    opener = ArtifactOpener()

    def build_artifact_opener(*_args: object) -> ArtifactOpener:
        return opener

    monkeypatch.setattr(policy, "build_opener", build_artifact_opener)
    client = policy.GitHubClient(
        token="test-token", repository="owner/repo", api_url="https://api.test"
    )
    assert client.artifact_bytes(123) == b"artifact"
    assert len(opener.requests) == 2


@pytest.mark.parametrize(
    "location", ["http://storage.example/a", "https://user:secret@example.invalid/a"]
)
def test_artifact_rejects_unsafe_storage_redirect(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    class ArtifactOpener:
        def open(self, request: Request, *, timeout: float) -> BytesIO:
            assert timeout > 0
            headers = Message()
            headers["Location"] = location
            raise HTTPError(request.full_url, 302, "Found", headers, BytesIO())

    def build_artifact_opener(*_args: object) -> ArtifactOpener:
        return ArtifactOpener()

    monkeypatch.setattr(policy, "build_opener", build_artifact_opener)
    client = policy.GitHubClient(
        token="test-token", repository="owner/repo", api_url="https://api.test"
    )
    with pytest.raises(
        policy.ReconciliationError, match="unsafe artifact storage redirect"
    ) as raised:
        client.artifact_bytes(123)
    assert location not in str(raised.value)


def test_artifact_rejects_oversize_archive(monkeypatch: pytest.MonkeyPatch) -> None:
    class ArtifactOpener:
        def open(self, request: Request, *, timeout: float) -> BytesIO:
            assert timeout > 0
            assert request.full_url.startswith("https://api.test/")
            return BytesIO(b"x" * 1_048_577)

    def build_artifact_opener(*_args: object) -> ArtifactOpener:
        return ArtifactOpener()

    monkeypatch.setattr(policy, "build_opener", build_artifact_opener)
    client = policy.GitHubClient(
        token="test-token", repository="owner/repo", api_url="https://api.test"
    )
    with pytest.raises(policy.ReconciliationError, match="exceeds archive budget"):
        client.artifact_bytes(123)
