from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeGuard

import pytest

from repo_standards.github_review_policy import (
    GitHubClient,
    ReconciliationError,
    reconcile_merge_group,
)
from tests.test_activation_verification import MANIFEST, REPOSITORY, Provider


if TYPE_CHECKING:
    from collections.abc import Mapping


WORKFLOW = ".github/workflows/review-policy.yml"
BASE_TIP = "0" * 40
QUEUE_REF_PREFIX = "refs/heads/gh-readonly-queue/dev/"
REPO_PATH = "/repos/owner/repo/"


@dataclass
class QueuedPull:
    number: int
    base_ref: str
    head_ref: str
    head_sha: str
    group_sha: str
    group_parent_sha: str
    receipt_passed: bool = True
    state: str = "open"


@dataclass
class FakeQueue:
    pulls: list[QueuedPull]
    queue_heads: dict[int, str] = field(default_factory=dict)
    behind_by: dict[tuple[str, str], int] = field(default_factory=dict)
    hidden_refs: set[int] = field(default_factory=set)
    posted: list[dict[str, object]] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def by_number(self, number: int) -> QueuedPull:
        return next(pull for pull in self.pulls if pull.number == number)

    def by_head(self, sha: str) -> QueuedPull:
        return next(pull for pull in self.pulls if pull.head_sha == sha)

    def client(self) -> GitHubClient:
        client = GitHubClient(token="token", repository="owner/repo", api_url="https://api.test")
        client.request = self.request
        client.rest_pages = self.pages
        client.graphql = self.graphql
        return client

    def request(
        self, method: str, path: str, *, payload: Mapping[str, object] | None = None
    ) -> object:
        self.calls.append(path)
        if method == "POST":
            assert payload is not None
            self.posted.append(dict(payload))
            return None
        resource, _, rest = path.removeprefix(REPO_PATH).partition("/")
        handler = {
            "actions": self._run,
            "commits": self._merge_group_commit,
            "compare": self._comparison,
            "git": self._queue_refs,
            "pulls": self._pull,
        }.get(resource)
        if handler is None:
            message = f"unexpected request: {method} {path}"
            raise AssertionError(message)
        return handler(rest)

    def _merge_group_commit(self, sha: str) -> object:
        pull = next(pull for pull in self.pulls if pull.group_sha == sha)
        return {"sha": sha, "parents": [{"sha": pull.group_parent_sha}]}

    def _pull(self, number: str) -> object:
        pull = self.by_number(int(number))
        bases = {other.head_ref: other.head_sha for other in self.pulls}
        return {
            "base": {
                "sha": bases.get(pull.base_ref, BASE_TIP),
                "ref": pull.base_ref,
                "repo": {"id": 1, "full_name": "owner/repo"},
            },
            "head": {
                "sha": pull.head_sha,
                "ref": pull.head_ref,
                "repo": {"id": 1, "full_name": "owner/repo"},
            },
            "user": {"id": 10, "login": "author", "type": "User"},
            "body": "",
            "draft": False,
            "state": pull.state,
        }

    def _queue_refs(self, ref_path: str) -> object:
        assert ref_path == "matching-refs/heads/gh-readonly-queue/dev/"
        visible = [pull for pull in self.pulls if pull.number not in self.hidden_refs]
        return [
            {
                "ref": f"{QUEUE_REF_PREFIX}pr-{pull.number}-{pull.group_parent_sha}",
                "object": {"sha": pull.group_sha},
            }
            for pull in visible
        ]

    def _comparison(self, revisions: str) -> object:
        ancestor, head = revisions.split("...")
        return {"behind_by": self.behind_by.get((ancestor, head), 0)}

    def _run(self, run_path: str) -> object:
        assert run_path == "runs/123"
        return {
            "path": f"{WORKFLOW}@refs/heads/dev",
            "status": "completed",
            "conclusion": "success",
            "event": "pull_request_target",
        }

    def pages(self, path: str, *, collection_key: str | None = None) -> list[object]:
        assert collection_key is None
        self.calls.append(path)
        sha = path.removeprefix("/repos/owner/repo/commits/").removesuffix("/statuses")
        if not self.by_head(sha).receipt_passed:
            return []
        return [
            {
                "id": 1,
                "context": "Review Policy",
                "state": "success",
                "target_url": "https://github.com/owner/repo/actions/runs/123",
                "creator": {"login": "github-actions[bot]", "type": "Bot"},
            }
        ]

    def graphql(self, query: str, variables: Mapping[str, object]) -> Mapping[str, object]:
        assert "mergeQueueEntry" in query
        number = variables["number"]
        assert isinstance(number, int)
        oid = self.queue_heads.get(number, self.by_number(number).group_sha)
        return {"repository": {"pullRequest": {"mergeQueueEntry": {"headCommit": {"oid": oid}}}}}

    def reconcile(self, number: int) -> int:
        pull = self.by_number(number)
        return reconcile_merge_group(
            client=self.client(),
            head_sha=pull.group_sha,
            head_ref=f"{QUEUE_REF_PREFIX}pr-{number}-{pull.group_parent_sha}",
            workflow_path=WORKFLOW,
        )

    def final_status(self) -> dict[str, object]:
        return self.posted[-1]


def _stack(depth: int) -> FakeQueue:
    pulls: list[QueuedPull] = []
    base_ref, parent_group = "dev", BASE_TIP
    for level in range(depth):
        number = 10 + level
        pull = QueuedPull(
            number=number,
            base_ref=base_ref,
            head_ref=f"feature-{level}",
            head_sha=f"{level + 1:x}" * 40,
            group_sha=f"{level + 0xA:x}" * 40,
            group_parent_sha=parent_group,
        )
        pulls.append(pull)
        base_ref, parent_group = pull.head_ref, pull.group_sha
    return FakeQueue(pulls)


@pytest.mark.parametrize("depth", [2, 3])
def test_stacked_pull_request_merges_on_top_of_its_queued_base(depth: int) -> None:
    queue = _stack(depth)
    top = queue.pulls[-1].number

    assert queue.reconcile(top) == 0
    assert queue.final_status()["state"] == "success"
    for pull in queue.pulls:
        assert queue.calls.count(f"{REPO_PATH}commits/{pull.head_sha}/statuses") == 2


def test_stacked_pull_request_needs_its_base_queued_directly_ahead() -> None:
    queue = _stack(2)
    queue.hidden_refs.add(10)

    assert queue.reconcile(11) == 1
    status = queue.final_status()
    assert status["state"] == "failure"
    assert "not queued directly below #11" in str(status["description"])


def test_stacked_pull_request_must_contain_its_base_head() -> None:
    queue = _stack(2)
    base, top = queue.pulls
    queue.behind_by[base.head_sha, top.head_sha] = 1

    assert queue.reconcile(11) == 1
    assert "#11 does not contain the head of #10; rebase it" in str(
        queue.final_status()["description"]
    )


def test_stacked_pull_request_needs_a_passing_receipt_all_the_way_down() -> None:
    queue = _stack(3)
    queue.pulls[0].receipt_passed = False

    assert queue.reconcile(12) == 1
    assert "base pull request #10 has no passing review policy receipt" in str(
        queue.final_status()["description"]
    )


def test_stacked_pull_request_must_target_the_queued_base_head_branch() -> None:
    queue = _stack(2)
    queue.pulls[0].head_ref = "elsewhere"

    assert queue.reconcile(11) == 1
    assert "#11 does not target the head branch of queued #10" in str(
        queue.final_status()["description"]
    )


def test_stacked_pull_request_needs_an_open_base() -> None:
    queue = _stack(2)
    queue.pulls[0].state = "closed"

    assert queue.reconcile(11) == 1
    assert "base pull request #10 is not open" in str(queue.final_status()["description"])


def test_stacked_pull_request_stops_when_its_base_leaves_the_queue() -> None:
    queue = _stack(2)
    queue.queue_heads[10] = "f" * 40

    with pytest.raises(ReconciliationError, match="pull request 10 queue entry changed"):
        queue.reconcile(11)


def test_own_receipt_still_gates_a_stacked_pull_request() -> None:
    queue = _stack(2)
    queue.pulls[1].receipt_passed = False

    assert queue.reconcile(11) == 1
    assert queue.final_status()["description"] == ("Pull request 11 review policy receipt blocked")


def test_pull_request_targeting_the_queue_base_skips_stack_lookups() -> None:
    queue = _stack(1)

    assert queue.reconcile(10) == 0
    assert queue.final_status()["state"] == "success"
    assert queue.calls.count(f"{REPO_PATH}commits/{queue.pulls[0].head_sha}/statuses") == 2
    assert not any("/matching-refs/" in path or "/compare/" in path for path in queue.calls)


def _is_status(value: object) -> TypeGuard[Mapping[str, object]]:
    return isinstance(value, dict)


def test_merge_group_reauthenticates_activation_receipt() -> None:
    provider = Provider()
    queue = _stack(1)
    original_request = queue.request
    original_pages = queue.pages
    base = BASE_TIP
    provider.contents[base, ".repo-standards/repository.toml"] = MANIFEST.encode()

    def request(method: str, path: str, *, payload: Mapping[str, object] | None = None) -> object:
        if path.startswith(f"{REPO_PATH}git/") and "/matching-refs/" not in path:
            queue.calls.append(path)
            return provider.request(
                method, path.replace(REPO_PATH, f"/repos/{REPOSITORY}/", 1), payload=payload
            )
        return original_request(method, path, payload=payload)

    def activation_status(path: str, *, collection_key: str | None = None) -> list[object]:
        result: list[object] = []
        for item in original_pages(path, collection_key=collection_key):
            assert _is_status(item)
            result.append({**item, "description": "Verified activation: review policy passed"})
        return result

    client = queue.client()
    client.request = request
    client.rest_pages = activation_status
    pull = queue.pulls[-1]
    assert (
        reconcile_merge_group(
            client=client,
            head_sha=pull.group_sha,
            head_ref=f"{QUEUE_REF_PREFIX}pr-{pull.number}-{pull.group_parent_sha}",
            workflow_path=WORKFLOW,
        )
        == 1
    )
    # A previously verified status is insufficient: the real authenticator checks
    # the trusted policy and rejects this pull request's ordinary human author.
    assert f"{REPO_PATH}git/commits/{base}" in queue.calls
    assert queue.calls.count(f"{REPO_PATH}pulls/{pull.number}") >= 3
    assert queue.posted[-1]["state"] == "failure"
