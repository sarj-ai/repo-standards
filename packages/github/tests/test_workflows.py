from __future__ import annotations

import pytest
from repo_lint_github import WorkflowDocument, inspect_workflow, inspect_workflows


_SHA = "0123456789abcdef0123456789abcdef01234567"


def test_inspection_is_syntax_aware_for_comments_quotes_and_triggers() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/ci.yml",
            f"""name: CI # uses: bad/action@main
on: [pull_request, merge_group]
permissions:
  contents: read
concurrency:
  group: ci-${{{{ github.ref }}}}
  cancel-in-progress: true
jobs:
  test:
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@{_SHA} # immutable
      - uses: ./local
      - run: echo '# not a YAML comment'
""".encode(),
        )
    )

    assert workflow.has_pull_request_trigger
    assert workflow.has_merge_group_trigger
    assert workflow.has_permissions
    assert workflow.has_timeout
    assert workflow.has_concurrency
    assert workflow.cancels_in_progress is True
    assert [reference.value for reference in workflow.action_references] == [
        f"actions/checkout@{_SHA}"
    ]
    assert workflow.action_references[0].pinned_to_full_sha


def test_unpinned_action_and_invalid_utf8_are_reported_as_facts() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/ci.yaml",
            b"on: push\njobs:\n  test:\n    steps:\n      - uses: acme/a@v1\n#\xff",
        )
    )
    assert not workflow.valid_utf8
    assert not workflow.action_references[0].pinned_to_full_sha


@pytest.mark.parametrize(
    "path",
    ["/absolute/a.yml", ".github/workflows/../a.yml", ".github/workflows/a.txt", "ci.yml"],
)
def test_paths_are_confined_to_workflow_directory(path: str) -> None:
    with pytest.raises(ValueError, match="workflow path"):
        inspect_workflow(WorkflowDocument(path, b"on: push"))


def test_documents_are_sorted_and_duplicate_paths_rejected() -> None:
    documents = (
        WorkflowDocument(
            ".github/workflows/z.yml", b"on: push\njobs:\n  x:\n    steps:\n      - run: 'true'"
        ),
        WorkflowDocument(
            ".github/workflows/a.yml", b"on: push\njobs:\n  x:\n    steps:\n      - run: 'true'"
        ),
    )
    assert [item.path for item in inspect_workflows(documents)] == [
        ".github/workflows/a.yml",
        ".github/workflows/z.yml",
    ]
    with pytest.raises(ValueError, match="unique"):
        inspect_workflows((documents[0], documents[0]))


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"on: push\non: pull_request\njobs: {}", "duplicate key"),
        (b"on: &event push\njobs: {x: {steps: [{run: *event}]}}", "anchors and aliases"),
        (b"on: push\njobs:\n  x:\n    steps: wrong", "steps must be a list"),
    ],
)
def test_rejects_duplicate_aliased_and_invalid_workflow_structure(
    content: bytes, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        inspect_workflow(WorkflowDocument(".github/workflows/ci.yml", content))


def test_only_real_job_steps_contribute_security_evidence() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/ci.yml",
            b"""on: push
permissions: {}
concurrency:
  group: ci
  cancel-in-progress: false
decoy: |
  gh pr create --base preview --head main
  gh pr merge --auto
  ${{ secrets.BACKSYNC_TOKEN }} source_sha headRefOid merge-tree exit 1
jobs:
  test:
    timeout-minutes: 5
    steps:
      - run: echo safe
""",
        )
    )

    assert not workflow.creates_pull_request
    assert not workflow.enables_auto_merge
    assert not workflow.uses_non_default_token
    assert not workflow.pins_source_sha
    assert not workflow.guards_stale_head
    assert not workflow.refuses_conflicts


def test_rejects_nested_workflow_paths() -> None:
    with pytest.raises(ValueError, match="direct"):
        inspect_workflow(
            WorkflowDocument(
                ".github/workflows/nested/ci.yml",
                b"on: push\njobs:\n  x:\n    steps:\n      - run: 'true'",
            )
        )


def test_reusable_job_action_is_sha_checked_and_timeout_exempt() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/reuse.yml",
            b"""on: workflow_call
permissions: {}
jobs:
  call:
    uses: acme/automation/.github/workflows/ci.yml@main
""",
        )
    )

    assert workflow.has_timeout
    assert [reference.value for reference in workflow.action_references] == [
        "acme/automation/.github/workflows/ci.yml@main"
    ]
    assert not workflow.action_references[0].pinned_to_full_sha


def test_container_actions_require_an_immutable_digest() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/containers.yml",
            b"""on: push
permissions: {}
jobs:
  scan:
    timeout-minutes: 5
    steps:
      - uses: docker://vendor/scanner:latest
      - uses: docker://vendor/scanner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
""",
        )
    )

    assert [reference.pinned_to_full_sha for reference in workflow.action_references] == [
        False,
        True,
    ]


def test_write_all_permissions_are_not_treated_as_bounded() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/broad.yml",
            b"""on: push
permissions: write-all
jobs:
  test:
    timeout-minutes: 5
    steps:
      - run: 'true'
""",
        )
    )

    assert not workflow.has_permissions


def test_repeated_action_locations_do_not_depend_on_sorted_job_order() -> None:
    workflow = inspect_workflow(
        WorkflowDocument(
            ".github/workflows/repeated.yml",
            b"""on: push
permissions: {}
jobs:
  z-first-in-file:
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/setup@v1
  a-second-in-file:
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
""",
        )
    )

    locations = sorted((item.value, item.line) for item in workflow.action_references)
    assert locations == [
        ("actions/checkout@v4", 7),
        ("actions/checkout@v4", 12),
        ("vendor/setup@v1", 8),
    ]
