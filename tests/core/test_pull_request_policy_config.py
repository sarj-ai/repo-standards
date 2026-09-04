from __future__ import annotations

import pytest

from repo_standards.core.parser import parse_manifest_bytes


_BASE = b"""
schema_version = 5
repository_id = "example"
components = []
"""


def _transition(**overrides: str) -> bytes:
    fields = {
        "id": '"dev-preview"',
        "source_ref": '"dev"',
        "base_ref": '"preview"',
        "head_prefix": '"automation/promote-dev-"',
    }
    fields.update(overrides)
    lines = [
        "[[pull_request.commit_history.transitions]]",
        *(f"{key} = {value}" for key, value in fields.items()),
    ]
    return ("\n".join(lines) + "\n").encode()


def test_schema_five_parses_commit_history_defaults_and_transitions() -> None:
    manifest = parse_manifest_bytes(
        _BASE
        + b"""
[pull_request.commit_history]
advisory_base_ref = "dev"

[[pull_request.commit_history.transitions]]
id = "dev-preview"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-dev-"
"""
    )

    assert manifest.pull_request is not None
    history = manifest.pull_request.commit_history
    assert history.maximum_commits == 5
    assert history.advisory_base_ref == "dev"
    assert len(history.transitions) == 1
    transition = history.transitions[0]
    assert transition.transition_id == "dev-preview"
    assert transition.source_ref == "dev"
    assert transition.base_ref == "preview"
    assert transition.head_prefix == "automation/promote-dev-"
    assert transition.sha_prefix_length == 12


def test_schema_five_allows_a_bounded_maximum_and_distinct_destinations() -> None:
    manifest = parse_manifest_bytes(
        _BASE
        + b"""
[pull_request.commit_history]
maximum_commits = 9
advisory_base_ref = "release/dev"

[[pull_request.commit_history.transitions]]
id = "dev-preview"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-"
sha_prefix_length = 40

[[pull_request.commit_history.transitions]]
id = "dev-main"
source_ref = "dev"
base_ref = "main"
head_prefix = "automation/main-promote-"
"""
    )

    assert manifest.pull_request is not None
    assert manifest.pull_request.commit_history.maximum_commits == 9
    assert len(manifest.pull_request.commit_history.transitions) == 2


@pytest.mark.parametrize("schema_version", [2, 3, 4])
def test_older_manifest_schemas_remain_supported(schema_version: int) -> None:
    manifest = parse_manifest_bytes(
        f'schema_version = {schema_version}\nrepository_id = "example"\ncomponents = []\n'.encode()
    )

    assert manifest.pull_request is None


def test_schema_four_keeps_enabled_rules_support() -> None:
    manifest = parse_manifest_bytes(
        b'schema_version = 4\nrepository_id = "example"\ncomponents = []\n'
        b'enabled_rules = ["repository/no-empty-readme"]\n'
    )

    assert manifest.enabled_rules == ("repository/no-empty-readme",)


@pytest.mark.parametrize("schema_version", [2, 3, 4])
def test_pull_request_policy_requires_schema_five(schema_version: int) -> None:
    content = _BASE.replace(b"schema_version = 5", f"schema_version = {schema_version}".encode())

    with pytest.raises(ValueError, match="schema version 5 is required for pull_request"):
        parse_manifest_bytes(
            content + b'\n[pull_request.commit_history]\nadvisory_base_ref = "dev"\n'
        )


@pytest.mark.parametrize(
    ("setting", "message"),
    [
        ("maximum_commits = true", "maximum_commits must be an integer"),
        ("maximum_commits = 0", "maximum_commits must be between 1 and 9999"),
        ("maximum_commits = 10000", "maximum_commits must be between 1 and 9999"),
        ('advisory_base_ref = "origin/dev"', "must be a safe logical branch name"),
        ('advisory_base_ref = "refs/heads/dev"', "must be a safe logical branch name"),
        ('advisory_base_ref = "feature..dev"', "must be a safe logical branch name"),
        ('advisory_base_ref = "feature dev"', "must be a safe logical branch name"),
    ],
)
def test_commit_history_rejects_unsafe_or_unbounded_settings(setting: str, message: str) -> None:
    advisory_base = "" if setting.startswith("advisory_base_ref") else 'advisory_base_ref = "dev"\n'
    content = _BASE + f"\n[pull_request.commit_history]\n{advisory_base}{setting}\n".encode()

    with pytest.raises(ValueError, match=message):
        parse_manifest_bytes(content)


def test_commit_history_requires_an_advisory_base_ref() -> None:
    with pytest.raises(ValueError, match="is missing fields: advisory_base_ref"):
        parse_manifest_bytes(_BASE + b"\n[pull_request.commit_history]\n")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source_ref", '"preview"', "source_ref and base_ref must differ"),
        ("source_ref", '"origin/dev"', "must be a safe logical branch name"),
        ("head_prefix", '"automation bad-"', "must be a safe logical branch name"),
        ("sha_prefix_length", "true", "sha_prefix_length must be an integer"),
        ("sha_prefix_length", "11", "sha_prefix_length must be between 12 and 40"),
        ("sha_prefix_length", "41", "sha_prefix_length must be between 12 and 40"),
    ],
)
def test_transition_rejects_ambiguous_or_unsafe_identity(
    field: str, value: str, message: str
) -> None:
    content = (
        _BASE
        + b'\n[pull_request.commit_history]\nadvisory_base_ref = "dev"\n'
        + _transition(**{field: value})
    )

    with pytest.raises(ValueError, match=message):
        parse_manifest_bytes(content)


def test_transitions_reject_duplicate_ids() -> None:
    content = (
        _BASE
        + b"""
[pull_request.commit_history]
advisory_base_ref = "dev"

[[pull_request.commit_history.transitions]]
id = "promotion"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-dev-"

[[pull_request.commit_history.transitions]]
id = "promotion"
source_ref = "preview"
base_ref = "main"
head_prefix = "automation/promote-preview-"
"""
    )

    with pytest.raises(ValueError, match="transitions must have unique IDs"):
        parse_manifest_bytes(content)


def test_transitions_reject_overlapping_prefixes_across_destinations() -> None:
    content = (
        _BASE
        + b"""
[pull_request.commit_history]
advisory_base_ref = "dev"

[[pull_request.commit_history.transitions]]
id = "promotion"
source_ref = "dev"
base_ref = "preview"
head_prefix = "automation/promote-"

[[pull_request.commit_history.transitions]]
id = "dev-promotion"
source_ref = "dev"
base_ref = "main"
head_prefix = "automation/promote-dev-"
"""
    )

    with pytest.raises(ValueError, match="must not have overlapping head prefixes"):
        parse_manifest_bytes(content)


def test_pull_request_tables_reject_unknown_fields() -> None:
    content = (
        _BASE
        + b"""
[pull_request.commit_history]
advisory_base_ref = "dev"
exempt_all_automation = true
"""
    )

    with pytest.raises(ValueError, match="unknown fields: exempt_all_automation"):
        parse_manifest_bytes(content)
