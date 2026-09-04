from __future__ import annotations

import pytest

from repo_standards.core.models import CommitMessageEnforcement
from repo_standards.core.parser import enable_commit_message_policy_bytes, parse_manifest_bytes


def _manifest(extra: bytes = b"") -> bytes:
    return b'schema_version = 6\nrepository_id = "example"\ncomponents = []\n' + extra


def test_schema_six_enables_strict_commit_messages_by_default() -> None:
    manifest = parse_manifest_bytes(_manifest())
    assert manifest.commit_message is not None
    assert manifest.commit_message.enforcement is CommitMessageEnforcement.STRICT


def test_schema_six_can_observe_commit_messages() -> None:
    manifest = parse_manifest_bytes(_manifest(b'\n[commit_message]\nenforcement = "observe"\n'))
    assert manifest.commit_message is not None
    assert manifest.commit_message.enforcement is CommitMessageEnforcement.OBSERVE


@pytest.mark.parametrize("version", [2, 3, 4, 5])
def test_older_schemas_do_not_implicitly_enable_commit_messages(version: int) -> None:
    manifest = parse_manifest_bytes(
        f'schema_version = {version}\nrepository_id = "example"\ncomponents = []\n'.encode()
    )
    assert manifest.commit_message is None


def test_commit_message_config_is_closed_and_schema_gated() -> None:
    with pytest.raises(ValueError, match="observe or strict"):
        parse_manifest_bytes(_manifest(b'\n[commit_message]\nenforcement = "lenient"\n'))
    with pytest.raises(ValueError, match="unknown fields"):
        parse_manifest_bytes(_manifest(b"\n[commit_message]\nignore_bots = true\n"))
    with pytest.raises(ValueError, match="schema version 6"):
        parse_manifest_bytes(
            b'schema_version = 5\nrepository_id = "example"\ncomponents = []\n'
            b'\n[commit_message]\nenforcement = "strict"\n'
        )


def test_adoption_api_only_changes_the_schema_value_and_is_idempotent() -> None:
    original = (
        b'schema_version  = 5 # preserve this comment\r\nrepository_id = "example"\r\n'
        b"components = []\r\n\r\n[pull_request.commit_history]\r\n"
        b'advisory_base_ref = "dev"\r\n'
    )

    migrated = enable_commit_message_policy_bytes(original)

    assert migrated == original.replace(b"= 5 #", b"= 6 #", 1)
    assert enable_commit_message_policy_bytes(migrated) == migrated
    assert parse_manifest_bytes(migrated).commit_message is not None
