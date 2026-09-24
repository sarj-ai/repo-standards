from __future__ import annotations

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import CommitMessageEnforcement
from repo_standards.core.parser import parse_manifest_bytes


def _manifest(extra: bytes = b"") -> bytes:
    return b'repository_id = "example"\ncomponents = []\n' + extra


def test_manifest_enables_strict_commit_messages_by_default() -> None:
    manifest = parse_manifest_bytes(_manifest())
    assert manifest.commit_message is not None
    assert manifest.commit_message.enforcement is CommitMessageEnforcement.STRICT


def test_manifest_rejects_invalid_repository_ids() -> None:
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(b'repository_id = "bad id"\ncomponents = []\n')


def test_manifest_can_observe_commit_messages() -> None:
    manifest = parse_manifest_bytes(_manifest(b'\n[commit_message]\nenforcement = "observe"\n'))
    assert manifest.commit_message is not None
    assert manifest.commit_message.enforcement is CommitMessageEnforcement.OBSERVE


def test_commit_message_config_is_closed() -> None:
    with pytest.raises(ValueError, match="observe or strict"):
        parse_manifest_bytes(_manifest(b'\n[commit_message]\nenforcement = "lenient"\n'))
    with pytest.raises(ValueError, match="unknown fields"):
        parse_manifest_bytes(_manifest(b"\n[commit_message]\nignore_bots = true\n"))


@pytest.mark.parametrize("version", [2, 3, 4, 5, 6, 7, 8])
def test_manifest_rejects_explicit_schema_versions(version: int) -> None:
    with pytest.raises(ConfigurationError, match="unknown fields: schema_version"):
        parse_manifest_bytes(_manifest(f"schema_version = {version}\n".encode()))


def test_noninteger_manifest_version_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="unknown fields: schema_version"):
        parse_manifest_bytes(_manifest(b'schema_version = "7"\n'))
