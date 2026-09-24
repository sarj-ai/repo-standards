from __future__ import annotations

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.parser import parse_manifest_bytes


_BASE = b"""
repository_id = "example-repository"
[[components]]
id = "alpha.api"
kind = "application"
path = "applications/alpha/api"
owner = "@example/alpha"
product = "alpha"
"""


def test_manifest_without_optional_documentation() -> None:
    manifest = parse_manifest_bytes(_BASE)
    assert manifest.documentation is None


def test_manifest_parses_documentation() -> None:
    manifest = parse_manifest_bytes(
        _BASE
        + b"""
[documentation]
entrypoints = ["README.md", "docs/index.md"]
"""
    )
    assert manifest.documentation is not None
    assert manifest.documentation.entrypoints == ("README.md", "docs/index.md")


def test_manifest_owns_stable_enabled_rule_ids() -> None:
    manifest = parse_manifest_bytes(
        _BASE.replace(
            b'repository_id = "example-repository"',
            b'repository_id = "example-repository"\n'
            b'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers"]',
        )
    )

    assert manifest.enabled_rules == ("repository/artifacts/bespoke-iac-verifiers",)


def test_manifest_rejects_duplicate_enabled_rules() -> None:
    content = _BASE.replace(
        b'repository_id = "example-repository"',
        b'repository_id = "example-repository"\n'
        b'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers", '
        b'"repository/artifacts/bespoke-iac-verifiers"]',
    )

    with pytest.raises(ConfigurationError, match="enabled_rules must be unique"):
        parse_manifest_bytes(content)


def test_manifest_rejects_duplicate_documentation_entrypoints() -> None:
    with pytest.raises(ConfigurationError, match="non-empty and unique"):
        parse_manifest_bytes(
            _BASE + b'\n[documentation]\nentrypoints = ["README.md", "README.md"]\n'
        )


@pytest.mark.parametrize(
    "field",
    [
        "migration_paths = []",
        "active_configuration = []",
        "delivery = {}",
    ],
)
def test_manifest_rejects_removed_root_fields(field: str) -> None:
    content = _BASE.replace(b"[[components]]", field.encode() + b"\n[[components]]")

    with pytest.raises(ConfigurationError, match="unknown fields"):
        parse_manifest_bytes(content)


def test_manifest_rejects_removed_component_dependencies() -> None:
    with pytest.raises(ConfigurationError, match="unknown fields: dependencies"):
        parse_manifest_bytes(_BASE + b"dependencies = []\n")


def test_manifest_rejects_legacy_component_field() -> None:
    content = _BASE.replace(b'kind = "application"', b'kind = "application"\nlegacy = true')

    with pytest.raises(ConfigurationError, match="unknown fields: legacy"):
        parse_manifest_bytes(content)
