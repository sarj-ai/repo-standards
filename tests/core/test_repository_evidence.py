from __future__ import annotations

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.parser import parse_manifest_bytes


_BASE = b"""
schema_version = 3
repository_id = "example-repository"
[[components]]
id = "alpha.api"
kind = "application"
path = "applications/alpha/api"
owner = "@example/alpha"
product = "alpha"
"""


def test_manifest_v2_remains_compatible_without_new_declarations() -> None:
    manifest = parse_manifest_bytes(_BASE.replace(b"schema_version = 3", b"schema_version = 2"))
    assert manifest.documentation is None
    assert manifest.active_configuration == ()
    assert manifest.delivery is None


def test_manifest_v3_parses_repository_evidence_and_authorities() -> None:
    manifest = parse_manifest_bytes(
        _BASE
        + b"""
[documentation]
entrypoints = ["README.md", "docs/index.md"]

[[active_configuration]]
component_id = "alpha.api"
path = "config/production.yaml"
format = "yaml"

[delivery]

[[delivery.authorities]]
id = "cloud-deploy-production"
component_id = "alpha.api"
environment = "production"
mechanism = "cloud-deploy"
path = "deploy/skaffold.yaml"
authority = "primary"
delegates = ["deploy/render.sh"]
"""
    )
    assert manifest.documentation is not None
    assert manifest.documentation.entrypoints == ("README.md", "docs/index.md")
    assert manifest.active_configuration[0].path == "config/production.yaml"
    assert manifest.delivery is not None
    assert manifest.delivery.authorities[0].authority == "primary"


def test_manifest_v4_owns_stable_enabled_rule_ids() -> None:
    manifest = parse_manifest_bytes(
        _BASE.replace(b"schema_version = 3", b"schema_version = 4").replace(
            b'repository_id = "example-repository"',
            b'repository_id = "example-repository"\n'
            b'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers"]',
        )
    )

    assert manifest.enabled_rules == ("repository/artifacts/bespoke-iac-verifiers",)


def test_manifest_v4_rejects_duplicate_enabled_rules() -> None:
    content = _BASE.replace(b"schema_version = 3", b"schema_version = 4").replace(
        b'repository_id = "example-repository"',
        b'repository_id = "example-repository"\n'
        b'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers", '
        b'"repository/artifacts/bespoke-iac-verifiers"]',
    )

    with pytest.raises(ConfigurationError, match="enabled_rules must be unique"):
        parse_manifest_bytes(content)


@pytest.mark.parametrize(
    ("addition", "message"),
    [
        pytest.param(
            b'\n[documentation]\nentrypoints = ["README.md", "README.md"]\n',
            "non-empty and unique",
            id="duplicate-entrypoint",
        ),
        pytest.param(
            b"""
[[active_configuration]]
component_id = "missing.component"
path = "config/production.json"
format = "json"
""",
            "unknown component",
            id="unknown-active-component",
        ),
        pytest.param(
            b"""
[delivery]
[[delivery.authorities]]
id = "writer"
component_id = "alpha.api"
environment = "production"
mechanism = "cloud-deploy"
path = "deploy/writer.yaml"
authority = "primary"
delegates = ["deploy/writer.yaml"]
""",
            "unique subordinate paths",
            id="self-delegation",
        ),
    ],
)
def test_manifest_v3_rejects_ambiguous_repository_evidence(addition: bytes, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        parse_manifest_bytes(_BASE + addition)


def test_manifest_v2_rejects_v3_evidence_fields() -> None:
    content = _BASE.replace(b"schema_version = 3", b"schema_version = 2")
    with pytest.raises(ConfigurationError, match="schema version 3"):
        parse_manifest_bytes(content + b'\n[documentation]\nentrypoints = ["README.md"]\n')


def test_manifest_v3_rejects_v4_rule_activation() -> None:
    content = _BASE.replace(
        b'repository_id = "example-repository"',
        b'repository_id = "example-repository"\n'
        b'enabled_rules = ["repository/artifacts/bespoke-iac-verifiers"]',
    )

    with pytest.raises(ConfigurationError, match="schema version 4"):
        parse_manifest_bytes(content)
