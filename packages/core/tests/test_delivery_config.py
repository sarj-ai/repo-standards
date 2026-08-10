"""Strict parsing tests for declared delivery topology."""

from __future__ import annotations

from dataclasses import replace

import pytest
from repo_lint_core.canonical import scope_digest
from repo_lint_core.errors import ConfigurationError
from repo_lint_core.models import DeliveryConfig
from repo_lint_core.parser import parse_manifest_bytes


_MANIFEST = b"""
schema_version = 1
repository_id = "example-repository"
policy = "example"
policy_version = 1
components = []
"""


def test_manifest_without_delivery_remains_compatible() -> None:
    manifest = parse_manifest_bytes(_MANIFEST)

    assert manifest.delivery is None


def test_delivery_defaults_are_immutable_and_conventional() -> None:
    manifest = parse_manifest_bytes(_MANIFEST + b"\n[delivery]\n")

    assert manifest.delivery == DeliveryConfig()
    with pytest.raises(AttributeError):
        manifest.delivery.production_branch = "release"  # type: ignore[misc,union-attr]


def test_delivery_parses_custom_topology() -> None:
    manifest = parse_manifest_bytes(
        _MANIFEST
        + b"""

[delivery]
provider = "github"
repository = "acme/widgets"
production_branch = "release"
preview_branch = "staging"
development_branch = "develop"
sync_workflows = [
  ".github/workflows/sync-staging.yml",
  ".github/workflows/sync-develop.yaml",
]
"""
    )

    assert manifest.delivery == DeliveryConfig(
        provider="github",
        repository="acme/widgets",
        production_branch="release",
        preview_branch="staging",
        development_branch="develop",
        sync_workflows=(
            ".github/workflows/sync-staging.yml",
            ".github/workflows/sync-develop.yaml",
        ),
    )


@pytest.mark.parametrize(
    ("delivery", "message"),
    [
        ('provider = "gitlab"', "provider"),
        ('repository = "missing-owner"', "owner/name"),
        ('production_branch = ""', "non-empty"),
        ('production_branch = "@"', "branch name"),
        ('production_branch = "bad branch"', "branch name"),
        ('preview_branch = "main"', "distinct"),
        ('sync_workflows = ["../outside.yml"]', "escapes repository root"),
        ('sync_workflows = ["sync.yml", "sync.yml"]', "duplicates"),
        ("unknown = true", "unknown fields"),
    ],
)
def test_delivery_rejects_invalid_configuration(delivery: str, message: str) -> None:
    content = _MANIFEST + f"\n[delivery]\n{delivery}\n".encode()

    with pytest.raises(ConfigurationError, match=message):
        parse_manifest_bytes(content)


def test_delivery_configuration_participates_in_scope_digest() -> None:
    manifest = parse_manifest_bytes(_MANIFEST + b"\n[delivery]\n")
    assert manifest.delivery is not None

    customized = replace(
        manifest,
        delivery=replace(manifest.delivery, production_branch="release"),
    )

    assert scope_digest(customized) != scope_digest(manifest)
