"""Strict parsers for repository manifests and baselines."""

from __future__ import annotations

import json
import re
import tomllib
from datetime import date
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_path
from .errors import ConfigurationError
from .models import Baseline, Component, Dependency, ExceptionRecord, Manifest, MigrationPath

_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_EXCEPTION_DAYS = 90


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{context} must be a table/object")
    return cast("dict[str, Any]", value)


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConfigurationError(f"{context} must be an array")
    return cast("list[Any]", value)


def _strict_keys(data: dict[str, Any], allowed: set[str], required: set[str], context: str) -> None:
    unknown = sorted(set(data) - allowed)
    missing = sorted(required - set(data))
    if unknown:
        raise ConfigurationError(f"{context} has unknown fields: {', '.join(unknown)}")
    if missing:
        raise ConfigurationError(f"{context} is missing fields: {', '.join(missing)}")


def _string(data: dict[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigurationError(f"{context}.{key} must be a non-empty string")
    return value


def _identifier(value: str, context: str) -> str:
    if not _ID.fullmatch(value):
        raise ConfigurationError(f"{context} must be lowercase ASCII segments: {value!r}")
    return value


def _parse_dependency(value: object, context: str) -> Dependency:
    data = _mapping(value, context)
    _strict_keys(data, {"target", "type"}, {"target", "type"}, context)
    return Dependency(
        target=_identifier(_string(data, "target", context), f"{context}.target"),
        kind=_identifier(_string(data, "type", context), f"{context}.type"),
    )


def _parse_component(value: object, index: int) -> Component:
    context = f"components[{index}]"
    data = _mapping(value, context)
    allowed = {
        "id",
        "kind",
        "path",
        "owner",
        "product",
        "capability",
        "legacy",
        "dependencies",
    }
    _strict_keys(data, allowed, {"id", "kind", "path", "owner"}, context)
    legacy = data.get("legacy", False)
    if not isinstance(legacy, bool):
        raise ConfigurationError(f"{context}.legacy must be a boolean")
    product = data.get("product")
    capability = data.get("capability")
    if product is not None and not isinstance(product, str):
        raise ConfigurationError(f"{context}.product must be a string")
    if capability is not None and not isinstance(capability, str):
        raise ConfigurationError(f"{context}.capability must be a string")
    dependencies = tuple(
        _parse_dependency(item, f"{context}.dependencies[{dependency_index}]")
        for dependency_index, item in enumerate(
            _list(data.get("dependencies", []), f"{context}.dependencies")
        )
    )
    return Component(
        component_id=_identifier(_string(data, "id", context), f"{context}.id"),
        kind=_identifier(_string(data, "kind", context), f"{context}.kind"),
        path=canonical_path(_string(data, "path", context)),
        owner=_string(data, "owner", context),
        product=_identifier(product, f"{context}.product") if product else None,
        capability=_identifier(capability, f"{context}.capability") if capability else None,
        legacy=legacy,
        dependencies=dependencies,
    )


def _parse_migration(value: object, index: int) -> MigrationPath:
    context = f"migration_paths[{index}]"
    data = _mapping(value, context)
    _strict_keys(data, {"component_id", "from", "to"}, {"component_id", "from", "to"}, context)
    return MigrationPath(
        component_id=_identifier(_string(data, "component_id", context), f"{context}.component_id"),
        old_path=canonical_path(_string(data, "from", context)),
        new_path=canonical_path(_string(data, "to", context)),
    )


def _parse_exception(value: object, index: int) -> ExceptionRecord:
    context = f"exceptions[{index}]"
    data = _mapping(value, context)
    fields = {
        "rule_id",
        "component_id",
        "owner",
        "reason",
        "issue",
        "created_on",
        "expires_on",
    }
    _strict_keys(data, fields, fields, context)
    created_on = _string(data, "created_on", context)
    expires_on = _string(data, "expires_on", context)
    try:
        created_date = date.fromisoformat(created_on)
        expiry_date = date.fromisoformat(expires_on)
    except ValueError as error:
        raise ConfigurationError(
            f"{context}.created_on and expires_on must be YYYY-MM-DD"
        ) from error
    if expiry_date < created_date:
        raise ConfigurationError(f"{context}.expires_on must not precede created_on")
    if (expiry_date - created_date).days > _MAX_EXCEPTION_DAYS:
        raise ConfigurationError(f"{context} may not exceed 90 days")
    return ExceptionRecord(
        rule_id=_string(data, "rule_id", context),
        component_id=_identifier(_string(data, "component_id", context), f"{context}.component_id"),
        owner=_string(data, "owner", context),
        reason=_string(data, "reason", context),
        issue=_string(data, "issue", context),
        created_on=created_on,
        expires_on=expires_on,
    )


def load_manifest(path: Path) -> Manifest:
    """Load a strict TOML manifest without executing repository code."""
    try:
        data = _mapping(tomllib.loads(path.read_text(encoding="utf-8")), "manifest")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError(f"cannot read manifest {path.name}: {error}") from error
    fields = {
        "schema_version",
        "repository_id",
        "policy",
        "policy_version",
        "components",
        "migration_paths",
        "exceptions",
    }
    required = {"schema_version", "repository_id", "policy", "policy_version", "components"}
    _strict_keys(data, fields, required, "manifest")
    if data["schema_version"] != 1:
        raise ConfigurationError("manifest.schema_version must be 1")
    if not isinstance(data["policy_version"], int) or isinstance(data["policy_version"], bool):
        raise ConfigurationError("manifest.policy_version must be an integer")
    components = tuple(
        _parse_component(item, index)
        for index, item in enumerate(_list(data["components"], "manifest.components"))
    )
    component_ids = [item.component_id for item in components]
    if len(component_ids) != len(set(component_ids)):
        raise ConfigurationError("manifest contains duplicate component IDs")
    return Manifest(
        repository_id=_identifier(_string(data, "repository_id", "manifest"), "repository_id"),
        policy_id=_identifier(_string(data, "policy", "manifest"), "policy"),
        policy_version=data["policy_version"],
        components=components,
        migration_paths=tuple(
            _parse_migration(item, index)
            for index, item in enumerate(_list(data.get("migration_paths", []), "migration_paths"))
        ),
        exceptions=tuple(
            _parse_exception(item, index)
            for index, item in enumerate(_list(data.get("exceptions", []), "exceptions"))
        ),
    )


def load_baseline(path: Path) -> Baseline:
    """Load an exact, strict JSON debt baseline."""
    try:
        data = _mapping(json.loads(path.read_text(encoding="utf-8")), "baseline")
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"cannot read baseline {path.name}: {error}") from error
    fields = {
        "schema_version",
        "repository_id",
        "source_sha",
        "policy",
        "policy_version",
        "scope_digest",
        "fingerprints",
    }
    _strict_keys(data, fields, fields, "baseline")
    if data["schema_version"] != 1:
        raise ConfigurationError("baseline.schema_version must be 1")
    source_sha = _string(data, "source_sha", "baseline")
    if not _SHA.fullmatch(source_sha):
        raise ConfigurationError("baseline.source_sha must be a full lowercase Git SHA")
    fingerprints = _list(data["fingerprints"], "baseline.fingerprints")
    if not all(
        isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints
    ):
        raise ConfigurationError("baseline fingerprints must be SHA-256 hex strings")
    if len(fingerprints) != len(set(fingerprints)):
        raise ConfigurationError("baseline contains duplicate fingerprints")
    policy_version = data["policy_version"]
    if not isinstance(policy_version, int) or isinstance(policy_version, bool):
        raise ConfigurationError("baseline.policy_version must be an integer")
    return Baseline(
        repository_id=_string(data, "repository_id", "baseline"),
        source_sha=source_sha,
        policy_id=_string(data, "policy", "baseline"),
        policy_version=policy_version,
        scope_digest=_string(data, "scope_digest", "baseline"),
        fingerprints=tuple(sorted(fingerprints)),
    )
