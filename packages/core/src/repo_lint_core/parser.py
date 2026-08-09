"""Strict parsers for repository manifests and baselines."""

from __future__ import annotations

from datetime import date, timedelta
import json
import re
import tomllib
from typing import TYPE_CHECKING

from .canonical import canonical_path
from .errors import ConfigurationError
from .models import (
    Baseline,
    Component,
    ComponentId,
    Dependency,
    ExceptionRecord,
    Manifest,
    MigrationPath,
    PolicyId,
    RepositoryId,
    RuleId,
)


if TYPE_CHECKING:
    from pathlib import Path


_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_EXCEPTION_DURATION = timedelta(days=90)
_MAX_INPUT_BYTES = 1_048_576
_MAX_COMPONENTS = 10_000
_MAX_MIGRATIONS = 10_000
_MAX_EXCEPTIONS = 1_000


def _read_bounded(path: Path, kind: str) -> bytes:
    """Read one inert policy input with a hard allocation ceiling."""
    try:
        size = path.stat().st_size
        if size > _MAX_INPUT_BYTES:
            ConfigurationError.fail(f"{kind} exceeds {_MAX_INPUT_BYTES} bytes: {path.name}")
        return path.read_bytes()
    except OSError:
        ConfigurationError.fail(f"cannot read {kind}: {path.name}")


def _bounded_content(content: bytes, kind: str) -> bytes:
    if len(content) > _MAX_INPUT_BYTES:
        ConfigurationError.fail(f"{kind} exceeds {_MAX_INPUT_BYTES} bytes")
    return content


def _mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        ConfigurationError.fail(f"{context} must be a table/object")
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        ConfigurationError.fail(f"{context} must be an array")
    return [  # ruff: ignore[unnecessary-comprehension] - narrows untyped JSON/TOML arrays
        item
        for item in value  # pyright: ignore[reportUnknownVariableType]
    ]


def _strict_keys(
    data: dict[str, object], allowed: set[str], required: set[str], context: str
) -> None:
    unknown = sorted(set(data) - allowed)
    missing = sorted(required - set(data))
    if unknown:
        ConfigurationError.fail(f"{context} has unknown fields: {', '.join(unknown)}")
    if missing:
        ConfigurationError.fail(f"{context} is missing fields: {', '.join(missing)}")


def _string(data: dict[str, object], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        ConfigurationError.fail(f"{context}.{key} must be a non-empty string")
    return value


def _identifier(value: str, context: str) -> str:
    if not _ID.fullmatch(value):
        ConfigurationError.fail(f"{context} must be lowercase ASCII segments: {value!r}")
    return value


def parse_dependency(value: object, context: str) -> Dependency:
    data = _mapping(value, context)
    _strict_keys(data, {"target", "type"}, {"target", "type"}, context)
    return Dependency(
        target=ComponentId(_identifier(_string(data, "target", context), f"{context}.target")),
        kind=_identifier(_string(data, "type", context), f"{context}.type"),
    )


def parse_component(value: object, index: int) -> Component:
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
        ConfigurationError.fail(f"{context}.legacy must be a boolean")
    product = data.get("product")
    capability = data.get("capability")
    if product is not None and not isinstance(product, str):
        ConfigurationError.fail(f"{context}.product must be a string")
    if isinstance(product, str) and not product:
        ConfigurationError.fail(f"{context}.product must not be empty")
    if capability is not None and not isinstance(capability, str):
        ConfigurationError.fail(f"{context}.capability must be a string")
    if isinstance(capability, str) and not capability:
        ConfigurationError.fail(f"{context}.capability must not be empty")
    dependencies = tuple(
        parse_dependency(item, f"{context}.dependencies[{dependency_index}]")
        for dependency_index, item in enumerate(
            _list(data.get("dependencies", []), f"{context}.dependencies")
        )
    )
    return Component(
        component_id=ComponentId(_identifier(_string(data, "id", context), f"{context}.id")),
        kind=_identifier(_string(data, "kind", context), f"{context}.kind"),
        path=canonical_path(_string(data, "path", context)),
        owner=_string(data, "owner", context),
        product=_identifier(product, f"{context}.product") if product else None,
        capability=_identifier(capability, f"{context}.capability") if capability else None,
        legacy=legacy,
        dependencies=dependencies,
    )


def parse_migration(value: object, index: int) -> MigrationPath:
    context = f"migration_paths[{index}]"
    data = _mapping(value, context)
    _strict_keys(data, {"component_id", "from", "to"}, {"component_id", "from", "to"}, context)
    return MigrationPath(
        component_id=ComponentId(
            _identifier(_string(data, "component_id", context), f"{context}.component_id")
        ),
        old_path=canonical_path(_string(data, "from", context)),
        new_path=canonical_path(_string(data, "to", context)),
    )


def parse_exception(value: object, index: int) -> ExceptionRecord:
    context = f"exceptions[{index}]"
    data = _mapping(value, context)
    fields = {
        "rule_id",
        "component_id",
        "manifest_anchor",
        "fingerprint",
        "owner",
        "reason",
        "issue",
        "created_on",
        "expires_on",
    }
    _strict_keys(data, fields, fields, context)
    created_on = _string(data, "created_on", context)
    expires_on = _string(data, "expires_on", context)
    fingerprint = _string(data, "fingerprint", context)
    if re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        ConfigurationError.fail(f"{context}.fingerprint must be a SHA-256 hex string")
    if not _DATE.fullmatch(created_on) or not _DATE.fullmatch(expires_on):
        ConfigurationError.fail(f"{context}.created_on and expires_on must be YYYY-MM-DD")
    try:
        created_date = date.fromisoformat(created_on)
        expiry_date = date.fromisoformat(expires_on)
    except ValueError:
        ConfigurationError.fail(f"{context}.created_on and expires_on must be YYYY-MM-DD")
    if expiry_date < created_date:
        ConfigurationError.fail(f"{context}.expires_on must not precede created_on")
    if expiry_date - created_date > _MAX_EXCEPTION_DURATION:
        ConfigurationError.fail(f"{context} may not exceed 90 days")
    return ExceptionRecord(
        rule_id=RuleId(_string(data, "rule_id", context)),
        component_id=ComponentId(
            _identifier(_string(data, "component_id", context), f"{context}.component_id")
        ),
        manifest_anchor=_string(data, "manifest_anchor", context),
        fingerprint=fingerprint,
        owner=_string(data, "owner", context),
        reason=_string(data, "reason", context),
        issue=_string(data, "issue", context),
        created_on=created_on,
        expires_on=expires_on,
    )


def parse_manifest_bytes(content: bytes) -> Manifest:
    """Parse bounded manifest bytes obtained from a trusted input selector."""
    try:
        parsed_manifest: object = tomllib.loads(
            _bounded_content(content, "manifest").decode("utf-8")
        )
        data = _mapping(parsed_manifest, "manifest")
    except (OSError, RecursionError, UnicodeError, ValueError, tomllib.TOMLDecodeError):
        ConfigurationError.fail("cannot read manifest")
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
        ConfigurationError.fail("manifest.schema_version must be 1")
    policy_version = data["policy_version"]
    if not isinstance(policy_version, int) or isinstance(policy_version, bool):
        ConfigurationError.fail("manifest.policy_version must be an integer")
    raw_components = _list(data["components"], "manifest.components")
    if len(raw_components) > _MAX_COMPONENTS:
        ConfigurationError.fail(f"manifest may contain at most {_MAX_COMPONENTS} components")
    raw_migrations = _list(data.get("migration_paths", []), "migration_paths")
    if len(raw_migrations) > _MAX_MIGRATIONS:
        ConfigurationError.fail(f"manifest may contain at most {_MAX_MIGRATIONS} migration paths")
    raw_exceptions = _list(data.get("exceptions", []), "exceptions")
    if len(raw_exceptions) > _MAX_EXCEPTIONS:
        ConfigurationError.fail(f"manifest may contain at most {_MAX_EXCEPTIONS} exceptions")
    components = tuple(parse_component(item, index) for index, item in enumerate(raw_components))
    component_ids = [item.component_id for item in components]
    if len(component_ids) != len(set(component_ids)):
        ConfigurationError.fail("manifest contains duplicate component IDs")
    return Manifest(
        repository_id=RepositoryId(
            _identifier(_string(data, "repository_id", "manifest"), "repository_id")
        ),
        policy_id=PolicyId(_identifier(_string(data, "policy", "manifest"), "policy")),
        policy_version=policy_version,
        components=components,
        migration_paths=tuple(
            parse_migration(item, index) for index, item in enumerate(raw_migrations)
        ),
        exceptions=tuple(parse_exception(item, index) for index, item in enumerate(raw_exceptions)),
    )


def load_manifest(path: Path) -> Manifest:
    """Load a strict TOML manifest without executing repository code."""
    return parse_manifest_bytes(_read_bounded(path, "manifest"))


def parse_baseline_bytes(content: bytes) -> Baseline:
    """Parse bounded baseline bytes obtained from a trusted input selector."""
    try:
        parsed_baseline: object = json.loads(  # pyright: ignore[reportAny]
            _bounded_content(content, "baseline").decode("utf-8")
        )
        data = _mapping(parsed_baseline, "baseline")
    except (OSError, RecursionError, UnicodeError, ValueError, json.JSONDecodeError):
        ConfigurationError.fail("cannot read baseline")
    fields = {
        "schema_version",
        "repository_id",
        "policy",
        "policy_version",
        "scope_digest",
        "fingerprints",
    }
    _strict_keys(data, fields, fields, "baseline")
    if data["schema_version"] != 1:
        ConfigurationError.fail("baseline.schema_version must be 1")
    raw_fingerprints = _list(data["fingerprints"], "baseline.fingerprints")
    if not all(isinstance(item, str) for item in raw_fingerprints):
        ConfigurationError.fail("baseline fingerprints must be strings")
    fingerprints = [item for item in raw_fingerprints if isinstance(item, str)]
    if not all(re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints):
        ConfigurationError.fail("baseline fingerprints must be SHA-256 hex strings")
    if len(fingerprints) != len(set(fingerprints)):
        ConfigurationError.fail("baseline contains duplicate fingerprints")
    policy_version = data["policy_version"]
    if not isinstance(policy_version, int) or isinstance(policy_version, bool):
        ConfigurationError.fail("baseline.policy_version must be an integer")
    return Baseline(
        repository_id=RepositoryId(_string(data, "repository_id", "baseline")),
        policy_id=PolicyId(_string(data, "policy", "baseline")),
        policy_version=policy_version,
        scope_digest=_string(data, "scope_digest", "baseline"),
        fingerprints=tuple(sorted(fingerprints)),
    )


def load_baseline(path: Path) -> Baseline:
    """Load an exact, strict JSON debt baseline."""
    return parse_baseline_bytes(_read_bounded(path, "baseline"))
