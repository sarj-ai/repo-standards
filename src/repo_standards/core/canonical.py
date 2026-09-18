from __future__ import annotations

from dataclasses import replace
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import PurePosixPath
import posixpath
from typing import TYPE_CHECKING
import unicodedata

from .errors import ConfigurationError


if TYPE_CHECKING:
    from .models import Diagnostic, Manifest


def canonical_path(value: str) -> str:
    if (
        not value
        or "\\" in value
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        ConfigurationError.fail(f"invalid repository-relative path: {value!r}")
    normalized_unicode = unicodedata.normalize("NFC", value)
    if normalized_unicode != value:
        ConfigurationError.fail(f"path must be NFC-normalized: {value!r}")
    normalized = posixpath.normpath(value)
    if value.startswith("/") or normalized in {".", ".."} or normalized.startswith("../"):
        ConfigurationError.fail(f"path escapes repository root: {value!r}")
    return normalized


def workspace_pattern_matches(relative: PurePosixPath, pattern: str) -> bool:
    if pattern == ".":
        return not relative.parts
    pending = [(0, 0)]
    visited: set[tuple[int, int]] = set()
    pattern_parts = PurePosixPath(pattern).parts
    while pending:
        path_index, pattern_index = pending.pop()
        state = (path_index, pattern_index)
        if state in visited:
            continue
        visited.add(state)
        if pattern_index == len(pattern_parts):
            if path_index == len(relative.parts):
                return True
            continue
        if pattern_parts[pattern_index] == "**":
            pending.append((path_index, pattern_index + 1))
            if path_index < len(relative.parts):
                pending.append((path_index + 1, pattern_index))
        elif path_index < len(relative.parts) and fnmatchcase(
            relative.parts[path_index], pattern_parts[pattern_index]
        ):
            pending.append((path_index + 1, pattern_index + 1))
    return False


def canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        ConfigurationError.fail("value cannot be encoded as canonical JSON")


def semantic_fingerprint(diagnostic: Diagnostic) -> str:
    parts = (
        "finding-v3",
        diagnostic.rule_id,
        str(diagnostic.rule_version),
        diagnostic.component_id,
        diagnostic.subject_kind,
        diagnostic.manifest_anchor,
        _semantic_value(
            diagnostic.observed if diagnostic.observed_value is None else diagnostic.observed_value
        ),
        _semantic_value(
            diagnostic.expected if diagnostic.expected_value is None else diagnostic.expected_value
        ),
    )
    payload = b"".join(len(part.encode()).to_bytes(4, "big") + part.encode() for part in parts)
    return hashlib.sha256(payload).hexdigest()


def semantic_finding_key(diagnostic: Diagnostic) -> str:
    parts = (
        "finding-key-v2",
        diagnostic.rule_id,
        diagnostic.component_id,
        diagnostic.subject_kind,
        diagnostic.manifest_anchor,
    )
    payload = b"".join(len(part.encode()).to_bytes(4, "big") + part.encode() for part in parts)
    return hashlib.sha256(payload).hexdigest()


def _semantic_value(value: object) -> str:
    return value if isinstance(value, str) else canonical_json(value)


def with_fingerprint(diagnostic: Diagnostic) -> Diagnostic:
    return replace(
        diagnostic,
        fingerprint=semantic_fingerprint(diagnostic),
        finding_key=semantic_finding_key(diagnostic),
    )


def scope_digest(manifest: Manifest) -> str:
    payload: dict[str, object] = {
        "repository_id": manifest.repository_id,
    }
    if manifest.delivery is not None:
        payload["delivery"] = {
            "authorities": [
                {
                    "id": item.authority_id,
                    "component_id": item.component_id,
                    "environment": item.environment,
                    "mechanism": item.mechanism,
                    "path": item.path,
                    "authority": item.authority,
                    "delegates": list(item.delegates),
                }
                for item in manifest.delivery.authorities
            ]
        }
    if manifest.documentation is not None:
        payload["documentation"] = {
            "entrypoints": list(manifest.documentation.entrypoints),
            "maximum_added_pages": manifest.documentation.maximum_added_pages,
            "addition_exemptions": list(manifest.documentation.addition_exemptions),
        }
    if manifest.active_configuration:
        payload["active_configuration"] = [
            {"component_id": item.component_id, "path": item.path, "format": item.format}
            for item in manifest.active_configuration
        ]
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()
