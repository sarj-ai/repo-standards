from __future__ import annotations

from dataclasses import replace
import hashlib
import json
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
        "finding-key-v1",
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
        "policy_id": manifest.policy_id,
        "policy_version": manifest.policy_version,
    }
    if manifest.delivery is not None:
        payload["delivery"] = {
            "provider": manifest.delivery.provider,
            "repository": manifest.delivery.repository,
            "production_branch": manifest.delivery.production_branch,
            "preview_branch": manifest.delivery.preview_branch,
            "development_branch": manifest.delivery.development_branch,
            "sync_workflows": list(manifest.delivery.sync_workflows),
        }
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()
