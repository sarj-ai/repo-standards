from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Literal, TypedDict, TypeGuard


class ActivationChangePayload(TypedDict):
    path: str
    before_sha256: str
    after_sha256: str


class ActivationPayload(TypedDict):
    schema_version: int
    repository: str
    pull_request: int
    base_ref: Literal["dev", "preview"]
    base_sha: str
    head_ref: str
    head_sha: str
    environment: Literal["dev", "preview"]
    producer_source_sha: str
    activation_source_sha: str
    feature_id: str
    changes: list[ActivationChangePayload]


@dataclass(frozen=True, slots=True)
class ActivationChange:
    path: str
    before_sha256: str
    after_sha256: str


@dataclass(frozen=True, slots=True)
class ActivationBinding:
    repository: str
    pull_request: int
    base_ref: Literal["dev", "preview"]
    base_sha: str
    head_ref: str
    head_sha: str
    environment: Literal["dev", "preview"]
    producer_source_sha: str
    activation_source_sha: str
    feature_id: str
    changes: tuple[ActivationChange, ...]

    def payload(self) -> ActivationPayload:
        return {
            "schema_version": 1,
            "repository": self.repository,
            "pull_request": self.pull_request,
            "base_ref": self.base_ref,
            "base_sha": self.base_sha,
            "head_ref": self.head_ref,
            "head_sha": self.head_sha,
            "environment": self.environment,
            "producer_source_sha": self.producer_source_sha,
            "activation_source_sha": self.activation_source_sha,
            "feature_id": self.feature_id,
            "changes": [
                {
                    "path": change.path,
                    "before_sha256": change.before_sha256,
                    "after_sha256": change.after_sha256,
                }
                for change in self.changes
            ],
        }


def matches_activation_payload(raw: bytes, expected: ActivationBinding) -> bool:
    maximum_receipt_bytes = 16_384
    if len(raw) > maximum_receipt_bytes:
        return False
    try:
        parsed: object = json.loads(raw, object_pairs_hook=_unique_object)  # pyright: ignore[reportAny] -- exact recursive validation follows
    except ValueError, UnicodeError:
        return False
    if not _is_object(parsed):
        return False
    wanted = expected.payload()
    return _exact_value(parsed, wanted)


def _is_object(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _exact_value(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if _is_object(expected) and _is_object(actual):
        return actual.keys() == expected.keys() and all(
            _exact_value(actual[key], value) for key, value in expected.items()
        )
    if _is_array(expected) and _is_array(actual):
        return len(actual) == len(expected) and all(
            map(_exact_value, actual, expected, strict=True)
        )
    return actual == expected


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            message = "duplicate receipt field"
            raise ValueError(message)
        result[key] = value
    return result


def exact_registered_activation(
    *,
    base_content: bytes,
    head_content: bytes,
    registered_false: bytes,
    registered_true: bytes,
    expected_content_sha256: str,
) -> bool:
    return (
        bool(registered_false)
        and bool(registered_true)
        and registered_false != registered_true
        and base_content.count(registered_false) == 1
        and head_content == base_content.replace(registered_false, registered_true, 1)
        and hashlib.sha256(head_content).hexdigest() == expected_content_sha256
    )


def _is_array(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def exact_registered_append(
    *,
    base_content: bytes,
    head_content: bytes,
    registered_true: bytes,
    expected_content_sha256: str,
) -> bool:
    return (
        bool(registered_true)
        and b"\r" not in registered_true
        and b"\n" not in registered_true
        and registered_true not in base_content
        and head_content.count(registered_true) == 1
        and head_content == base_content.rstrip() + b"\n" + registered_true + b"\n"
        and hashlib.sha256(head_content).hexdigest() == expected_content_sha256
    )
