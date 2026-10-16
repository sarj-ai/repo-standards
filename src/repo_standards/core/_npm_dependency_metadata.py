from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ._json import parse_json_object


if TYPE_CHECKING:
    from .models import JSONValue


_DEPENDENCY_FIELDS = frozenset(
    {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
)
_PACKAGE_FIELDS = _DEPENDENCY_FIELDS | {"overrides"}
_RESOLUTION_FIELDS = frozenset({"packages", "dependencies"})


def package_dependency_update(before: bytes, after: bytes) -> bool:
    old, new = _object(before), _object(after)
    return old is not None and new is not None and _package_update(old, new)


def lock_dependency_update(
    before: bytes, after: bytes, base_package: bytes, head_package: bytes
) -> bool:
    old, new = _object(before), _object(after)
    base, head = _object(base_package), _object(head_package)
    if old is None or new is None or base is None or head is None:
        return False
    if not _package_update(base, head):
        return False
    if not _same_metadata(old, new, _RESOLUTION_FIELDS):
        return False
    old_root, new_root = _lock_root(old, base["name"]), _lock_root(new, head["name"])
    return old_root is not None and new_root is not None and _package_update(old_root, new_root)


def _package_update(old: dict[str, JSONValue], new: dict[str, JSONValue]) -> bool:
    name = old.get("name")
    if not isinstance(name, str) or not name.strip():
        return False
    if not _same_metadata(old, new, _PACKAGE_FIELDS):
        return False
    return all(_valid_overrides(document.get("overrides", {})) for document in (old, new)) and all(
        isinstance(values := document.get(field, {}), dict)
        and all(isinstance(value, str) for value in values.values())
        for document in (old, new)
        for field in _DEPENDENCY_FIELDS
    )


def _valid_overrides(value: JSONValue, *, nested: bool = False) -> bool:
    if not isinstance(value, dict):
        return False
    for selector, resolution in value.items():
        if not selector.strip() or (selector == "." and not nested):
            return False
        if isinstance(resolution, str):
            if not resolution.strip():
                return False
        elif not _valid_overrides(resolution, nested=True):
            return False
    return True


def _lock_root(document: dict[str, JSONValue], name: JSONValue) -> dict[str, JSONValue] | None:
    version = document.get("lockfileVersion")
    if document.get("name") != name or type(version) is not int or version not in {2, 3}:
        return None
    packages = document.get("packages")
    if not isinstance(packages, dict) or not all(
        isinstance(item, dict) for item in packages.values()
    ):
        return None
    root = packages.get("")
    if not isinstance(root, dict) or root.get("name") != name:
        return None
    dependencies = document.get("dependencies", {})
    if not isinstance(dependencies, dict) or not all(
        isinstance(item, dict) for item in dependencies.values()
    ):
        return None
    return root


def _same_metadata(
    old: dict[str, JSONValue], new: dict[str, JSONValue], fields: frozenset[str]
) -> bool:
    return json.dumps(
        {key: value for key, value in old.items() if key not in fields}, sort_keys=True
    ) == json.dumps({key: value for key, value in new.items() if key not in fields}, sort_keys=True)


def _object(content: bytes) -> dict[str, JSONValue] | None:
    try:
        return parse_json_object(content)
    except UnicodeError, ValueError, RecursionError:
        return None
