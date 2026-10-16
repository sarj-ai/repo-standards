from __future__ import annotations

import json

from pydantic import ConfigDict, TypeAdapter  # ruff: ignore[banned-api] -- validates the shared generic JSON boundary, not a domain object.

from .models import JSONValue


_OBJECT = TypeAdapter(dict[str, JSONValue], config=ConfigDict(allow_inf_nan=False))


def parse_json_object(content: bytes) -> dict[str, JSONValue]:
    parsed: object = json.loads(  # pyright: ignore[reportAny] -- strict JSON parser boundary.
        content.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_invalid_constant,
    )
    return _OBJECT.validate_python(parsed, strict=True)


def _unique_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            message = "duplicate JSON object key"
            raise ValueError(message)
        result[key] = value
    return result


def _invalid_constant(value: str) -> JSONValue:
    message = f"invalid JSON constant: {value}"
    raise ValueError(message)
