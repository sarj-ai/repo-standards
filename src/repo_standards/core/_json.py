from __future__ import annotations

import json

from pydantic import ConfigDict, TypeAdapter  # ruff: ignore[banned-api] -- validates the shared generic JSON boundary, not a domain object.

from .outcome import JSONValue


_VALUE = TypeAdapter(JSONValue, config=ConfigDict(allow_inf_nan=False))


def parse_json_object(content: bytes) -> dict[str, JSONValue]:
    match parse_json_value(content):
        case dict() as value:
            return value
        case _:
            message = "JSON document must be an object"
            raise ValueError(message)


def parse_json_value(content: bytes) -> JSONValue:
    parsed: object = json.loads(  # pyright: ignore[reportAny] -- stdlib decoder boundary; strict recursive validation follows.
        content.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_invalid_constant,
    )
    return _VALUE.validate_python(parsed, strict=True)


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
