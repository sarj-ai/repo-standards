from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Mapping


def analysis_schema() -> Mapping[str, object]:
    location: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["document", "json_pointer", "precision"],
        "properties": {
            "document": {"type": "string"},
            "json_pointer": {"type": "string"},
            "precision": {"const": "json-pointer"},
        },
    }
    remediation: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["summary", "steps", "validation"],
        "properties": {
            "summary": {"type": "string"},
            "steps": {"type": "array", "items": {"type": "string"}},
            "validation": {"type": "array", "items": {"type": "string"}},
        },
    }
    diagnostic: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "rule_id",
            "rule_version",
            "severity",
            "message",
            "observed",
            "expected",
            "location",
            "remediation",
            "fingerprint",
        ],
        "properties": {
            "rule_id": {"type": "string"},
            "rule_version": {"type": "integer", "minimum": 1},
            "severity": {"enum": ["warning", "error"]},
            "message": {"type": "string"},
            "observed": {"type": "string"},
            "expected": {"type": "string"},
            "location": location,
            "remediation": remediation,
            "fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    issue: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["code", "phase", "message", "remediation"],
        "properties": {
            "code": {"type": "string"},
            "phase": {"type": "string"},
            "message": {"type": "string"},
            "remediation": {"type": "array", "items": {"type": "string"}},
            "retryable": {"type": "boolean"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sarj.ai/repo-lint/openapi-analysis-v2.schema.json",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "completion",
            "conclusion",
            "entrypoint",
            "openapi_version",
            "diagnostics",
            "execution_issues",
        ],
        "properties": {
            "schema_version": {"const": 2},
            "completion": {"enum": ["complete", "incomplete"]},
            "conclusion": {"enum": ["passed", "findings", "inconclusive"]},
            "entrypoint": {"type": "string"},
            "openapi_version": {"type": ["string", "null"]},
            "diagnostics": {"type": "array", "items": diagnostic},
            "execution_issues": {"type": "array", "items": issue},
        },
    }
