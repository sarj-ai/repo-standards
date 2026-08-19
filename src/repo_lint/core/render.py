from __future__ import annotations

from dataclasses import asdict
import json
from typing import TYPE_CHECKING

from .canonical import canonical_json


if TYPE_CHECKING:
    from collections.abc import Mapping

    from .models import (
        AnalysisReport,
        Diagnostic,
        InputProvenance,
        RatchetComparison,
        RelatedLocation,
        Rule,
        SourceLocation,
    )


OUTPUT_SCHEMA_VERSION = 1


def diagnostic_dict(diagnostic: Diagnostic) -> Mapping[str, object]:
    exception = asdict(diagnostic.exception) if diagnostic.exception is not None else None
    remediation = {
        "summary": diagnostic.remediation.summary,
        "steps": list(diagnostic.remediation.steps),
        "validation": list(diagnostic.remediation.validation),
    }
    location = _source_location_dict(diagnostic.location)
    if location is None:
        location = {
            "path": diagnostic.path,
            "manifest_anchor": diagnostic.manifest_anchor,
        }
    else:
        location["manifest_anchor"] = diagnostic.manifest_anchor
    payload: dict[str, object] = {
        "rule_id": diagnostic.rule_id,
        "rule_version": diagnostic.rule_version,
        "severity": diagnostic.severity,
        "evidence_level": diagnostic.evidence_level,
        "component_id": diagnostic.component_id,
        "subject_kind": diagnostic.subject_kind,
        "observed": (
            diagnostic.observed if diagnostic.observed_value is None else diagnostic.observed_value
        ),
        "expected": (
            diagnostic.expected if diagnostic.expected_value is None else diagnostic.expected_value
        ),
        "message": diagnostic.message,
        "path": diagnostic.path,
        "manifest_anchor": diagnostic.manifest_anchor,
        "location": location,
        "remediation": remediation,
        "prerequisites": list(diagnostic.prerequisites),
        "disposition": diagnostic.disposition,
        "exception": exception,
        "fingerprint": diagnostic.fingerprint,
    }
    if diagnostic.finding_key:
        payload["finding_key"] = diagnostic.finding_key
    if diagnostic.related_locations:
        payload["related_locations"] = [
            _related_location_dict(item) for item in diagnostic.related_locations
        ]
    return payload


def _source_location_dict(location: SourceLocation | None) -> dict[str, object] | None:
    if location is None:
        return None
    payload: dict[str, object] = {"path": location.path}
    if location.line is not None:
        payload["line"] = location.line
    if location.column is not None:
        payload["column"] = location.column
    if location.end_line is not None:
        payload["end_line"] = location.end_line
    if location.end_column is not None:
        payload["end_column"] = location.end_column
    if location.pointer is not None:
        payload["pointer"] = location.pointer
    return payload


def _related_location_dict(location: RelatedLocation) -> Mapping[str, object]:
    return {
        "location": _source_location_dict(location.location),
        "message": location.message,
        "relationship": location.relationship,
    }


def input_provenance_dict(provenance: InputProvenance) -> Mapping[str, object]:
    return asdict(provenance)


def ratchet_dict(comparison: RatchetComparison) -> Mapping[str, object]:
    return {
        "entries": [
            {
                "fingerprint": item.fingerprint,
                "classification": item.classification,
                "diagnostic": (
                    diagnostic_dict(item.diagnostic) if item.diagnostic is not None else None
                ),
            }
            for item in comparison.entries
        ]
    }


def report_dict(report: AnalysisReport) -> Mapping[str, object]:
    payload: dict[str, object] = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "completion": report.completion,
        "conclusion": report.conclusion,
        "mode": report.mode,
        "repository_id": report.repository_id,
        "policy": {"id": report.policy_id, "version": report.policy_version},
        "scope_digest": report.scope_digest,
        "summary": dict(sorted(report.summary.items())),
        "execution_issues": [asdict(item) for item in report.execution_issues],
        "diagnostics": [diagnostic_dict(item) for item in report.diagnostics],
    }
    if report.input_provenance is not None:
        payload["input_provenance"] = input_provenance_dict(report.input_provenance)
    if report.ratchet is not None:
        payload["ratchet_comparison"] = ratchet_dict(report.ratchet)
    return payload


def render_json(report: AnalysisReport, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(report_dict(report), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    return canonical_json(report_dict(report)) + "\n"


def render_text(report: AnalysisReport) -> str:
    lines = [
        f"repo-lint: analysis incomplete: {issue.code}: {issue.message}"
        for issue in report.execution_issues
    ]
    lines.extend(
        f"{item.path}: {item.rule_id} {item.message} "
        f"[observed={item.observed!r}; expected={item.expected!r}]"
        f" [anchor={item.manifest_anchor}; disposition={item.disposition}]"
        for item in report.diagnostics
    )
    lines.append(
        f"repo-lint: {report.conclusion}; {report.summary.get('errors', 0)} errors, "
        f"{report.summary.get('warnings', 0)} warnings"
    )
    return "\n".join(lines) + "\n"


def render_rules(rules: tuple[Rule, ...]) -> str:
    payload = [asdict(item) for item in sorted(rules, key=lambda item: item.rule_id)]
    return canonical_json({"schema_version": 1, "rules": payload}) + "\n"


def output_schema() -> Mapping[str, object]:
    remediation = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "summary",
            "steps",
            "validation",
        ],
        "properties": {
            "summary": {"type": "string"},
            "steps": {"type": "array", "items": {"type": "string"}},
            "validation": {"type": "array", "items": {"type": "string"}},
        },
    }
    exception = {
        "type": ["object", "null"],
        "additionalProperties": False,
        "required": ["owner", "issue", "reason", "created_on", "expires_on"],
        "properties": {
            "owner": {"type": "string"},
            "issue": {"type": "string"},
            "reason": {"type": "string"},
            "created_on": {"type": "string", "format": "date"},
            "expires_on": {"type": "string", "format": "date"},
        },
    }
    diagnostic = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "rule_id",
            "rule_version",
            "severity",
            "evidence_level",
            "component_id",
            "subject_kind",
            "observed",
            "expected",
            "message",
            "path",
            "manifest_anchor",
            "location",
            "remediation",
            "prerequisites",
            "disposition",
            "exception",
            "fingerprint",
        ],
        "properties": {
            "rule_id": {"type": "string"},
            "rule_version": {"type": "integer", "minimum": 1},
            "severity": {"enum": ["warning", "error"]},
            "evidence_level": {"enum": ["verified", "declared", "external", "unknown"]},
            "component_id": {"type": "string"},
            "subject_kind": {"type": "string"},
            "observed": {},
            "expected": {},
            "message": {"type": "string"},
            "path": {"type": "string"},
            "manifest_anchor": {"type": "string"},
            "location": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "manifest_anchor"],
                "properties": {
                    "path": {"type": "string"},
                    "manifest_anchor": {"type": "string"},
                    "line": {"type": "integer", "minimum": 1},
                    "column": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                    "end_column": {"type": "integer", "minimum": 1},
                    "pointer": {"type": "string"},
                },
            },
            "remediation": remediation,
            "prerequisites": {"type": "array", "items": {"type": "string"}},
            "disposition": {"enum": ["active", "excepted"]},
            "exception": exception,
            "fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "finding_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "related_locations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["location", "message", "relationship"],
                    "properties": {
                        "location": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["path"],
                            "properties": {
                                "path": {"type": "string"},
                                "line": {"type": "integer", "minimum": 1},
                                "column": {"type": "integer", "minimum": 1},
                                "end_line": {"type": "integer", "minimum": 1},
                                "end_column": {"type": "integer", "minimum": 1},
                                "pointer": {"type": "string"},
                            },
                        },
                        "message": {"type": "string"},
                        "relationship": {"type": "string"},
                    },
                },
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:repo-lint:schema:report:v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "completion",
            "conclusion",
            "mode",
            "repository_id",
            "policy",
            "scope_digest",
            "summary",
            "execution_issues",
            "diagnostics",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "completion": {"enum": ["complete", "incomplete"]},
            "conclusion": {"enum": ["passed", "findings", "inconclusive"]},
            "mode": {"enum": ["report", "ratchet", "strict"]},
            "repository_id": {"type": "string"},
            "policy": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "version"],
                "properties": {"id": {"type": "string"}, "version": {"type": "integer"}},
            },
            "scope_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "summary": {"type": "object", "additionalProperties": {"type": "integer"}},
            "execution_issues": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "phase", "message", "retryable", "remediation"],
                    "properties": {
                        "code": {"type": "string", "pattern": "^[a-z][a-z0-9.-]+$"},
                        "phase": {"type": "string"},
                        "message": {"type": "string"},
                        "retryable": {"type": "boolean"},
                        "remediation": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "diagnostics": {"type": "array", "items": diagnostic},
            "input_provenance": {"type": "object"},
            "ratchet_comparison": {"type": "object"},
        },
    }
