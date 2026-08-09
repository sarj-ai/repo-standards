"""Deterministic human and machine renderers."""

from __future__ import annotations

from dataclasses import asdict
import json
from typing import TYPE_CHECKING

from .canonical import canonical_json


if TYPE_CHECKING:
    from collections.abc import Mapping

    from .models import AnalysisReport, Diagnostic, Rule


OUTPUT_SCHEMA_VERSION = 1


def diagnostic_dict(diagnostic: Diagnostic) -> Mapping[str, object]:
    """Return the stable wire representation of a diagnostic."""
    exception = asdict(diagnostic.exception) if diagnostic.exception is not None else None
    remediation = {
        "summary": diagnostic.remediation.summary,
        "steps": list(diagnostic.remediation.steps),
        "validation": list(diagnostic.remediation.validation),
    }
    return {
        "rule_id": diagnostic.rule_id,
        "rule_version": diagnostic.rule_version,
        "severity": diagnostic.severity,
        "evidence_level": diagnostic.evidence_level,
        "component_id": diagnostic.component_id,
        "subject_kind": diagnostic.subject_kind,
        "observed": diagnostic.observed,
        "expected": diagnostic.expected,
        "message": diagnostic.message,
        "path": diagnostic.path,
        "manifest_anchor": diagnostic.manifest_anchor,
        "location": {
            "path": diagnostic.path,
            "manifest_anchor": diagnostic.manifest_anchor,
        },
        "remediation": remediation,
        "prerequisites": list(diagnostic.prerequisites),
        "disposition": diagnostic.disposition,
        "exception": exception,
        "fingerprint": diagnostic.fingerprint,
    }


def report_dict(report: AnalysisReport) -> Mapping[str, object]:
    """Return canonical JSON-compatible report data."""
    return {
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


def render_json(report: AnalysisReport, *, pretty: bool = False) -> str:
    """Render one valid JSON value and nothing else."""
    if pretty:
        return json.dumps(report_dict(report), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    return canonical_json(report_dict(report)) + "\n"


def render_text(report: AnalysisReport) -> str:
    """Render concise editor-compatible diagnostics."""
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
    """Render deterministic rule metadata."""
    payload = [asdict(item) for item in sorted(rules, key=lambda item: item.rule_id)]
    return canonical_json({"schema_version": 1, "rules": payload}) + "\n"


def output_schema() -> Mapping[str, object]:
    """Return the minimal stable report JSON Schema."""
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
            "observed": {"type": "string"},
            "expected": {"type": "string"},
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
                },
            },
            "remediation": remediation,
            "prerequisites": {"type": "array", "items": {"type": "string"}},
            "disposition": {"enum": ["active", "excepted"]},
            "exception": exception,
            "fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
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
        },
    }
