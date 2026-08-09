"""Frozen public models for path-free OpenAPI analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Severity = Literal["warning", "error"]
Completion = Literal["complete", "incomplete"]
Conclusion = Literal["passed", "findings", "inconclusive"]


@dataclass(frozen=True, slots=True)
class DocumentInput:
    """One logical tracked document supplied entirely as bytes."""

    name: str
    content: bytes


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    """Bounded, inert inputs for one OpenAPI entry document."""

    entrypoint: str
    documents: tuple[DocumentInput, ...]
    semantics: bytes | None = None


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """A JSON Pointer anchored in one logical source document."""

    document: str
    json_pointer: str
    precision: Literal["json-pointer"] = "json-pointer"


@dataclass(frozen=True, slots=True)
class Remediation:
    """Non-executable, ordered repair guidance."""

    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One deterministic finding from syntax-aware evidence."""

    rule_id: str
    rule_version: int
    severity: Severity
    message: str
    observed: str
    expected: str
    location: SourceLocation
    remediation: Remediation
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ExecutionIssue:
    """A reason analysis could not produce trustworthy policy conclusions."""

    code: str
    phase: str
    message: str
    remediation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Source-derived RuleProblem and governance metadata."""

    rule_id: str
    version: int
    default_severity: Severity
    problem: str
    harm: str
    non_goals: tuple[str, ...]
    evidence_required: str
    upstream: str | None
    references: tuple[str, ...]
    bad_example: str
    good_example: str
    false_positive_controls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Canonical result; incomplete evidence is separate from findings."""

    schema_version: int
    completion: Completion
    conclusion: Conclusion
    entrypoint: str
    openapi_version: str | None
    diagnostics: tuple[Diagnostic, ...]
    execution_issues: tuple[ExecutionIssue, ...]
