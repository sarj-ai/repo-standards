from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from repo_standards.core.models import RuleDefinition as _RuleDefinition


RuleDefinition = _RuleDefinition


Severity = Literal["warning", "error"]


@dataclass(frozen=True, slots=True)
class DocumentInput:
    name: str
    content: bytes


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    entrypoint: str
    documents: tuple[DocumentInput, ...]
    semantics: bytes | None = None


@dataclass(frozen=True, slots=True)
class SourceLocation:
    document: str
    json_pointer: str
    precision: Literal["json-pointer"] = "json-pointer"


@dataclass(frozen=True, slots=True)
class Remediation:
    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Diagnostic:
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
    code: str
    phase: str
    message: str
    remediation: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class _AnalysisReportBase:
    schema_version: Literal[3] = field(init=False, default=3)
    entrypoint: str
    openapi_version: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class PassedReport(_AnalysisReportBase):
    completion: Literal["complete"] = field(init=False, default="complete")
    conclusion: Literal["passed"] = field(init=False, default="passed")
    diagnostics: tuple[Diagnostic, ...] = field(init=False, default=())
    execution_issues: tuple[ExecutionIssue, ...] = field(init=False, default=())


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingsReport(_AnalysisReportBase):
    diagnostics: tuple[Diagnostic, ...]
    completion: Literal["complete"] = field(init=False, default="complete")
    conclusion: Literal["findings"] = field(init=False, default="findings")
    execution_issues: tuple[ExecutionIssue, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        if not self.diagnostics:
            message = "OpenAPI findings reports require at least one diagnostic"
            raise ValueError(message)


@dataclass(frozen=True, slots=True, kw_only=True)
class IncompleteReport(_AnalysisReportBase):
    execution_issues: tuple[ExecutionIssue, ...]
    completion: Literal["incomplete"] = field(init=False, default="incomplete")
    conclusion: Literal["inconclusive"] = field(init=False, default="inconclusive")
    diagnostics: tuple[Diagnostic, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        if not self.execution_issues:
            message = "incomplete OpenAPI reports require at least one execution issue"
            raise ValueError(message)


type AnalysisReport = PassedReport | FindingsReport | IncompleteReport
