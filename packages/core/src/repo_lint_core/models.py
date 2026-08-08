"""Stable public data model for repository analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

Severity = Literal["warning", "error"]
EvidenceLevel = Literal["verified", "declared", "external", "unknown"]
Mode = Literal["report", "ratchet", "strict"]


@dataclass(frozen=True, slots=True)
class Dependency:
    """A typed, declared relation between two stable components."""

    target: str
    kind: str


@dataclass(frozen=True, slots=True)
class Component:
    """A stable repository component declared by the repository owner."""

    component_id: str
    kind: str
    path: str
    owner: str
    product: str | None = None
    capability: str | None = None
    legacy: bool = False
    dependencies: tuple[Dependency, ...] = ()


@dataclass(frozen=True, slots=True)
class MigrationPath:
    """An explicit path relocation used to preserve diagnostic identity."""

    component_id: str
    old_path: str
    new_path: str


@dataclass(frozen=True, slots=True)
class ExceptionRecord:
    """A narrow, time-bounded policy exception."""

    rule_id: str
    component_id: str
    owner: str
    reason: str
    issue: str
    created_on: str
    expires_on: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """Strict repository declaration consumed by the engine."""

    repository_id: str
    policy_id: str
    policy_version: int
    components: tuple[Component, ...]
    migration_paths: tuple[MigrationPath, ...] = ()
    exceptions: tuple[ExceptionRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class Remediation:
    """Non-executable remediation guidance."""

    summary: str
    steps: tuple[str, ...]
    validation: tuple[str, ...]
    rollback: tuple[str, ...] = ()
    suggested_manifest: dict[str, object] | None = None
    auto_applicable: bool = False


@dataclass(frozen=True, slots=True)
class ExceptionUse:
    """Visible metadata for an applied, reviewed exception."""

    owner: str
    issue: str
    reason: str
    created_on: str
    expires_on: str


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One deterministic policy finding."""

    rule_id: str
    rule_version: int
    severity: Severity
    evidence_level: EvidenceLevel
    component_id: str
    subject_kind: str
    observed: str
    expected: str
    message: str
    path: str
    manifest_anchor: str
    remediation: Remediation
    prerequisites: tuple[str, ...] = ()
    disposition: Literal["active", "excepted"] = "active"
    exception: ExceptionUse | None = None
    fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class Rule:
    """Discoverable rule documentation."""

    rule_id: str
    version: int
    severity: Severity
    summary: str
    rationale: str
    bad_example: str
    good_example: str


class Policy(Protocol):
    """Non-executable interface implemented by installed policy packages."""

    policy_id: str
    policy_version: int

    def rules(self) -> tuple[Rule, ...]:
        """Return every immutable rule definition in the policy."""
        ...

    def evaluate(self, manifest: Manifest) -> tuple[Diagnostic, ...]:
        """Evaluate already-parsed repository facts."""
        ...


@dataclass(frozen=True, slots=True)
class Baseline:
    """Exact reviewed legacy debt."""

    repository_id: str
    source_sha: str
    policy_id: str
    policy_version: int
    scope_digest: str
    fingerprints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Canonical result with completion separate from policy conclusion."""

    mode: Mode
    repository_id: str
    policy_id: str
    policy_version: int
    scope_digest: str
    completion: Literal["complete", "incomplete"]
    conclusion: Literal["passed", "findings", "inconclusive"]
    diagnostics: tuple[Diagnostic, ...] = ()
    execution_issues: tuple[str, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)
