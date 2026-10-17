from __future__ import annotations

from dataclasses import replace
from datetime import date
import json
from typing import ClassVar, TypedDict

import pytest

from repo_standards.core.canonical import (
    ComponentIndex,
    canonical_json,
    canonical_path,
    semantic_finding_key,
    semantic_fingerprint,
)
from repo_standards.core.engine import analyze, check_baseline, classify_baseline
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import (
    Baseline,
    Component,
    ComponentId,
    Diagnostic,
    ExceptionRecord,
    ExecutionIssue,
    FindingsReport,
    IncompleteReport,
    Manifest,
    Mode,
    PassedReport,
    PolicyId,
    RatchetClassification,
    Remediation,
    RepositoryId,
    Rule,
    RuleId,
)
from repo_standards.core.parser import parse_baseline_bytes
from repo_standards.core.rule_reviews import RuleVersion


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("apps", "apps"),
        ("apps/service", "service"),
        ("apps/service/src/main.py", "service"),
        ("apps/service-extra/src/main.py", "apps"),
        ("apps/other/main.py", "apps"),
        ("libraries/main.py", None),
    ],
)
def test_component_index_preserves_nearest_owner_and_segment_boundaries(
    path: str, expected: str | None
) -> None:
    components = (
        Component(ComponentId("apps"), "application", "apps", "@example/team"),
        Component(ComponentId("service"), "application", "apps/service", "@example/team"),
        Component(ComponentId("duplicate"), "application", "apps/service", "@example/team"),
    )
    owner = ComponentIndex(components).nearest(path)
    assert (owner.component_id if owner is not None else None) == expected


class EmptyPolicy:
    policy_id: ClassVar[PolicyId] = PolicyId("example")
    policy_version: ClassVar[int] = 1

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        return ()

    @staticmethod
    def evaluate(_manifest: Manifest) -> tuple[Diagnostic, ...]:
        return ()


def test_analysis_rejects_an_enabled_rule_version_absent_from_the_policy_registry() -> None:
    obsolete = RuleVersion(RuleId("repository/artifacts/bespoke-iac-verifiers"), 3)

    with pytest.raises(ConfigurationError, match="not current for this policy"):
        analyze(
            _manifest(),
            EmptyPolicy(),
            mode=Mode.STRICT,
            enabled_rules=frozenset({obsolete}),
        )


def _execution_issue() -> ExecutionIssue:
    return ExecutionIssue(
        code="analysis.failed",
        phase="analysis",
        message="Analysis could not complete.",
        retryable=False,
        remediation=("Correct the input and retry.",),
    )


def _finding() -> Diagnostic:
    return Diagnostic(
        rule_id=RuleId("example/rule"),
        rule_version=1,
        severity="error",
        evidence_level="verified",
        component_id=ComponentId("child"),
        subject_kind="component",
        observed="unexpected",
        expected="expected",
        message="Example finding",
        path="services/a/child",
        manifest_anchor="components.child",
        remediation=Remediation("Fix the example", ("Change it.",), ("Check it.",)),
    )


def test_finding_identity_preserves_the_published_length_prefixed_encoding() -> None:
    finding = _finding()

    assert semantic_fingerprint(finding) == (
        "7c5e074c8c033adb8cd692b7f34e65375f8415c06cf745e98349a1e9ab79c19b"
    )
    assert semantic_finding_key(finding) == (
        "ff5b57c26d773f515ffaa8577fa6a8691789f23d26e6f9827b33d045fbe365d6"
    )


class _ReportArguments(TypedDict):
    mode: Mode
    repository_id: RepositoryId
    policy_id: PolicyId
    policy_version: int
    scope_digest: str


def test_analysis_report_variants_reject_empty_required_payloads() -> None:
    finding = analyze(
        _manifest(),
        EmptyPolicy(),
        mode=Mode.STRICT,
        additional_diagnostics=(_finding(),),
    ).diagnostics[0]
    common: _ReportArguments = {
        "mode": Mode.STRICT,
        "repository_id": RepositoryId("example-repository"),
        "policy_id": PolicyId("example"),
        "policy_version": 1,
        "scope_digest": "a" * 64,
    }
    with pytest.raises(ValueError, match="at least one diagnostic"):
        FindingsReport(diagnostics=(), **common)
    with pytest.raises(ValueError, match="at least one execution issue"):
        IncompleteReport(execution_issues=(), **common)

    findings = FindingsReport(diagnostics=(finding,), **common)
    incomplete = IncompleteReport(
        execution_issues=(_execution_issue(),),
        **common,
    )
    passed = PassedReport(**common)
    assert findings.conclusion == "findings"
    assert incomplete.diagnostics == ()
    assert passed.conclusion == "passed"


def test_canonical_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ConfigurationError, match="canonical JSON"):
        canonical_json({"value": float("nan")})


@pytest.mark.parametrize(
    "replacement",
    [
        '"schema_version": 2.0',
        '"schema_version": 2, "schema_version": 2',
        '"schema_version": 2, "\\u0073chema_version": 2',
    ],
)
def test_baseline_rejects_ambiguous_schema_identity(replacement: str) -> None:
    payload = json.dumps(
        {
            "schema_version": 2,
            "repository_id": "example",
            "policy": "example",
            "policy_version": 1,
            "scope_digest": "a" * 64,
            "fingerprints": [],
        }
    ).replace('"schema_version": 2', replacement)

    with pytest.raises(ConfigurationError):
        parse_baseline_bytes(payload.encode())


def _manifest(*components: Component) -> Manifest:
    return Manifest(
        repository_id=RepositoryId("example-repository"),
        components=components,
    )


def test_fingerprint_ignores_message_and_path_but_tracks_evidence() -> None:
    finding = Diagnostic(
        rule_id=RuleId("example/rule"),
        rule_version=1,
        severity="error",
        evidence_level="verified",
        component_id=ComponentId("service"),
        subject_kind="edge",
        observed="a->b",
        expected="a->library",
        message="first message",
        path="old/path",
        manifest_anchor="components.service.dependencies.b",
        remediation=Remediation("Fix it", ("Change the edge.",), ("Check it.",)),
    )
    moved = replace(
        finding,
        message="different words",
        path="new/path",
    )
    assert semantic_fingerprint(finding) == semantic_fingerprint(moved)
    assert semantic_fingerprint(finding) != semantic_fingerprint(
        replace(finding, observed="different edge")
    )


@pytest.mark.parametrize("path", ["../outside", "/absolute", "a\\b", "", "."])
def test_unsafe_paths_fail_closed(path: str) -> None:
    with pytest.raises(ConfigurationError):
        canonical_path(path)


def test_ascii_filename_controls_and_allowed_punctuation() -> None:
    for codepoint in range(128):
        path = f"src/name{chr(codepoint)}file.py"
        if codepoint < 32 or codepoint == 127 or chr(codepoint) == "\\":
            with pytest.raises(ConfigurationError):
                canonical_path(path)
        else:
            assert canonical_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "src/zero\u200bwidth.py",
        "src/private\ue000.py",
        "src/surrogate\ud800.py",
        "src/cafe\u0301.py",
    ],
)
def test_unicode_controls_and_non_normalized_names_still_fail(path: str) -> None:
    with pytest.raises(ConfigurationError):
        canonical_path(path)


def test_normalized_unicode_filename_remains_valid() -> None:
    assert canonical_path("src/caf\u00e9.py") == "src/caf\u00e9.py"


def test_ratchet_rejects_new_and_stale_findings() -> None:
    report = analyze(
        _manifest(),
        EmptyPolicy(),
        mode=Mode("ratchet"),
        additional_diagnostics=(_finding(),),
    )
    baseline = Baseline(
        repository_id=report.repository_id,
        policy_id=report.policy_id,
        policy_version=report.policy_version,
        scope_digest=report.scope_digest,
        fingerprints=("f" * 64,),
    )
    with pytest.raises(ConfigurationError, match="resolved fingerprints"):
        check_baseline(report, baseline)
    comparison = classify_baseline(report, baseline)
    assert comparison.fingerprints(RatchetClassification.NEW) == (
        report.diagnostics[0].fingerprint,
    )
    assert comparison.fingerprints(RatchetClassification.KNOWN) == ()
    assert comparison.fingerprints(RatchetClassification.RESOLVED) == ("f" * 64,)


def test_scope_digest_allows_inventory_changes_to_be_ratcheted() -> None:
    clean = analyze(
        _manifest(Component(ComponentId("parent"), "service", "services/a", "@example/team")),
        EmptyPolicy(),
        mode=Mode("ratchet"),
    )
    baseline = Baseline(
        repository_id=clean.repository_id,
        policy_id=clean.policy_id,
        policy_version=clean.policy_version,
        scope_digest=clean.scope_digest,
        fingerprints=(),
    )
    changed = analyze(
        _manifest(
            Component(ComponentId("parent"), "service", "services/a", "@example/team"),
            Component(ComponentId("child"), "service", "services/a/child", "@example/team"),
        ),
        EmptyPolicy(),
        mode=Mode("ratchet"),
        additional_diagnostics=(_finding(),),
    )
    assert changed.scope_digest == clean.scope_digest
    assert [item.rule_id for item in check_baseline(changed, baseline)] == ["example/rule"]


def test_valid_exception_stays_visible_and_nonblocking() -> None:
    manifest = _manifest(
        Component(ComponentId("parent"), "service", "services/a", "@example/team"),
        Component(ComponentId("child"), "service", "services/a/child", "@example/team"),
    )
    finding = analyze(
        manifest, EmptyPolicy(), mode=Mode.STRICT, additional_diagnostics=(_finding(),)
    ).diagnostics[0]
    manifest = replace(
        manifest,
        exceptions=(
            ExceptionRecord(
                rule_id=RuleId("example/rule"),
                component_id=ComponentId("child"),
                manifest_anchor=finding.manifest_anchor,
                fingerprint=finding.fingerprint,
                owner="@example/team",
                reason="migration in progress",
                issue="EXAMPLE-1",
                created_on="2029-01-01",
                expires_on="2029-03-01",
            ),
        ),
    )
    report = analyze(
        manifest,
        EmptyPolicy(),
        mode=Mode("strict"),
        as_of=date(2029, 1, 1),
        additional_diagnostics=(_finding(),),
    )
    assert report.diagnostics[0].disposition == "excepted"
    assert report.diagnostics[0].exception is not None
    assert report.summary["errors"] == 0
