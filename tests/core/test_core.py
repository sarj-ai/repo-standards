from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import ClassVar

import pytest

from repo_lint.core.canonical import canonical_json, canonical_path, semantic_fingerprint
from repo_lint.core.engine import analyze, check_baseline, classify_baseline
from repo_lint.core.errors import ConfigurationError
from repo_lint.core.models import (
    Baseline,
    Component,
    ComponentId,
    Diagnostic,
    ExceptionRecord,
    Manifest,
    MigrationPath,
    Mode,
    PolicyId,
    RatchetClassification,
    Remediation,
    RepositoryId,
    Rule,
    RuleId,
)


class EmptyPolicy:
    policy_id: ClassVar[PolicyId] = PolicyId("example")
    policy_version: ClassVar[int] = 1

    @staticmethod
    def rules() -> tuple[Rule, ...]:
        return ()

    @staticmethod
    def evaluate(manifest: Manifest) -> tuple[Diagnostic, ...]:
        del manifest
        return ()


def test_canonical_json_rejects_non_finite_numbers() -> None:
    with pytest.raises(ConfigurationError, match="canonical JSON"):
        canonical_json({"value": float("nan")})


def _manifest(*components: Component) -> Manifest:
    return Manifest(
        repository_id=RepositoryId("example-repository"),
        policy_id=PolicyId("example"),
        policy_version=1,
        components=components,
    )


def test_overlapping_roots_are_verified_errors() -> None:
    report = analyze(
        _manifest(
            Component(ComponentId("service"), "service", "services/payments", "@example/payments"),
            Component(
                ComponentId("worker"), "worker", "services/payments/worker", "@example/payments"
            ),
        ),
        EmptyPolicy(),
        mode=Mode("strict"),
    )
    assert [item.rule_id for item in report.diagnostics] == ["core/layout/non-overlapping-root"]
    assert report.diagnostics[0].evidence_level == "verified"


def test_duplicate_roots_are_verified_errors() -> None:
    report = analyze(
        _manifest(
            Component(ComponentId("first"), "service", "services/payments", "@example/payments"),
            Component(ComponentId("second"), "service", "services/payments", "@example/payments"),
        ),
        EmptyPolicy(),
        mode=Mode.STRICT,
    )
    assert [item.rule_id for item in report.diagnostics] == ["core/layout/non-overlapping-root"]


def test_casefold_colliding_roots_are_verified_errors() -> None:
    report = analyze(
        _manifest(
            Component(ComponentId("first"), "service", "services/Payments", "@example/payments"),
            Component(ComponentId("second"), "service", "services/payments", "@example/payments"),
        ),
        EmptyPolicy(),
        mode=Mode.STRICT,
    )
    assert [item.rule_id for item in report.diagnostics] == ["core/layout/non-overlapping-root"]


def test_migration_swap_fails_closed() -> None:
    manifest = replace(
        _manifest(
            Component(ComponentId("first"), "service", "services/a", "@example/payments"),
            Component(ComponentId("second"), "service", "services/b", "@example/payments"),
        ),
        migration_paths=(
            MigrationPath(ComponentId("first"), "services/b", "services/a"),
            MigrationPath(ComponentId("second"), "services/a", "services/b"),
        ),
    )
    with pytest.raises(ConfigurationError, match="swap or cycle"):
        analyze(manifest, EmptyPolicy(), mode=Mode.STRICT)


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


def test_ratchet_rejects_new_and_stale_findings() -> None:
    report = analyze(
        _manifest(
            Component(ComponentId("parent"), "service", "services/a", "@example/team"),
            Component(ComponentId("child"), "service", "services/a/child", "@example/team"),
        ),
        EmptyPolicy(),
        mode=Mode("ratchet"),
    )
    baseline = Baseline(
        repository_id=report.repository_id,
        policy_id=report.policy_id,
        policy_version=report.policy_version,
        scope_digest=report.scope_digest,
        fingerprints=("f" * 64,),
    )
    regressions = check_baseline(report, baseline)
    assert {item.rule_id for item in regressions} == {
        "core/layout/non-overlapping-root",
        "core/baseline/stale-entry",
    }
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
    )
    assert changed.scope_digest == clean.scope_digest
    assert [item.rule_id for item in check_baseline(changed, baseline)] == [
        "core/layout/non-overlapping-root"
    ]


def test_valid_exception_stays_visible_and_nonblocking() -> None:
    manifest = _manifest(
        Component(ComponentId("parent"), "service", "services/a", "@example/team"),
        Component(ComponentId("child"), "service", "services/a/child", "@example/team"),
    )
    finding = analyze(manifest, EmptyPolicy(), mode=Mode.STRICT).diagnostics[0]
    manifest = replace(
        manifest,
        exceptions=(
            ExceptionRecord(
                rule_id=RuleId("core/layout/non-overlapping-root"),
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
    report = analyze(manifest, EmptyPolicy(), mode=Mode("strict"), as_of=date(2029, 1, 1))
    assert report.diagnostics[0].disposition == "excepted"
    assert report.diagnostics[0].exception is not None
    assert report.summary["errors"] == 0
