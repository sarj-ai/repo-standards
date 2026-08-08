"""Neutral engine tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import date

import pytest
from repo_lint_core.canonical import canonical_path, semantic_fingerprint
from repo_lint_core.engine import analyze, check_baseline
from repo_lint_core.errors import ConfigurationError
from repo_lint_core.models import (
    Baseline,
    Component,
    Diagnostic,
    ExceptionRecord,
    Manifest,
    Remediation,
    Rule,
)


class EmptyPolicy:
    """Fictional policy proving that core has no organization vocabulary."""

    policy_id = "example"
    policy_version = 1

    def rules(self) -> tuple[Rule, ...]:
        return ()

    def evaluate(self, manifest: Manifest) -> tuple[Diagnostic, ...]:
        del manifest
        return ()


def _manifest(*components: Component) -> Manifest:
    return Manifest(
        repository_id="example-repository",
        policy_id="example",
        policy_version=1,
        components=components,
    )


def test_overlapping_roots_are_verified_errors() -> None:
    report = analyze(
        _manifest(
            Component("service", "service", "services/payments", "@example/payments"),
            Component("worker", "worker", "services/payments/worker", "@example/payments"),
        ),
        EmptyPolicy(),
        mode="strict",
    )
    assert [item.rule_id for item in report.diagnostics] == ["core/layout/non-overlapping-root"]
    assert report.diagnostics[0].evidence_level == "verified"


def test_fingerprint_ignores_message_and_path() -> None:
    finding = Diagnostic(
        rule_id="example/rule",
        rule_version=1,
        severity="error",
        evidence_level="verified",
        component_id="service",
        subject_kind="edge",
        observed="a->b",
        expected="a->library",
        message="first message",
        path="old/path",
        manifest_anchor="components.service.dependencies.b",
        remediation=Remediation("Fix it", ("Change the edge.",), ("Check it.",)),
    )
    moved = replace(finding, message="different words", path="new/path")
    assert semantic_fingerprint(finding) == semantic_fingerprint(moved)


@pytest.mark.parametrize("path", ["../outside", "/absolute", "a\\b", "", "."])
def test_unsafe_paths_fail_closed(path: str) -> None:
    with pytest.raises(ConfigurationError):
        canonical_path(path)


def test_ratchet_rejects_new_and_stale_findings() -> None:
    report = analyze(
        _manifest(
            Component("parent", "service", "services/a", "@example/team"),
            Component("child", "service", "services/a/child", "@example/team"),
        ),
        EmptyPolicy(),
        mode="ratchet",
    )
    baseline = Baseline(
        repository_id=report.repository_id,
        source_sha="0" * 40,
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


def test_scope_digest_allows_inventory_changes_to_be_ratcheted() -> None:
    clean = analyze(
        _manifest(Component("parent", "service", "services/a", "@example/team")),
        EmptyPolicy(),
        mode="ratchet",
    )
    baseline = Baseline(
        repository_id=clean.repository_id,
        source_sha="0" * 40,
        policy_id=clean.policy_id,
        policy_version=clean.policy_version,
        scope_digest=clean.scope_digest,
        fingerprints=(),
    )
    changed = analyze(
        _manifest(
            Component("parent", "service", "services/a", "@example/team"),
            Component("child", "service", "services/a/child", "@example/team"),
        ),
        EmptyPolicy(),
        mode="ratchet",
    )
    assert changed.scope_digest == clean.scope_digest
    assert [item.rule_id for item in check_baseline(changed, baseline)] == [
        "core/layout/non-overlapping-root"
    ]


def test_valid_exception_stays_visible_and_nonblocking() -> None:
    manifest = _manifest(
        Component("parent", "service", "services/a", "@example/team"),
        Component("child", "service", "services/a/child", "@example/team"),
    )
    manifest = replace(
        manifest,
        exceptions=(
            ExceptionRecord(
                rule_id="core/layout/non-overlapping-root",
                component_id="child",
                owner="@example/team",
                reason="migration in progress",
                issue="EXAMPLE-1",
                created_on="2029-01-01",
                expires_on="2029-03-01",
            ),
        ),
    )
    report = analyze(manifest, EmptyPolicy(), mode="strict", as_of=date(2029, 1, 1))
    assert report.diagnostics[0].disposition == "excepted"
    assert report.diagnostics[0].exception is not None
    assert report.summary["errors"] == 0
