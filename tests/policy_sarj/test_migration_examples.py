from __future__ import annotations

from pydantic import ValidationError
import pytest

from repo_standards.core.models import FixtureId
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.policy_sarj.migrations import MIGRATION_CONSOLIDATION_RULE_ID
from repo_standards.policy_sarj.policy import POLICY_SPEC, RULES
from repo_standards.policy_sarj.spec import RuleClassification, RuleMaturity


def test_migration_rule_starts_as_a_verified_pending_warning() -> None:
    rule = next(item for item in RULES if item.rule_id == MIGRATION_CONSOLIDATION_RULE_ID)
    governance = next(
        item
        for item in POLICY_SPEC.rule_governance
        if item.rule_id == MIGRATION_CONSOLIDATION_RULE_ID
    )
    assert rule.default_severity == "warning"
    assert governance.maturity is RuleMaturity.WARNING
    assert governance.classification is RuleClassification.JUDGMENT
    assert governance.evidence == "verified"


def test_migration_fixture_refuses_path_only_input() -> None:
    with pytest.raises(ValidationError, match="Invalid JSON"):
        run_rule_example(FixtureId("sarj-migration-consolidation"), "migrations/001.sql")
