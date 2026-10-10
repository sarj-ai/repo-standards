from __future__ import annotations

from pydantic import ValidationError
import pytest

from repo_standards.core.models import FixtureId, RuleId
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.policy_sarj.policy import POLICY_SPEC, RULES
from repo_standards.policy_sarj.spec import RuleClassification, RuleMaturity


RULE_ID = RuleId("repository/artifacts/makefile-growth")
GROWTH_EXAMPLE = FixtureId("sarj-artifact-makefile-growth")
ADDITION_EXAMPLE = FixtureId("sarj-artifact-new-empty-makefile")


@pytest.mark.parametrize(
    ("fixture_id", "source", "expected"),
    [
        (GROWTH_EXAMPLE, '{"base":{"Makefile":2},"head":{"Makefile":3}}', (RULE_ID,)),
        (GROWTH_EXAMPLE, '{"base":{"Makefile":2},"head":{"Makefile":2}}', ()),
        (GROWTH_EXAMPLE, '{"base":{"Makefile":3},"head":{"Makefile":2}}', ()),
        (GROWTH_EXAMPLE, '{"base":{"Makefile":2},"head":{}}', ()),
        (ADDITION_EXAMPLE, '{"base":{},"head":{"tools/Makefile":0}}', (RULE_ID,)),
        (ADDITION_EXAMPLE, '{"base":{},"head":{}}', ()),
    ],
    ids=("growth", "unchanged", "shrink", "delete", "empty-addition", "no-addition"),
)
def test_makefile_examples_compare_two_snapshots(
    fixture_id: FixtureId, source: str, expected: tuple[RuleId, ...]
) -> None:
    result = run_rule_example(fixture_id, source)

    assert result.complete
    assert result.execution_issue_codes == ()
    assert result.rule_ids == expected


def test_makefile_metadata_records_verified_policy_preference_without_activation() -> None:
    rule = next(item for item in RULES if item.rule_id == RULE_ID)
    governance = next(item for item in POLICY_SPEC.rule_governance if item.rule_id == RULE_ID)

    assert rule.version == 1
    assert rule.default_severity == "warning"
    assert POLICY_SPEC.policy_version == 19
    assert governance.maturity is RuleMaturity.WARNING
    assert governance.classification is RuleClassification.JUDGMENT
    assert governance.evidence == "verified"
    assert {example.language for example in rule.examples} == {"json"}
    assert {example.expected_severity for example in rule.examples} == {"warning"}


def test_makefile_example_fixture_rejects_path_only_input() -> None:
    with pytest.raises(ValidationError, match="Invalid JSON"):
        run_rule_example(GROWTH_EXAMPLE, "Makefile")
