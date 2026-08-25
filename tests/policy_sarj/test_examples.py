from __future__ import annotations

import pytest

from repo_standards.policy_sarj.examples import (
    RuleExampleCase,
    rule_example_cases,
    run_rule_example,
)
from repo_standards.policy_sarj.policy import RULES


def _case_id(case: RuleExampleCase) -> str:
    return str(case.fixture_id)


@pytest.mark.parametrize("case", rule_example_cases(), ids=_case_id)
def test_canonical_rule_examples_execute(case: RuleExampleCase) -> None:
    flagged = run_rule_example(case.fixture_id, case.flagged)
    passes = run_rule_example(case.fixture_id, case.passes)

    assert flagged.complete
    assert flagged.execution_issue_codes == ()
    assert flagged.rule_ids == (case.rule_id,)
    assert passes.complete
    assert passes.execution_issue_codes == ()
    assert passes.rule_ids == ()


def test_every_sarj_rule_has_unique_executable_issue_examples() -> None:
    cases = rule_example_cases()
    assert len(RULES) == 12
    assert len(cases) >= len(RULES)
    assert len({case.fixture_id for case in cases}) == len(cases)
    assert {case.rule_id for case in cases} == {str(rule.rule_id) for rule in RULES}
