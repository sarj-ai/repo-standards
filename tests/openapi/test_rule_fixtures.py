from __future__ import annotations

from dataclasses import dataclass

import pytest

from repo_lint.core.models import FixtureId, RuleId, Severity
from repo_lint.openapi import analyze
from repo_lint.openapi.catalog import rules
from repo_lint.openapi.fixtures import REST_RULE_FIXTURES, examples_for_rule


@dataclass(frozen=True, slots=True)
class FixtureExpectation:
    fixture_id: FixtureId
    rule_id: RuleId
    severity: Severity


_EXPECTED_FIXTURES = (
    FixtureExpectation(
        FixtureId("api/references/local-resolution/remote"),
        RuleId("api/references/local-resolution"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("api/http/message-semantics/response"),
        RuleId("api/http/message-semantics"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("api/http/message-semantics/trace"),
        RuleId("api/http/message-semantics"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("api/http/message-semantics/304"),
        RuleId("api/http/message-semantics"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("api/errors/problem-details/media-type"),
        RuleId("api/errors/problem-details"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("api/errors/problem-details/status-member"),
        RuleId("api/errors/problem-details"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("api/artifact/provenance/incomplete"),
        RuleId("api/artifact/provenance"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("api/artifact/provenance/digest-mismatch"),
        RuleId("api/artifact/provenance"),
        "error",
    ),
)
_FIXTURES_BY_ID = {fixture.fixture_id: fixture for fixture in REST_RULE_FIXTURES}


def _expectation_id(expectation: FixtureExpectation) -> str:
    return str(expectation.fixture_id)


@pytest.mark.parametrize(
    "expectation",
    _EXPECTED_FIXTURES,
    ids=_expectation_id,
)
def test_rule_fixture_is_executable_and_exact(expectation: FixtureExpectation) -> None:
    fixture = _FIXTURES_BY_ID[expectation.fixture_id]
    assert fixture.rule_id == expectation.rule_id
    assert tuple((finding.rule_id, finding.severity) for finding in fixture.expected_findings) == (
        (expectation.rule_id, expectation.severity),
    )

    flagged = analyze(fixture.flagged)
    assert flagged.completion == "complete"
    assert tuple((item.rule_id, item.severity) for item in flagged.diagnostics) == (
        (expectation.rule_id, expectation.severity),
    )

    passing = analyze(fixture.passes)
    assert passing.completion == "complete"
    assert passing.diagnostics == ()


def test_fixture_registry_matches_independent_expectations() -> None:
    assert set(_FIXTURES_BY_ID) == {expectation.fixture_id for expectation in _EXPECTED_FIXTURES}


def test_catalog_examples_are_rendered_from_executable_fixture_bytes() -> None:
    catalog = {rule.rule_id: rule for rule in rules()}
    assert set(catalog) == {
        RuleId("api/artifact/provenance"),
        RuleId("api/references/local-resolution"),
        RuleId("api/http/message-semantics"),
        RuleId("api/errors/problem-details"),
    }
    for rule_id, rule in catalog.items():
        assert rule.examples == examples_for_rule(rule_id)
        assert rule.fixture_ids
