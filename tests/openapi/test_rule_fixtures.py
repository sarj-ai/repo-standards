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
        FixtureId("rest/source/nonhermetic-ref/remote"),
        RuleId("rest/source/nonhermetic-ref"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/http/forbidden-content/response"),
        RuleId("rest/http/forbidden-content"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/http/forbidden-content/trace"),
        RuleId("rest/http/forbidden-content"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/http/status-method-contradiction/304"),
        RuleId("rest/http/status-method-contradiction"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/security/insecure-server/literal-http"),
        RuleId("rest/security/insecure-server"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("rest/security/oauth-password-grant/password"),
        RuleId("rest/security/oauth-password-grant"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/security/oauth-implicit-grant/implicit"),
        RuleId("rest/security/oauth-implicit-grant"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("rest/security/exposure-contradiction/public"),
        RuleId("rest/security/exposure-contradiction"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/security/exposure-contradiction/authenticated"),
        RuleId("rest/security/exposure-contradiction"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/errors/problem-contract/media-type"),
        RuleId("rest/errors/problem-contract"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("rest/errors/problem-contract/status-member"),
        RuleId("rest/errors/problem-contract"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("rest/lifecycle/sunset-order/reversed"),
        RuleId("rest/lifecycle/sunset-order"),
        "error",
    ),
    FixtureExpectation(
        FixtureId("rest/artifact/provenance-incomplete/incomplete"),
        RuleId("rest/artifact/provenance-incomplete"),
        "warning",
    ),
    FixtureExpectation(
        FixtureId("rest/artifact/provenance-contradiction/digest-mismatch"),
        RuleId("rest/artifact/provenance-contradiction"),
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
    assert set(catalog) == {fixture.rule_id for fixture in REST_RULE_FIXTURES}
    for rule_id, rule in catalog.items():
        assert rule.examples == examples_for_rule(rule_id)
        assert rule.fixture_ids
