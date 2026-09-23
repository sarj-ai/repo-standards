from __future__ import annotations

import pytest

from repo_standards.core.models import RuleId
from repo_standards.core.rule_reviews import (
    RuleVersion,
    activated_rule_ids,
    activated_rule_versions,
)
from repo_standards.policy_sarj import SarjPolicy


def _current_rule_versions() -> frozenset[RuleVersion]:
    return frozenset(RuleVersion(rule.rule_id, rule.version) for rule in SarjPolicy.rules())


def test_any_current_rule_can_be_explicitly_activated() -> None:
    current = _current_rule_versions()
    terraform = next(
        item for item in current if item.rule_id == "repository/artifacts/terraform-examples"
    )
    assert activated_rule_versions(
        (f"{terraform.rule_id}@{terraform.version}",), current_rules=current
    ) == frozenset({terraform})
    assert activated_rule_ids((str(terraform.rule_id),), current_rules=current) == frozenset(
        {terraform}
    )
    assert activated_rule_versions((), current_rules=current) == frozenset()


def test_obsolete_versions_are_rejected() -> None:
    with pytest.raises(ValueError, match="selectors are obsolete"):
        activated_rule_versions(
            ("repository/artifacts/bespoke-iac-verifiers@4",),
            current_rules=_current_rule_versions(),
        )


def test_activation_rejects_duplicates_and_unknown_rules() -> None:
    current = _current_rule_versions()
    rule = next(iter(current))
    selector = f"{rule.rule_id}@{rule.version}"
    with pytest.raises(ValueError, match="must be unique"):
        activated_rule_versions((selector, selector), current_rules=current)
    with pytest.raises(ValueError, match="must be unique"):
        activated_rule_ids((str(rule.rule_id), str(rule.rule_id)), current_rules=current)
    with pytest.raises(ValueError, match="not available"):
        activated_rule_ids(("unknown/rule/id",), current_rules=current)


@pytest.mark.parametrize("selector", ["example/rule/id", "example/rule/id@0", "@1"])
def test_activation_requires_exact_positive_version(selector: str) -> None:
    with pytest.raises(ValueError, match=r"exact rule-id@version|versions must be positive"):
        activated_rule_versions((selector,), current_rules=frozenset())


def test_manifest_activation_uses_versionless_ids() -> None:
    with pytest.raises(ValueError, match="versionless rule IDs"):
        activated_rule_ids(
            ("repository/artifacts/terraform-examples@1",), current_rules=_current_rule_versions()
        )


def test_rule_versions_must_be_positive() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RuleVersion(RuleId("example/rule/id"), 0)
