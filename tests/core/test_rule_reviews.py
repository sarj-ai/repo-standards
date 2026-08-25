from __future__ import annotations

import pytest

from repo_standards.core import rule_reviews
from repo_standards.core.models import RuleId
from repo_standards.core.rule_reviews import (
    ApprovedRuleReview,
    PendingRuleReview,
    RuleVersion,
    activated_rule_versions,
    approved_rule_versions,
    review_for,
)
from repo_standards.policy_sarj import SarjPolicy


def test_only_reviewed_rule_version_is_available_for_explicit_activation() -> None:
    review = ApprovedRuleReview(reviewed_in="0e124af8dde6016278bda7db96bd6b9b1bc12a76")
    assert approved_rule_versions() == frozenset(
        {
            RuleVersion(RuleId("repository/artifacts/bespoke-iac-verifiers"), 2),
            RuleVersion(RuleId("repository/artifacts/terraform-test-files"), 1),
        }
    )
    assert review_for(
        RuleId("repository/artifacts/bespoke-iac-verifiers"), 2
    ) == review
    assert review_for(RuleId("repository/artifacts/terraform-test-files"), 1) == review
    assert review_for(RuleId("core/layout/non-overlapping-root"), 1) == PendingRuleReview()


def test_every_approved_rule_version_exists_in_the_current_registry() -> None:
    current = frozenset(RuleVersion(rule.rule_id, rule.version) for rule in SarjPolicy.rules())

    assert approved_rule_versions() <= current


def test_approved_review_requires_immutable_review_reference() -> None:
    with pytest.raises(ValueError, match="immutable 40- or 64-character object ID"):
        ApprovedRuleReview(reviewed_in="")
    with pytest.raises(ValueError, match="immutable 40- or 64-character object ID"):
        ApprovedRuleReview(reviewed_in="release/1")


def test_activation_is_explicit_and_version_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = RuleId("architecture/dependencies/policy")
    approval = ApprovedRuleReview(reviewed_in="a" * 40)
    monkeypatch.setattr(rule_reviews, "APPROVED_RULE_REVIEWS", ((rule_id, 1, approval),))

    assert activated_rule_versions(()) == frozenset()
    selector = f"{rule_id}@1"
    assert activated_rule_versions((selector,)) == frozenset({RuleVersion(rule_id, 1)})
    with pytest.raises(ValueError, match="not approved for activation"):
        activated_rule_versions((f"{rule_id}@2",))
    assert review_for(rule_id, 2) == PendingRuleReview()


@pytest.mark.parametrize(
    "selector",
    ["architecture/dependencies/policy", "architecture/dependencies/policy@0", "@1"],
)
def test_activation_rejects_selectors_without_an_exact_positive_version(selector: str) -> None:
    with pytest.raises(ValueError, match=r"exact rule-id@version|versions must be positive"):
        activated_rule_versions((selector,))


def test_duplicate_approval_versions_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = RuleId("architecture/dependencies/policy")
    approval = ApprovedRuleReview(reviewed_in="a" * 40)
    monkeypatch.setattr(
        rule_reviews,
        "APPROVED_RULE_REVIEWS",
        ((rule_id, 1, approval), (rule_id, 1, approval)),
    )

    with pytest.raises(ValueError, match="unique"):
        approved_rule_versions()
