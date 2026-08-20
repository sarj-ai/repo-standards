from __future__ import annotations

import pytest

from repo_lint.core import rule_reviews
from repo_lint.core.models import RuleId
from repo_lint.core.rule_reviews import (
    REQUIRED_RULE_REVIEW_CHECKS,
    ApprovedRuleReview,
    PendingRuleReview,
    RuleVersion,
    activated_rule_versions,
    approved_rule_versions,
    review_for,
)


def test_every_unapproved_rule_is_pending_and_disabled() -> None:
    assert approved_rule_versions() == frozenset()
    assert review_for(RuleId("core/layout/non-overlapping-root"), 1) == PendingRuleReview()


def test_approved_review_requires_all_checks_and_review_reference() -> None:
    with pytest.raises(ValueError, match="every review check"):
        ApprovedRuleReview(completed_checks=(), reviewed_in="a" * 40)
    with pytest.raises(ValueError, match="immutable 40- or 64-character object ID"):
        ApprovedRuleReview(completed_checks=REQUIRED_RULE_REVIEW_CHECKS, reviewed_in="")
    with pytest.raises(ValueError, match="immutable 40- or 64-character object ID"):
        ApprovedRuleReview(reviewed_in="release/1")


def test_pending_review_rejects_duplicate_checks() -> None:
    with pytest.raises(ValueError, match="unique"):
        PendingRuleReview(completed_checks=("name", "name"))


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
