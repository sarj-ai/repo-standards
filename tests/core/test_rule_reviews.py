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
        ApprovedRuleReview(completed_checks=(), reviewed_in="release/1")
    with pytest.raises(ValueError, match="immutable review reference"):
        ApprovedRuleReview(completed_checks=REQUIRED_RULE_REVIEW_CHECKS, reviewed_in="")


def test_pending_review_rejects_duplicate_checks() -> None:
    with pytest.raises(ValueError, match="unique"):
        PendingRuleReview(completed_checks=("name", "name"))


def test_activation_is_explicit_and_version_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = RuleId("architecture/dependencies/policy")
    approval = ApprovedRuleReview(reviewed_in="release/1")
    monkeypatch.setattr(rule_reviews, "APPROVED_RULE_REVIEWS", ((rule_id, 1, approval),))

    assert activated_rule_versions(()) == frozenset()
    assert activated_rule_versions((str(rule_id),)) == frozenset({RuleVersion(rule_id, 1)})
    assert RuleVersion(rule_id, 2) not in activated_rule_versions((str(rule_id),))
    assert review_for(rule_id, 2) == PendingRuleReview()


def test_duplicate_approval_versions_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = RuleId("architecture/dependencies/policy")
    approval = ApprovedRuleReview(reviewed_in="release/1")
    monkeypatch.setattr(
        rule_reviews,
        "APPROVED_RULE_REVIEWS",
        ((rule_id, 1, approval), (rule_id, 1, approval)),
    )

    with pytest.raises(ValueError, match="unique"):
        approved_rule_versions()
