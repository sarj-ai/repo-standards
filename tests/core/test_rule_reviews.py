from __future__ import annotations

import pytest

from repo_lint.core.models import RuleId
from repo_lint.core.rule_reviews import (
    REQUIRED_RULE_REVIEW_CHECKS,
    ApprovedRuleReview,
    PendingRuleReview,
    approved_rule_ids,
    review_for,
)


def test_every_unapproved_rule_is_pending_and_disabled() -> None:
    assert approved_rule_ids() == frozenset()
    assert review_for(RuleId("core/layout/non-overlapping-root"), 1) == PendingRuleReview()


def test_approved_review_requires_all_checks_and_review_reference() -> None:
    with pytest.raises(ValueError, match="every review check"):
        ApprovedRuleReview(completed_checks=(), reviewed_in="release/1")
    with pytest.raises(ValueError, match="immutable review reference"):
        ApprovedRuleReview(completed_checks=REQUIRED_RULE_REVIEW_CHECKS, reviewed_in="")


def test_pending_review_rejects_duplicate_checks() -> None:
    with pytest.raises(ValueError, match="unique"):
        PendingRuleReview(completed_checks=("name", "name"))
