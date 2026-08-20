from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from .models import RuleId


ReviewCheck = Literal[
    "name",
    "description",
    "trigger",
    "impact",
    "remediation",
    "flagged-case",
    "passing-case",
]

REQUIRED_RULE_REVIEW_CHECKS: tuple[ReviewCheck, ...] = (
    "name",
    "description",
    "trigger",
    "impact",
    "remediation",
    "flagged-case",
    "passing-case",
)


@dataclass(frozen=True, slots=True)
class PendingRuleReview:
    status: Literal["pending"] = "pending"
    completed_checks: tuple[ReviewCheck, ...] = ()
    reviewed_in: None = None

    def __post_init__(self) -> None:
        allowed = set(REQUIRED_RULE_REVIEW_CHECKS)
        if len(self.completed_checks) != len(set(self.completed_checks)):
            message = "pending review checks must be unique"
            raise ValueError(message)
        if any(check not in allowed for check in self.completed_checks):
            message = "pending review contains an unknown check"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ApprovedRuleReview:
    status: Literal["approved"] = "approved"
    completed_checks: tuple[ReviewCheck, ...] = REQUIRED_RULE_REVIEW_CHECKS
    reviewed_in: str = ""

    def __post_init__(self) -> None:
        if self.completed_checks != REQUIRED_RULE_REVIEW_CHECKS:
            message = "approved rules require every review check in canonical order"
            raise ValueError(message)
        if not self.reviewed_in.strip():
            message = "approved rules require an immutable review reference"
            raise ValueError(message)


type RuleReview = PendingRuleReview | ApprovedRuleReview

# Approval is deliberately version-bound. Adding an entry makes a reviewed rule
# available to consumers; it never activates that rule in an existing repository.
APPROVED_RULE_REVIEWS: tuple[tuple[RuleId, int, ApprovedRuleReview], ...] = ()


def review_for(rule_id: RuleId, version: int) -> RuleReview:
    for approved_id, approved_version, review in APPROVED_RULE_REVIEWS:
        if approved_id == rule_id and approved_version == version:
            return review
    return PendingRuleReview()


def approved_rule_ids() -> frozenset[RuleId]:
    return frozenset(rule_id for rule_id, _version, _review in APPROVED_RULE_REVIEWS)
