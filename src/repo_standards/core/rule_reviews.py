from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

from .errors import ConfigurationError
from .models import RuleId


_IMMUTABLE_REVIEW_REFERENCE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


@dataclass(frozen=True, slots=True)
class PendingRuleReview:
    status: Literal["pending"] = "pending"
    reviewed_in: None = None


@dataclass(frozen=True, slots=True)
class ApprovedRuleReview:
    status: Literal["approved"] = "approved"
    reviewed_in: str = ""

    def __post_init__(self) -> None:
        if _IMMUTABLE_REVIEW_REFERENCE.fullmatch(self.reviewed_in) is None:
            message = "approved rules require an immutable 40- or 64-character object ID"
            raise ValueError(message)


type RuleReview = PendingRuleReview | ApprovedRuleReview


@dataclass(frozen=True, slots=True)
class RuleVersion:
    rule_id: RuleId
    version: int

    def __post_init__(self) -> None:
        if self.version < 1:
            message = "rule versions must be positive"
            raise ValueError(message)


# Approval is deliberately version-bound. Adding an entry makes a reviewed rule
# available to consumers; it never activates that rule in an existing repository.
APPROVED_RULE_REVIEWS: tuple[tuple[RuleId, int, ApprovedRuleReview], ...] = (
    (
        RuleId("repository/artifacts/bespoke-iac-verifiers"),
        3,
        ApprovedRuleReview(reviewed_in="8080480deab8e7f8573f0338bb840f4e0aff28f4"),
    ),
    (
        RuleId("repository/artifacts/bespoke-iac-verifiers"),
        4,
        ApprovedRuleReview(reviewed_in="6a52b0723886f591c733edc6ca2836cbedffc7ee"),
    ),
    (
        RuleId("repository/artifacts/operational-script-tests"),
        1,
        ApprovedRuleReview(reviewed_in="8080480deab8e7f8573f0338bb840f4e0aff28f4"),
    ),
    (
        RuleId("repository/artifacts/schema-derived-config-examples"),
        2,
        ApprovedRuleReview(reviewed_in="8080480deab8e7f8573f0338bb840f4e0aff28f4"),
    ),
    (
        RuleId("repository/artifacts/terraform-test-files"),
        1,
        ApprovedRuleReview(reviewed_in="0e124af8dde6016278bda7db96bd6b9b1bc12a76"),
    ),
    (
        RuleId("repository/documentation/placement"),
        2,
        ApprovedRuleReview(reviewed_in="8080480deab8e7f8573f0338bb840f4e0aff28f4"),
    ),
    (
        RuleId("repository/documentation/placement"),
        3,
        ApprovedRuleReview(reviewed_in="6a52b0723886f591c733edc6ca2836cbedffc7ee"),
    ),
)


def review_for(rule_id: RuleId, version: int) -> RuleReview:
    for approved_id, approved_version, review in APPROVED_RULE_REVIEWS:
        if approved_id == rule_id and approved_version == version:
            return review
    return PendingRuleReview()


def approved_rule_versions() -> frozenset[RuleVersion]:
    approved = frozenset(
        RuleVersion(rule_id, version) for rule_id, version, _review in APPROVED_RULE_REVIEWS
    )
    if len(approved) != len(APPROVED_RULE_REVIEWS):
        message = "approved rule reviews must have unique rule ID and version pairs"
        raise ValueError(message)
    return approved


def activated_rule_versions(
    requested_rules: tuple[str, ...], *, current_rules: frozenset[RuleVersion]
) -> frozenset[RuleVersion]:
    requested = tuple(_parse_rule_version(value) for value in requested_rules)
    if len(requested) != len(set(requested)):
        ConfigurationError.fail("enabled rule ID and version selectors must be unique")
    approved = approved_rule_versions()
    unavailable = sorted(f"{item.rule_id}@{item.version}" for item in set(requested) - approved)
    if unavailable:
        ConfigurationError.fail(f"rules are not approved for activation: {', '.join(unavailable)}")
    obsolete = sorted(f"{item.rule_id}@{item.version}" for item in set(requested) - current_rules)
    if obsolete:
        ConfigurationError.fail(
            "enabled rule selectors are obsolete; use the current registry version: "
            + ", ".join(obsolete)
        )
    return frozenset(requested)


def _parse_rule_version(value: str) -> RuleVersion:
    rule_id, separator, version_text = value.rpartition("@")
    if not separator or not rule_id or not version_text.isascii() or not version_text.isdecimal():
        ConfigurationError.fail(
            f"enabled rules must use an exact rule-id@version selector: {value}"
        )
    version = int(version_text)
    if version < 1:
        ConfigurationError.fail(f"enabled rule versions must be positive: {value}")
    return RuleVersion(RuleId(rule_id), version)
