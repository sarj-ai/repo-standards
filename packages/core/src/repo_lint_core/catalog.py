"""Authoritative metadata for rules implemented by the neutral core engine."""

from __future__ import annotations

from .models import Rule, RuleId


_CORE_RULES = (
    Rule(
        rule_id=RuleId("core/layout/non-overlapping-root"),
        version=1,
        severity="error",
        summary="Component ownership roots are disjoint.",
        rationale="Overlapping roots make ownership and affected analysis ambiguous.",
        bad_example="component B is nested beneath component A",
        good_example="components A and B have disjoint roots",
    ),
    Rule(
        rule_id=RuleId("core/exception/expired"),
        version=1,
        severity="error",
        summary="Policy exceptions are narrow and unexpired.",
        rationale="Expired exceptions cannot silently become permanent policy holes.",
        bad_example="expires_on is before the analysis date",
        good_example="fix the finding or renew it through review",
    ),
    Rule(
        rule_id=RuleId("core/baseline/stale-entry"),
        version=1,
        severity="error",
        summary="Resolved debt is removed from the exact baseline.",
        rationale="Shrink-only baselines must lock in improvements.",
        bad_example="baseline contains a fingerprint no longer emitted",
        good_example="delete the resolved fingerprint in the same change",
    ),
)


def core_rules() -> tuple[Rule, ...]:
    """Return immutable metadata for every rule implemented by core."""
    return _CORE_RULES
