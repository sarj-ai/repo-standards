from __future__ import annotations

import pytest

from repo_standards.core import rule_reviews
from repo_standards.core.models import RuleId
from repo_standards.core.rule_reviews import (
    ApprovedRuleReview,
    PendingRuleReview,
    RuleVersion,
    activated_rule_ids,
    activated_rule_versions,
    approved_rule_versions,
    review_for,
)
from repo_standards.policy_sarj import SarjPolicy


def test_only_reviewed_rule_versions_are_available_for_explicit_activation() -> None:
    implementation_review = ApprovedRuleReview(
        reviewed_in="8080480deab8e7f8573f0338bb840f4e0aff28f4"
    )
    terraform_test_review = ApprovedRuleReview(
        reviewed_in="0e124af8dde6016278bda7db96bd6b9b1bc12a76"
    )
    package_ownership_review = ApprovedRuleReview(
        reviewed_in="6a52b0723886f591c733edc6ca2836cbedffc7ee"
    )
    root_verifier_review = ApprovedRuleReview(
        reviewed_in="319d3ee27278f2b915ee7fb063592298a8b49485"
    )
    assert approved_rule_versions() == frozenset(
        {
            RuleVersion(RuleId("repository/artifacts/bespoke-iac-verifiers"), 3),
            RuleVersion(RuleId("repository/artifacts/bespoke-iac-verifiers"), 4),
            RuleVersion(RuleId("repository/artifacts/bespoke-iac-verifiers"), 5),
            RuleVersion(RuleId("repository/artifacts/operational-script-tests"), 1),
            RuleVersion(RuleId("repository/artifacts/schema-derived-config-examples"), 2),
            RuleVersion(RuleId("repository/artifacts/terraform-test-files"), 1),
            RuleVersion(RuleId("repository/documentation/placement"), 2),
            RuleVersion(RuleId("repository/documentation/placement"), 3),
        }
    )
    assert (
        review_for(RuleId("repository/artifacts/terraform-test-files"), 1) == terraform_test_review
    )
    for rule_id, version in (
        ("repository/artifacts/bespoke-iac-verifiers", 3),
        ("repository/artifacts/operational-script-tests", 1),
        ("repository/artifacts/schema-derived-config-examples", 2),
        ("repository/documentation/placement", 2),
    ):
        assert review_for(RuleId(rule_id), version) == implementation_review
    assert (
        review_for(RuleId("repository/artifacts/bespoke-iac-verifiers"), 4)
        == package_ownership_review
    )
    assert (
        review_for(RuleId("repository/documentation/placement"), 3)
        == package_ownership_review
    )
    assert (
        review_for(RuleId("repository/artifacts/bespoke-iac-verifiers"), 5)
        == root_verifier_review
    )
    assert review_for(RuleId("core/layout/non-overlapping-root"), 1) == PendingRuleReview()


def test_every_approved_rule_id_exists_in_the_current_registry() -> None:
    current_rule_ids = frozenset(rule.rule_id for rule in SarjPolicy.rules())

    assert {item.rule_id for item in approved_rule_versions()} <= current_rule_ids


def _current_rule_versions() -> frozenset[RuleVersion]:
    return frozenset(RuleVersion(rule.rule_id, rule.version) for rule in SarjPolicy.rules())


def test_historical_reviews_remain_auditable_but_obsolete_selectors_are_rejected() -> None:
    old_selectors = (
        "repository/artifacts/bespoke-iac-verifiers@3",
        "repository/documentation/placement@2",
    )
    assert all(
        review_for(item.rule_id, item.version).status == "approved"
        for item in approved_rule_versions()
    )
    with pytest.raises(ValueError, match="selectors are obsolete"):
        activated_rule_versions(old_selectors, current_rules=_current_rule_versions())
    obsolete_selectors = (
        "repository/artifacts/bespoke-iac-verifiers@4",
        "repository/documentation/placement@3",
    )
    with pytest.raises(ValueError, match="selectors are obsolete"):
        activated_rule_versions(obsolete_selectors, current_rules=_current_rule_versions())
    current_selectors = (
        "repository/artifacts/bespoke-iac-verifiers@5",
        "repository/documentation/placement@3",
    )
    assert activated_rule_versions(
        current_selectors, current_rules=_current_rule_versions()
    ) == frozenset(
        {
            RuleVersion(RuleId("repository/artifacts/bespoke-iac-verifiers"), 5),
            RuleVersion(RuleId("repository/documentation/placement"), 3),
        }
    )


def test_approved_review_requires_immutable_review_reference() -> None:
    with pytest.raises(ValueError, match="immutable 40- or 64-character object ID"):
        ApprovedRuleReview(reviewed_in="")
    with pytest.raises(ValueError, match="immutable 40- or 64-character object ID"):
        ApprovedRuleReview(reviewed_in="release/1")


def test_activation_is_explicit_and_version_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    rule_id = RuleId("architecture/dependencies/policy")
    approval = ApprovedRuleReview(reviewed_in="a" * 40)
    monkeypatch.setattr(rule_reviews, "APPROVED_RULE_REVIEWS", ((rule_id, 1, approval),))

    current_rules = frozenset({RuleVersion(rule_id, 1)})
    assert activated_rule_versions((), current_rules=current_rules) == frozenset()
    selector = f"{rule_id}@1"
    assert activated_rule_versions((selector,), current_rules=current_rules) == current_rules
    with pytest.raises(ValueError, match="not approved for activation"):
        activated_rule_versions((f"{rule_id}@2",), current_rules=current_rules)
    assert review_for(rule_id, 2) == PendingRuleReview()


def test_manifest_activation_selects_only_the_current_approved_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule_id = RuleId("architecture/dependencies/policy")
    approval = ApprovedRuleReview(reviewed_in="a" * 40)
    monkeypatch.setattr(rule_reviews, "APPROVED_RULE_REVIEWS", ((rule_id, 2, approval),))
    current = frozenset({RuleVersion(rule_id, 2)})

    assert activated_rule_ids((str(rule_id),), current_rules=current) == current
    with pytest.raises(ValueError, match="versionless rule IDs"):
        activated_rule_ids((f"{rule_id}@2",), current_rules=current)


@pytest.mark.parametrize(
    "selector",
    ["architecture/dependencies/policy", "architecture/dependencies/policy@0", "@1"],
)
def test_activation_rejects_selectors_without_an_exact_positive_version(selector: str) -> None:
    with pytest.raises(ValueError, match=r"exact rule-id@version|versions must be positive"):
        activated_rule_versions((selector,), current_rules=frozenset())


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
