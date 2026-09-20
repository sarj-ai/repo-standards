from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from repo_standards.core.models import GitObjectId
from repo_standards.pull_request import (
    CheckConclusion,
    HumanReviewEvidence,
    RequiredCheckEvidence,
    ReviewPolicyConfig,
    ReviewPolicyEvidence,
    ReviewPolicyReason,
    ReviewState,
    evaluate_review_policy,
)


HEAD = GitObjectId("a" * 40)
OTHER_HEAD = GitObjectId("b" * 40)
PASSING_CHECKS = (RequiredCheckEvidence("test", CheckConclusion.SUCCESS),)
MIGRATION_ROOTS = (
    "products/platform/apps/web/migrations",
    "products/platform/datastores/clickhouse/migrations",
    "products/platform/datastores/kamailio/migrations",
    "products/platform/datastores/postgres/migrations",
    "python/integration/migrations",
)
PLATFORM_POLICY = ReviewPolicyConfig(migration_roots=MIGRATION_ROOTS)


def _evidence(  # ruff: ignore[too-many-arguments] - evidence dimensions are independently varied
    *,
    counted_lines: int = 0,
    changed_paths: tuple[str, ...] = ("README.md",),
    current_head_sha: GitObjectId | None = HEAD,
    required_checks: tuple[RequiredCheckEvidence, ...] | None = PASSING_CHECKS,
    latest_human_reviews: tuple[HumanReviewEvidence, ...] | None = (),
    threads_resolved: bool | None = True,
) -> ReviewPolicyEvidence:
    return ReviewPolicyEvidence(
        counted_lines=counted_lines,
        changed_paths=changed_paths,
        evaluated_head_sha=HEAD,
        current_head_sha=current_head_sha,
        required_checks=required_checks,
        latest_human_reviews=latest_human_reviews,
        threads_resolved=threads_resolved,
    )


def _approval(
    reviewer: str = "reviewer",
    *,
    commit_sha: GitObjectId | None = HEAD,
) -> HumanReviewEvidence:
    return HumanReviewEvidence(reviewer, ReviewState.APPROVED, commit_sha)


@pytest.mark.parametrize(
    ("lines", "required", "reason"),
    [
        (0, 0, ReviewPolicyReason.ZERO_REVIEW_THRESHOLD),
        (199, 0, ReviewPolicyReason.ZERO_REVIEW_THRESHOLD),
        (200, 1, ReviewPolicyReason.ONE_REVIEW_THRESHOLD),
        (800, 1, ReviewPolicyReason.ONE_REVIEW_THRESHOLD),
        (801, 2, ReviewPolicyReason.TWO_REVIEW_THRESHOLD),
    ],
)
def test_exact_line_thresholds(lines: int, required: int, reason: ReviewPolicyReason) -> None:
    reviews = tuple(_approval(str(index)) for index in range(required))

    result = evaluate_review_policy(_evidence(counted_lines=lines, latest_human_reviews=reviews))

    assert result.required_human_reviews == required
    assert result.current_human_approvals == required
    assert result.merge_ready
    assert result.reasons[0] is reason


@pytest.mark.parametrize(
    "path",
    [
        "products/platform/apps/web/migrations/0001.sql",
        "products/platform/datastores/clickhouse/migrations/0001.sql",
        "products/platform/datastores/kamailio/migrations/0001.sql",
        "products/platform/datastores/postgres/migrations/0001.sql",
        "python/integration/migrations/0001.sql",
    ],
)
def test_migration_roots_raise_zero_review_change_to_one(path: str) -> None:
    result = evaluate_review_policy(
        _evidence(changed_paths=(path,), latest_human_reviews=(_approval(),)),
        PLATFORM_POLICY,
    )

    assert result.required_human_reviews == 1
    assert result.touches_migration
    assert result.merge_ready
    assert ReviewPolicyReason.MIGRATION_REVIEW_FLOOR in result.reasons


def test_migration_floor_does_not_lower_or_raise_larger_thresholds() -> None:
    path = "products/platform/datastores/postgres/migrations/0001.sql"
    result = evaluate_review_policy(
        _evidence(
            counted_lines=801,
            changed_paths=(path,),
            latest_human_reviews=(_approval("one"), _approval("two")),
        ),
        PLATFORM_POLICY,
    )

    assert result.required_human_reviews == 2
    assert ReviewPolicyReason.MIGRATION_REVIEW_FLOOR not in result.reasons


def test_migration_root_requires_a_path_boundary() -> None:
    result = evaluate_review_policy(
        _evidence(changed_paths=("python/integration/migrations-old/0001.sql",)),
        PLATFORM_POLICY,
    )

    assert not result.touches_migration
    assert result.merge_ready


@pytest.mark.parametrize(
    ("checks", "reason"),
    [
        (None, ReviewPolicyReason.CHECK_EVIDENCE_MISSING),
        (
            (
                RequiredCheckEvidence("same", CheckConclusion.SUCCESS),
                RequiredCheckEvidence("same", CheckConclusion.SUCCESS),
            ),
            ReviewPolicyReason.CHECK_EVIDENCE_AMBIGUOUS,
        ),
        (
            (RequiredCheckEvidence("test", CheckConclusion.MISSING),),
            ReviewPolicyReason.REQUIRED_CHECK_MISSING,
        ),
        (
            (RequiredCheckEvidence("test", CheckConclusion.PENDING),),
            ReviewPolicyReason.REQUIRED_CHECK_PENDING,
        ),
        (
            (RequiredCheckEvidence("test", CheckConclusion.FAILURE),),
            ReviewPolicyReason.REQUIRED_CHECK_FAILED,
        ),
        (
            (RequiredCheckEvidence("test", CheckConclusion.CANCELLED),),
            ReviewPolicyReason.REQUIRED_CHECK_FAILED,
        ),
    ],
)
def test_check_evidence_fails_closed(
    checks: tuple[RequiredCheckEvidence, ...] | None,
    reason: ReviewPolicyReason,
) -> None:
    result = evaluate_review_policy(_evidence(required_checks=checks))

    assert not result.merge_ready
    assert reason in result.reasons


def test_only_success_is_accepted_by_default() -> None:
    result = evaluate_review_policy(
        _evidence(required_checks=(RequiredCheckEvidence("test", CheckConclusion.NEUTRAL),))
    )

    assert not result.merge_ready
    assert ReviewPolicyReason.REQUIRED_CHECK_FAILED in result.reasons


@pytest.mark.parametrize("conclusion", [CheckConclusion.NEUTRAL, CheckConclusion.SKIPPED])
def test_policy_can_explicitly_accept_other_github_passing_states(
    conclusion: CheckConclusion,
) -> None:
    policy = ReviewPolicyConfig(
        accepted_check_conclusions=frozenset({CheckConclusion.SUCCESS, conclusion})
    )

    result = evaluate_review_policy(
        _evidence(required_checks=(RequiredCheckEvidence("test", conclusion),)),
        policy,
    )

    assert result.merge_ready


@pytest.mark.parametrize(
    ("reviews", "reason"),
    [
        (None, ReviewPolicyReason.REVIEW_EVIDENCE_MISSING),
        (
            (_approval("same"), _approval("SAME")),
            ReviewPolicyReason.REVIEW_EVIDENCE_AMBIGUOUS,
        ),
        ((_approval(commit_sha=OTHER_HEAD),), ReviewPolicyReason.STALE_APPROVAL),
        (
            (HumanReviewEvidence("reviewer", ReviewState.CHANGES_REQUESTED, HEAD),),
            ReviewPolicyReason.CHANGES_REQUESTED,
        ),
    ],
)
def test_review_evidence_fails_closed(
    reviews: tuple[HumanReviewEvidence, ...] | None,
    reason: ReviewPolicyReason,
) -> None:
    result = evaluate_review_policy(_evidence(latest_human_reviews=reviews))

    assert not result.merge_ready
    assert reason in result.reasons


def test_insufficient_exact_head_approvals_fail_closed() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=801, latest_human_reviews=(_approval(),))
    )

    assert result.current_human_approvals == 1
    assert not result.merge_ready
    assert ReviewPolicyReason.APPROVALS_MISSING in result.reasons


@pytest.mark.parametrize(
    ("current_head", "reason"),
    [
        (None, ReviewPolicyReason.HEAD_EVIDENCE_MISSING),
        (OTHER_HEAD, ReviewPolicyReason.HEAD_MISMATCH),
    ],
)
def test_head_evidence_fails_closed(
    current_head: GitObjectId | None,
    reason: ReviewPolicyReason,
) -> None:
    result = evaluate_review_policy(
        _evidence(current_head_sha=current_head, latest_human_reviews=(_approval(),))
    )

    assert result.current_human_approvals == 0
    assert not result.merge_ready
    assert reason in result.reasons


@pytest.mark.parametrize(
    ("threads_resolved", "reason"),
    [
        (None, ReviewPolicyReason.THREAD_EVIDENCE_MISSING),
        (False, ReviewPolicyReason.THREADS_UNRESOLVED),
    ],
)
def test_thread_evidence_fails_closed(
    threads_resolved: bool | None,
    reason: ReviewPolicyReason,
) -> None:
    result = evaluate_review_policy(_evidence(threads_resolved=threads_resolved))

    assert not result.merge_ready
    assert reason in result.reasons


def test_zero_review_lane_still_blocks_a_change_request() -> None:
    review = HumanReviewEvidence("reviewer", ReviewState.CHANGES_REQUESTED, HEAD)

    result = evaluate_review_policy(_evidence(latest_human_reviews=(review,)))

    assert result.required_human_reviews == 0
    assert not result.merge_ready
    assert ReviewPolicyReason.CHANGES_REQUESTED in result.reasons


def test_missing_evidence_accumulates_stable_reason_codes() -> None:
    result = evaluate_review_policy(
        _evidence(
            counted_lines=200,
            current_head_sha=None,
            required_checks=None,
            latest_human_reviews=None,
            threads_resolved=None,
        )
    )

    assert result.reasons == (
        ReviewPolicyReason.ONE_REVIEW_THRESHOLD,
        ReviewPolicyReason.HEAD_EVIDENCE_MISSING,
        ReviewPolicyReason.CHECK_EVIDENCE_MISSING,
        ReviewPolicyReason.REVIEW_EVIDENCE_MISSING,
        ReviewPolicyReason.THREAD_EVIDENCE_MISSING,
    )
    assert not result.merge_ready


def test_evidence_and_result_are_frozen() -> None:
    evidence = _evidence()
    result = evaluate_review_policy(evidence)

    with pytest.raises(FrozenInstanceError):
        evidence.counted_lines = 1  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(FrozenInstanceError):
        result.merge_ready = False  # pyright: ignore[reportAttributeAccessIssue]


def test_invalid_scalar_and_path_inputs_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        _evidence(counted_lines=-1)
    with pytest.raises(ValueError, match="normalized"):
        _evidence(changed_paths=("/absolute",))
    with pytest.raises(ValueError, match="unique"):
        _evidence(changed_paths=("same", "same"))
    with pytest.raises(ValueError, match="check name"):
        RequiredCheckEvidence(" bad ", CheckConclusion.SUCCESS)
    with pytest.raises(ValueError, match="reviewer"):
        HumanReviewEvidence("", ReviewState.APPROVED, HEAD)
    with pytest.raises(ValueError, match="object ID"):
        _evidence(current_head_sha=GitObjectId("short"))
    with pytest.raises(ValueError, match="object ID"):
        HumanReviewEvidence("reviewer", ReviewState.APPROVED, GitObjectId("short"))


def test_thresholds_and_migration_floor_are_configurable() -> None:
    policy = ReviewPolicyConfig(
        zero_review_below_lines=10,
        one_review_maximum_lines=20,
        migration_review_floor=2,
        migration_roots=("db/migrations",),
    )
    result = evaluate_review_policy(
        _evidence(
            counted_lines=1,
            changed_paths=("db/migrations/001.sql",),
            latest_human_reviews=(_approval("one"), _approval("two")),
        ),
        policy,
    )

    assert result.required_human_reviews == 2
    assert result.merge_ready


def test_invalid_policy_is_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        ReviewPolicyConfig(zero_review_below_lines=0)
    with pytest.raises(ValueError, match="one-review maximum"):
        ReviewPolicyConfig(zero_review_below_lines=200, one_review_maximum_lines=199)
    with pytest.raises(ValueError, match="accepted check conclusions"):
        ReviewPolicyConfig(accepted_check_conclusions=frozenset())
    with pytest.raises(ValueError, match="accepted check conclusions"):
        ReviewPolicyConfig(
            accepted_check_conclusions=frozenset({CheckConclusion.FAILURE})
        )
