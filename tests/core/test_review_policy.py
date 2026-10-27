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
    ReviewPolicyResult,
    ReviewState,
    SinceReviewEvidence,
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
    author_is_bot: bool = False,
) -> ReviewPolicyEvidence:
    return ReviewPolicyEvidence(
        counted_lines=counted_lines,
        changed_paths=changed_paths,
        evaluated_head_sha=HEAD,
        current_head_sha=current_head_sha,
        required_checks=required_checks,
        latest_human_reviews=latest_human_reviews,
        threads_resolved=threads_resolved,
        author_is_bot=author_is_bot,
    )


@pytest.mark.parametrize("lines", [0.5, float("nan"), float("inf")])
def test_fractional_or_nonfinite_line_counts_are_rejected(lines: float) -> None:
    with pytest.raises(ValueError, match="integer"):
        _evidence(counted_lines=lines)  # pyright: ignore[reportArgumentType] -- exercise runtime refusal of non-integer input.
    with pytest.raises(ValueError, match="integer"):
        SinceReviewEvidence(counted_lines=lines, changed_paths=())  # pyright: ignore[reportArgumentType] -- exercise runtime refusal of non-integer input.
    with pytest.raises(ValueError, match="integer"):
        ReviewPolicyConfig(zero_review_below_lines=lines)  # pyright: ignore[reportArgumentType] -- exercise runtime refusal of non-integer input.
    with pytest.raises(ValueError, match="one-review maximum"):
        ReviewPolicyConfig(one_review_maximum_lines=lines)  # pyright: ignore[reportArgumentType] -- exercise runtime refusal of non-integer input.


@pytest.mark.parametrize("floor", [True, 1.0])
def test_migration_review_floor_requires_an_actual_integer(floor: bool | float) -> None:
    with pytest.raises(ValueError, match="migration review floor"):
        ReviewPolicyConfig(migration_review_floor=floor)  # pyright: ignore[reportArgumentType] -- exercise runtime refusal of invalid review counts.


@pytest.mark.parametrize("floor", [True, 3])
def test_author_review_floor_requires_a_review_count(floor: bool | int) -> None:
    with pytest.raises(ValueError, match="author review floor"):
        ReviewPolicyConfig(author_review_floor=floor)  # pyright: ignore[reportArgumentType] -- exercise runtime refusal of invalid review counts.


@pytest.mark.parametrize(
    "path", ["db/../other", "./db", "db/./001.sql", "db\\001.sql", "db/\x00.sql"]
)
def test_review_paths_must_be_canonical_before_migration_matching(path: str) -> None:
    with pytest.raises(ValueError, match="normalized"):
        _evidence(changed_paths=(path,))
    with pytest.raises(ValueError, match="normalized"):
        SinceReviewEvidence(counted_lines=0, changed_paths=(path,))
    with pytest.raises(ValueError, match="normalized"):
        ReviewPolicyConfig(migration_roots=(path,))


def _approval(
    reviewer: str = "reviewer",
    *,
    commit_sha: GitObjectId | None = HEAD,
    since_review: SinceReviewEvidence | None = None,
    allowlisted_bot: bool = False,
) -> HumanReviewEvidence:
    return HumanReviewEvidence(
        reviewer, ReviewState.APPROVED, commit_sha, since_review, allowlisted_bot=allowlisted_bot
    )


def _bot_approval(reviewer: str = "bulbul-review[bot]") -> HumanReviewEvidence:
    return _approval(reviewer, allowlisted_bot=True)


def _earlier_approval(
    lines: int,
    paths: tuple[str, ...] = ("README.md",),
    reviewer: str = "reviewer",
    *,
    allowlisted_bot: bool = False,
) -> HumanReviewEvidence:
    return _approval(
        reviewer,
        commit_sha=OTHER_HEAD,
        since_review=SinceReviewEvidence(counted_lines=lines, changed_paths=paths),
        allowlisted_bot=allowlisted_bot,
    )


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


def test_stale_approval_is_reported_without_blocking() -> None:
    reviews = (_approval("early", commit_sha=OTHER_HEAD), _approval("a"), _approval("b"))

    result = evaluate_review_policy(_evidence(counted_lines=801, latest_human_reviews=reviews))

    assert result.current_human_approvals == 2
    assert result.merge_ready
    assert ReviewPolicyReason.STALE_APPROVAL in result.reasons


def test_stale_approval_does_not_count_toward_required_reviews() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=200, latest_human_reviews=(_approval(commit_sha=OTHER_HEAD),))
    )

    assert result.current_human_approvals == 0
    assert not result.merge_ready
    assert ReviewPolicyReason.APPROVALS_MISSING in result.reasons


@pytest.mark.parametrize("lines", [0, 200, 800])
def test_approval_carries_forward_up_to_two_review_threshold(lines: int) -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=800, latest_human_reviews=(_earlier_approval(lines),))
    )

    assert result.current_human_approvals == 1
    assert result.merge_ready
    assert ReviewPolicyReason.APPROVAL_CARRIED_FORWARD in result.reasons
    assert ReviewPolicyReason.STALE_APPROVAL not in result.reasons


def test_approval_goes_stale_above_two_review_threshold() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=801, latest_human_reviews=(_earlier_approval(801),))
    )

    assert result.current_human_approvals == 0
    assert not result.merge_ready
    assert ReviewPolicyReason.STALE_APPROVAL in result.reasons
    assert ReviewPolicyReason.APPROVAL_CARRIED_FORWARD not in result.reasons


@pytest.mark.parametrize(("lines", "carried"), [(20, True), (21, False)])
def test_carry_forward_follows_configured_two_review_threshold(
    *, lines: int, carried: bool
) -> None:
    policy = ReviewPolicyConfig(zero_review_below_lines=10, one_review_maximum_lines=20)

    result = evaluate_review_policy(
        _evidence(counted_lines=20, latest_human_reviews=(_earlier_approval(lines),)),
        policy,
    )

    assert result.merge_ready is carried
    assert (ReviewPolicyReason.STALE_APPROVAL in result.reasons) is not carried


def test_migration_change_since_review_does_not_carry_forward() -> None:
    since_paths = ("products/platform/datastores/postgres/migrations/0002.sql",)

    result = evaluate_review_policy(
        _evidence(
            counted_lines=500,
            latest_human_reviews=(_earlier_approval(1, since_paths),),
        ),
        PLATFORM_POLICY,
    )

    assert result.current_human_approvals == 0
    assert not result.merge_ready
    assert ReviewPolicyReason.STALE_APPROVAL in result.reasons


def test_unmeasured_change_since_review_does_not_carry_forward() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=500, latest_human_reviews=(_approval(commit_sha=OTHER_HEAD),))
    )

    assert result.current_human_approvals == 0
    assert not result.merge_ready
    assert ReviewPolicyReason.APPROVAL_CARRIED_FORWARD not in result.reasons


def test_carried_and_exact_approvals_together_meet_two_review_tier() -> None:
    result = evaluate_review_policy(
        _evidence(
            counted_lines=801,
            latest_human_reviews=(_earlier_approval(5, reviewer="early"), _approval("late")),
        )
    )

    assert result.current_human_approvals == 2
    assert result.carried_forward_reviewers == ("early",)
    assert result.merge_ready


def test_head_mismatch_never_carries_an_approval_forward() -> None:
    result = evaluate_review_policy(
        _evidence(
            counted_lines=500,
            current_head_sha=OTHER_HEAD,
            latest_human_reviews=(_earlier_approval(0),),
        )
    )

    assert result.current_human_approvals == 0
    assert ReviewPolicyReason.APPROVAL_CARRIED_FORWARD not in result.reasons


def test_carried_approval_does_not_clear_a_change_request() -> None:
    reviews = (
        _earlier_approval(0, reviewer="early"),
        HumanReviewEvidence("blocker", ReviewState.CHANGES_REQUESTED, OTHER_HEAD),
    )

    result = evaluate_review_policy(_evidence(counted_lines=500, latest_human_reviews=reviews))

    assert result.current_human_approvals == 1
    assert not result.merge_ready
    assert ReviewPolicyReason.CHANGES_REQUESTED in result.reasons


def test_insufficient_exact_head_approvals_fail_closed() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=801, latest_human_reviews=(_approval(),))
    )

    assert result.current_human_approvals == 1
    assert not result.merge_ready
    assert ReviewPolicyReason.APPROVALS_MISSING in result.reasons


def test_allowlisted_bot_approval_meets_one_review_tier() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=500, latest_human_reviews=(_bot_approval(),))
    )

    assert result.merge_ready
    assert result.current_human_approvals == 0
    assert result.allowlisted_bot_approvers == ("bulbul-review[bot]",)


def test_allowlisted_bot_approval_never_counts_on_bot_authored_pull_request() -> None:
    result = evaluate_review_policy(
        _evidence(counted_lines=500, latest_human_reviews=(_bot_approval(),), author_is_bot=True)
    )

    assert not result.merge_ready
    assert result.allowlisted_bot_approvers == ()
    assert ReviewPolicyReason.ALLOWLISTED_BOT_APPROVAL_NOT_COUNTED in result.reasons
    assert ReviewPolicyReason.APPROVALS_MISSING in result.reasons


def test_only_one_allowlisted_bot_approval_counts() -> None:
    reviews = (_bot_approval("first[bot]"), _bot_approval("second[bot]"))

    result = evaluate_review_policy(_evidence(counted_lines=801, latest_human_reviews=reviews))

    assert not result.merge_ready
    assert result.allowlisted_bot_approvers == ("first[bot]",)
    assert ReviewPolicyReason.ALLOWLISTED_BOT_APPROVAL_NOT_COUNTED in result.reasons
    assert ReviewPolicyReason.APPROVALS_MISSING in result.reasons


@pytest.mark.parametrize(("human_approvals", "merge_ready"), [(0, False), (1, True)])
def test_two_review_tier_needs_a_human_beside_a_allowlisted_bot(
    *, human_approvals: int, merge_ready: bool
) -> None:
    reviews = (_bot_approval(), *(_approval(f"human-{index}") for index in range(human_approvals)))

    result = evaluate_review_policy(_evidence(counted_lines=801, latest_human_reviews=reviews))

    assert result.required_human_reviews == 2
    assert result.merge_ready is merge_ready
    assert result.current_human_approvals == human_approvals
    assert result.allowlisted_bot_approvers == ("bulbul-review[bot]",)
    assert (ReviewPolicyReason.APPROVALS_MISSING in result.reasons) is not merge_ready


@pytest.mark.parametrize(("lines_since_review", "approvals"), [(5, 1), (801, 0)])
def test_earlier_allowlisted_bot_approval_follows_human_carry_forward_rules(
    *, lines_since_review: int, approvals: int
) -> None:
    def evaluate(*, allowlisted_bot: bool) -> ReviewPolicyResult:
        review = _earlier_approval(lines_since_review, allowlisted_bot=allowlisted_bot)
        return evaluate_review_policy(_evidence(counted_lines=500, latest_human_reviews=(review,)))

    human = evaluate(allowlisted_bot=False)
    bot = evaluate(allowlisted_bot=True)

    assert bot.reasons == human.reasons
    assert bot.merge_ready is human.merge_ready is (approvals == 1)
    assert bot.carried_forward_reviewers == human.carried_forward_reviewers
    assert human.current_human_approvals == len(bot.allowlisted_bot_approvers) == approvals
    assert bot.current_human_approvals == 0


def test_allowlisted_bot_change_request_blocks_like_a_human_one() -> None:
    reviews = (
        _approval("human"),
        HumanReviewEvidence(
            "bulbul-review[bot]", ReviewState.CHANGES_REQUESTED, HEAD, allowlisted_bot=True
        ),
    )

    result = evaluate_review_policy(_evidence(counted_lines=500, latest_human_reviews=reviews))

    assert not result.merge_ready
    assert ReviewPolicyReason.CHANGES_REQUESTED in result.reasons


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


@pytest.mark.parametrize("threads_resolved", [None, False])
def test_thread_evidence_is_ignored_when_resolution_is_not_required(
    threads_resolved: bool | None,
) -> None:
    result = evaluate_review_policy(
        _evidence(threads_resolved=threads_resolved),
        ReviewPolicyConfig(require_resolved_threads=False),
    )

    assert result.merge_ready
    assert ReviewPolicyReason.THREAD_EVIDENCE_MISSING not in result.reasons
    assert ReviewPolicyReason.THREADS_UNRESOLVED not in result.reasons


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
        evidence.counted_lines = 1  # pyright: ignore[reportAttributeAccessIssue] -- exercise runtime refusal to mutate frozen evidence.
    with pytest.raises(FrozenInstanceError):
        result.merge_ready = False  # pyright: ignore[reportAttributeAccessIssue] -- exercise runtime refusal to mutate a frozen result.


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
    with pytest.raises(ValueError, match="since review"):
        SinceReviewEvidence(counted_lines=-1, changed_paths=())
    with pytest.raises(ValueError, match="since review"):
        SinceReviewEvidence(counted_lines=0, changed_paths=("/absolute",))


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
        ReviewPolicyConfig(accepted_check_conclusions=frozenset({CheckConclusion.FAILURE}))
