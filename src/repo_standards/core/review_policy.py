from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Literal

from .models import GitObjectId


ZERO_REVIEW_BELOW_LINES = 200
ONE_REVIEW_MAXIMUM_LINES = 800
MIGRATION_REVIEW_FLOOR = 1

RequiredReviewCount = Literal[0, 1, 2]
_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")


class CheckConclusion(StrEnum):
    """Closed states accepted from a required-check evidence adapter."""

    SUCCESS = "success"
    NEUTRAL = "neutral"
    SKIPPED = "skipped"
    PENDING = "pending"
    MISSING = "missing"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"


class ReviewState(StrEnum):
    """Latest effective state for one human reviewer."""

    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    COMMENTED = "commented"
    DISMISSED = "dismissed"


class ReviewPolicyReason(StrEnum):
    """Stable, machine-readable explanations emitted by the evaluator."""

    ZERO_REVIEW_THRESHOLD = "zero_review_threshold"
    ONE_REVIEW_THRESHOLD = "one_review_threshold"
    TWO_REVIEW_THRESHOLD = "two_review_threshold"
    MIGRATION_REVIEW_FLOOR = "migration_review_floor"
    HEAD_EVIDENCE_MISSING = "head_evidence_missing"
    HEAD_MISMATCH = "head_mismatch"
    CHECK_EVIDENCE_MISSING = "check_evidence_missing"
    CHECK_EVIDENCE_AMBIGUOUS = "check_evidence_ambiguous"
    REQUIRED_CHECK_MISSING = "required_check_missing"
    REQUIRED_CHECK_PENDING = "required_check_pending"
    REQUIRED_CHECK_FAILED = "required_check_failed"
    REVIEW_EVIDENCE_MISSING = "review_evidence_missing"
    REVIEW_EVIDENCE_AMBIGUOUS = "review_evidence_ambiguous"
    STALE_APPROVAL = "stale_approval"
    CHANGES_REQUESTED = "changes_requested"
    APPROVALS_MISSING = "approvals_missing"
    THREAD_EVIDENCE_MISSING = "thread_evidence_missing"
    THREADS_UNRESOLVED = "threads_unresolved"


@dataclass(frozen=True, slots=True)
class ReviewPolicyConfig:
    zero_review_below_lines: int = ZERO_REVIEW_BELOW_LINES
    one_review_maximum_lines: int = ONE_REVIEW_MAXIMUM_LINES
    migration_review_floor: RequiredReviewCount = MIGRATION_REVIEW_FLOOR
    migration_roots: tuple[str, ...] = ()
    accepted_check_conclusions: frozenset[CheckConclusion] = frozenset(
        {CheckConclusion.SUCCESS}
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.zero_review_below_lines, bool)
            or self.zero_review_below_lines <= 0
        ):
            message = "zero-review threshold must be a positive integer"
            raise ValueError(message)
        if (
            isinstance(self.one_review_maximum_lines, bool)
            or self.one_review_maximum_lines < self.zero_review_below_lines
        ):
            message = "one-review maximum must be at least the zero-review threshold"
            raise ValueError(message)
        if self.migration_review_floor not in {0, 1, 2}:
            message = "migration review floor must be 0, 1, or 2"
            raise ValueError(message)
        _validate_paths(self.migration_roots, "migration root")
        allowed = {
            CheckConclusion.SUCCESS,
            CheckConclusion.NEUTRAL,
            CheckConclusion.SKIPPED,
        }
        if not self.accepted_check_conclusions or not self.accepted_check_conclusions <= allowed:
            message = "accepted check conclusions must be a non-empty subset of passing states"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class RequiredCheckEvidence:
    name: str
    conclusion: CheckConclusion

    def __post_init__(self) -> None:
        if not self.name or self.name != self.name.strip():
            message = "required check name must be non-empty and stripped"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class HumanReviewEvidence:
    reviewer: str
    state: ReviewState
    commit_sha: GitObjectId | None

    def __post_init__(self) -> None:
        if not self.reviewer or self.reviewer != self.reviewer.strip():
            message = "reviewer must be non-empty and stripped"
            raise ValueError(message)
        if self.commit_sha is not None and _OBJECT_ID.fullmatch(self.commit_sha) is None:
            message = "review commit SHA must be a lowercase 40-character object ID"
            raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ReviewPolicyEvidence:
    counted_lines: int
    changed_paths: tuple[str, ...]
    evaluated_head_sha: GitObjectId
    current_head_sha: GitObjectId | None
    required_checks: tuple[RequiredCheckEvidence, ...] | None
    latest_human_reviews: tuple[HumanReviewEvidence, ...] | None
    threads_resolved: bool | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.counted_lines, bool)
            or self.counted_lines < 0
        ):
            message = "counted lines must be a non-negative integer"
            raise ValueError(message)
        if _OBJECT_ID.fullmatch(self.evaluated_head_sha) is None:
            message = "evaluated head SHA must be a lowercase 40-character object ID"
            raise ValueError(message)
        if (
            self.current_head_sha is not None
            and _OBJECT_ID.fullmatch(self.current_head_sha) is None
        ):
            message = "current head SHA must be a lowercase 40-character object ID"
            raise ValueError(message)
        _validate_paths(self.changed_paths, "changed path")


@dataclass(frozen=True, slots=True)
class ReviewPolicyResult:
    required_human_reviews: RequiredReviewCount
    current_human_approvals: int
    touches_migration: bool
    merge_ready: bool
    reasons: tuple[ReviewPolicyReason, ...]


def evaluate_review_policy(
    evidence: ReviewPolicyEvidence,
    config: ReviewPolicyConfig | None = None,
) -> ReviewPolicyResult:
    if config is None:
        config = ReviewPolicyConfig()
    reasons: list[ReviewPolicyReason] = []
    required_reviews = _line_threshold(evidence.counted_lines, config=config)
    reasons.append(_threshold_reason(required_reviews))

    touches_migration = _touches_migration(
        changed_paths=evidence.changed_paths,
        migration_roots=config.migration_roots,
    )
    if touches_migration and required_reviews < config.migration_review_floor:
        required_reviews = config.migration_review_floor
        reasons.append(ReviewPolicyReason.MIGRATION_REVIEW_FLOOR)

    head_matches = evidence.current_head_sha is not None and (
        evidence.current_head_sha == evidence.evaluated_head_sha
    )
    if evidence.current_head_sha is None:
        reasons.append(ReviewPolicyReason.HEAD_EVIDENCE_MISSING)
    elif not head_matches:
        reasons.append(ReviewPolicyReason.HEAD_MISMATCH)

    reasons.extend(
        _check_reasons(
            evidence.required_checks,
            accepted=config.accepted_check_conclusions,
        )
    )
    review_reasons, approvals = _review_reasons(
        evidence.latest_human_reviews,
        expected_head=evidence.evaluated_head_sha,
        required_reviews=required_reviews,
        head_matches=head_matches,
    )
    reasons.extend(review_reasons)

    if evidence.threads_resolved is None:
        reasons.append(ReviewPolicyReason.THREAD_EVIDENCE_MISSING)
    elif not evidence.threads_resolved:
        reasons.append(ReviewPolicyReason.THREADS_UNRESOLVED)

    blocking = frozenset(ReviewPolicyReason) - {
        ReviewPolicyReason.ZERO_REVIEW_THRESHOLD,
        ReviewPolicyReason.ONE_REVIEW_THRESHOLD,
        ReviewPolicyReason.TWO_REVIEW_THRESHOLD,
        ReviewPolicyReason.MIGRATION_REVIEW_FLOOR,
    }
    return ReviewPolicyResult(
        required_human_reviews=required_reviews,
        current_human_approvals=approvals,
        touches_migration=touches_migration,
        merge_ready=not any(reason in blocking for reason in reasons),
        reasons=tuple(reasons),
    )


def _validate_paths(paths: tuple[str, ...], kind: str) -> None:
    if len(paths) != len(set(paths)):
        message = f"{kind}s must be unique"
        raise ValueError(message)
    for path in paths:
        if not path or path != path.strip("/") or "//" in path:
            message = f"{kind} must be a normalized repository-relative path: {path!r}"
            raise ValueError(message)


def _line_threshold(
    counted_lines: int,
    *,
    config: ReviewPolicyConfig,
) -> RequiredReviewCount:
    if counted_lines < config.zero_review_below_lines:
        return 0
    if counted_lines <= config.one_review_maximum_lines:
        return 1
    return 2


def _threshold_reason(required_reviews: RequiredReviewCount) -> ReviewPolicyReason:
    return (
        ReviewPolicyReason.ZERO_REVIEW_THRESHOLD,
        ReviewPolicyReason.ONE_REVIEW_THRESHOLD,
        ReviewPolicyReason.TWO_REVIEW_THRESHOLD,
    )[required_reviews]


def _touches_migration(*, changed_paths: tuple[str, ...], migration_roots: tuple[str, ...]) -> bool:
    return any(
        path == root or path.startswith(f"{root}/")
        for path in changed_paths
        for root in migration_roots
    )


def _check_reasons(
    checks: tuple[RequiredCheckEvidence, ...] | None,
    *,
    accepted: frozenset[CheckConclusion],
) -> tuple[ReviewPolicyReason, ...]:
    if checks is None:
        return (ReviewPolicyReason.CHECK_EVIDENCE_MISSING,)
    names = tuple(check.name for check in checks)
    if len(names) != len(set(names)):
        return (ReviewPolicyReason.CHECK_EVIDENCE_AMBIGUOUS,)
    conclusions = {check.conclusion for check in checks}
    reasons: list[ReviewPolicyReason] = []
    if CheckConclusion.MISSING in conclusions:
        reasons.append(ReviewPolicyReason.REQUIRED_CHECK_MISSING)
    if CheckConclusion.PENDING in conclusions:
        reasons.append(ReviewPolicyReason.REQUIRED_CHECK_PENDING)
    if conclusions - accepted - {CheckConclusion.MISSING, CheckConclusion.PENDING}:
        reasons.append(ReviewPolicyReason.REQUIRED_CHECK_FAILED)
    return tuple(reasons)


def _review_reasons(
    reviews: tuple[HumanReviewEvidence, ...] | None,
    *,
    expected_head: GitObjectId,
    required_reviews: RequiredReviewCount,
    head_matches: bool,
) -> tuple[tuple[ReviewPolicyReason, ...], int]:
    if reviews is None:
        return (ReviewPolicyReason.REVIEW_EVIDENCE_MISSING,), 0
    reviewers = tuple(review.reviewer.casefold() for review in reviews)
    if len(reviewers) != len(set(reviewers)):
        return (ReviewPolicyReason.REVIEW_EVIDENCE_AMBIGUOUS,), 0

    stale_approval = any(
        review.state is ReviewState.APPROVED and review.commit_sha != expected_head
        for review in reviews
    )
    approvals = sum(
        review.state is ReviewState.APPROVED
        and review.commit_sha == expected_head
        and head_matches
        for review in reviews
    )
    reasons: list[ReviewPolicyReason] = []
    if stale_approval:
        reasons.append(ReviewPolicyReason.STALE_APPROVAL)
    if any(review.state is ReviewState.CHANGES_REQUESTED for review in reviews):
        reasons.append(ReviewPolicyReason.CHANGES_REQUESTED)
    if approvals < required_reviews:
        reasons.append(ReviewPolicyReason.APPROVALS_MISSING)
    return tuple(reasons), approvals
