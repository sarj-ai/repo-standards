from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
import re
from typing import Literal

from repo_standards.activation_verification import VerifiedActivation

from .canonical import canonical_path
from .description import DescriptionMetrics, analyze_description, without_bot_footer
from .errors import ConfigurationError
from .models import (
    DEFAULT_MAXIMUM_BODY_CHARACTERS,
    DEFAULT_MAXIMUM_PROSE_CHARACTERS,
    MAXIMUM_BODY_CHARACTERS,
    GitObjectId,
    MigrationCouplingException,
)
from .pull_request_size import is_test_path


ZERO_REVIEW_BELOW_LINES = 200
ONE_REVIEW_MAXIMUM_LINES = 800
MIGRATION_REVIEW_FLOOR = 1
ALLOWLISTED_BOT_APPROVAL_LIMIT = 1
MIGRATION_EXCEPTION_REVIEW_COUNT = 2

_MIGRATION_DISCOVERY_EXCLUSIONS = frozenset(
    {
        "testing",
        "fixture",
        "fixtures",
        "__fixtures__",
        "testdata",
        "example",
        "examples",
        "vendor",
        "node_modules",
        "generated",
    }
)

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
    AUTHOR_REVIEW_FLOOR = "author_review_floor"
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
    APPROVAL_CARRIED_FORWARD = "approval_carried_forward"
    ALLOWLISTED_BOT_APPROVAL_NOT_COUNTED = "allowlisted_bot_approval_not_counted"
    CHANGES_REQUESTED = "changes_requested"
    APPROVALS_MISSING = "approvals_missing"
    THREAD_EVIDENCE_MISSING = "thread_evidence_missing"
    THREADS_UNRESOLVED = "threads_unresolved"
    BODY_TOO_LONG = "body_too_long"
    BODY_PROSE_TOO_LONG = "body_prose_too_long"
    BODY_CODE_EXAMPLE_INVALID = "body_code_example_invalid"
    DOMAIN_REVIEW_FLOOR = "domain_review_floor"
    SENSITIVE_APPROVAL_MISSING = "sensitive_approval_missing"
    MIGRATION_CHANGES_MIXED = "migration_changes_mixed"
    MIGRATION_EXCEPTION_ACCEPTED = "migration_exception_accepted"


@dataclass(frozen=True, slots=True)
class ReviewPolicyConfig:
    zero_review_below_lines: int = ZERO_REVIEW_BELOW_LINES
    one_review_maximum_lines: int = ONE_REVIEW_MAXIMUM_LINES
    migration_review_floor: RequiredReviewCount = MIGRATION_REVIEW_FLOOR
    migration_roots: tuple[str, ...] = ()
    author_review_floor: RequiredReviewCount = 0
    verified_activation: VerifiedActivation | None = None
    accepted_check_conclusions: frozenset[CheckConclusion] = frozenset({CheckConclusion.SUCCESS})
    require_resolved_threads: bool = True
    maximum_body_characters: int = DEFAULT_MAXIMUM_BODY_CHARACTERS
    domain_roots: tuple[str, ...] = ("domain", "domains")
    maximum_prose_characters: int = DEFAULT_MAXIMUM_PROSE_CHARACTERS

    def __post_init__(self) -> None:
        if type(self.zero_review_below_lines) is not int or self.zero_review_below_lines <= 0:
            message = "zero-review threshold must be a positive integer"
            raise ValueError(message)
        if (
            type(self.one_review_maximum_lines) is not int
            or self.one_review_maximum_lines < self.zero_review_below_lines
        ):
            message = "one-review maximum must be at least the zero-review threshold"
            raise ValueError(message)
        for name, floor in (
            ("migration", self.migration_review_floor),
            ("author", self.author_review_floor),
        ):
            if type(floor) is not int or floor not in {0, 1, 2}:
                message = f"{name} review floor must be 0, 1, or 2"
                raise ValueError(message)
        for kind, roots in (
            ("migration", self.migration_roots),
            ("domain", self.domain_roots),
        ):
            _validate_paths(roots, f"{kind} root")
            if any("*" in root or "?" in root for root in roots):
                message = f"{kind} roots must be exact repository paths"
                raise ValueError(message)
        for label, maximum in (
            ("maximum body characters", self.maximum_body_characters),
            ("maximum prose characters", self.maximum_prose_characters),
        ):
            if type(maximum) is not int or not 1 <= maximum <= MAXIMUM_BODY_CHARACTERS:
                message = f"{label} must be an integer between 1 and 10000"
                raise ValueError(message)
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
class SinceReviewEvidence:
    counted_lines: int
    changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.counted_lines) is not int or self.counted_lines < 0:
            message = "counted lines since review must be a non-negative integer"
            raise ValueError(message)
        _validate_paths(self.changed_paths, "changed path since review")


@dataclass(frozen=True, slots=True)
class HumanReviewEvidence:
    reviewer: str
    state: ReviewState
    commit_sha: GitObjectId | None
    since_review: SinceReviewEvidence | None = None
    allowlisted_bot: bool = False

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
    author_is_bot: bool = False
    body: str = ""
    migration_exception: MigrationCouplingException | None = None

    def __post_init__(self) -> None:
        if type(self.counted_lines) is not int or self.counted_lines < 0:
            message = "counted lines must be a non-negative integer"
            raise ValueError(message)
        if type(self.body) is not str:
            message = "pull request body must be a string"
            raise TypeError(message)
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
        if self.migration_exception is not None:
            _validate_paths(self.migration_exception.paths, "migration exception path")
            if (
                not self.migration_exception.reason.strip()
                or not self.migration_exception.alternatives.strip()
            ):
                message = "migration exception requires a reason and alternatives considered"
                raise ValueError(message)


@dataclass(frozen=True, slots=True)
class ReviewPolicyResult:
    required_human_reviews: RequiredReviewCount
    current_human_approvals: int
    touches_migration: bool
    merge_ready: bool
    reasons: tuple[ReviewPolicyReason, ...]
    carried_forward_reviewers: tuple[str, ...] = ()
    allowlisted_bot_approvers: tuple[str, ...] = ()
    touches_domain: bool = False
    migration_coupled_paths: tuple[str, ...] = ()
    migration_exception_accepted: bool = False
    description: DescriptionMetrics | None = None


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
    touches_domain = any(_under_roots(path, config.domain_roots) for path in evidence.changed_paths)
    if touches_domain and required_reviews < 1:
        required_reviews = 1
        reasons.append(ReviewPolicyReason.DOMAIN_REVIEW_FLOOR)
    coupled_paths = migration_coupled_paths(evidence.changed_paths, config.migration_roots)
    if coupled_paths:
        required_reviews = 2
    if required_reviews < config.author_review_floor:
        required_reviews = config.author_review_floor
        reasons.append(ReviewPolicyReason.AUTHOR_REVIEW_FLOOR)

    if _verified_activation(evidence, config):
        required_reviews = 0

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
    review_assessment = _review_reasons(
        evidence,
        required_reviews=required_reviews,
        head_matches=head_matches,
        config=config,
    )
    reasons.extend(review_assessment.reasons)
    reasons.extend(_focus_reasons(evidence, config))

    body = without_bot_footer(evidence.body)
    description = analyze_description(body) if len(body) <= config.maximum_body_characters else None
    reasons.extend(
        description_reasons(description, maximum_prose_characters=config.maximum_prose_characters)
    )

    if config.require_resolved_threads:
        if evidence.threads_resolved is None:
            reasons.append(ReviewPolicyReason.THREAD_EVIDENCE_MISSING)
        elif not evidence.threads_resolved:
            reasons.append(ReviewPolicyReason.THREADS_UNRESOLVED)

    blocking = frozenset(ReviewPolicyReason) - {
        ReviewPolicyReason.ZERO_REVIEW_THRESHOLD,
        ReviewPolicyReason.ONE_REVIEW_THRESHOLD,
        ReviewPolicyReason.TWO_REVIEW_THRESHOLD,
        ReviewPolicyReason.MIGRATION_REVIEW_FLOOR,
        ReviewPolicyReason.AUTHOR_REVIEW_FLOOR,
        ReviewPolicyReason.STALE_APPROVAL,
        ReviewPolicyReason.APPROVAL_CARRIED_FORWARD,
        ReviewPolicyReason.ALLOWLISTED_BOT_APPROVAL_NOT_COUNTED,
        ReviewPolicyReason.DOMAIN_REVIEW_FLOOR,
        ReviewPolicyReason.MIGRATION_EXCEPTION_ACCEPTED,
    }
    return ReviewPolicyResult(
        required_human_reviews=required_reviews,
        current_human_approvals=review_assessment.human_approvals,
        touches_migration=touches_migration,
        merge_ready=not any(reason in blocking for reason in reasons),
        reasons=tuple(reasons),
        carried_forward_reviewers=review_assessment.carried_forward_reviewers,
        allowlisted_bot_approvers=review_assessment.allowlisted_bot_approvers,
        touches_domain=touches_domain,
        migration_coupled_paths=coupled_paths,
        migration_exception_accepted=ReviewPolicyReason.MIGRATION_EXCEPTION_ACCEPTED in reasons,
        description=description,
    )


def description_reasons(
    description: DescriptionMetrics | None,
    *,
    maximum_prose_characters: int = DEFAULT_MAXIMUM_PROSE_CHARACTERS,
) -> tuple[ReviewPolicyReason, ...]:
    if description is None:
        return (ReviewPolicyReason.BODY_TOO_LONG,)
    reasons: list[ReviewPolicyReason] = []
    if description.prose_characters > maximum_prose_characters:
        reasons.append(ReviewPolicyReason.BODY_PROSE_TOO_LONG)
    if description.invalid_code_examples:
        reasons.append(ReviewPolicyReason.BODY_CODE_EXAMPLE_INVALID)
    return tuple(reasons)


def _verified_activation(evidence: ReviewPolicyEvidence, config: ReviewPolicyConfig) -> bool:
    proof = config.verified_activation
    return bool(
        proof is not None
        and proof.binding.head_sha == evidence.evaluated_head_sha == evidence.current_head_sha
        and set(evidence.changed_paths) == {item.path for item in proof.binding.changes}
    )


def _focus_reasons(
    evidence: ReviewPolicyEvidence, config: ReviewPolicyConfig
) -> tuple[ReviewPolicyReason, ...]:
    reasons: list[ReviewPolicyReason] = []
    exact_humans = frozenset(
        review.reviewer.casefold()
        for review in evidence.latest_human_reviews or ()
        if evidence.current_head_sha == evidence.evaluated_head_sha
        and review.state is ReviewState.APPROVED
        and review.commit_sha == evidence.evaluated_head_sha
        and not review.allowlisted_bot
    )
    sensitive_floor = max(
        config.migration_review_floor
        if _touches_migration(
            changed_paths=evidence.changed_paths, migration_roots=config.migration_roots
        )
        else 0,
        int(any(_under_roots(path, config.domain_roots) for path in evidence.changed_paths)),
    )
    if len(exact_humans) < sensitive_floor and not _verified_activation(evidence, config):
        reasons.append(ReviewPolicyReason.SENSITIVE_APPROVAL_MISSING)
    coupled_paths = migration_coupled_paths(evidence.changed_paths, config.migration_roots)
    exception = evidence.migration_exception
    exception_accepted = bool(
        coupled_paths
        and exception is not None
        and set(exception.paths) == set(coupled_paths)
        and len(exact_humans) >= MIGRATION_EXCEPTION_REVIEW_COUNT
    )
    if coupled_paths:
        reasons.append(
            ReviewPolicyReason.MIGRATION_EXCEPTION_ACCEPTED
            if exception_accepted
            else ReviewPolicyReason.MIGRATION_CHANGES_MIXED
        )
    return tuple(reasons)


def _validate_paths(paths: tuple[str, ...], kind: str) -> None:
    if len(paths) != len(set(paths)):
        message = f"{kind}s must be unique"
        raise ValueError(message)
    for path in paths:
        try:
            normalized = canonical_path(path)
        except ConfigurationError as error:
            message = f"{kind} must be a normalized repository-relative path: {path!r}"
            raise ValueError(message) from error
        if normalized != path:
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
        _under_roots(path, migration_roots) or _is_sql_migration(path, migration_roots)
        for path in changed_paths
    )


def _under_roots(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _is_sql_migration(path: str, roots: tuple[str, ...]) -> bool:
    if not path.casefold().endswith(".sql"):
        return False
    if _under_roots(path, roots):
        return True
    directories = PurePosixPath(path).parts[:-1]

    return (
        "migrations" in directories
        and not is_test_path(path)
        and not any(part.casefold() in _MIGRATION_DISCOVERY_EXCLUSIONS for part in directories)
    )


def migration_coupled_paths(
    changed_paths: tuple[str, ...], migration_roots: tuple[str, ...]
) -> tuple[str, ...]:
    if not any(_is_sql_migration(path, migration_roots) for path in changed_paths):
        return ()
    return tuple(
        sorted(path for path in changed_paths if not _is_sql_migration(path, migration_roots))
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


@dataclass(frozen=True, slots=True)
class _ReviewAssessment:
    reasons: tuple[ReviewPolicyReason, ...]
    human_approvals: int
    carried_forward_reviewers: tuple[str, ...] = ()
    allowlisted_bot_approvers: tuple[str, ...] = ()


def _review_reasons(
    evidence: ReviewPolicyEvidence,
    *,
    required_reviews: RequiredReviewCount,
    head_matches: bool,
    config: ReviewPolicyConfig,
) -> _ReviewAssessment:
    reviews = evidence.latest_human_reviews
    if reviews is None:
        return _ReviewAssessment((ReviewPolicyReason.REVIEW_EVIDENCE_MISSING,), 0)
    reviewers = tuple(review.reviewer.casefold() for review in reviews)
    if len(reviewers) != len(set(reviewers)):
        return _ReviewAssessment((ReviewPolicyReason.REVIEW_EVIDENCE_AMBIGUOUS,), 0)

    approvals = _current_approvals(
        reviews,
        expected_head=evidence.evaluated_head_sha,
        head_matches=head_matches,
        config=config,
    )
    bot_approvals = sum(review.allowlisted_bot for review in approvals.current)
    human_approvals = len(approvals.current) - bot_approvals
    counted_bot_approvers = _counted_allowlisted_bot_approvers(
        approvals.current, author_is_bot=evidence.author_is_bot
    )
    reasons: list[ReviewPolicyReason] = []
    if approvals.stale:
        reasons.append(ReviewPolicyReason.STALE_APPROVAL)
    if approvals.carried:
        reasons.append(ReviewPolicyReason.APPROVAL_CARRIED_FORWARD)
    if len(counted_bot_approvers) < bot_approvals:
        reasons.append(ReviewPolicyReason.ALLOWLISTED_BOT_APPROVAL_NOT_COUNTED)
    if any(review.state is ReviewState.CHANGES_REQUESTED for review in reviews):
        reasons.append(ReviewPolicyReason.CHANGES_REQUESTED)
    if human_approvals + len(counted_bot_approvers) < required_reviews:
        reasons.append(ReviewPolicyReason.APPROVALS_MISSING)
    return _ReviewAssessment(
        tuple(reasons),
        human_approvals,
        tuple(review.reviewer for review in approvals.carried),
        counted_bot_approvers,
    )


@dataclass(frozen=True, slots=True)
class _CurrentApprovals:
    current: tuple[HumanReviewEvidence, ...]
    carried: tuple[HumanReviewEvidence, ...]
    stale: bool


def _current_approvals(
    reviews: tuple[HumanReviewEvidence, ...],
    *,
    expected_head: GitObjectId,
    head_matches: bool,
    config: ReviewPolicyConfig,
) -> _CurrentApprovals:
    approved = tuple(review for review in reviews if review.state is ReviewState.APPROVED)
    exact = tuple(
        review for review in approved if head_matches and review.commit_sha == expected_head
    )
    earlier = tuple(review for review in approved if review.commit_sha != expected_head)
    carried = tuple(
        review
        for review in earlier
        if head_matches and _carries_forward(review.since_review, config=config)
    )
    return _CurrentApprovals(exact + carried, carried, stale=len(carried) < len(earlier))


def _counted_allowlisted_bot_approvers(
    current: tuple[HumanReviewEvidence, ...],
    *,
    author_is_bot: bool,
) -> tuple[str, ...]:
    if author_is_bot:
        return ()
    approvers = tuple(review.reviewer for review in current if review.allowlisted_bot)
    return approvers[:ALLOWLISTED_BOT_APPROVAL_LIMIT]


def _carries_forward(
    since_review: SinceReviewEvidence | None,
    *,
    config: ReviewPolicyConfig,
) -> bool:
    return (
        since_review is not None
        and since_review.counted_lines <= config.one_review_maximum_lines
        and not _touches_migration(
            changed_paths=since_review.changed_paths,
            migration_roots=config.migration_roots,
        )
        and not any(_under_roots(path, config.domain_roots) for path in since_review.changed_paths)
    )
