from __future__ import annotations

from dataclasses import replace

import pytest

from repo_standards.core.models import GitObjectId, MigrationCouplingException
from repo_standards.core.review_policy import (
    CheckConclusion,
    HumanReviewEvidence,
    RequiredCheckEvidence,
    ReviewPolicyConfig,
    ReviewPolicyEvidence,
    ReviewPolicyReason,
    ReviewState,
    SinceReviewEvidence,
    evaluate_review_policy,
)


HEAD = GitObjectId("a" * 40)
OLD = GitObjectId("b" * 40)
MIGRATION = "db/migrations/001.sql"
COUPLED = (".repo-standards/repository.toml", "src/reader.py")
EXCEPTION = MigrationCouplingException(
    reason="The migration runner imports the new codec in the same transaction.",
    alternatives="An expand/contract deployment cannot decode the existing encrypted values.",
    paths=COUPLED,
)


def _evidence(*paths: str) -> ReviewPolicyEvidence:
    return ReviewPolicyEvidence(
        counted_lines=1,
        changed_paths=paths,
        evaluated_head_sha=HEAD,
        current_head_sha=HEAD,
        required_checks=(RequiredCheckEvidence("ci", CheckConclusion.SUCCESS),),
        latest_human_reviews=(),
        threads_resolved=True,
    )


def _approval(name: str, *, commit: GitObjectId = HEAD, bot: bool = False) -> HumanReviewEvidence:
    return HumanReviewEvidence(name, ReviewState.APPROVED, commit, allowlisted_bot=bot)


@pytest.mark.parametrize("length", [1999, 2000, 2001])
def test_description_budget_counts_all_characters(length: int) -> None:
    evidence = replace(_evidence("src/reader.py"), body="x" * length)

    result = evaluate_review_policy(evidence)

    assert result.merge_ready == (length <= 2000)
    assert (ReviewPolicyReason.BODY_TOO_LONG in result.reasons) == (length > 2000)


def test_hidden_comments_and_unbroken_text_cannot_bypass_description_budget() -> None:
    evidence = replace(_evidence("src/reader.py"), body="<!--" + "x" * 2000 + "-->")

    assert not evaluate_review_policy(evidence).merge_ready


def test_short_description_leaves_room_for_automation_links() -> None:
    footer = f'<a href="https://ci.example.invalid/{"x" * 1600}">CI status</a>'
    evidence = replace(
        _evidence("src/reader.py"), body=f"Fix account hydration. Tested with pytest.\n\n{footer}"
    )

    assert 1500 < len(evidence.body) < 2000
    assert evaluate_review_policy(evidence).merge_ready


@pytest.mark.parametrize(
    "other",
    ["src/reader.py", "tests/test_migration.py", "README.md", "uv.lock", "db/migrations/helper.py"],
)
def test_migration_pr_rejects_every_nonmigration_change(other: str) -> None:
    evidence = replace(_evidence(MIGRATION, other), latest_human_reviews=(_approval("alice"),))

    result = evaluate_review_policy(evidence)

    assert not result.merge_ready
    assert result.migration_coupled_paths == (other,)
    assert ReviewPolicyReason.MIGRATION_CHANGES_MIXED in result.reasons


def test_only_migration_sql_can_merge_after_review() -> None:
    evidence = replace(
        _evidence(MIGRATION, "db/migrations/001.down.sql", "prisma/migrations/next/migration.sql"),
        latest_human_reviews=(_approval("alice"),),
    )

    assert evaluate_review_policy(evidence).merge_ready


@pytest.mark.parametrize(
    "path", ["tests/migrations/fixture.sql", "examples/migrations/001.sql", "sql/query.sql"]
)
def test_fixture_and_ordinary_sql_do_not_create_a_migration_pr(path: str) -> None:
    result = evaluate_review_policy(_evidence(path, "src/reader.py"))

    assert result.merge_ready
    assert not result.touches_migration


def test_explicit_migration_root_overrides_fixture_exclusion() -> None:
    result = evaluate_review_policy(
        _evidence("tests/migrations/001.sql", "src/reader.py"),
        ReviewPolicyConfig(migration_roots=("tests/migrations",)),
    )

    assert ReviewPolicyReason.MIGRATION_CHANGES_MIXED in result.reasons


@pytest.mark.parametrize(
    "reviews",
    [
        pytest.param((_approval("alice"),), id="single-human"),
        pytest.param((_approval("alice"), _approval("review-bot", bot=True)), id="bot-second"),
        pytest.param((_approval("alice"), _approval("bob", commit=OLD)), id="stale-second"),
        pytest.param((_approval("alice"), _approval("ALICE")), id="duplicate-human"),
    ],
)
def test_migration_exception_needs_two_distinct_humans_on_current_head(
    reviews: tuple[HumanReviewEvidence, ...],
) -> None:
    evidence = replace(
        _evidence(MIGRATION, *COUPLED),
        latest_human_reviews=reviews,
        migration_exception=EXCEPTION,
    )

    assert not evaluate_review_policy(evidence).merge_ready


def test_complete_migration_exception_requires_no_other_gate_bypass() -> None:
    evidence = replace(
        _evidence(MIGRATION, *COUPLED),
        latest_human_reviews=(_approval("alice"), _approval("bob")),
        migration_exception=EXCEPTION,
    )
    result = evaluate_review_policy(evidence)

    assert result.merge_ready
    assert result.migration_exception_accepted
    assert result.required_human_reviews == 2
    assert not evaluate_review_policy(replace(evidence, threads_resolved=False)).merge_ready
    assert not evaluate_review_policy(replace(evidence, current_head_sha=OLD)).merge_ready
    assert not evaluate_review_policy(
        replace(evidence, changed_paths=(*evidence.changed_paths, "uv.lock"))
    ).merge_ready


def test_carried_approval_cannot_authorize_migration_exception() -> None:
    carried = replace(
        _approval("bob", commit=OLD),
        since_review=SinceReviewEvidence(1, ("src/reader.py",)),
    )
    evidence = replace(
        _evidence(MIGRATION, *COUPLED),
        latest_human_reviews=(_approval("alice"), carried),
        migration_exception=EXCEPTION,
    )

    assert not evaluate_review_policy(evidence).merge_ready


def test_exception_cannot_be_reused_for_a_different_path_set() -> None:
    evidence = replace(
        _evidence(MIGRATION, "src/other.py"),
        latest_human_reviews=(_approval("alice"), _approval("bob")),
        migration_exception=EXCEPTION,
    )

    assert not evaluate_review_policy(evidence).merge_ready


@pytest.mark.parametrize("path", ["domains/billing.py", "domain/subscriptions.ts"])
def test_domain_contracts_require_current_human_consensus(path: str) -> None:
    evidence = _evidence(path)

    assert not evaluate_review_policy(evidence).merge_ready
    assert evaluate_review_policy(
        replace(evidence, latest_human_reviews=(_approval("alice"),))
    ).merge_ready
    assert not evaluate_review_policy(
        replace(evidence, latest_human_reviews=(_approval("bot", bot=True),))
    ).merge_ready


def test_declared_domain_roots_do_not_match_adjacent_names() -> None:
    policy = ReviewPolicyConfig(domain_roots=("src/models",))

    assert not evaluate_review_policy(_evidence("src/models/account.py"), policy).merge_ready
    assert evaluate_review_policy(_evidence("src/models_extra/account.py"), policy).merge_ready
