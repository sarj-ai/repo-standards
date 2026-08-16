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
        rule_id=RuleId("core/migration/batch-too-large"),
        version=1,
        severity="warning",
        summary="Path migrations remain independently reversible component slices.",
        rationale=(
            "One declared component move per exact tree bounds review, verification, and rollback."
        ),
        bad_example="one manifest declares dozens of unrelated component relocations",
        good_example="one exact tree declares and verifies one component relocation",
        problem="Large migration batches couple otherwise independent component relocations.",
        harm="One failure can require reverting unrelated verified moves as a single unit.",
        non_goals=("prohibiting a separately reviewed orchestration sequence",),
        evidence_required=("migration_paths from the exact selected manifest",),
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("core/migration/target-missing"),
        version=1,
        severity="warning",
        summary="Declared migration targets contain tracked component files.",
        rationale="A path declaration cannot prove a relocation that is absent from the Git tree.",
        bad_example="the manifest points to applications/platform/api but no files exist there",
        good_example="the selected commit contains the component at its declared target",
        problem="A migration can otherwise appear complete using manifest evidence alone.",
        harm="Checks and ownership analysis evaluate a target that was never materialized.",
        non_goals=("checking untracked worktree files", "executing repository build commands"),
        evidence_required=("tracked paths from the exact selected Git tree",),
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("core/migration/tracked-install-artifacts"),
        version=1,
        severity="warning",
        summary="Migration commits do not track generated dependency installation state.",
        rationale=(
            "Generated install trees can turn a small relocation into tens of thousands of "
            "unreviewable files and platform-specific bytes."
        ),
        bad_example="node_modules/** or .yarn/install-state.gz is tracked during a path migration",
        good_example="lockfiles are tracked while generated installation outputs remain ignored",
        problem="A dependency install can be accidentally staged with a mechanical path move.",
        harm="Review and CI are flooded by generated, machine-specific files.",
        non_goals=("rejecting committed dependency lockfiles", "reading untracked worktree files"),
        evidence_required=("tracked paths from the exact selected Git tree",),
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("core/migration/source-retained"),
        version=1,
        severity="warning",
        summary="Declared migration sources do not retain undeclared tracked files.",
        rationale=(
            "Files left under an old root preserve ambiguous ownership and stale entrypoints."
        ),
        bad_example="both python/api and applications/platform/api contain tracked files",
        good_example="the old root is empty or separately declared as a compatibility component",
        non_goals=("forbidding reviewed compatibility components",),
        evidence_required=("tracked paths from the exact selected Git tree",),
        maturity="beta",
    ),
    Rule(
        rule_id=RuleId("core/migration/workspace-membership-lost"),
        version=1,
        severity="warning",
        summary="Relocated packages remain in their native workspace.",
        rationale="A path move can silently remove a package from installs, builds, tests, and CI.",
        bad_example="packages/* selected the old package but not its new applications/* path",
        good_example="workspace member patterns select the relocated package",
        non_goals=("requiring every discovered package to belong to a workspace",),
        evidence_required=("parser-backed workspace and package metadata from one Git tree",),
        maturity="beta",
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
