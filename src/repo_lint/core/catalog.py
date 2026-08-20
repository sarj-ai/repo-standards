from __future__ import annotations

from dataclasses import replace

from .models import (
    FixtureId,
    RuleDefinition,
    RuleExamplePair,
    RuleId,
    RuleRemediation,
)
from .taxonomy import (
    ARCHITECTURE,
    BASELINES,
    CHANGE_SAFETY,
    EXCEPTIONS,
    MIGRATIONS,
    REPOSITORY_LAYOUT,
    taxonomy,
)


_CORE_RULES = (
    RuleDefinition(
        rule_id=RuleId("core/layout/non-overlapping-root"),
        version=1,
        default_severity="error",
        title="Keep component roots disjoint",
        summary="Each tracked path has one declared component owner.",
        detects=(
            "Reports when two component paths are equal after case-folding, or one component "
            "path is nested beneath another."
        ),
        impact=(
            "The same files acquire multiple owners, making affected-component and policy "
            "results ambiguous."
        ),
        taxonomy=taxonomy(
            ARCHITECTURE,
            REPOSITORY_LAYOUT,
            "component-ownership",
            "paths",
        ),
        remediation=RuleRemediation(
            summary="Give each component one disjoint ownership root.",
            steps=(
                "Choose which component owns the overlapping files.",
                "Merge duplicate declarations or move one component to a disjoint root.",
            ),
            validation=("Run repo-lint check and confirm no component roots overlap.",),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.layout.non-overlapping-root.v2"),
                title="Overlapping component roots",
                severity="error",
                language="toml",
                flagged='''schema_version = 2
repository_id = "example-repository"
policy = "example"
policy_version = 1

[[components]]
id = "payments"
kind = "service"
path = "services/payments"
owner = "@example/payments"

[[components]]
id = "worker"
kind = "worker"
path = "services/payments/worker"
owner = "@example/payments"''',
                passes='''schema_version = 2
repository_id = "example-repository"
policy = "example"
policy_version = 1

[[components]]
id = "payments"
kind = "service"
path = "services/payments"
owner = "@example/payments"

[[components]]
id = "worker"
kind = "worker"
path = "workers/payments"
owner = "@example/payments"''',
            ),
        ),
        evidence_required=("Component paths from the exact selected manifest.",),
        false_positive_controls=(
            "Path comparison is case-insensitive and respects complete path segments.",
        ),
    ),
    RuleDefinition(
        rule_id=RuleId("core/migration/batch-too-large"),
        version=1,
        default_severity="warning",
        title="Move one component at a time",
        summary="One selected Git tree declares at most one component relocation.",
        detects=("Reports when the selected manifest contains more than one migration path entry."),
        impact=(
            "Independent moves share one review and rollback boundary, so one failed move can "
            "force all verified moves to be reverted together."
        ),
        taxonomy=taxonomy(
            CHANGE_SAFETY,
            MIGRATIONS,
            "reviewability",
            "rollback",
        ),
        remediation=RuleRemediation(
            summary="Split the migration into independently reversible component moves.",
            steps=(
                "Keep one migration path entry in the selected tree.",
                "Verify and merge that move before declaring the next relocation.",
            ),
            validation=("Run repo-lint check and confirm one migration path remains.",),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.migration.batch-too-large.v2"),
                title="Multiple migrations",
                severity="warning",
                language="toml",
                flagged='''schema_version = 2
repository_id = "example-repository"
policy = "example"
policy_version = 1

[[components]]
id = "api"
kind = "service"
path = "applications/alpha/api"
owner = "@example/alpha"

[[components]]
id = "worker"
kind = "worker"
path = "applications/alpha/worker"
owner = "@example/alpha"

[[migration_paths]]
component_id = "api"
from = "apps/api"
to = "applications/alpha/api"

[[migration_paths]]
component_id = "worker"
from = "apps/worker"
to = "applications/alpha/worker"''',
                passes='''schema_version = 2
repository_id = "example-repository"
policy = "example"
policy_version = 1

[[components]]
id = "api"
kind = "service"
path = "applications/alpha/api"
owner = "@example/alpha"

[[migration_paths]]
component_id = "api"
from = "apps/api"
to = "applications/alpha/api"''',
            ),
        ),
        evidence_required=("Migration path entries from the exact selected manifest.",),
        non_goals=("Prohibiting a separately reviewed sequence of component moves.",),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("core/migration/target-missing"),
        version=1,
        default_severity="warning",
        title="Commit files at the migration target",
        summary="Every declared migration target contains at least one tracked file.",
        detects=(
            "Reports when the selected Git tree has no tracked file at or below a migration's "
            "declared target path."
        ),
        impact=(
            "The manifest can claim a completed move while ownership and checks point to a path "
            "that does not exist."
        ),
        taxonomy=taxonomy(CHANGE_SAFETY, MIGRATIONS, "git-tree", "path-moves"),
        remediation=RuleRemediation(
            summary="Commit the component files at the declared migration target.",
            steps=(
                "Move and add the component's files at the declared target path.",
                "Update path-sensitive build and workspace configuration in the same change.",
            ),
            validation=("Run repo-lint check against the resulting commit.",),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.migration.target-missing.v2"),
                title="Missing migration target",
                severity="warning",
                language="text",
                flagged="README.md",
                passes="applications/alpha/api/pyproject.toml",
            ),
        ),
        evidence_required=("Tracked paths from the exact selected Git tree.",),
        non_goals=("Checking untracked worktree files.", "Executing repository build commands."),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("core/migration/tracked-install-artifacts"),
        version=1,
        default_severity="warning",
        title="Do not track Node install artifacts during migrations",
        summary=(
            "A tree with declared migrations does not track node_modules files or Yarn install "
            "state."
        ),
        detects=(
            "When a migration is declared, reports tracked .yarn/install-state.gz files and files "
            "beneath any node_modules directory as one repository-level finding."
        ),
        impact="Generated, machine-specific install state can dominate review and CI inputs.",
        taxonomy=taxonomy(
            CHANGE_SAFETY,
            MIGRATIONS,
            "dependency-installs",
            "generated-files",
        ),
        remediation=RuleRemediation(
            summary="Remove generated installation outputs from the selected tree.",
            steps=(
                "Untrack node_modules trees and Yarn installation state.",
                "Add or repair ignore rules before reinstalling from the lockfile.",
            ),
            validation=("Inspect the exact committed tree and rerun repo-lint check.",),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.migration.tracked-install-artifacts.v2"),
                title="Tracked install artifacts",
                severity="warning",
                language="text",
                flagged="""applications/alpha/api/pyproject.toml
node_modules/example/index.js
.yarn/install-state.gz""",
                passes="""applications/alpha/api/pyproject.toml
package-lock.json
.gitignore""",
            ),
        ),
        evidence_required=("Tracked paths from the exact selected Git tree.",),
        non_goals=(
            "Rejecting committed dependency lockfiles.",
            "Reading untracked worktree files.",
        ),
        false_positive_controls=(
            (
                "The rule recognizes only node_modules paths and .yarn/install-state.gz, and "
                "runs only when a migration is declared."
            ),
        ),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("core/migration/source-retained"),
        version=1,
        default_severity="warning",
        title="Empty or reassign the migration source",
        summary="A moved component leaves no unowned tracked files at its old root.",
        detects=(
            "Reports tracked files beneath a migration source when that exact path has no "
            "separately declared component owner, or remains owned by the moving component."
        ),
        impact=(
            "Files at the old root preserve ambiguous ownership and stale entry points after the "
            "move."
        ),
        taxonomy=taxonomy(
            CHANGE_SAFETY,
            MIGRATIONS,
            "component-ownership",
            "git-tree",
            "path-moves",
        ),
        remediation=RuleRemediation(
            summary="Finish the relocation or explicitly own the compatibility surface.",
            steps=(
                "Move or delete obsolete files beneath the old component root.",
                "Declare intentional compatibility files as a separately owned component.",
            ),
            validation=(
                "Run repo-lint check and confirm the old root is empty or separately owned.",
            ),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.migration.source-retained.v2"),
                title="Retained migration source",
                severity="warning",
                language="text",
                flagged="""apps/api/legacy.py
applications/alpha/api/main.py""",
                passes="applications/alpha/api/main.py",
            ),
        ),
        evidence_required=("Tracked paths from the exact selected Git tree.",),
        non_goals=("Forbidding separately owned compatibility components.",),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("core/migration/workspace-membership-lost"),
        version=1,
        default_severity="warning",
        title="Keep moved packages in their workspace",
        summary=(
            "A relocated package remains selected by every same-ecosystem workspace that "
            "selected its old path."
        ),
        detects=(
            "For a package beneath a migration target, reports when a same-ecosystem workspace "
            "included its reconstructed old path but does not include its new path."
        ),
        impact="Package installs, builds, tests, and CI can silently omit the moved package.",
        taxonomy=taxonomy(
            CHANGE_SAFETY,
            MIGRATIONS,
            "packages",
            "workspaces",
        ),
        remediation=RuleRemediation(
            summary="Update the native workspace declaration for the relocated package.",
            steps=(
                "Add a member pattern covering the package's new directory.",
                "Keep exclusions at least as narrow as they were before the relocation.",
            ),
            validation=(
                "Run the package manager's immutable workspace install and repo-lint check.",
            ),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.migration.workspace-membership-lost.v2"),
                title="Lost workspace membership",
                severity="warning",
                language="json",
                flagged='{"private":true,"workspaces":["apps/*"]}',
                passes='{"private":true,"workspaces":["applications/*/*"]}',
            ),
        ),
        evidence_required=(
            "Parser-backed package and workspace metadata from the exact selected Git tree.",
        ),
        non_goals=("Requiring every discovered package to belong to a workspace.",),
        false_positive_controls=(
            "The rule reports only a workspace that selected the reconstructed old package path.",
        ),
        maturity="beta",
    ),
    RuleDefinition(
        rule_id=RuleId("core/exception/expired"),
        version=1,
        default_severity="error",
        title="Renew or remove expired exceptions",
        summary="A matching policy exception remains valid through the analysis date.",
        detects=(
            "Reports when an exception matching a current finding has an expires_on date earlier "
            "than the explicit analysis date."
        ),
        impact=(
            "The exception no longer suppresses its finding and leaves stale review metadata "
            "beside an active violation."
        ),
        taxonomy=taxonomy(
            CHANGE_SAFETY,
            EXCEPTIONS,
            "policy-debt",
            "time-bounded",
        ),
        remediation=RuleRemediation(
            summary="Resolve the finding or renew its narrow exception through review.",
            steps=(
                (
                    "Fix the underlying finding and remove the exception, or extend its reviewed "
                    "expiry without broadening its scope."
                ),
            ),
            validation=("Run repo-lint check with the same explicit analysis date.",),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.exception.expired.v2"),
                title="Expired exception",
                severity="error",
                language="toml",
                flagged="""rule_id = "core/layout/non-overlapping-root"
component_id = "worker"
manifest_anchor = "components.worker.path"
fingerprint = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
owner = "@example/payments"
reason = "migration in progress"
issue = "EXAMPLE-1"
created_on = "2029-01-01"
expires_on = "2029-03-01"
# analysis date: 2029-03-02""",
                passes="""rule_id = "core/layout/non-overlapping-root"
component_id = "worker"
manifest_anchor = "components.worker.path"
fingerprint = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
owner = "@example/payments"
reason = "migration in progress"
issue = "EXAMPLE-1"
created_on = "2029-01-01"
expires_on = "2029-04-01"
# analysis date: 2029-03-02""",
            ),
        ),
        evidence_required=(
            "A current finding, its exact matching exception, and an explicit analysis date.",
        ),
        non_goals=(
            "Validating duplicate, unmatched, or future-dated exception records as findings.",
        ),
        false_positive_controls=("An exception remains valid on its expires_on date.",),
    ),
    RuleDefinition(
        rule_id=RuleId("core/baseline/stale-entry"),
        version=1,
        default_severity="error",
        title="Remove resolved findings from the baseline",
        summary="The ratchet baseline contains only fingerprints still emitted as active errors.",
        detects=(
            "After repository, policy, and scope validation, reports each baseline fingerprint "
            "absent from the current active-error fingerprint set."
        ),
        impact=(
            "Resolved debt remains recorded, so the baseline no longer shows the repository's "
            "actual remaining error budget or locks in cleanup."
        ),
        taxonomy=taxonomy(
            CHANGE_SAFETY,
            BASELINES,
            "policy-debt",
            "ratchet",
        ),
        remediation=RuleRemediation(
            summary="Delete the resolved fingerprint from the reviewed baseline.",
            steps=("Remove the exact resolved fingerprint from .repo-lint/baseline.json.",),
            validation=("Run repo-lint check --mode ratchet again.",),
        ),
        examples=(
            RuleExamplePair(
                fixture_id=FixtureId("core.baseline.stale-entry.v2"),
                title="Resolved baseline entry",
                severity="error",
                language="json",
                flagged=(
                    '{"schema_version":2,"repository_id":"example-repository",'
                    '"policy":"example","policy_version":1,"scope_digest":"scope",'
                    '"fingerprints":['
                    '"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]}'
                ),
                passes=(
                    '{"schema_version":2,"repository_id":"example-repository",'
                    '"policy":"example","policy_version":1,"scope_digest":"scope",'
                    '"fingerprints":[]}'
                ),
            ),
        ),
        evidence_required=(
            "The reviewed baseline and fingerprints of current active error findings.",
        ),
        non_goals=("Removing fingerprints that still match active error findings.",),
    ),
)


def core_rules() -> tuple[RuleDefinition, ...]:
    by_id = {str(rule.rule_id): rule for rule in _CORE_RULES}
    sources = tuple(
        by_id[rule_id]
        for rule_id in (
            "core/migration/target-missing",
            "core/migration/source-retained",
            "core/migration/workspace-membership-lost",
        )
    )
    representative = sources[0]
    return (
        replace(
            representative,
            rule_id=RuleId("repository/migration/consistency"),
            title="Complete component migrations",
            summary="A declared component move is complete in the selected Git tree.",
            detects="Reports a missing target, retained source, or lost workspace membership.",
            impact=(
                "Incomplete moves split ownership and build discovery across old and new paths."
            ),
            remediation=RuleRemediation(
                summary="Finish every declared relocation as one internally consistent move.",
                steps=(
                    "Commit the component at its declared target.",
                    "Empty or explicitly reassign its former source root.",
                    "Update native workspace membership for relocated packages.",
                ),
                validation=("Run repo-lint against the resulting commit.",),
            ),
            examples=tuple(example for rule in sources for example in rule.examples),
            evidence_required=(
                "tracked paths plus parsed package and workspace metadata from the selected tree",
            ),
            non_goals=(
                "Checking untracked worktree files.",
                "Executing repository build commands.",
                "Forbidding separately owned compatibility components.",
            ),
            false_positive_controls=tuple(
                dict.fromkeys(item for rule in sources for item in rule.false_positive_controls)
            ),
        ),
    )
