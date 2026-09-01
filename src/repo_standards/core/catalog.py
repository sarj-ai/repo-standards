from __future__ import annotations

from .models import FixtureId, RuleDefinition, RuleExamplePair, RuleId
from .taxonomy import CHANGE_SAFETY, MIGRATIONS, taxonomy


_MIGRATION_CONSISTENCY = RuleDefinition(
    rule_id=RuleId("repository/migration/consistency"),
    version=1,
    default_severity="warning",
    title="Complete component migrations",
    description="A declared component move is complete in the selected Git tree.",
    why="Incomplete moves split ownership and build discovery across old and new paths.",
    fix="Commit the target, empty or reassign the source, and update workspace membership.",
    taxonomy=taxonomy(CHANGE_SAFETY, MIGRATIONS),
    examples=(
        RuleExamplePair(
            example_id=FixtureId("core.migration.target-missing.v2"),
            title="Missing migration target",
            language="text",
            before="README.md",
            after="applications/alpha/api/pyproject.toml",
            expected_severity="warning",
        ),
        RuleExamplePair(
            example_id=FixtureId("core.migration.source-retained.v2"),
            title="Retained migration source",
            language="text",
            before="apps/api/legacy.py\napplications/alpha/api/main.py",
            after="applications/alpha/api/main.py",
            expected_severity="warning",
        ),
        RuleExamplePair(
            example_id=FixtureId("core.migration.workspace-membership-lost.v2"),
            title="Lost workspace membership",
            language="json",
            before='{"private":true,"workspaces":["apps/*"]}',
            after='{"private":true,"workspaces":["applications/*/*"]}',
            expected_severity="warning",
        ),
    ),
)

_GENERATED_SCHEMA_PROVENANCE = RuleDefinition(
    rule_id=RuleId("repository/database/generated-schema-provenance"),
    version=1,
    default_severity="warning",
    title="Regenerate PostgreSQL schemas from migrations",
    description=(
        "Every semantic PostgreSQL object added to a generated schema is attributable to an "
        "authored migration in the same pull-request diff."
    ),
    why=(
        "Dump-only types, tables, columns, constraints, and indexes cannot be reproduced when "
        "another environment runs migrations."
    ),
    fix="Add the migration that creates the object, then regenerate the committed schema dump.",
    taxonomy=taxonomy(CHANGE_SAFETY, MIGRATIONS),
    examples=(
        RuleExamplePair(
            example_id=FixtureId("core.schema-provenance.dump-only-enum.v1"),
            title="Dump-only enum gains its migration",
            language="text",
            before=(
                "db/schema.sql\n"
                "CREATE TYPE public.workflow_status AS ENUM ('pending', 'completed');"
            ),
            after=(
                "db/migrations/20260831_workflow_status.sql\n"
                "CREATE TYPE workflow_status AS ENUM ('pending', 'completed');\n"
                "db/schema.sql\n"
                "CREATE TYPE public.workflow_status AS ENUM ('pending', 'completed');"
            ),
            expected_severity="warning",
        ),
    ),
)


def core_rules() -> tuple[RuleDefinition, ...]:
    return (_MIGRATION_CONSISTENCY, _GENERATED_SCHEMA_PROVENANCE)
