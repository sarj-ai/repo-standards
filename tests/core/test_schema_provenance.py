from __future__ import annotations

import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local Git fixture only
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

from repo_standards.core.schema_provenance import (
    SchemaObject,
    analyze_schema_provenance,
    parse_postgresql_objects,
)


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed local Git fixture only
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )
    return completed.stdout.decode().strip()


def _commit(repository: Path) -> str:
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Schema Test",
        "-c",
        "user.email=schema@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path, schema: str) -> str:
    _git(tmp_path, "init", "--quiet")
    path = tmp_path / "svcs" / "db" / "db"
    path.mkdir(parents=True)
    (path / "schema.sql").write_text(schema, encoding="utf-8")
    return _commit(tmp_path)


def test_dump_only_enum_is_a_warning(tmp_path: Path) -> None:
    base = _repository(tmp_path, "-- empty schema\n")
    schema = tmp_path / "svcs" / "db" / "db" / "schema.sql"
    schema.write_text(
        """\
-- Name: workflow_status; Type: TYPE; Schema: public; Owner: -
CREATE TYPE public.workflow_status AS ENUM (
    'pending',
    'failed',
    'completed'
);
""",
        encoding="utf-8",
    )
    _commit(tmp_path)

    result = analyze_schema_provenance(tmp_path, base=base)

    observed = [
        (item.severity, item.subject_kind, item.observed_value) for item in result.diagnostics
    ]
    assert observed == [
        (
            "warning",
            "postgresql-type",
            {"kind": "type", "identity": "public.workflow_status"},
        )
    ]


def test_authored_migration_attributable_after_schema_regeneration(tmp_path: Path) -> None:
    base = _repository(tmp_path, "CREATE TABLE public.jobs (id bigint);\n")
    root = tmp_path / "svcs" / "db" / "db"
    migrations = root / "migrations"
    migrations.mkdir()
    (migrations / "20260831120000_add_status.sql").write_text(
        """\
CREATE TYPE workflow_status AS ENUM ('pending', 'failed', 'completed');
ALTER TABLE jobs ADD COLUMN status workflow_status NOT NULL;
CREATE INDEX jobs_status_idx ON jobs (status);
""",
        encoding="utf-8",
    )
    (root / "schema.sql").write_text(
        """\
CREATE TYPE public.workflow_status AS ENUM ('pending', 'failed', 'completed');
CREATE TABLE public.jobs (
    id bigint,
    status public.workflow_status NOT NULL
);
CREATE INDEX jobs_status_idx ON public.jobs USING btree (status);
""",
        encoding="utf-8",
    )
    _commit(tmp_path)

    result = analyze_schema_provenance(tmp_path, base=base)

    assert result.diagnostics == ()


def test_unrelated_database_migration_cannot_supply_provenance(tmp_path: Path) -> None:
    base = _repository(tmp_path, "-- empty schema\n")
    root = tmp_path / "svcs" / "db" / "db"
    (root / "schema.sql").write_text(
        "CREATE TYPE public.workflow_status AS ENUM ('pending', 'completed');\n",
        encoding="utf-8",
    )
    unrelated = tmp_path / "other" / "db" / "migrations"
    unrelated.mkdir(parents=True)
    (unrelated / "20260831120000_add_status.sql").write_text(
        "CREATE TYPE workflow_status AS ENUM ('pending', 'completed');\n",
        encoding="utf-8",
    )
    _commit(tmp_path)

    result = analyze_schema_provenance(tmp_path, base=base)

    assert [item.observed_value for item in result.diagnostics] == [
        {"kind": "type", "identity": "public.workflow_status"}
    ]


def test_parser_normalizes_objects_and_ignores_dump_presentation() -> None:
    first = parse_postgresql_objects(
        b"""\
-- owner and dump headings are not provenance
CREATE TABLE "public"."Widget" ("ID" bigint, value text);
ALTER TABLE ONLY "public"."Widget" ADD CONSTRAINT "Widget_pkey" PRIMARY KEY ("ID");
CREATE UNIQUE INDEX "Widget_value_idx" ON "public"."Widget" (value);
"""
    )
    reordered = parse_postgresql_objects(
        b"""\
/* formatting and ordering differ */
CREATE UNIQUE INDEX "public"."Widget_value_idx"
  ON "public"."Widget" USING btree (value);
CREATE TABLE "public"."Widget" (
 value text,
 "ID" bigint
);
ALTER TABLE ONLY "public"."Widget"
 ADD CONSTRAINT "Widget_pkey" PRIMARY KEY ("ID");
COMMENT ON TABLE "public"."Widget" IS 'ignored';
ALTER TABLE "public"."Widget" OWNER TO postgres;
"""
    )

    assert first == reordered
    assert SchemaObject("column", "public.Widget.ID") in first
    assert SchemaObject("constraint", "public.Widget.Widget_pkey") in first
    assert SchemaObject("index", "public.Widget_value_idx") in first
