from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType

from .errors import ConfigurationError
from .models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation


_RULE_ID = RuleId("repository/database/generated-schema-provenance")
_SCHEMA_BASENAMES = frozenset({"schema.sql", "structure.sql"})
_GIT_ENVIRONMENT = MappingProxyType(
    {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
)
_IDENTIFIER = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z_0-9$]*)'
_QUALIFIED = rf"{_IDENTIFIER}(?:\s*\.\s*{_IDENTIFIER})?"
_CREATE_TYPE = re.compile(rf"^\s*CREATE\s+TYPE\s+({_QUALIFIED})(?=\s|$)", re.IGNORECASE | re.DOTALL)
_CREATE_TABLE = re.compile(
    rf"^\s*CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({_QUALIFIED})\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_ALTER_COLUMN = re.compile(
    rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?({_QUALIFIED})\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?({_IDENTIFIER})(?=\s|$)",
    re.IGNORECASE | re.DOTALL,
)
_ALTER_CONSTRAINT = re.compile(
    rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?({_QUALIFIED})\s+ADD\s+CONSTRAINT\s+({_IDENTIFIER})(?=\s|$)",
    re.IGNORECASE | re.DOTALL,
)
_CREATE_INDEX = re.compile(
    rf"^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?({_QUALIFIED})\s+ON\s+(?:ONLY\s+)?({_QUALIFIED})(?=\s|$)",
    re.IGNORECASE | re.DOTALL,
)
_INLINE_CONSTRAINT = re.compile(rf"^\s*CONSTRAINT\s+({_IDENTIFIER})(?=\s|$)", re.IGNORECASE)
_NON_COLUMN_PREFIXES = frozenset(
    {"constraint", "primary", "unique", "check", "exclude", "foreign", "like", "partition"}
)


@dataclass(frozen=True, slots=True, order=True)
class SchemaObject:
    kind: str
    identity: str


@dataclass(frozen=True, slots=True)
class SchemaProvenanceResult:
    base: str
    head: str
    diagnostics: tuple[Diagnostic, ...]
    generated_paths: tuple[str, ...]
    migration_paths: tuple[str, ...]


def analyze_schema_provenance(
    root: Path, *, base: str, head: str = "HEAD"
) -> SchemaProvenanceResult:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    base_sha = _revision(resolved, base)
    head_sha = _revision(resolved, head)
    changed = _changed_paths(resolved, base_sha, head_sha)
    migrations = tuple(path for status, path in changed if status != "D" and _is_migration(path))
    generated = tuple(
        path for status, path in changed if status == "M" and _is_generated_schema(path)
    )
    migration_objects: dict[str, frozenset[SchemaObject]] = {}
    for status, path in changed:
        if status == "D" or not _is_migration(path):
            continue
        head_objects = parse_postgresql_objects(_blob(resolved, head_sha, path))
        base_objects: frozenset[SchemaObject] = (
            parse_postgresql_objects(_blob(resolved, base_sha, path))
            if status != "A"
            else frozenset()
        )
        migration_objects[path] = head_objects - base_objects

    diagnostics: list[Diagnostic] = []
    for path in generated:
        old_objects = parse_postgresql_objects(_blob(resolved, base_sha, path))
        new_objects = parse_postgresql_objects(_blob(resolved, head_sha, path))
        attributable: set[SchemaObject] = set()
        for migration_path, objects in migration_objects.items():
            if _migration_applies(schema_path=path, migration_path=migration_path):
                attributable.update(objects)
        diagnostics.extend(
            _diagnostic(path, item)
            for item in unattributed_schema_objects(old_objects, new_objects, attributable)
        )
    return SchemaProvenanceResult(
        base=base_sha,
        head=head_sha,
        diagnostics=tuple(diagnostics),
        generated_paths=generated,
        migration_paths=migrations,
    )


def unattributed_schema_objects(
    old_generated: frozenset[SchemaObject],
    new_generated: frozenset[SchemaObject],
    migration_objects: set[SchemaObject] | frozenset[SchemaObject],
) -> tuple[SchemaObject, ...]:
    return tuple(sorted(new_generated - old_generated - migration_objects))


def parse_postgresql_objects(source: bytes) -> frozenset[SchemaObject]:
    text = source.decode("utf-8", errors="replace")
    objects: set[SchemaObject] = set()
    for statement in _statements(text):
        match = _CREATE_TYPE.match(statement)
        if match:
            objects.add(SchemaObject("type", _qualified(match.group(1))))
            continue
        match = _CREATE_TABLE.match(statement)
        if match:
            table = _qualified(match.group(1))
            objects.add(SchemaObject("table", table))
            opening = statement.find("(", match.start())
            closing = _matching_parenthesis(statement, opening)
            if closing is not None:
                for entry in _comma_parts(statement[opening + 1 : closing]):
                    if constraint := _INLINE_CONSTRAINT.match(entry):
                        objects.add(
                            SchemaObject(
                                "constraint", f"{table}.{_identifier(constraint.group(1))}"
                            )
                        )
                        continue
                    identifier = _leading_identifier(entry)
                    if identifier is not None and identifier.casefold() not in _NON_COLUMN_PREFIXES:
                        objects.add(SchemaObject("column", f"{table}.{_identifier(identifier)}"))
            continue
        match = _ALTER_CONSTRAINT.match(statement)
        if match:
            objects.add(
                SchemaObject(
                    "constraint", f"{_qualified(match.group(1))}.{_identifier(match.group(2))}"
                )
            )
            continue
        match = _ALTER_COLUMN.match(statement)
        if match:
            objects.add(
                SchemaObject(
                    "column", f"{_qualified(match.group(1))}.{_identifier(match.group(2))}"
                )
            )
            continue
        if match := _CREATE_INDEX.match(statement):
            table = _qualified(match.group(2))
            index = _qualified(match.group(1), default_schema=table.split(".", 1)[0])
            objects.add(SchemaObject("index", index))
    return frozenset(objects)


def _diagnostic(path: str, item: SchemaObject) -> Diagnostic:
    return Diagnostic(
        rule_id=_RULE_ID,
        rule_version=1,
        severity="warning",
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind=f"postgresql-{item.kind}",
        observed=f"generated schema adds {item.kind} {item.identity}",
        expected="the same pull-request diff contains an authored SQL migration for this object",
        message=(
            f"Generated PostgreSQL {item.kind} {item.identity} has no authored migration in "
            "this diff."
        ),
        path=path,
        manifest_anchor=path,
        remediation=Remediation(
            summary="Add the authored migration or remove stale generated schema output.",
            steps=("Create the object in a tracked SQL migration under a migrations directory.",),
            validation=(
                "Regenerate the schema and rerun the provenance check against the same SHAs.",
            ),
        ),
        location=SourceLocation(path=path),
        observed_value={"kind": item.kind, "identity": item.identity},
        expected_value={"migration_in_diff": True},
    )


def _is_generated_schema(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.name.casefold() in _SCHEMA_BASENAMES and "migrations" not in {
        part.casefold() for part in pure.parts
    }


def _is_migration(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.suffix.casefold() == ".sql" and "migrations" in {
        part.casefold() for part in pure.parts
    }


def _migration_applies(*, schema_path: str, migration_path: str) -> bool:
    schema_parent = PurePosixPath(schema_path).parent.parts
    migration_parts = PurePosixPath(migration_path).parts
    return migration_parts[: len(schema_parent)] == schema_parent


def _revision(root: Path, revision: str) -> str:
    if not revision:
        ConfigurationError.fail("base and head revisions must be non-empty")
    return _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()


def _changed_paths(root: Path, base: str, head: str) -> tuple[tuple[str, str], ...]:
    output = _git(root, "diff", "--name-status", "-z", "--no-renames", base, head, "--")
    fields = output.split(b"\0")
    records: list[tuple[str, str]] = []
    for index in range(0, len(fields) - 1, 2):
        status = fields[index].decode("ascii", errors="replace")
        path = fields[index + 1].decode("utf-8", errors="surrogateescape")
        if status and path:
            records.append((status, path))
    return tuple(records)


def _blob(root: Path, revision: str, path: str) -> bytes:
    return _git(root, "show", "--no-ext-diff", "--no-textconv", f"{revision}:{path}")


def _git(root: Path, *arguments: str) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required for generated schema provenance analysis")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed read-only Git invocation
            [executable, "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            timeout=30,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        ConfigurationError.fail("Git could not complete generated schema provenance analysis")
    if completed.returncode != 0:
        ConfigurationError.fail("Git could not resolve generated schema provenance inputs")
    return completed.stdout


def _identifier(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith('"'):
        return stripped[1:-1].replace('""', '"')
    return stripped.casefold()


def _qualified(value: str, *, default_schema: str = "public") -> str:
    parts = _qualified_parts(value)
    if len(parts) == 1:
        return f"{default_schema}.{_identifier(parts[0])}"
    return f"{_identifier(parts[0])}.{_identifier(parts[1])}"


def _qualified_parts(value: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    quoted = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == '"':
            if quoted and index + 1 < len(value) and value[index + 1] == '"':
                index += 2
                continue
            quoted = not quoted
        elif char == "." and not quoted:
            parts.append(value[start:index].strip())
            start = index + 1
        index += 1
    parts.append(value[start:].strip())
    return tuple(parts)


def _leading_identifier(value: str) -> str | None:
    match = re.match(rf"\s*({_IDENTIFIER})", value)
    return match.group(1) if match else None


def _statements(  # ruff: ignore[too-many-branches] - SQL lexer states
    text: str,
) -> tuple[str, ...]:
    statements: list[str] = []
    start = 0
    index = 0
    quote: str | None = None
    dollar: str | None = None
    while index < len(text):
        if dollar is not None:
            if text.startswith(dollar, index):
                index += len(dollar)
                dollar = None
            else:
                index += 1
            continue
        if quote is not None:
            if text[index] == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if text.startswith("--", index):
            end = text.find("\n", index)
            next_index = len(text) if end < 0 else end + 1
            if not text[start:index].strip():
                start = next_index
            index = next_index
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            next_index = len(text) if end < 0 else end + 2
            if not text[start:index].strip():
                start = next_index
            index = next_index
            continue
        char = text[index]
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "$" and (match := re.match(r"\$[A-Za-z_0-9]*\$", text[index:])):
            dollar = match.group(0)
            index += len(dollar)
            continue
        if char == ";":
            statements.append(text[start:index])
            start = index + 1
        index += 1
    if text[start:].strip():
        statements.append(text[start:])
    return tuple(statements)


def _matching_parenthesis(value: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    for index in range(opening, len(value)):
        char = value[index]
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _comma_parts(value: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    for index, char in enumerate(value):
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return tuple(parts)
