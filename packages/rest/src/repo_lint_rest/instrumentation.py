"""Inert REST instrumentation discovery and operation-map validation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import Literal, NoReturn, cast  # ruff: ignore[banned-api] - checks precede narrowing


type Language = Literal["artifact", "python", "typescript", "java", "go", "rust"]
type StaticCoverage = Literal["committed-contract", "operation-identity-map", "manifest-candidate"]
type TrustRequirement = Literal["not-required", "required-for-runtime-evidence"]
type SupportLevel = Literal["stable", "preview", "experimental"]
type RuntimeIntegration = Literal["not-applicable", "preview", "unsupported"]
type DetectionCompletion = Literal["complete", "incomplete"]
type EvidenceKind = Literal[
    "manifest-dependency", "manifest-project", "committed-spec", "operation-map"
]
type EvidenceTriple = tuple[str, EvidenceKind, str]

_MAX_FILES = 1_000
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 20 * 1024 * 1024
_MAX_OPERATION_MAP_BYTES = 2 * 1024 * 1024
_MAX_OPERATIONS = 10_000
_MAX_ROUTE_LENGTH = 2_048
_MIN_REQUIRE_PARTS = 2
_SPACE_ORDINAL = 0x20
_DELETE_ORDINAL = 0x7F
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
_PEP508_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")
_GRADLE_COORDINATE_RE = re.compile(
    r'^\s*(?:api|implementation|compileOnly|runtimeOnly)\s*(?:\(\s*)?["\']'
    r"(org\.springdoc:[A-Za-z0-9_.-]+)(?::[^\"']+)?[\"']"
)
_POM_DEPENDENCY_RE = re.compile(r"<dependency\b[^>]*>(.*?)</dependency\s*>", re.DOTALL)
_POM_GROUP_RE = re.compile(r"<groupId\b[^>]*>\s*([^<\s]+)\s*</groupId\s*>")
_POM_ARTIFACT_RE = re.compile(r"<artifactId\b[^>]*>\s*([^<\s]+)\s*</artifactId\s*>")
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTTP_METHODS = frozenset(
    {"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "QUERY"}
)
_CONVENTIONAL_SPEC_NAMES = frozenset(
    {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"}
)
_CONVENTIONAL_OPERATION_MAP_NAME = "api-operation-map.json"


class InstrumentationInputError(ValueError):
    """A caller-supplied byte collection or operation map is invalid."""

    @classmethod
    def fail(cls, message: str, *, cause: Exception | None = None) -> NoReturn:
        if cause is None:
            raise cls(message)
        raise cls(message) from cause


@dataclass(frozen=True, slots=True)
class TrackedFile:
    """One immutable tracked file supplied by the caller."""

    path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class InstrumentationCapability:
    """Source-derived support metadata for one REST integration."""

    capability_id: str
    language: Language
    framework: str
    support: SupportLevel
    runtime_integration: RuntimeIntegration
    static_coverage: StaticCoverage
    trust: TrustRequirement
    setup_guidance: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectionEvidence:
    """Exact inert evidence for a capability candidate."""

    path: str
    kind: EvidenceKind
    value: str


@dataclass(frozen=True, slots=True)
class DetectedInstrumentation:
    """One candidate with all supporting evidence preserved."""

    capability: InstrumentationCapability
    evidence: tuple[DetectionEvidence, ...]


@dataclass(frozen=True, slots=True)
class DetectionIssue:
    """One manifest or conventional-spec input that could not be inspected."""

    code: str
    path: str
    message: str


@dataclass(frozen=True, slots=True)
class InstrumentationDetectionReport:
    """Deterministic zero-config capability detection result."""

    schema_version: int
    completion: DetectionCompletion
    candidates: tuple[DetectedInstrumentation, ...]
    issues: tuple[DetectionIssue, ...]
    files_scanned: int
    bytes_scanned: int


@dataclass(frozen=True, slots=True)
class RuntimeOperation:
    """One stable operation identity bound to a runtime route key."""

    operation_id: str
    method: str
    route_template: str


@dataclass(frozen=True, slots=True)
class ApiOperationMap:
    """A bounded operation-to-runtime binding for one exact OpenAPI document."""

    schema_version: Literal["api-operation-map.v1"]
    openapi_sha256: str
    operations: tuple[RuntimeOperation, ...]


def _framework_capability(  # ruff: ignore[too-many-arguments] - immutable capability fields
    capability_id: str,
    language: Language,
    framework: str,
    *,
    limitation: str,
    guidance: str,
    preview: bool = False,
) -> InstrumentationCapability:
    return InstrumentationCapability(
        capability_id=capability_id,
        language=language,
        framework=framework,
        support="preview" if preview else "experimental",
        runtime_integration="preview" if preview else "unsupported",
        static_coverage="manifest-candidate",
        trust="required-for-runtime-evidence",
        setup_guidance=(guidance, "Run trusted export only for reviewed application code."),
        limitations=(
            limitation,
            "Manifest evidence does not prove that a dependency is used by a mounted application.",
        ),
    )


_CAPABILITIES: tuple[InstrumentationCapability, ...] = tuple(
    sorted(
        (
            InstrumentationCapability(
                "committed-openapi",
                "artifact",
                "OpenAPI",
                "stable",
                "not-applicable",
                "committed-contract",
                "not-required",
                (
                    "Analyze the committed document as inert bytes.",
                    "Add a trusted exporter later only when runtime drift evidence is required.",
                ),
                (
                    "A committed document does not prove that runtime routes implement it.",
                    "Swagger 2 documents require an explicit versioned conversion lane.",
                ),
            ),
            InstrumentationCapability(
                "operation-map",
                "artifact",
                "API operation map",
                "stable",
                "not-applicable",
                "operation-identity-map",
                "not-required",
                ("Bind stable operation IDs to normalized runtime route keys.",),
                ("The map does not discover routes or prove runtime instrumentation coverage.",),
            ),
            _framework_capability(
                "fastapi",
                "python",
                "FastAPI",
                limitation=(
                    "Manifest detection is inert; AST route coverage and trusted export remain "
                    "preview."
                ),
                guidance=(
                    "Provide reviewed application bytes before enabling preview AST discovery."
                ),
                preview=True,
            ),
            _framework_capability(
                "django-drf-spectacular",
                "python",
                "Django REST Framework with drf-spectacular",
                limitation=(
                    "Django settings, URL configuration, and schema generation are not imported."
                ),
                guidance=(
                    "Provide a reviewed drf-spectacular export command with explicit settings."
                ),
            ),
            _framework_capability(
                "flask-smorest",
                "python",
                "flask-smorest",
                limitation=(
                    "Blueprint registration and Flask application factories are not imported."
                ),
                guidance=(
                    "Provide a reviewed exporter that constructs the schema without listening."
                ),
            ),
            _framework_capability(
                "nestjs",
                "typescript",
                "NestJS",
                limitation=(
                    "Decorators, compiler plugins, dependency injection, and modules are not run."
                ),
                guidance="Provide a reviewed SwaggerModule.createDocument exporter.",
            ),
            _framework_capability(
                "express",
                "typescript",
                "Express",
                limitation=(
                    "Express has no native complete OpenAPI contract or stable router traversal "
                    "API."
                ),
                guidance=(
                    "Commit an authored contract or provide an application-owned schema exporter."
                ),
            ),
            _framework_capability(
                "hono",
                "typescript",
                "Hono",
                limitation="Route and schema modules, including Zod refinements, are not imported.",
                guidance="Prefer a reviewed OpenAPIHono or application-owned contract exporter.",
            ),
            _framework_capability(
                "springdoc",
                "java",
                "Spring with springdoc-openapi",
                limitation=(
                    "Spring configuration, bean discovery, annotations, and context are not run."
                ),
                guidance="Provide a reviewed build/runtime schema export isolated from services.",
            ),
            _framework_capability(
                "go-net-http",
                "go",
                "net/http",
                limitation=(
                    "The standard-library router has no dependency marker and is not inferred from "
                    "source."
                ),
                guidance=(
                    "Declare a service profile and provide an operation map or reviewed exporter."
                ),
            ),
            _framework_capability(
                "go-chi",
                "go",
                "chi",
                limitation="Router construction and chi.Walk are not executed.",
                guidance="Provide a reviewed exporter using chi's public route traversal API.",
            ),
            _framework_capability(
                "go-gin",
                "go",
                "Gin",
                limitation="Router construction and Engine.Routes are not executed.",
                guidance="Provide a reviewed exporter using Engine.Routes plus an OpenAPI source.",
            ),
            _framework_capability(
                "go-echo",
                "go",
                "Echo",
                limitation="Router construction and Echo.Routes are not executed.",
                guidance=(
                    "Provide a reviewed exporter using route enumeration plus an OpenAPI source."
                ),
            ),
            _framework_capability(
                "go-huma",
                "go",
                "Huma",
                limitation="Typed operation registration and schema generation are not executed.",
                guidance="Provide a reviewed exporter that marshals the Huma OpenAPI document.",
            ),
            _framework_capability(
                "rust-axum",
                "rust",
                "Axum",
                limitation=(
                    "Cargo, build scripts, procedural macros, and Router construction are not run."
                ),
                guidance="Provide a reviewed code-first exporter or operation map.",
            ),
            _framework_capability(
                "rust-actix",
                "rust",
                "Actix Web",
                limitation="Cargo, route attributes, factories, guards, and macros are not run.",
                guidance="Provide a reviewed collecting-wrapper or code-first exporter.",
            ),
            _framework_capability(
                "rust-rocket",
                "rust",
                "Rocket",
                limitation="Cargo, route macros, mounts, ranks, and guards are not run.",
                guidance="Provide a reviewed exporter with explicit ranked-route handling.",
            ),
            _framework_capability(
                "rust-utoipa",
                "rust",
                "utoipa",
                limitation="Cargo and utoipa derive/path procedural macros are not run.",
                guidance="Provide a reviewed exporter that serializes ApiDoc::openapi().",
            ),
        ),
        key=lambda item: item.capability_id,
    )
)
_CAPABILITY_BY_ID = {item.capability_id: item for item in _CAPABILITIES}

_PYTHON_DEPENDENCIES = {
    "fastapi": "fastapi",
    "drf-spectacular": "django-drf-spectacular",
    "flask-smorest": "flask-smorest",
}
_NPM_DEPENDENCIES = {"@nestjs/core": "nestjs", "express": "express", "hono": "hono"}
_GO_DEPENDENCIES = {
    "github.com/go-chi/chi": "go-chi",
    "github.com/go-chi/chi/v5": "go-chi",
    "github.com/gin-gonic/gin": "go-gin",
    "github.com/labstack/echo/v4": "go-echo",
    "github.com/danielgtaylor/huma/v2": "go-huma",
}
_RUST_DEPENDENCIES = {
    "axum": "rust-axum",
    "actix-web": "rust-actix",
    "rocket": "rust-rocket",
    "utoipa": "rust-utoipa",
}


def instrumentation_capabilities() -> tuple[InstrumentationCapability, ...]:
    """Return the closed v1 capability registry in stable ID order."""
    return _CAPABILITIES


def detect_instrumentation(files: tuple[TrackedFile, ...]) -> InstrumentationDetectionReport:
    """Detect candidates from caller-supplied manifests and conventional specs only."""
    ordered, total_bytes = _validate_files(files)
    evidence_by_id: dict[str, set[DetectionEvidence]] = {}
    issues: list[DetectionIssue] = []
    for tracked in ordered:
        basename = PurePosixPath(tracked.path).name.lower()
        try:
            detected = _detect_file(tracked, basename)
        except (
            InstrumentationInputError,
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
            UnicodeDecodeError,
        ) as error:
            if _is_relevant_manifest(basename):
                issues.append(
                    DetectionIssue(
                        "instrumentation.manifest-invalid",
                        tracked.path,
                        f"cannot parse {basename}: {type(error).__name__}",
                    )
                )
            continue
        for capability_id, kind, value in detected:
            evidence_by_id.setdefault(capability_id, set()).add(
                DetectionEvidence(tracked.path, kind, value)
            )
    candidates = tuple(
        DetectedInstrumentation(
            _CAPABILITY_BY_ID[capability_id],
            tuple(sorted(evidence, key=lambda item: (item.path, item.kind, item.value))),
        )
        for capability_id, evidence in sorted(evidence_by_id.items())
    )
    ordered_issues = tuple(sorted(issues, key=lambda item: (item.path, item.code, item.message)))
    return InstrumentationDetectionReport(
        1,
        "incomplete" if ordered_issues else "complete",
        candidates,
        ordered_issues,
        len(ordered),
        total_bytes,
    )


def _validate_files(files: tuple[TrackedFile, ...]) -> tuple[tuple[TrackedFile, ...], int]:
    if len(files) > _MAX_FILES:
        InstrumentationInputError.fail(f"tracked file count exceeds {_MAX_FILES}")
    paths: set[str] = set()
    total = 0
    for tracked in files:
        path = PurePosixPath(tracked.path)
        if (
            not tracked.path
            or "\\" in tracked.path
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != tracked.path
        ):
            InstrumentationInputError.fail("tracked file path must be canonical and relative")
        if tracked.path in paths:
            InstrumentationInputError.fail("tracked file paths must be unique")
        paths.add(tracked.path)
        size = len(tracked.content)
        if size > _MAX_FILE_BYTES:
            InstrumentationInputError.fail(f"tracked file {tracked.path!r} exceeds byte limit")
        total += size
        if total > _MAX_TOTAL_BYTES:
            InstrumentationInputError.fail(f"tracked file bytes exceed {_MAX_TOTAL_BYTES}")
    return tuple(sorted(files, key=lambda item: item.path)), total


def _is_relevant_manifest(basename: str) -> bool:
    return basename in {
        "package.json",
        "pyproject.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "cargo.toml",
        _CONVENTIONAL_OPERATION_MAP_NAME,
        *_CONVENTIONAL_SPEC_NAMES,
    } or basename.startswith("requirements")


def _detect_file(tracked: TrackedFile, basename: str) -> tuple[EvidenceTriple, ...]:
    result: tuple[EvidenceTriple, ...]
    if basename == _CONVENTIONAL_OPERATION_MAP_NAME:
        operation_map = parse_api_operation_map(tracked.content)
        result = (("operation-map", "operation-map", operation_map.openapi_sha256),)
    elif basename in _CONVENTIONAL_SPEC_NAMES:
        marker = _spec_marker(tracked.content, basename)
        result = (("committed-openapi", "committed-spec", marker),) if marker is not None else ()
    elif basename == "package.json":
        result = _mapped_manifest(
            _package_json_dependencies(tracked.content),
            _package_json_project_name(tracked.content),
            _NPM_DEPENDENCIES,
        )
    elif basename == "pyproject.toml":
        result = _mapped_manifest(
            _pyproject_dependencies(tracked.content),
            _pyproject_project_name(tracked.content),
            _PYTHON_DEPENDENCIES,
        )
    elif basename.startswith("requirements") and basename.endswith((".txt", ".in")):
        result = _mapped_dependencies(
            _requirements_dependencies(tracked.content), _PYTHON_DEPENDENCIES
        )
    elif basename == "pom.xml":
        springdoc = sorted(
            item for item in _pom_dependencies(tracked.content) if item.startswith("org.springdoc:")
        )
        result = tuple(("springdoc", "manifest-dependency", item) for item in springdoc)
    elif basename in {"build.gradle", "build.gradle.kts"}:
        result = tuple(
            ("springdoc", "manifest-dependency", item)
            for item in _gradle_dependencies(tracked.content)
        )
    elif basename == "go.mod":
        result = _mapped_dependencies(_go_dependencies(tracked.content), _GO_DEPENDENCIES)
    elif basename == "cargo.toml":
        result = _mapped_dependencies(_cargo_dependencies(tracked.content), _RUST_DEPENDENCIES)
    else:
        result = ()
    return result


def _mapped_dependencies(
    dependencies: set[str], mapping: dict[str, str]
) -> tuple[EvidenceTriple, ...]:
    return tuple(
        sorted(
            (mapping[dependency], "manifest-dependency", dependency)
            for dependency in dependencies
            if dependency in mapping
        )
    )


def _mapped_manifest(
    dependencies: set[str], project_name: str | None, mapping: dict[str, str]
) -> tuple[EvidenceTriple, ...]:
    result = list(_mapped_dependencies(dependencies, mapping))
    if project_name in mapping:
        result.append((mapping[project_name], "manifest-project", project_name))
    return tuple(sorted(result))


def _json_object(content: bytes) -> dict[str, object]:
    parsed: object = json.loads(  # pyright: ignore[reportAny]
        content.decode("utf-8"), object_pairs_hook=_duplicate_object
    )
    result = _mapping(parsed)
    if result is None:
        InstrumentationInputError.fail("JSON manifest root must be an object")
    return result


def _duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            InstrumentationInputError.fail("JSON contains a duplicate object key")
        result[key] = value
    return result


def _package_json_dependencies(content: bytes) -> set[str]:
    root = _json_object(content)
    dependencies: set[str] = set()
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        value = root.get(field)
        dependency_map = _mapping(value)
        if dependency_map is not None:
            dependencies.update(dependency_map)
    return dependencies


def _package_json_project_name(content: bytes) -> str | None:
    name = _json_object(content).get("name")
    return name if isinstance(name, str) else None


def _toml_object(content: bytes) -> dict[str, object]:
    return cast("dict[str, object]", tomllib.loads(content.decode("utf-8")))


def _dependency_name(requirement: str) -> str | None:
    match = _PEP508_NAME_RE.match(requirement)
    if match is None:
        return None
    return match.group(1).lower().replace("_", "-").replace(".", "-")


def _mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw = cast("dict[object, object]", value)
    if not all(isinstance(key, str) for key in raw):
        return None
    return {key: item for key, item in raw.items() if isinstance(key, str)}


def _pyproject_dependencies(content: bytes) -> set[str]:
    root = _toml_object(content)
    result: set[str] = set()
    project = _mapping(root.get("project"))
    if project is not None:
        requirements = list(_string_list(project.get("dependencies")))
        optional = _mapping(project.get("optional-dependencies"))
        if optional is not None:
            for value in optional.values():
                requirements.extend(_string_list(value))
        result.update(name for item in requirements if (name := _dependency_name(item)) is not None)
    tool = _mapping(root.get("tool"))
    poetry = _mapping(tool.get("poetry")) if tool is not None else None
    poetry_dependencies = _mapping(poetry.get("dependencies")) if poetry is not None else None
    if poetry_dependencies is not None:
        result.update(_dependency_name(name) or "" for name in poetry_dependencies)
        result.discard("")
    return result


def _pyproject_project_name(content: bytes) -> str | None:
    project = _mapping(_toml_object(content).get("project"))
    if project is None:
        return None
    name = project.get("name")
    return _dependency_name(name) if isinstance(name, str) else None


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in cast("list[object]", value) if isinstance(item, str))


def _requirements_dependencies(content: bytes) -> set[str]:
    result: set[str] = set()
    for raw_line in content.decode("utf-8").splitlines():
        line = raw_line.split("#", maxsplit=1)[0].strip()
        if not line or line.startswith(("-", "http:", "https:", "git+")):
            continue
        name = _dependency_name(line)
        if name is not None:
            result.add(name)
    return result


def _pom_dependencies(content: bytes) -> set[str]:
    text = _XML_COMMENT_RE.sub("", content.decode("utf-8"))
    result: set[str] = set()
    for block_match in _POM_DEPENDENCY_RE.finditer(text):
        block = block_match.group(1)
        group_match = _POM_GROUP_RE.search(block)
        artifact_match = _POM_ARTIFACT_RE.search(block)
        if group_match is None or artifact_match is None:
            continue
        result.add(f"{group_match.group(1)}:{artifact_match.group(1)}")
    return result


def _gradle_dependencies(content: bytes) -> tuple[str, ...]:
    result: set[str] = set()
    in_block_comment = False
    for raw_line in content.decode("utf-8").splitlines():
        line = raw_line.strip()
        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
            continue
        if line.startswith("/*"):
            in_block_comment = "*/" not in line
            continue
        if line.startswith(("//", "#")):
            continue
        if match := _GRADLE_COORDINATE_RE.match(raw_line):
            result.add(match.group(1))
    return tuple(sorted(result))


def _go_dependencies(content: bytes) -> set[str]:
    result: set[str] = set()
    in_require = False
    for raw_line in content.decode("utf-8").splitlines():
        line = raw_line.split("//", maxsplit=1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        parts = line.split()
        if in_require and parts:
            result.add(parts[0])
        elif len(parts) >= _MIN_REQUIRE_PARTS and parts[0] == "require":
            result.add(parts[1])
    return result


def _cargo_dependencies(content: bytes) -> set[str]:
    root = _toml_object(content)
    result: set[str] = set()

    def visit(value: object, path: tuple[str, ...]) -> None:
        current = _mapping(value)
        if current is None:
            return
        if path and path[-1] == "dependencies":
            for name, declaration in current.items():
                details = _mapping(declaration)
                package = details.get("package") if details is not None else None
                result.add(package if isinstance(package, str) else name)
            return
        for key, child in current.items():
            if key in {"dev-dependencies", "build-dependencies"}:
                continue
            visit(child, (*path, key))

    visit(root, ())
    return result


def _spec_marker(content: bytes, basename: str) -> str | None:
    marker: str | None = None
    if basename.endswith(".json"):
        root = _json_object(content)
        openapi = root.get("openapi")
        if isinstance(openapi, str) and openapi.startswith("3."):
            marker = f"openapi:{openapi}"
        else:
            swagger = root.get("swagger")
            if isinstance(swagger, str) and swagger == "2.0":
                marker = "swagger:2.0"
    else:
        marker = _yaml_spec_marker(content)
    return marker


def _yaml_spec_marker(content: bytes) -> str | None:
    for raw_line in content.decode("utf-8").splitlines()[:32]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if match := re.fullmatch(r"openapi:\s*[\"']?(3\.[0-9.]+)[\"']?", line):
            return f"openapi:{match.group(1)}"
        if re.fullmatch(r"swagger:\s*[\"']?2\.0[\"']?", line):
            return "swagger:2.0"
        break
    return None


def parse_api_operation_map(content: bytes) -> ApiOperationMap:
    """Parse and validate a bounded ``api-operation-map.v1`` JSON document."""
    if len(content) > _MAX_OPERATION_MAP_BYTES:
        InstrumentationInputError.fail("operation map exceeds byte limit")
    try:
        root = _json_object(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        InstrumentationInputError.fail("cannot parse operation map JSON", cause=error)
    if set(root) != {"schema_version", "openapi_sha256", "operations"}:
        InstrumentationInputError.fail("operation map keys must match api-operation-map.v1")
    if root["schema_version"] != "api-operation-map.v1":
        InstrumentationInputError.fail("operation map schema_version must be api-operation-map.v1")
    digest = root["openapi_sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        InstrumentationInputError.fail("operation map openapi_sha256 must be lowercase SHA-256")
    raw_operations = root["operations"]
    if not isinstance(raw_operations, list):
        InstrumentationInputError.fail("operation map operations must be an array")
    raw_operation_list = cast("list[object]", raw_operations)
    if len(raw_operation_list) > _MAX_OPERATIONS:
        InstrumentationInputError.fail(f"operation count exceeds {_MAX_OPERATIONS}")
    operations: list[RuntimeOperation] = []
    operation_ids: set[str] = set()
    runtime_keys: set[tuple[str, str]] = set()
    for index, raw_operation in enumerate(raw_operation_list):
        parsed = _parse_runtime_operation(raw_operation, index)
        operation_id = parsed.operation_id
        if operation_id in operation_ids:
            InstrumentationInputError.fail("operation IDs must be unique")
        runtime_key = (parsed.method, parsed.route_template)
        if runtime_key in runtime_keys:
            InstrumentationInputError.fail("runtime method and route keys must be unique")
        operation_ids.add(operation_id)
        runtime_keys.add(runtime_key)
        operations.append(parsed)
    return ApiOperationMap(
        "api-operation-map.v1",
        digest,
        tuple(
            sorted(
                operations,
                key=lambda item: (item.method, item.route_template, item.operation_id),
            )
        ),
    )


def _parse_runtime_operation(raw_operation: object, index: int) -> RuntimeOperation:
    operation = _mapping(raw_operation)
    if operation is None or set(operation) != {"operation_id", "method", "route_template"}:
        InstrumentationInputError.fail(f"operations[{index}] has invalid keys")
    operation_id = operation["operation_id"]
    method = operation["method"]
    route = operation["route_template"]
    if not isinstance(operation_id, str) or _OPERATION_ID_RE.fullmatch(operation_id) is None:
        InstrumentationInputError.fail(f"operations[{index}].operation_id has invalid grammar")
    if not isinstance(method, str) or method not in _HTTP_METHODS:
        InstrumentationInputError.fail(
            f"operations[{index}].method must be a supported uppercase HTTP method"
        )
    if not isinstance(route, str) or not _valid_route_template(route):
        InstrumentationInputError.fail(f"operations[{index}].route_template is invalid")
    return RuntimeOperation(operation_id, method, route)


def _valid_route_template(route: str) -> bool:
    if not route.startswith("/") or len(route) > _MAX_ROUTE_LENGTH:
        return False
    if "?" in route or "#" in route:
        return False
    return not any(
        ord(character) < _SPACE_ORDINAL or ord(character) == _DELETE_ORDINAL for character in route
    )
