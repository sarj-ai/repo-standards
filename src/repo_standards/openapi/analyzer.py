from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
from pathlib import PurePosixPath
import posixpath
import re
from typing import (
    Literal,
    NamedTuple,
    NoReturn,
    cast,  # ruff: ignore[banned-api] - parser checks precede every narrowing
)
from urllib.parse import unquote, urlsplit

from pydantic import TypeAdapter, ValidationError

from .models import (
    AnalysisReport,
    AnalysisRequest,
    Diagnostic,
    DocumentInput,
    ExecutionIssue,
    Remediation,
    SourceLocation,
)


type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
_JSON_VALUE_ADAPTER: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_BYTES = 20 * 1024 * 1024
_MAX_DOCUMENTS = 100
_MAX_DEPTH = 64
_MAX_NODES = 100_000
_MAX_NUMERIC_TOKEN_LENGTH = 256
_MAX_POINTER_INDEX_LENGTH = 20
_MAX_DIAGNOSTICS = 5_000
_MAX_RENDERED_VALUE_LENGTH = 512
_HTTP_STATUS_WIDTH = 3
_INFORMATIONAL_START = 100
_SUCCESS_START = 200
_PARTIAL_CONTENT = 206
_NOT_MODIFIED = 304
_CLIENT_ERROR_START = 400
_SHA256_HEX_LENGTH = 64
_SEMANTICS_SCHEMA_VERSION = 2
_OAS_VERSION = re.compile(r"^3\.(?:0|1|2)\.\d+$")
_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace", "query"})
_PROBLEM_STRING_MEMBERS = frozenset({"type", "title", "detail", "instance"})


class _InputError(ValueError):
    @classmethod
    def fail(cls, message: str, *, cause: Exception | None = None) -> NoReturn:
        if cause is None:
            raise cls(message)
        raise cls(message) from cause


class _DuplicateKeyError(_InputError):
    pass


@dataclass(frozen=True, slots=True)
class _OperationSemantics:
    operation_ref: str
    error_profile: Literal["rfc9457"] | None


@dataclass(frozen=True, slots=True)
class _Artifact:
    pointer: str
    artifact: str
    role: str
    derived_from: str | None
    source_digest: str | None
    output_digest: str | None
    producer_name: str | None
    producer_version: str | None
    config_digest: str | None


@dataclass(frozen=True, slots=True)
class _Semantics:
    operations: tuple[_OperationSemantics, ...]
    artifacts: tuple[_Artifact, ...]


class _WalkEntry(NamedTuple):
    pointer: str
    value: JsonValue


class _ReferenceTarget(NamedTuple):
    document: str
    fragment: str


class _Operation(NamedTuple):
    method: str
    pointer: str
    operation: JsonObject
    path_item: JsonObject


class _OperationMapEntry(NamedTuple):
    method: str
    operation: JsonObject


class _Collector:
    entrypoint: str

    def __init__(self, entrypoint: str) -> None:
        self.entrypoint = entrypoint
        self.diagnostics: list[Diagnostic] = []
        self.issues: list[ExecutionIssue] = []

    def issue(self, code: str, phase: str, message: str, remediation: str) -> None:
        if len(self.issues) >= _MAX_DIAGNOSTICS:
            return
        self.issues.append(
            ExecutionIssue(
                code,
                phase,
                _bounded_text(message),
                (_bounded_text(remediation),),
            )
        )

    def finding(  # ruff: ignore[too-many-arguments] - one centralized diagnostic constructor
        self,
        *,
        rule_id: str,
        severity: Literal["warning", "error"],
        message: str,
        observed: str,
        expected: str,
        document: str,
        pointer: str,
        summary: str,
        steps: tuple[str, ...],
    ) -> None:
        if len(self.diagnostics) >= _MAX_DIAGNOSTICS:
            self.issue(
                "output.diagnostic-limit",
                "output",
                f"diagnostic count exceeds {_MAX_DIAGNOSTICS}",
                "Reduce the selected contract graph before analysis.",
            )
            return
        message = _bounded_text(message)
        observed = _bounded_text(observed)
        expected = _bounded_text(expected)
        pointer = _bounded_text(pointer)
        payload = {
            "document": document,
            "expected": expected,
            "observed": observed,
            "pointer": pointer,
            "rule_id": rule_id,
            "rule_version": 1,
        }
        fingerprint = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.diagnostics.append(
            Diagnostic(
                rule_id,
                1,
                severity,
                message,
                observed,
                expected,
                SourceLocation(document, pointer),
                Remediation(summary, steps, ("Run the same byte-for-byte analysis again.",)),
                fingerprint,
            )
        )


def _bounded_text(value: str) -> str:
    if len(value) <= _MAX_RENDERED_VALUE_LENGTH:
        return value
    digest = sha256(value.encode("utf-8", errors="replace")).hexdigest()
    retained = value[:_MAX_RENDERED_VALUE_LENGTH]
    return f"{retained}...[truncated length={len(value)} sha256={digest}]"


def analyze_bytes(
    content: bytes,
    *,
    name: str = "openapi.json",
    semantics: bytes | None = None,
    additional_documents: tuple[DocumentInput, ...] = (),
) -> AnalysisReport:
    request = AnalysisRequest(
        name, (DocumentInput(name, content), *additional_documents), semantics
    )
    return analyze(request)


def local_reference_paths(name: str, content: bytes) -> tuple[str, ...]:
    collector = _Collector(name)
    document = _parse_document(name, content, collector)
    if document is None:
        return ()
    targets: set[str] = set()
    for _pointer, value in _walk(document):
        if not isinstance(value, dict):
            continue
        reference = value.get("$ref")
        if not isinstance(reference, str):
            continue
        target = _reference_target(name, reference)
        if target is not None and target[0] != name:
            targets.add(target[0])
    return tuple(sorted(targets))


def analyze(request: AnalysisRequest) -> AnalysisReport:
    collector = _Collector(request.entrypoint)
    documents = _prepare_documents(request, collector)
    if documents is None:
        return _report(request.entrypoint, None, collector)
    parsed: dict[str, JsonObject] = {}
    entry = _parse_document(request.entrypoint, documents[request.entrypoint], collector)
    if entry is None:
        return _report(request.entrypoint, None, collector)
    parsed[request.entrypoint] = entry
    version = entry.get("openapi")
    if not isinstance(version, str):
        collector.issue(
            "openapi.not-document",
            "discovery",
            "entry document does not contain a string openapi version",
            "Select an OpenAPI entry document explicitly.",
        )
        return _report(request.entrypoint, None, collector)
    if _OAS_VERSION.fullmatch(version) is None:
        collector.issue(
            "openapi.version-unsupported",
            "discovery",
            f"OpenAPI version {version!r} is unsupported",
            "Use a configured 3.0, 3.1, or 3.2 validation lane.",
        )
        return _report(request.entrypoint, version, collector)
    _validate_prerequisite_shapes(request.entrypoint, entry, collector)
    if collector.issues:
        return _report(request.entrypoint, version, collector)

    _preflight_references(request.entrypoint, entry, documents, parsed, collector)
    semantics_data = _parse_semantics(request.semantics, collector)
    _check_http(request.entrypoint, entry, parsed, collector)
    if semantics_data is not None:
        _check_semantics(request.entrypoint, entry, parsed, semantics_data, collector)
        _check_artifacts(documents, semantics_data, collector)
    return _report(request.entrypoint, version, collector)


def _validate_prerequisite_shapes(name: str, root: JsonObject, collector: _Collector) -> None:
    info = root.get("info")
    paths = root.get("paths")
    if not isinstance(info, dict):
        collector.issue(
            "openapi.structure-invalid",
            "validation",
            f"document {name!r} has no Info Object",
            "Validate the document with the pinned upstream OpenAPI validator.",
        )
    if not isinstance(paths, dict):
        collector.issue(
            "openapi.structure-invalid",
            "validation",
            f"document {name!r} paths is not an object",
            "Validate the document with the pinned upstream OpenAPI validator.",
        )
        return
    for path_name, path_item in paths.items():
        if not isinstance(path_item, dict):
            collector.issue(
                "openapi.structure-invalid",
                "validation",
                f"Path Item {path_name!r} is not an object",
                "Validate the document with the pinned upstream OpenAPI validator.",
            )
            continue
        for method, operation in path_item.items():
            if method.lower() not in _METHODS:
                continue
            if not isinstance(operation, dict) or not isinstance(operation.get("responses"), dict):
                collector.issue(
                    "openapi.structure-invalid",
                    "validation",
                    f"operation {method.upper()} {path_name!r} has no Responses Object",
                    "Validate the document with the pinned upstream OpenAPI validator.",
                )


def _report(entrypoint: str, version: str | None, collector: _Collector) -> AnalysisReport:
    diagnostics = tuple(
        sorted(
            collector.diagnostics,
            key=lambda item: (
                item.location.document,
                item.location.json_pointer,
                item.rule_id,
                item.fingerprint,
            ),
        )
    )
    issues = tuple(sorted(collector.issues, key=lambda item: (item.phase, item.code, item.message)))
    completion: Literal["complete", "incomplete"] = "incomplete" if issues else "complete"
    conclusion: Literal["passed", "findings", "inconclusive"]
    if issues:
        conclusion = "inconclusive"
    elif diagnostics:
        conclusion = "findings"
    else:
        conclusion = "passed"
    return AnalysisReport(2, completion, conclusion, entrypoint, version, diagnostics, issues)


def _prepare_documents(request: AnalysisRequest, collector: _Collector) -> dict[str, bytes] | None:
    if len(request.documents) > _MAX_DOCUMENTS:
        collector.issue(
            "input.too-many-documents",
            "input",
            f"document count exceeds {_MAX_DOCUMENTS}",
            "Select a smaller explicit contract graph.",
        )
        return None
    result: dict[str, bytes] = {}
    total = 0
    for document in request.documents:
        try:
            name = _canonical_name(document.name)
        except _InputError as error:
            collector.issue("input.invalid-name", "input", str(error), "Use a relative POSIX path.")
            continue
        if name in result:
            collector.issue(
                "input.duplicate-document",
                "input",
                f"duplicate logical document {name!r}",
                "Supply each logical path exactly once.",
            )
            continue
        if len(document.content) > _MAX_FILE_BYTES:
            collector.issue(
                "input.file-too-large",
                "input",
                f"document {name!r} exceeds {_MAX_FILE_BYTES} bytes",
                "Split or reduce the contract before analysis.",
            )
            continue
        total += len(document.content)
        result[name] = document.content
    if total > _MAX_TOTAL_BYTES:
        collector.issue(
            "input.total-too-large",
            "input",
            f"aggregate bytes exceed {_MAX_TOTAL_BYTES}",
            "Select a smaller explicit contract graph.",
        )
    try:
        entrypoint = _canonical_name(request.entrypoint)
    except _InputError as error:
        collector.issue(
            "input.invalid-entrypoint", "input", str(error), "Use a relative POSIX path."
        )
        return None
    if entrypoint != request.entrypoint or entrypoint not in result:
        collector.issue(
            "input.entrypoint-missing",
            "input",
            f"entrypoint {request.entrypoint!r} is not supplied exactly",
            "Supply the selected entrypoint bytes under its canonical name.",
        )
    return None if collector.issues else result


def _canonical_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        _InputError.fail(f"invalid logical document name {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _InputError.fail(f"logical document name must be canonical and relative: {name!r}")
    canonical = path.as_posix()
    if canonical != name:
        _InputError.fail(f"logical document name is not canonical: {name!r}")
    return canonical


def _parse_document(name: str, content: bytes, collector: _Collector) -> JsonObject | None:
    stripped = content.lstrip()
    if not stripped.startswith((b"{", b"[")):
        collector.issue(
            "openapi.yaml-unsupported",
            "parse",
            f"document {name!r} is not JSON; YAML is unsupported by this package version",
            "Provide an equivalent JSON OpenAPI document or install a future safe YAML adapter.",
        )
        return None
    try:
        parsed = cast(
            "JsonValue",
            json.loads(
                content.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
                parse_float=_parse_json_float,
                parse_int=_parse_json_int,
            ),
        )
        _bound_json(parsed)
    except (
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
        _InputError,
        RecursionError,
    ) as error:
        collector.issue(
            "openapi.parse-failed",
            "parse",
            f"cannot parse {name!r}: {error}",
            "Correct the bounded JSON document.",
        )
        return None
    if not isinstance(parsed, dict):
        collector.issue(
            "openapi.root-invalid",
            "parse",
            f"document {name!r} root is not an object",
            "Use an OpenAPI Object or Schema Object at the document root.",
        )
        return None
    return cast("JsonObject", parsed)


def _reject_json_constant(value: str) -> NoReturn:
    _InputError.fail(f"non-finite JSON number is forbidden: {value}")


def _parse_json_int(value: str) -> int:
    if len(value) > _MAX_NUMERIC_TOKEN_LENGTH:
        _InputError.fail("JSON integer exceeds the numeric-token safety limit")
    return int(value)


def _parse_json_float(value: str) -> float:
    if len(value) > _MAX_NUMERIC_TOKEN_LENGTH:
        _InputError.fail("JSON number exceeds the numeric-token safety limit")
    result = float(value)
    if not math.isfinite(result):
        _InputError.fail("non-finite JSON number is forbidden")
    return result


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            _DuplicateKeyError.fail(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _bound_json(value: JsonValue) -> None:
    nodes = 0
    pending: list[tuple[JsonValue, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_NODES:
            _InputError.fail(f"JSON node count exceeds {_MAX_NODES}")
        if depth > _MAX_DEPTH:
            _InputError.fail(f"JSON depth exceeds {_MAX_DEPTH}")
        match current:
            case dict():
                pending.extend((item, depth + 1) for item in current.values())
            case list():
                pending.extend((item, depth + 1) for item in current)
            case _:
                pass


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _preflight_references(
    name: str,
    root: JsonObject,
    documents: dict[str, bytes],
    parsed: dict[str, JsonObject],
    collector: _Collector,
) -> None:
    queue: list[tuple[str, JsonObject]] = [(name, root)]
    visited = {name}
    while queue:
        source_name, document = queue.pop(0)
        for pointer, value in _walk(document):
            if not isinstance(value, dict) or "$ref" not in value:
                continue
            reference = value["$ref"]
            ref_pointer = f"{pointer}/$ref"
            if not isinstance(reference, str):
                collector.finding(
                    rule_id="api/references/local-resolution",
                    severity="error",
                    message="$ref must be a string URI reference",
                    observed=repr(reference),
                    expected="a relative local URI reference",
                    document=source_name,
                    pointer=ref_pointer,
                    summary="Use a string local reference.",
                    steps=("Replace the value with a relative local $ref.",),
                )
                continue
            target = _reference_target(source_name, reference)
            if target is None:
                collector.finding(
                    rule_id="api/references/local-resolution",
                    severity="error",
                    message="$ref crosses the bounded local-document graph",
                    observed=reference,
                    expected="a relative reference inside the supplied document graph",
                    document=source_name,
                    pointer=ref_pointer,
                    summary="Make the reference hermetic.",
                    steps=(
                        "Move the target under the contract root.",
                        "Use a relative local $ref.",
                    ),
                )
                continue
            target_name, fragment = target
            if target_name not in documents:
                collector.finding(
                    rule_id="api/references/local-resolution",
                    severity="error",
                    message="$ref target was not supplied",
                    observed=target_name,
                    expected="a supplied local document",
                    document=source_name,
                    pointer=ref_pointer,
                    summary="Supply the immutable target document.",
                    steps=("Add the exact tracked target bytes to the analysis request.",),
                )
                continue
            if target_name not in parsed:
                parsed_target = _parse_document(target_name, documents[target_name], collector)
                if parsed_target is None:
                    continue
                parsed[target_name] = parsed_target
            if fragment and _resolve_pointer(parsed[target_name], fragment) is None:
                collector.finding(
                    rule_id="api/references/local-resolution",
                    severity="error",
                    message="$ref JSON Pointer does not resolve",
                    observed=fragment,
                    expected="an existing JSON Pointer",
                    document=source_name,
                    pointer=ref_pointer,
                    summary="Correct the local JSON Pointer.",
                    steps=("Point to an existing object in the supplied target document.",),
                )
            if target_name not in visited:
                visited.add(target_name)
                queue.append((target_name, parsed[target_name]))


def _walk(value: JsonValue, pointer: str = "") -> list[_WalkEntry]:
    result = [_WalkEntry(pointer, value)]
    match value:
        case dict():
            for key, item in value.items():
                if key in {"default", "example", "examples"} or key.startswith("x-"):
                    continue
                result.extend(_walk(item, f"{pointer}/{_pointer_token(str(key))}"))
        case list():
            for index, item in enumerate(value):
                result.extend(_walk(item, f"{pointer}/{index}"))
        case _:
            pass
    return result


def _reference_target(source_name: str, reference: str) -> _ReferenceTarget | None:
    try:
        split = urlsplit(reference)
    except ValueError:
        return None
    if split.scheme or split.netloc or split.query:
        return None
    decoded = unquote(split.path)
    if "\\" in decoded or decoded.startswith("/"):
        return None
    base = posixpath.dirname(source_name)
    normalized = posixpath.normpath(posixpath.join(base, decoded)) if decoded else source_name
    if normalized == ".." or normalized.startswith(("../", "/")):
        return None
    try:
        target_name = _canonical_name(normalized)
    except _InputError:
        return None
    return _ReferenceTarget(target_name, unquote(split.fragment))


def _resolve_pointer(root: JsonValue, fragment: str) -> JsonValue | None:
    if not fragment:
        return root
    if not fragment.startswith("/"):
        return None
    current = root
    for raw_token in fragment[1:].split("/"):
        if "~" in raw_token.replace("~0", "").replace("~1", ""):
            return None
        token = raw_token.replace("~1", "/").replace("~0", "~")
        match current:
            case dict() if token in current:
                current = current[token]
            case list() if (
                len(token) <= _MAX_POINTER_INDEX_LENGTH
                and token.isdigit()
                and int(token) < len(current)
            ):
                current = current[int(token)]
            case _:
                return None
    return current


def _operations(root: JsonObject) -> list[_Operation]:
    paths = root.get("paths")
    if not isinstance(paths, dict):
        return []
    result: list[_Operation] = []
    for path_name, raw_path_item in paths.items():
        if not isinstance(raw_path_item, dict):
            continue
        path_item = cast("JsonObject", raw_path_item)
        path_pointer = f"/paths/{_pointer_token(str(path_name))}"
        for method, raw_operation in path_item.items():
            lowered = method.lower()
            if lowered not in _METHODS or not isinstance(raw_operation, dict):
                continue
            result.append(
                _Operation(
                    lowered,
                    f"{path_pointer}/{_pointer_token(method)}",
                    cast("JsonObject", raw_operation),
                    path_item,
                )
            )
    return result


def _response_status(value: str) -> int | None:
    return int(value) if len(value) == _HTTP_STATUS_WIDTH and value.isdigit() else None


def _check_http(
    name: str,
    root: JsonObject,
    parsed: dict[str, JsonObject],
    collector: _Collector,
) -> None:
    for method, pointer, operation, _path_item in _operations(root):
        if method == "trace" and operation.get("requestBody") is not None:
            collector.finding(
                rule_id="api/http/message-semantics",
                severity="error",
                message="TRACE must not declare a request body",
                observed="requestBody is present",
                expected="no requestBody field",
                document=name,
                pointer=f"{pointer}/requestBody",
                summary="Remove TRACE request content.",
                steps=("Remove the requestBody from the TRACE operation.",),
            )
        responses = operation.get("responses")
        if not isinstance(responses, dict):
            continue
        for response_key, raw_response in responses.items():
            if not isinstance(raw_response, dict):
                continue
            response = _resolve_local_object(name, raw_response, parsed)
            if response is None:
                continue
            response_pointer = f"{pointer}/responses/{_pointer_token(str(response_key))}"
            status = _response_status(str(response_key))
            content = response.get("content")
            forbidden_status = status is not None and (
                _INFORMATIONAL_START <= status < _SUCCESS_START
                or status in {204, 205, _NOT_MODIFIED}
            )
            wildcard_1xx = str(response_key).upper() == "1XX"
            if (
                isinstance(content, dict)
                and content
                and (method == "head" or forbidden_status or wildcard_1xx)
            ):
                content_count = len(content)
                collector.finding(
                    rule_id="api/http/message-semantics",
                    severity="error",
                    message="response content is forbidden by HTTP semantics",
                    observed=(
                        f"method={method}, status={response_key}, content entries={content_count}"
                    ),
                    expected="no response content",
                    document=name,
                    pointer=f"{response_pointer}/content",
                    summary="Remove the forbidden response content.",
                    steps=("Keep response headers and links if needed.", "Remove the content map."),
                )
            if status == _NOT_MODIFIED and method not in {"get", "head"}:
                _status_contradiction(name, collector, method, status, response_pointer)
            if status == _PARTIAL_CONTENT and method != "get":
                _status_contradiction(name, collector, method, status, response_pointer)


def _status_contradiction(
    name: str, collector: _Collector, method: str, status: int, pointer: str
) -> None:
    allowed = "GET or HEAD" if status == _NOT_MODIFIED else "GET"
    collector.finding(
        rule_id="api/http/message-semantics",
        severity="error",
        message=f"status {status} cannot describe a {method.upper()} response",
        observed=f"{method.upper()} {status}",
        expected=f"status {status} only on {allowed}",
        document=name,
        pointer=pointer,
        summary="Use a status compatible with the operation method.",
        steps=(f"Remove {status} from this operation or move it to a compatible operation.",),
    )


def _parse_semantics(content: bytes | None, collector: _Collector) -> _Semantics | None:
    if content is None:
        return _Semantics((), ())
    if len(content) > _MAX_FILE_BYTES:
        collector.issue(
            "semantics.too-large",
            "semantics",
            "semantics sidecar exceeds the per-file byte limit",
            "Reduce the explicit sidecar.",
        )
        return None
    try:
        return _decode_semantics(content)
    except (UnicodeDecodeError, json.JSONDecodeError, _InputError, RecursionError) as error:
        collector.issue(
            "semantics.invalid",
            "semantics",
            str(error),
            "Correct the closed contract-semantics v2 JSON sidecar.",
        )
        return None


def _decode_semantics(content: bytes) -> _Semantics:
    unvalidated: object = json.loads(  # pyright: ignore[reportAny]
        content.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_json_constant,
        parse_float=_parse_json_float,
        parse_int=_parse_json_int,
    )
    try:
        raw = _JSON_VALUE_ADAPTER.validate_python(unvalidated, strict=True)
    except ValidationError as error:
        _InputError.fail("semantics must contain valid JSON values", cause=error)
    _bound_json(raw)
    data = _as_object(raw, "semantics")
    _strict_keys(data, {"schema_version", "operations", "artifacts"}, "semantics")
    if data.get("schema_version") != _SEMANTICS_SCHEMA_VERSION:
        _InputError.fail(f"semantics.schema_version must be {_SEMANTICS_SCHEMA_VERSION}")
    operations = _parse_operation_semantics(data.get("operations", []))
    artifacts = _parse_artifacts(data.get("artifacts", []))
    return _Semantics(operations, artifacts)


def _as_object(value: JsonValue, context: str) -> JsonObject:
    if not isinstance(value, dict):
        _InputError.fail(f"{context} must be an object")
    return cast("JsonObject", value)


def _as_list(value: JsonValue, context: str) -> list[JsonValue]:
    if not isinstance(value, list):
        _InputError.fail(f"{context} must be an array")
    return value


def _strict_keys(value: JsonObject, allowed: set[str], context: str) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        _InputError.fail(f"{context} has unknown fields: {', '.join(extras)}")


def _optional_string(value: JsonObject, key: str, context: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        _InputError.fail(f"{context}.{key} must be a non-empty string")
    return item


def _parse_operation_semantics(value: JsonValue) -> tuple[_OperationSemantics, ...]:
    result: list[_OperationSemantics] = []
    seen: set[str] = set()
    for index, raw in enumerate(_as_list(value, "semantics.operations")):
        context = f"semantics.operations[{index}]"
        item = _as_object(raw, context)
        _strict_keys(
            item,
            {"operation_ref", "error_profile"},
            context,
        )
        operation_ref = _optional_string(item, "operation_ref", context)
        if operation_ref is None:
            _InputError.fail(f"{context}.operation_ref is required")
        if operation_ref in seen:
            _InputError.fail(f"duplicate operation_ref {operation_ref!r}")
        seen.add(operation_ref)
        error_profile = _optional_string(item, "error_profile", context)
        if error_profile not in {None, "rfc9457"}:
            _InputError.fail(f"{context}.error_profile must be rfc9457")
        result.append(
            _OperationSemantics(
                operation_ref,
                cast("Literal['rfc9457'] | None", error_profile),
            )
        )
    return tuple(result)


def _parse_artifacts(value: JsonValue) -> tuple[_Artifact, ...]:
    result: list[_Artifact] = []
    seen: set[str] = set()
    for index, raw in enumerate(_as_list(value, "semantics.artifacts")):
        context = f"semantics.artifacts[{index}]"
        item = _as_object(raw, context)
        _strict_keys(
            item,
            {"artifact", "role", "derived_from", "source_digest", "output_digest", "producer"},
            context,
        )
        artifact = _optional_string(item, "artifact", context)
        role = _optional_string(item, "role", context)
        if artifact is None or role is None:
            _InputError.fail(f"{context}.artifact and role are required")
        artifact = _canonical_name(artifact)
        if artifact in seen:
            _InputError.fail(f"duplicate artifact {artifact!r}")
        seen.add(artifact)
        if role not in {"source", "bundle", "effective", "generated"}:
            _InputError.fail(f"{context}.role is unsupported")
        producer_raw = item.get("producer")
        producer: JsonObject = (
            {} if producer_raw is None else _as_object(producer_raw, f"{context}.producer")
        )
        _strict_keys(producer, {"name", "version", "config_digest"}, f"{context}.producer")
        derived_from = _optional_string(item, "derived_from", context)
        if derived_from is not None:
            derived_from = _canonical_name(derived_from)
        result.append(
            _Artifact(
                f"/artifacts/{index}",
                artifact,
                role,
                derived_from,
                _digest(item, "source_digest", context),
                _digest(item, "output_digest", context),
                _optional_string(producer, "name", f"{context}.producer"),
                _optional_string(producer, "version", f"{context}.producer"),
                _digest(producer, "config_digest", f"{context}.producer"),
            )
        )
    return tuple(result)


def _digest(value: JsonObject, key: str, context: str) -> str | None:
    result = _optional_string(value, key, context)
    if result is not None and (
        len(result) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in result)
    ):
        _InputError.fail(f"{context}.{key} must be a lowercase SHA-256 digest")
    return result


def _check_semantics(
    name: str,
    root: JsonObject,
    parsed: dict[str, JsonObject],
    semantics: _Semantics,
    collector: _Collector,
) -> None:
    operation_map = _operation_map(root)
    for declaration in semantics.operations:
        resolved_ref = declaration.operation_ref
        if resolved_ref.startswith(f"{name}#"):
            resolved_ref = resolved_ref[len(name) :]
        target = operation_map.get(resolved_ref)
        if target is None:
            collector.issue(
                "semantics.operation-unresolved",
                "semantics",
                f"operation_ref {declaration.operation_ref!r} does not resolve "
                "in the entry document",
                "Use an exact entry-document Operation Object JSON Pointer.",
            )
            continue
        _method, operation = target
        pointer = resolved_ref[1:]
        if declaration.error_profile == "rfc9457":
            _check_problem_responses(name, operation, pointer, parsed, collector)


def _operation_map(root: JsonObject) -> dict[str, _OperationMapEntry]:
    return {
        f"#{pointer}": _OperationMapEntry(method, operation)
        for method, pointer, operation, _ in _operations(root)
    }


def _check_problem_responses(
    name: str,
    operation: JsonObject,
    pointer: str,
    parsed: dict[str, JsonObject],
    collector: _Collector,
) -> None:
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return
    for response_key, raw_response in responses.items():
        status = _response_status(str(response_key))
        is_error = (status is not None and status >= _CLIENT_ERROR_START) or str(
            response_key
        ).upper() in {
            "4XX",
            "5XX",
        }
        if not is_error or not isinstance(raw_response, dict):
            continue
        response = _resolve_local_object(name, raw_response, parsed)
        if response is None:
            continue
        content = response.get("content")
        if content is None:
            continue
        response_pointer = f"{pointer}/responses/{_pointer_token(str(response_key))}"
        if not isinstance(content, dict) or "application/problem+json" not in content:
            _problem_finding(
                name,
                collector,
                response_pointer,
                "documented error body does not use application/problem+json",
                "a documented non-problem error content map",
                "application/problem+json or no body",
            )
            continue
        media = content["application/problem+json"]
        schema = media.get("schema") if isinstance(media, dict) else None
        resolved = _resolve_schema(name, schema, parsed)
        if resolved is None:
            _problem_finding(
                name,
                collector,
                f"{response_pointer}/content/application~1problem+json/schema",
                "problem schema cannot be resolved for coherence checking",
                "missing or unresolved schema",
                "an inline or supplied local object schema",
            )
            continue
        problem = _problem_schema_error(resolved, status)
        if problem is not None:
            _problem_finding(
                name,
                collector,
                f"{response_pointer}/content/application~1problem+json/schema",
                problem,
                "RFC-incompatible problem schema",
                "RFC 9457-compatible optional members",
            )


def _resolve_schema(
    current_name: str, schema: JsonValue, parsed: dict[str, JsonObject]
) -> JsonObject | None:
    if not isinstance(schema, dict):
        return None
    reference = schema.get("$ref")
    if reference is None:
        return cast("JsonObject", schema)
    if not isinstance(reference, str):
        return None
    target = _reference_target(current_name, reference)
    if target is None:
        return None
    target_name, fragment = target
    document = parsed.get(target_name)
    resolved = _resolve_pointer(document, fragment) if document is not None else None
    return cast("JsonObject", resolved) if isinstance(resolved, dict) else None


def _resolve_local_object(
    current_name: str, value: JsonObject, parsed: dict[str, JsonObject]
) -> JsonObject | None:
    reference = value.get("$ref")
    if reference is None:
        return value
    if not isinstance(reference, str):
        return None
    target = _reference_target(current_name, reference)
    if target is None:
        return None
    target_name, fragment = target
    document = parsed.get(target_name)
    resolved = _resolve_pointer(document, fragment) if document is not None else None
    return cast("JsonObject", resolved) if isinstance(resolved, dict) else None


def _problem_schema_error(  # ruff: ignore[too-many-return-statements] - ordered schema contradictions
    schema: JsonObject, status: int | None
) -> str | None:
    schema_type = schema.get("type")
    if schema_type not in {None, "object"}:
        return "problem detail schema must describe an object"
    properties = schema.get("properties")
    if properties is None:
        return None
    if not isinstance(properties, dict):
        return "problem detail properties must be an object"
    for member in _PROBLEM_STRING_MEMBERS:
        definition = properties.get(member)
        if isinstance(definition, dict) and not _accepts_type(definition.get("type"), "string"):
            return f"problem member {member!r} must be a string when declared"
    status_definition = properties.get("status")
    if isinstance(status_definition, dict):
        if not _accepts_type(status_definition.get("type"), "integer"):
            return "problem member 'status' must be an integer when declared"
        const = status_definition.get("const")
        if status is not None and const is not None and const != status:
            return f"problem status const {const!r} contradicts response status {status}"
    return None


def _accepts_type(value: JsonValue, expected: str) -> bool:
    if value is None:
        return True
    if value == expected:
        return True
    return isinstance(value, list) and expected in value


def _problem_finding(  # ruff: ignore[too-many-arguments, too-many-positional-arguments] - rule-specific diagnostic adapter
    name: str,
    collector: _Collector,
    pointer: str,
    message: str,
    observed: str,
    expected: str,
) -> None:
    collector.finding(
        rule_id="api/errors/problem-details",
        severity="warning",
        message=message,
        observed=observed,
        expected=expected,
        document=name,
        pointer=pointer,
        summary="Align the opted-in error representation.",
        steps=(
            "Use application/problem+json with RFC-compatible member types, or remove the opt-in.",
        ),
    )


def _check_artifacts(  # ruff: ignore[too-many-branches] - independent provenance evidence fields
    documents: dict[str, bytes], semantics: _Semantics, collector: _Collector
) -> None:
    digests = {name: sha256(content).hexdigest() for name, content in documents.items()}
    for artifact in semantics.artifacts:
        if artifact.role == "source":
            continue
        pointer = artifact.pointer
        if artifact.artifact not in documents:
            _artifact_finding(
                collector,
                "error",
                "$semantics",
                pointer,
                "declared artifact bytes were not supplied",
                "missing artifact",
                "supplied immutable artifact bytes",
            )
            continue
        missing: list[str] = []
        if artifact.derived_from is None:
            missing.append("derived_from")
        if artifact.source_digest is None:
            missing.append("source_digest")
        if artifact.output_digest is None:
            missing.append("output_digest")
        if artifact.producer_name is None:
            missing.append("producer.name")
        if artifact.producer_version is None:
            missing.append("producer.version")
        if artifact.config_digest is None:
            missing.append("producer.config_digest")
        if missing:
            _artifact_finding(
                collector,
                "warning",
                "$semantics",
                pointer,
                "derived artifact provenance is incomplete",
                ", ".join(missing),
                "pinned source, producer, config, and output evidence",
            )
        if artifact.derived_from is not None:
            source_name = artifact.derived_from
            actual_source = digests.get(source_name)
            if actual_source is None:
                _artifact_finding(
                    collector,
                    "error",
                    "$semantics",
                    pointer,
                    "canonical source bytes were not supplied",
                    source_name,
                    "one supplied canonical source",
                )
            elif artifact.source_digest is not None and artifact.source_digest != actual_source:
                _artifact_finding(
                    collector,
                    "error",
                    "$semantics",
                    pointer,
                    "declared source digest does not match supplied bytes",
                    artifact.source_digest,
                    actual_source,
                )
        actual_output = digests[artifact.artifact]
        if artifact.output_digest is not None and artifact.output_digest != actual_output:
            _artifact_finding(
                collector,
                "error",
                "$semantics",
                pointer,
                "declared output digest does not match supplied bytes",
                artifact.output_digest,
                actual_output,
            )


def _artifact_finding(  # ruff: ignore[too-many-arguments, too-many-positional-arguments] - rule-specific diagnostic adapter
    collector: _Collector,
    severity: Literal["warning", "error"],
    artifact: str,
    pointer: str,
    message: str,
    observed: str,
    expected: str,
) -> None:
    rule_id = "api/artifact/provenance"
    collector.finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        observed=observed,
        expected=expected,
        document=artifact,
        pointer=pointer,
        summary="Make derivation evidence complete and reproducible.",
        steps=("Record exactly one supplied source and pinned producer/config/output digests.",),
    )
