from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import TYPE_CHECKING

from pydantic import TypeAdapter

from repo_standards.core.models import FixtureId, RuleExamplePair, RuleId, Severity

from .models import AnalysisRequest, DocumentInput


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


_JSON_OBJECT = TypeAdapter(dict[str, object])


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    rule_id: RuleId
    severity: Severity


@dataclass(frozen=True, slots=True)
class OpenApiRuleFixture:
    fixture_id: FixtureId
    rule_id: RuleId
    flagged: AnalysisRequest
    passes: AnalysisRequest
    expected_findings: tuple[ExpectedFinding, ...]

    @property
    def example(self) -> RuleExamplePair:
        return RuleExamplePair(
            example_id=self.fixture_id,
            title=_example_title(self.fixture_id),
            language="json",
            before=render_request(self.flagged),
            after=render_request(self.passes),
            expected_severity=self.expected_findings[0].severity,
        )


def _example_title(fixture_id: FixtureId) -> str:
    suffix = str(fixture_id).rsplit("/", maxsplit=1)[-1]
    return {
        "remote": "Remote reference",
        "response": "Forbidden response content",
        "trace": "TRACE request body",
        "304": "Method and status mismatch",
        "media-type": "Problem Details media type",
        "status-member": "Problem Details status member",
        "incomplete": "Incomplete provenance",
        "digest-mismatch": "Contradictory provenance digest",
    }[suffix]


def _bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _spec(
    *,
    operation: Mapping[str, object] | None = None,
    method: str = "get",
    components: Mapping[str, object] | None = None,
) -> dict[str, object]:
    operation_value = (
        dict(operation) if operation is not None else {"responses": {"200": {"description": "ok"}}}
    )
    result: dict[str, object] = {
        "openapi": "3.1.2",
        "info": {"title": "Fixture", "version": "1"},
        "paths": {"/widgets": {method: operation_value}},
    }
    if components is not None:
        result["components"] = dict(components)
    return result


def _semantics(*, operations: Sequence[object] = (), artifacts: Sequence[object] = ()) -> bytes:
    return _bytes(
        {
            "schema_version": 2,
            "operations": operations,
            "artifacts": artifacts,
        }
    )


def _request(
    spec: Mapping[str, object],
    *,
    semantics: bytes | None = None,
    additional_documents: tuple[DocumentInput, ...] = (),
) -> AnalysisRequest:
    entrypoint = DocumentInput("openapi.json", _bytes(dict(spec)))
    return AnalysisRequest(
        entrypoint.name,
        (entrypoint, *additional_documents),
        semantics,
    )


def _fixture(
    *,
    fixture_id: str,
    rule_id: str,
    flagged: AnalysisRequest,
    passes: AnalysisRequest,
    severity: Severity,
) -> OpenApiRuleFixture:
    return OpenApiRuleFixture(
        FixtureId(fixture_id),
        RuleId(rule_id),
        flagged,
        passes,
        _finding(rule_id, severity),
    )


def _finding(rule_id: str, severity: Severity) -> tuple[ExpectedFinding, ...]:
    return (ExpectedFinding(RuleId(rule_id), severity),)


def _reference_fixture() -> OpenApiRuleFixture:
    rule_id = "api/references/local-resolution"
    flagged = _request(
        _spec(components={"schemas": {"Widget": {"$ref": "https://example.invalid/schema.json"}}})
    )
    target = DocumentInput(
        "schemas.json",
        _bytes({"$defs": {"Widget": {"type": "object"}}}),
    )
    passes = _request(
        _spec(components={"schemas": {"Widget": {"$ref": "./schemas.json#/$defs/Widget"}}}),
        additional_documents=(target,),
    )
    return _fixture(
        fixture_id=f"{rule_id}/remote",
        rule_id=rule_id,
        flagged=flagged,
        passes=passes,
        severity="error",
    )


def _forbidden_response_fixture() -> OpenApiRuleFixture:
    rule_id = "api/http/message-semantics"
    flagged = _request(
        _spec(
            operation={
                "responses": {
                    "204": {
                        "description": "done",
                        "content": {"application/json": {}},
                    }
                }
            }
        )
    )
    passes = _request(
        _spec(
            operation={
                "responses": {
                    "204": {
                        "description": "done",
                        "headers": {"ETag": {"schema": {"type": "string"}}},
                    }
                }
            }
        )
    )
    return _fixture(
        fixture_id=f"{rule_id}/response",
        rule_id=rule_id,
        flagged=flagged,
        passes=passes,
        severity="error",
    )


def _forbidden_trace_fixture() -> OpenApiRuleFixture:
    rule_id = "api/http/message-semantics"
    flagged = _request(
        _spec(
            method="trace",
            operation={
                "requestBody": {"content": {"application/json": {}}},
                "responses": {"200": {"description": "trace"}},
            },
        )
    )
    passes = _request(
        _spec(method="trace", operation={"responses": {"200": {"description": "trace"}}})
    )
    return _fixture(
        fixture_id=f"{rule_id}/trace",
        rule_id=rule_id,
        flagged=flagged,
        passes=passes,
        severity="error",
    )


def _status_method_fixture() -> OpenApiRuleFixture:
    rule_id = "api/http/message-semantics"
    operation = {"responses": {"304": {"description": "cached"}}}
    return _fixture(
        fixture_id=f"{rule_id}/304",
        rule_id=rule_id,
        flagged=_request(_spec(method="post", operation=operation)),
        passes=_request(_spec(method="get", operation=operation)),
        severity="error",
    )


def _problem_fixture(
    suffix: str, flagged_response: Mapping[str, object], passing_response: Mapping[str, object]
) -> OpenApiRuleFixture:
    rule_id = "api/errors/problem-details"
    semantics = _semantics(
        operations=[
            {
                "operation_ref": "#/paths/~1widgets/get",
                "error_profile": "rfc9457",
            }
        ]
    )

    def request(response: Mapping[str, object]) -> AnalysisRequest:
        return _request(
            _spec(operation={"responses": {"422": dict(response)}}),
            semantics=semantics,
        )

    return _fixture(
        fixture_id=f"{rule_id}/{suffix}",
        rule_id=rule_id,
        flagged=request(flagged_response),
        passes=request(passing_response),
        severity="warning",
    )


def _artifact_fixture(suffix: str, *, incomplete: bool) -> OpenApiRuleFixture:
    rule_id = "api/artifact/provenance"
    return _fixture(
        fixture_id=f"{rule_id}/{suffix}",
        rule_id=rule_id,
        flagged=_artifact_request(complete=not incomplete, mismatch=not incomplete),
        passes=_artifact_request(complete=True),
        severity="warning" if incomplete else "error",
    )


def _artifact_request(*, complete: bool, mismatch: bool = False) -> AnalysisRequest:
    source = _bytes(_spec())
    artifact = b'{"bundled":true}'
    declaration: dict[str, object] = {
        "artifact": "dist/bundle.json",
        "role": "bundle",
    }
    if complete:
        declaration.update(
            {
                "derived_from": "openapi.json",
                "source_digest": "0" * 64 if mismatch else sha256(source).hexdigest(),
                "output_digest": sha256(artifact).hexdigest(),
                "producer": {
                    "name": "fixture-bundler",
                    "version": "1.2.3",
                    "config_digest": "a" * 64,
                },
            }
        )
    return AnalysisRequest(
        "openapi.json",
        (
            DocumentInput("openapi.json", source),
            DocumentInput("dist/bundle.json", artifact),
        ),
        _semantics(artifacts=[declaration]),
    )


_PROBLEM_MEDIA_FLAGGED = {
    "description": "wrong media",
    "content": {"application/json": {"schema": {"type": "object"}}},
}
_PROBLEM_MEDIA_PASSES = {
    "description": "problem",
    "content": {"application/problem+json": {"schema": {"type": "object"}}},
}
_PROBLEM_STATUS_FLAGGED = {
    "description": "wrong status",
    "content": {
        "application/problem+json": {
            "schema": {"type": "object", "properties": {"status": {"type": "string"}}}
        }
    },
}
_PROBLEM_STATUS_PASSES = {
    "description": "problem",
    "content": {
        "application/problem+json": {
            "schema": {
                "type": "object",
                "properties": {"status": {"type": "integer", "const": 422}},
            }
        }
    },
}


REST_RULE_FIXTURES: tuple[OpenApiRuleFixture, ...] = (
    _reference_fixture(),
    _forbidden_response_fixture(),
    _forbidden_trace_fixture(),
    _status_method_fixture(),
    _problem_fixture("media-type", _PROBLEM_MEDIA_FLAGGED, _PROBLEM_MEDIA_PASSES),
    _problem_fixture("status-member", _PROBLEM_STATUS_FLAGGED, _PROBLEM_STATUS_PASSES),
    _artifact_fixture("incomplete", incomplete=True),
    _artifact_fixture("digest-mismatch", incomplete=False),
)


def examples_for_rule(rule_id: RuleId) -> tuple[RuleExamplePair, ...]:
    return tuple(fixture.example for fixture in REST_RULE_FIXTURES if fixture.rule_id == rule_id)


def render_request(request: AnalysisRequest) -> str:
    documents = {
        document.name: _JSON_OBJECT.validate_json(document.content, strict=True)
        for document in sorted(request.documents, key=lambda item: item.name)
    }
    value: dict[str, object] = {
        "documents": documents,
        "entrypoint": request.entrypoint,
    }
    if request.semantics is not None:
        value["semantics"] = _JSON_OBJECT.validate_json(request.semantics, strict=True)
    return json.dumps(value, indent=2, sort_keys=True)
