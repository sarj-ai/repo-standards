from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import TYPE_CHECKING

from pydantic import TypeAdapter

from repo_lint.core.models import FixtureId, RuleExamplePair, RuleId, Severity

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
            fixture_id=self.fixture_id,
            language="json",
            flagged=render_request(self.flagged),
            passes=render_request(self.passes),
            title=_example_title(self.fixture_id),
            severity=self.expected_findings[0].severity,
        )


def _example_title(fixture_id: FixtureId) -> str:
    suffix = str(fixture_id).rsplit("/", maxsplit=1)[-1]
    return {
        "remote": "Remote reference",
        "response": "Forbidden response content",
        "trace": "TRACE request body",
        "304": "Method and status mismatch",
        "literal-http": "Unencrypted server URL",
        "password": "OAuth password flow",
        "implicit": "OAuth implicit flow",
        "public": "Public operation requires authentication",
        "authenticated": "Authenticated operation allows anonymous access",
        "media-type": "Problem Details media type",
        "status-member": "Problem Details status member",
        "reversed": "Sunset before deprecation",
        "incomplete": "Incomplete provenance",
        "digest-mismatch": "Contradictory provenance digest",
    }[suffix]


def _bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _spec(
    *,
    operation: Mapping[str, object] | None = None,
    method: str = "get",
    servers: list[object] | None = None,
    security: list[object] | None = None,
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
    if servers is not None:
        result["servers"] = servers
    if security is not None:
        result["security"] = security
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


def _server_fixture() -> OpenApiRuleFixture:
    rule_id = "api/security/transport"
    return _fixture(
        fixture_id=f"{rule_id}/literal-http",
        rule_id=rule_id,
        flagged=_request(_spec(servers=[{"url": "http://api.example.test"}])),
        passes=_request(_spec(servers=[{"url": "https://api.example.test"}])),
        severity="warning",
    )


def _oauth_fixture(flow: str, replacement: str, severity: Severity) -> OpenApiRuleFixture:
    rule_id = "api/security/authentication"

    def request(selected_flow: str) -> AnalysisRequest:
        return _request(
            _spec(
                components={
                    "securitySchemes": {"oauth": {"type": "oauth2", "flows": {selected_flow: {}}}}
                }
            )
        )

    return _fixture(
        fixture_id=f"{rule_id}/{flow}",
        rule_id=rule_id,
        flagged=request(flow),
        passes=request(replacement),
        severity=severity,
    )


def _exposure_fixture(
    exposure: str,
    flagged_security: list[object],
    passing_security: list[object],
) -> OpenApiRuleFixture:
    rule_id = "api/security/authentication"
    semantics = _semantics(
        operations=[
            {
                "operation_ref": "#/paths/~1widgets/get",
                "exposure": exposure,
            }
        ]
    )
    return _fixture(
        fixture_id=f"{rule_id}/{exposure}",
        rule_id=rule_id,
        flagged=_request(_spec(security=flagged_security), semantics=semantics),
        passes=_request(_spec(security=passing_security), semantics=semantics),
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


def _sunset_fixture() -> OpenApiRuleFixture:
    rule_id = "api/lifecycle/deprecation-window"

    def request(deprecation: str, sunset: str) -> AnalysisRequest:
        return _request(
            _spec(),
            semantics=_semantics(
                operations=[
                    {
                        "operation_ref": "#/paths/~1widgets/get",
                        "deprecation_at": deprecation,
                        "sunset_at": sunset,
                    }
                ]
            ),
        )

    return _fixture(
        fixture_id=f"{rule_id}/reversed",
        rule_id=rule_id,
        flagged=request("2027-01-01T00:00:00Z", "2026-12-01T00:00:00Z"),
        passes=request("2026-01-01T00:00:00Z", "2026-12-01T00:00:00Z"),
        severity="error",
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
    _server_fixture(),
    _oauth_fixture("password", "authorizationCode", "error"),
    _oauth_fixture("implicit", "authorizationCode", "warning"),
    _exposure_fixture("public", [{"oauth": []}], [{}]),
    _exposure_fixture("authenticated", [{}], [{"oauth": []}]),
    _problem_fixture("media-type", _PROBLEM_MEDIA_FLAGGED, _PROBLEM_MEDIA_PASSES),
    _problem_fixture("status-member", _PROBLEM_STATUS_FLAGGED, _PROBLEM_STATUS_PASSES),
    _sunset_fixture(),
    _artifact_fixture("incomplete", incomplete=True),
    _artifact_fixture("digest-mismatch", incomplete=False),
)

_CONSOLIDATED_RULE_TARGETS: Mapping[str, str] = MappingProxyType(
    {
        "rest/source/nonhermetic-ref": "api/references/local-resolution",
        "rest/http/forbidden-content": "api/http/message-semantics",
        "rest/http/status-method-contradiction": "api/http/message-semantics",
        "rest/security/insecure-server": "api/security/transport",
        "rest/security/oauth-password-grant": "api/security/authentication",
        "rest/security/oauth-implicit-grant": "api/security/authentication",
        "rest/security/exposure-contradiction": "api/security/authentication",
        "rest/errors/problem-contract": "api/errors/problem-details",
        "rest/lifecycle/sunset-order": "api/lifecycle/deprecation-window",
        "rest/artifact/provenance-incomplete": "api/artifact/provenance",
        "rest/artifact/provenance-contradiction": "api/artifact/provenance",
    }
)


def examples_for_rule(rule_id: RuleId) -> tuple[RuleExamplePair, ...]:
    selected = RuleId(_CONSOLIDATED_RULE_TARGETS.get(str(rule_id), str(rule_id)))
    return tuple(fixture.example for fixture in REST_RULE_FIXTURES if fixture.rule_id == selected)


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
