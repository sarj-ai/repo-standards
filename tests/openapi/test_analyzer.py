from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import TYPE_CHECKING

from jsonschema import ValidationError as JSONSchemaValidationError
from jsonschema import validate
import pytest

from repo_lint.openapi import AnalysisReport, DocumentInput, analyze_bytes, rules
from repo_lint.openapi.schema import analysis_schema


if TYPE_CHECKING:
    from collections.abc import Mapping


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
        "info": {"title": "Example", "version": "1"},
        "paths": {"/widgets": {method: operation_value}},
    }
    if components is not None:
        result["components"] = dict(components)
    return result


def _sidecar(
    *, operations: list[object] | None = None, artifacts: list[object] | None = None
) -> bytes:
    return _bytes(
        {
            "schema_version": 2,
            "operations": operations or [],
            "artifacts": artifacts or [],
        }
    )


def _rule_ids(report: AnalysisReport) -> list[str]:
    diagnostics = report.diagnostics
    return [item.rule_id for item in diagnostics]


def test_minimal_json_document_is_clean_and_deterministic() -> None:
    content = _bytes(_spec())
    first = analyze_bytes(content)
    second = analyze_bytes(content)
    assert first.completion == "complete"
    assert first.conclusion == "passed"
    assert first == second


def test_openapi_report_rejects_incoherent_outcome_states() -> None:
    with pytest.raises(ValueError, match="complete OpenAPI reports cannot be inconclusive"):
        AnalysisReport(2, "complete", "inconclusive", "openapi.json", None, (), ())


def test_openapi_schema_rejects_incoherent_outcome_states() -> None:
    with pytest.raises(JSONSchemaValidationError):
        validate(
            instance={
                "schema_version": 2,
                "completion": "complete",
                "conclusion": "inconclusive",
                "entrypoint": "openapi.json",
                "openapi_version": None,
                "diagnostics": [],
                "execution_issues": [],
            },
            schema=analysis_schema(),
        )


@pytest.mark.parametrize(
    ("content", "issue"),
    [
        pytest.param(b"openapi: 3.1.2\ninfo: {}\n", "openapi.yaml-unsupported", id="yaml"),
        pytest.param(
            b'{"openapi":"3.1.2","openapi":"3.2.0"}', "openapi.parse-failed", id="duplicate-key"
        ),
        pytest.param(b"[]", "openapi.root-invalid", id="non-object-root"),
    ],
)
def test_untrusted_parse_failures_are_structured_incomplete(content: bytes, issue: str) -> None:
    report = analyze_bytes(content)
    assert report.completion == "incomplete"
    assert report.conclusion == "inconclusive"
    assert [item.code for item in report.execution_issues] == [issue]


@dataclass(frozen=True)
class ReferenceCase:
    reference: object
    additional: tuple[DocumentInput, ...]
    expected: int


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(ReferenceCase("https://example.test/schema.json", (), 1), id="remote-tp"),
        pytest.param(ReferenceCase("../../secret.json", (), 1), id="traversal-tp"),
        pytest.param(ReferenceCase("/absolute/schema.json", (), 1), id="absolute-tp"),
        pytest.param(ReferenceCase("./missing.json", (), 1), id="missing-tp"),
        pytest.param(ReferenceCase(42, (), 1), id="non-string-tp"),
        pytest.param(
            ReferenceCase(
                "./schemas.json#/$defs/Widget",
                (
                    DocumentInput(
                        "schemas.json",
                        _bytes({"$defs": {"Widget": {"type": "object"}}}),
                    ),
                ),
                0,
            ),
            id="local-ref-tn",
        ),
        pytest.param(ReferenceCase("#/components/schemas/Widget", (), 0), id="fragment-tn"),
    ],
)
def test_reference_boundary_evaluation_cases(case: ReferenceCase) -> None:
    spec = _spec(components={"schemas": {"Widget": {"$ref": case.reference}}})
    report = analyze_bytes(_bytes(spec), additional_documents=case.additional)
    findings = [
        item for item in report.diagnostics if item.rule_id == "api/references/local-resolution"
    ]
    assert len(findings) == case.expected


def test_ref_like_text_in_examples_is_not_a_reference() -> None:
    spec = _spec(
        components={
            "schemas": {
                "Widget": {
                    "type": "object",
                    "example": {"note": "$ref: https://example.test/not-a-reference"},
                }
            }
        }
    )
    assert _rule_ids(analyze_bytes(_bytes(spec))) == []


@pytest.mark.parametrize(
    ("method", "status"),
    [
        pytest.param("get", "204", id="204"),
        pytest.param("get", "205", id="205"),
        pytest.param("get", "304", id="304"),
        pytest.param("get", "101", id="informational"),
        pytest.param("head", "200", id="head"),
    ],
)
def test_forbidden_response_content(method: str, status: str) -> None:
    operation: dict[str, object] = {
        "responses": {
            status: {
                "description": "not allowed",
                "content": {"application/json": {"schema": {"type": "object"}}},
            }
        }
    }
    report = analyze_bytes(_bytes(_spec(operation=operation, method=method)))
    assert "api/http/message-semantics" in _rule_ids(report)


def test_headers_on_content_free_response_are_clean() -> None:
    operation: dict[str, object] = {
        "responses": {
            "204": {
                "description": "empty",
                "headers": {"ETag": {"schema": {"type": "string"}}},
            }
        }
    }
    assert _rule_ids(analyze_bytes(_bytes(_spec(operation=operation)))) == []


def test_referenced_response_is_checked_without_duplicate_diagnostic() -> None:
    spec = _spec(
        operation={
            "responses": {"204": {"$ref": "#/components/responses/Empty"}},
        },
        components={
            "responses": {
                "Empty": {
                    "description": "invalid body",
                    "content": {"application/json": {"schema": {"type": "object"}}},
                }
            }
        },
    )
    report = analyze_bytes(_bytes(spec))
    findings = [item for item in report.diagnostics if item.rule_id == "api/http/message-semantics"]
    assert len(findings) == 1


def test_trace_request_body_is_forbidden() -> None:
    operation: dict[str, object] = {
        "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
        "responses": {"200": {"description": "trace"}},
    }
    report = analyze_bytes(_bytes(_spec(operation=operation, method="trace")))
    assert _rule_ids(report) == ["api/http/message-semantics"]


@pytest.mark.parametrize(
    ("method", "status", "expected"),
    [
        pytest.param("post", "304", 1, id="post-304-tp"),
        pytest.param("get", "304", 0, id="get-304-tn"),
        pytest.param("post", "206", 1, id="post-206-tp"),
        pytest.param("get", "206", 0, id="get-206-tn"),
    ],
)
def test_method_status_contradictions(method: str, status: str, expected: int) -> None:
    report = analyze_bytes(
        _bytes(_spec(operation={"responses": {status: {"description": "x"}}}, method=method))
    )
    findings = [item for item in report.diagnostics if item.rule_id == "api/http/message-semantics"]
    assert len(findings) == expected


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        pytest.param({"description": "bodyless"}, 0, id="bodyless-tn"),
        pytest.param(
            {
                "description": "problem",
                "content": {
                    "application/problem+json": {
                        "schema": {
                            "type": "object",
                            "properties": {"status": {"type": "integer", "const": 422}},
                        }
                    }
                },
            },
            0,
            id="problem-tn",
        ),
        pytest.param(
            {
                "description": "wrong media",
                "content": {"application/json": {"schema": {"type": "object"}}},
            },
            1,
            id="wrong-media-tp",
        ),
        pytest.param(
            {
                "description": "wrong status",
                "content": {
                    "application/problem+json": {
                        "schema": {
                            "type": "object",
                            "properties": {"status": {"type": "string"}},
                        }
                    }
                },
            },
            1,
            id="wrong-member-type-tp",
        ),
    ],
)
def test_rfc9457_is_checked_only_after_opt_in(response: object, expected: int) -> None:
    spec = _spec(operation={"responses": {"422": response}})
    sidecar = _sidecar(
        operations=[{"operation_ref": "#/paths/~1widgets/get", "error_profile": "rfc9457"}]
    )
    report = analyze_bytes(_bytes(spec), semantics=sidecar)
    findings = [item for item in report.diagnostics if item.rule_id == "api/errors/problem-details"]
    assert len(findings) == expected


def test_non_opted_domain_error_is_untouched() -> None:
    response = {
        "description": "domain error",
        "content": {"application/json": {"schema": {"type": "object"}}},
    }
    assert _rule_ids(analyze_bytes(_bytes(_spec(operation={"responses": {"422": response}})))) == []


def test_malformed_semantics_is_incomplete_not_a_finding() -> None:
    report = analyze_bytes(_bytes(_spec()), semantics=b'{"schema_version":2,"unknown":true}')
    assert report.completion == "incomplete"
    assert report.diagnostics == ()
    assert [item.code for item in report.execution_issues] == ["semantics.invalid"]


def test_artifact_provenance_exact_digests_are_clean() -> None:
    source = _bytes(_spec())
    bundle = b'{"bundled":true}'
    sidecar = _sidecar(
        artifacts=[
            {
                "artifact": "dist/bundle.json",
                "role": "bundle",
                "derived_from": "openapi.json",
                "source_digest": sha256(source).hexdigest(),
                "output_digest": sha256(bundle).hexdigest(),
                "producer": {
                    "name": "example-bundler",
                    "version": "1.2.3",
                    "config_digest": "a" * 64,
                },
            }
        ]
    )
    report = analyze_bytes(
        source,
        semantics=sidecar,
        additional_documents=(DocumentInput("dist/bundle.json", bundle),),
    )
    assert _rule_ids(report) == []


def test_artifact_provenance_missing_and_mismatch_are_distinct() -> None:
    source = _bytes(_spec())
    bundle = b"bundle"
    sidecar = _sidecar(
        artifacts=[
            {
                "artifact": "dist/bundle.json",
                "role": "generated",
                "derived_from": "openapi.json",
                "source_digest": "0" * 64,
            }
        ]
    )
    report = analyze_bytes(
        source,
        semantics=sidecar,
        additional_documents=(DocumentInput("dist/bundle.json", bundle),),
    )
    findings = [item for item in report.diagnostics if item.rule_id == "api/artifact/provenance"]
    assert {(item.rule_id, item.severity) for item in findings} == {
        ("api/artifact/provenance", "error"),
        ("api/artifact/provenance", "warning"),
    }


def test_rule_catalog_is_complete_unique_and_source_backed() -> None:
    catalog = rules()
    assert [item.rule_id for item in catalog] == sorted(item.rule_id for item in catalog)
    assert len({item.rule_id for item in catalog}) == len(catalog) == 4
    assert all(
        item.title and item.detects and item.impact and item.remediation.steps and item.references
        for item in catalog
    )


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b'{"openapi":"3.1.2","value":' + b"9" * 5_000 + b"}", id="huge-int"),
        pytest.param(b'{"openapi":"3.1.2","value":NaN}', id="nan"),
    ],
)
def test_adversarial_json_numbers_are_structured_incomplete(content: bytes) -> None:
    report = analyze_bytes(content)
    assert report.completion == "incomplete"
    assert report.execution_issues[0].code == "openapi.parse-failed"


@pytest.mark.parametrize(
    "spec",
    [
        pytest.param({"openapi": "3.1.999x", "info": {}, "paths": {}}, id="version-suffix"),
        pytest.param(
            {"openapi": "3.1.2", "info": {}, "paths": "not-an-object"},
            id="paths-shape",
        ),
        pytest.param({"openapi": "3.1.2", "paths": {}}, id="missing-info"),
    ],
)
def test_invalid_prerequisite_shapes_never_report_clean(spec: object) -> None:
    report = analyze_bytes(_bytes(spec))
    assert report.completion == "incomplete"
    assert report.conclusion == "inconclusive"


def test_invalid_reference_uri_and_huge_pointer_never_escape_as_exceptions() -> None:
    huge_pointer = analyze_bytes(
        _bytes(_spec(components={"schemas": {"Widget": {"$ref": "#/items/" + "9" * 5_000}}}))
    )
    invalid_ref = analyze_bytes(
        _bytes(_spec(components={"schemas": {"Widget": {"$ref": "http://["}}}))
    )
    assert huge_pointer.completion == "complete"
    assert "api/references/local-resolution" in _rule_ids(huge_pointer)
    assert "api/references/local-resolution" in _rule_ids(invalid_ref)


def test_ref_key_inside_example_payload_is_not_reference_evidence() -> None:
    spec = _spec(
        operation={
            "responses": {
                "200": {
                    "description": "ok",
                    "content": {
                        "application/json": {
                            "example": {"$ref": "https://example.invalid/user-data"}
                        }
                    },
                }
            }
        }
    )
    assert _rule_ids(analyze_bytes(_bytes(spec))) == []
