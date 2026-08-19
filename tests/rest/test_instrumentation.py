from __future__ import annotations

import json

import pytest

from repo_lint.rest import (
    InstrumentationInputError,
    TrackedFile,
    detect_instrumentation,
    instrumentation_capabilities,
    parse_api_operation_map,
)


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _candidate_ids(files: tuple[TrackedFile, ...]) -> list[str]:
    return [item.capability.capability_id for item in detect_instrumentation(files).candidates]


def _operation_map(*operations: object, digest: str = "a" * 64) -> bytes:
    return _json(
        {
            "schema_version": "api-operation-map.v1",
            "openapi_sha256": digest,
            "operations": list(operations),
        }
    )


def test_registry_is_closed_sorted_and_honest_about_support() -> None:
    capabilities = instrumentation_capabilities()
    identifiers = [item.capability_id for item in capabilities]
    assert identifiers == sorted(identifiers)
    assert len(identifiers) == len(set(identifiers))
    assert set(identifiers) == {
        "committed-openapi",
        "operation-map",
        "fastapi",
        "django-drf-spectacular",
        "flask-smorest",
        "nestjs",
        "express",
        "hono",
        "springdoc",
        "go-net-http",
        "go-chi",
        "go-gin",
        "go-echo",
        "go-huma",
        "rust-axum",
        "rust-actix",
        "rust-rocket",
        "rust-utoipa",
    }
    by_id = {item.capability_id: item for item in capabilities}
    assert {item.capability_id for item in capabilities if item.support == "stable"} == {
        "committed-openapi",
        "operation-map",
    }
    assert by_id["fastapi"].support == "preview"
    assert by_id["fastapi"].runtime_integration == "preview"
    assert all(
        item.runtime_integration == "unsupported"
        for item in capabilities
        if item.support == "experimental"
    )


def test_package_manifest_preserves_multiple_candidates_without_dev_only_guess() -> None:
    package = {
        "dependencies": {"@nestjs/core": "11", "express": "5"},
        "optionalDependencies": {"hono": "4"},
        "devDependencies": {"fastapi": "not-an-npm-framework"},
    }
    files = (TrackedFile("services/api/package.json", _json(package)),)
    assert _candidate_ids(files) == ["express", "hono", "nestjs"]


def test_python_manifest_and_requirements_are_normalized() -> None:
    pyproject = b"""
[project]
dependencies = ["FastAPI>=1", "flask_smorest[dev]"]
[project.optional-dependencies]
schema = ["drf-spectacular~=1"]
"""
    requirements = b"fastapi==1\n# flask-smorest is only a comment\n"
    files = (
        TrackedFile("pyproject.toml", pyproject),
        TrackedFile("requirements-prod.txt", requirements),
    )
    assert _candidate_ids(files) == [
        "django-drf-spectacular",
        "fastapi",
        "flask-smorest",
    ]


def test_framework_project_name_is_detection_evidence() -> None:
    files = (
        TrackedFile(
            "python/pyproject.toml",
            b'[project]\nname = "FastAPI"\ndependencies = []\n',
        ),
        TrackedFile(
            "typescript/package.json",
            _json({"name": "hono", "dependencies": {}}),
        ),
    )

    candidates = detect_instrumentation(files).candidates
    assert [item.capability.capability_id for item in candidates] == ["fastapi", "hono"]
    assert all(item.evidence[0].kind == "manifest-project" for item in candidates)


def test_go_cargo_and_spring_manifests_are_detected_without_building() -> None:
    go_mod = b"""
module example.test/api
require (
 github.com/go-chi/chi/v5 v5.2.0
 github.com/gin-gonic/gin v1.10.0
 github.com/labstack/echo/v4 v4.13.0
 github.com/danielgtaylor/huma/v2 v2.30.0
)
"""
    cargo = b"""
[dependencies]
axum = "0.8"
actix = { package = "actix-web", version = "4" }
rocket = "0.5"
utoipa = "5"
[dev-dependencies]
ignored = { package = "axum", version = "0.8" }
"""
    pom = b"""<project><dependencies><dependency>
<groupId>org.springdoc</groupId><artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
</dependency></dependencies></project>"""
    files = (
        TrackedFile("go.mod", go_mod),
        TrackedFile("Cargo.toml", cargo),
        TrackedFile("pom.xml", pom),
    )
    assert _candidate_ids(files) == [
        "go-chi",
        "go-echo",
        "go-gin",
        "go-huma",
        "rust-actix",
        "rust-axum",
        "rust-rocket",
        "rust-utoipa",
        "springdoc",
    ]


def test_source_imports_and_standard_library_go_are_not_guessed() -> None:
    files = (
        TrackedFile("main.go", b'import "net/http"\n'),
        TrackedFile("app.py", b"from fastapi import FastAPI\n"),
        TrackedFile("server.ts", b"import express from 'express'\n"),
    )
    assert _candidate_ids(files) == []


@pytest.mark.parametrize(
    ("path", "content", "marker"),
    [
        pytest.param(
            "api/openapi.json",
            b'{"openapi":"3.1.1","info":{},"paths":{}}',
            "openapi:3.1.1",
            id="openapi-json",
        ),
        pytest.param(
            "contract/openapi.yaml",
            b"# generated header\nopenapi: 3.2.0\ninfo: {}\n",
            "openapi:3.2.0",
            id="openapi-yaml",
        ),
        pytest.param(
            "legacy/swagger.json",
            b'{"swagger":"2.0","info":{},"paths":{}}',
            "swagger:2.0",
            id="swagger-json",
        ),
    ],
)
def test_conventional_committed_specs_are_detected(path: str, content: bytes, marker: str) -> None:
    report = detect_instrumentation((TrackedFile(path, content),))
    assert [item.capability.capability_id for item in report.candidates] == ["committed-openapi"]
    assert report.candidates[0].evidence[0].value == marker


def test_nonconventional_or_marker_free_json_is_not_a_contract_candidate() -> None:
    files = (
        TrackedFile("fixtures/openapi.json", b'{"title":"not a spec"}'),
        TrackedFile("contracts/service.json", b'{"openapi":"3.1.0"}'),
    )
    assert _candidate_ids(files) == []


def test_detection_is_order_independent_and_reports_malformed_manifest() -> None:
    files = (
        TrackedFile("z/package.json", b"{"),
        TrackedFile("a/package.json", _json({"dependencies": {"hono": "4"}})),
    )
    first = detect_instrumentation(files)
    second = detect_instrumentation(tuple(reversed(files)))
    assert first == second
    assert first.completion == "incomplete"
    assert [item.code for item in first.issues] == ["instrumentation.manifest-invalid"]
    assert [item.capability.capability_id for item in first.candidates] == ["hono"]


@pytest.mark.parametrize(
    "files",
    [
        pytest.param((TrackedFile("../package.json", b"{}"),), id="traversal"),
        pytest.param(
            (TrackedFile("package.json", b"{}"), TrackedFile("package.json", b"{}")),
            id="duplicate-path",
        ),
        pytest.param((TrackedFile("large.bin", b"x" * (2 * 1024 * 1024 + 1)),), id="large-file"),
    ],
)
def test_tracked_input_boundary_is_strict(files: tuple[TrackedFile, ...]) -> None:
    with pytest.raises(InstrumentationInputError):
        detect_instrumentation(files)


def test_operation_map_is_validated_and_canonicalized() -> None:
    content = _operation_map(
        {"operation_id": "widgets.create", "method": "POST", "route_template": "/widgets"},
        {"operation_id": "widgets.get", "method": "GET", "route_template": "/widgets/{id}"},
    )
    parsed = parse_api_operation_map(content)
    assert parsed.schema_version == "api-operation-map.v1"
    assert parsed.openapi_sha256 == "a" * 64
    assert [item.operation_id for item in parsed.operations] == ["widgets.get", "widgets.create"]
    assert parsed == parse_api_operation_map(content)


def test_conventional_operation_map_is_detected_only_after_validation() -> None:
    path = ".repo-lint/api-operation-map.json"
    report = detect_instrumentation((TrackedFile(path, _operation_map()),))
    assert [item.capability.capability_id for item in report.candidates] == ["operation-map"]
    assert report.candidates[0].evidence[0].value == "a" * 64

    invalid = detect_instrumentation((TrackedFile(path, _operation_map(digest="A" * 64)),))
    assert invalid.candidates == ()
    assert invalid.completion == "incomplete"
    assert [issue.code for issue in invalid.issues] == ["instrumentation.manifest-invalid"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        pytest.param(_operation_map(digest="A" * 64), "lowercase SHA-256", id="digest"),
        pytest.param(
            _operation_map(
                {"operation_id": "bad id", "method": "GET", "route_template": "/widgets"}
            ),
            "invalid grammar",
            id="operation-id-grammar",
        ),
        pytest.param(
            _operation_map(
                {"operation_id": "widgets.get", "method": "get", "route_template": "/widgets"}
            ),
            "uppercase HTTP method",
            id="uppercase-method",
        ),
        pytest.param(
            _operation_map(
                {"operation_id": "widgets.get", "method": "GET", "route_template": "widgets"}
            ),
            "route_template is invalid",
            id="route-template",
        ),
        pytest.param(
            _operation_map(
                {"operation_id": "widgets.get", "method": "GET", "route_template": "/widgets"},
                {"operation_id": "widgets.list", "method": "GET", "route_template": "/widgets"},
            ),
            "runtime method and route keys must be unique",
            id="runtime-key",
        ),
        pytest.param(
            _operation_map(
                {"operation_id": "widgets.get", "method": "GET", "route_template": "/one"},
                {"operation_id": "widgets.get", "method": "POST", "route_template": "/two"},
            ),
            "operation IDs must be unique",
            id="duplicate-operation-id",
        ),
        pytest.param(
            b'{"schema_version":"api-operation-map.v1","schema_version":"other",'
            b'"openapi_sha256":"' + b"a" * 64 + b'","operations":[]}',
            "duplicate object key",
            id="duplicate-json-key",
        ),
    ],
)
def test_operation_map_rejects_labeled_invalid_cases(content: bytes, message: str) -> None:
    with pytest.raises(InstrumentationInputError, match=message):
        parse_api_operation_map(content)


def test_operation_map_bounds_are_enforced_before_parsing() -> None:
    with pytest.raises(InstrumentationInputError, match="byte limit"):
        parse_api_operation_map(b" " * (2 * 1024 * 1024 + 1))
