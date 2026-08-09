"""Integrity checks for the public OpenAPI calibration manifest."""

from __future__ import annotations

import json
from pathlib import Path
import re


_ROOT = Path(__file__).parents[1]
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_EXPECTED_PATHS = {
    "cloudflare-api-schemas": "openapi.yaml",
    "digitalocean-openapi": "specification/DigitalOcean-public.v2.yaml",
    "github-rest-api-description": ("descriptions/api.github.com/api.github.com.2022-11-28.json"),
    "kubernetes": "api/openapi-spec/swagger.json",
    "openai-openapi": "openapi.yaml",
    "stripe-openapi": "latest/openapi.spec3.json",
}


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return {
        key: item
        for key, item in value.items()  # pyright: ignore[reportUnknownVariableType]
        if isinstance(key, str)
    }


def _object_list(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    return [
        _object(item)  # pyright: ignore[reportUnknownArgumentType]
        for item in value  # pyright: ignore[reportUnknownVariableType]
    ]


def _manifest() -> dict[str, object]:
    text = (_ROOT / "corpus" / "openapi-public-v1.json").read_text(encoding="utf-8")
    parsed: object = json.loads(text)  # pyright: ignore[reportAny]
    return _object(parsed)


def test_openapi_corpus_is_exact_pinned_and_not_downloaded() -> None:
    manifest = _manifest()
    assert manifest["schema_version"] == 1
    assert _object(manifest["selection"])["seed"]
    protocol = _object(manifest["protocol"])
    assert _object(protocol["no_substitution"])["enabled"] is True
    assert _object(protocol["privacy"])["credentials_permitted"] is False

    sources = _object_list(manifest["sources"])
    assert [str(source["source_id"]) for source in sources] == sorted(_EXPECTED_PATHS)
    assert len(sources) == 6
    for source in sources:
        assert _HEX40.fullmatch(str(source["commit"]))
        assert _HEX40.fullmatch(str(source["tree"]))
        assert source["default_branch"] is None
        assert _object(source["license"])["verification_status"] == "unverified-not-downloaded"
        assert _object(source["snapshot"]) == {
            "status": "not-downloaded",
            "commit_tree_verified_locally": False,
            "selected_content_sha256": None,
        }
        selected_paths = {
            str(artifact["path"]) for artifact in _object_list(source["selected_artifacts"])
        }
        assert _EXPECTED_PATHS[str(source["source_id"])] in selected_paths


def test_openapi_corpus_preserves_applicability_controls() -> None:
    sources = {str(source["source_id"]): source for source in _object_list(_manifest()["sources"])}

    kubernetes = sources["kubernetes"]
    assert _object_list(kubernetes["selected_artifacts"])[0]["format"] == "swagger-2.0"
    assert _object(kubernetes["applicability"])["not_applicable"] == ["OpenAPI 3-only rules"]
    assert (
        _object_list(sources["digitalocean-openapi"]["selected_artifacts"])[0][
            "classification_status"
        ]
        == "pending-build-graph-verification"
    )
    cloudflare_roles = {
        str(artifact["path"]): artifact["role"]
        for artifact in _object_list(sources["cloudflare-api-schemas"]["selected_artifacts"])
    }
    assert cloudflare_roles["common.yaml"] == "conditional-local-reference"
