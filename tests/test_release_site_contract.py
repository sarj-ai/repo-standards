from __future__ import annotations

from copy import deepcopy
from importlib.metadata import version
from typing import TYPE_CHECKING

from pydantic import TypeAdapter

from repo_lint.catalog import build_catalog, catalog_schema
from repo_lint.cli import app
from repo_lint.core.canonical import canonical_json
from repo_lint.core.models import JSONValue
from verify_release_artifacts import verify_site_catalog


if TYPE_CHECKING:
    from pathlib import Path


_JSON_OBJECT = TypeAdapter(dict[str, JSONValue])


def _site(directory: Path) -> tuple[dict[str, JSONValue], dict[str, JSONValue]]:
    api = directory / "api" / "v4"
    api.mkdir(parents=True)
    catalog = _JSON_OBJECT.validate_python(
        build_catalog(app, package_version=version("sarj-repo-lint")).model_dump(mode="json"),
        strict=True,
    )
    schema = _JSON_OBJECT.validate_python(catalog_schema(), strict=True)
    (api / "catalog.json").write_text(canonical_json(catalog), encoding="utf-8")
    (api / "catalog.schema.json").write_text(canonical_json(schema), encoding="utf-8")
    return catalog, schema


def _write(directory: Path, name: str, value: dict[str, JSONValue]) -> None:
    (directory / "api" / "v4" / name).write_text(canonical_json(value), encoding="utf-8")


def test_release_site_accepts_the_exact_catalog_v4_contract(tmp_path: Path) -> None:
    _site(tmp_path)

    assert verify_site_catalog(
        tmp_path,
        {"api/v4/catalog.json", "api/v4/catalog.schema.json"},
    ) == []


def test_release_site_rejects_legacy_routes_and_tombstones(tmp_path: Path) -> None:
    catalog, _schema = _site(tmp_path)
    catalog["tombstones"] = []
    _write(tmp_path, "catalog.json", catalog)

    violations = verify_site_catalog(
        tmp_path,
        {"api/v2/catalog.json", "api/v4/catalog.json", "api/v4/catalog.schema.json"},
    )

    assert any("legacy API contract" in item for item in violations)
    assert any("tombstones" in item for item in violations)


def test_release_site_rejects_a_forged_schema_or_catalog_digest(tmp_path: Path) -> None:
    catalog, schema = _site(tmp_path)
    forged_schema = deepcopy(schema)
    forged_schema["title"] = "Forged catalog schema"
    _write(tmp_path, "catalog.schema.json", forged_schema)
    product = catalog["product"]
    assert isinstance(product, dict)
    product["title"] = "Forged catalog"
    _write(tmp_path, "catalog.json", catalog)

    violations = verify_site_catalog(
        tmp_path,
        {"api/v4/catalog.json", "api/v4/catalog.schema.json"},
    )

    assert any("embedded catalog schema" in item for item in violations)
    assert any("content digest" in item for item in violations)


def test_release_site_rejects_a_non_v4_catalog(tmp_path: Path) -> None:
    catalog, _schema = _site(tmp_path)
    catalog["schema_version"] = 3
    _write(tmp_path, "catalog.json", catalog)

    violations = verify_site_catalog(
        tmp_path,
        {"api/v4/catalog.json", "api/v4/catalog.schema.json"},
    )

    assert any("invalid catalog v4" in item for item in violations)
