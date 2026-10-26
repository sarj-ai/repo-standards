from __future__ import annotations

from copy import deepcopy
from importlib.metadata import version
from typing import TYPE_CHECKING, NamedTuple

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic schema codecs preserve the tested wire representation without adding a model envelope.
import pytest

from repo_standards.catalog import build_catalog, catalog_schema
from repo_standards.cli import app
from repo_standards.core.canonical import canonical_json
from repo_standards.core.models import JSONValue
from repo_standards.verify_release_artifacts import verify_site, verify_site_catalog


if TYPE_CHECKING:
    from pathlib import Path


_JSON_OBJECT = TypeAdapter(dict[str, JSONValue])


class _SiteDocuments(NamedTuple):
    catalog: dict[str, JSONValue]
    schema: dict[str, JSONValue]


def _site(directory: Path) -> _SiteDocuments:
    api = directory / "api"
    api.mkdir(parents=True)
    catalog = _JSON_OBJECT.validate_python(
        build_catalog(app, package_version=version("repo-standards")).model_dump(mode="json"),
        strict=True,
    )
    schema = _JSON_OBJECT.validate_python(catalog_schema(), strict=True)
    (api / "catalog.json").write_text(canonical_json(catalog), encoding="utf-8")
    (api / "catalog.schema.json").write_text(canonical_json(schema), encoding="utf-8")
    return _SiteDocuments(catalog, schema)


def _write(directory: Path, name: str, value: dict[str, JSONValue]) -> None:
    (directory / "api" / name).write_text(canonical_json(value), encoding="utf-8")


def test_release_site_accepts_the_catalog_contract(tmp_path: Path) -> None:
    _site(tmp_path)

    assert verify_site_catalog(tmp_path) == []


@pytest.mark.parametrize("directory", [True, False], ids=("directory", "file"))
def test_release_site_rejects_symlinks_without_inspecting_their_targets(
    tmp_path: Path, *, directory: bool
) -> None:
    site = tmp_path / "site"
    _site(site)
    target = tmp_path / "external"
    if directory:
        target.mkdir()
        (target / "private.txt").write_text("not a site artifact", encoding="utf-8")
    else:
        target.write_text("not a site artifact", encoding="utf-8")
    (site / "external").symlink_to(target, target_is_directory=directory)

    violations = verify_site(site)

    assert "site:external: links are not publishable" in violations
    assert not any("private.txt" in violation for violation in violations)


def test_release_site_rejects_a_forged_schema_or_catalog_digest(tmp_path: Path) -> None:
    catalog, schema = _site(tmp_path)
    forged_schema = deepcopy(schema)
    forged_schema["title"] = "Forged catalog schema"
    _write(tmp_path, "catalog.schema.json", forged_schema)
    product = catalog["product"]
    assert isinstance(product, dict)
    product["title"] = "Forged catalog"
    _write(tmp_path, "catalog.json", catalog)

    violations = verify_site_catalog(tmp_path)

    assert any("embedded catalog schema" in item for item in violations)
    assert any("content digest" in item for item in violations)


def test_release_site_rejects_unknown_catalog_fields(tmp_path: Path) -> None:
    catalog, _schema = _site(tmp_path)
    catalog["schema_version"] = 3
    _write(tmp_path, "catalog.json", catalog)

    violations = verify_site_catalog(tmp_path)

    assert any("schema validation failed" in item for item in violations)


def test_release_site_verifies_the_rendered_git_policy_reference(tmp_path: Path) -> None:
    _site(tmp_path)
    page = tmp_path / "git-policies" / "index.html"
    page.parent.mkdir()
    page.write_text(
        """<html><head><title>Git policies</title><meta name="description" content="Policy"></head>
        <body><main><h1>Git policies</h1>
        <p>They are commands and hooks, so they do not appear in the rule count.</p>
        <code>[(i/N) ][TICKET] type(scope)!: description</code>
        <a href="/cli/#commit-message">Commit messages</a>
        <a href="/cli/#pull-request.commits">Commit history</a>
        <a href="/git-policies/">Git policies</a>
        </main></body></html>""",
        encoding="utf-8",
    )

    complete = verify_site(tmp_path)
    assert not any("missing public contract" in violation for violation in complete)

    page.write_text("<html><body><main><h1>Git policies</h1></main></body></html>")
    incomplete = verify_site(tmp_path)
    assert sum("missing public contract" in violation for violation in incomplete) == 5


@pytest.mark.parametrize(
    ("script", "expected_violation"),
    [
        ("<SCRIPT>alert('unsafe')</SCRIPT>", True),
        ("<ScRiPt>alert('unsafe')</sCrIpT>", True),
        ("<script>alert('unsafe')</script >", True),
        ("<script data-src=\"/lazy.js\">alert('unsafe')</script>", True),
        ("<script aria-src=\"/lazy.js\">alert('unsafe')</script>", True),
        ("<script>alert('unsafe')</script\t\n ignored>", True),
        ('<SCRIPT SRC="/app.js"></SCRIPT>', False),
        ('<script src = "/app.js"></script >', False),
    ],
)
def test_release_site_csp_handles_case_insensitive_script_tags(
    tmp_path: Path,
    script: str,
    *,
    expected_violation: bool,
) -> None:
    (tmp_path / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'\n")
    (tmp_path / "index.html").write_text(
        "<html><head><title>Test</title></head><body><main><h1>Test</h1>"
        f"{script}</main></body></html>",
        encoding="utf-8",
    )

    violations = verify_site(tmp_path)

    violation = "site:index.html: inline script is missing from the CSP"
    assert (violation in violations) is expected_violation


def test_mounted_site_validates_catalog_and_prefixed_policy_links(tmp_path: Path) -> None:
    project = tmp_path / "projects/repo-standards"
    _site(project)
    page = project / "git-policies/index.html"
    page.parent.mkdir()
    page.write_text(
        """<html><head><title>Git policies</title><meta name="description" content="Policy"></head>
        <body><main><h1>Git policies</h1>
        <p>They are commands and hooks, so they do not appear in the rule count.</p>
        <code>[(i/N) ][TICKET] type(scope)!: description</code>
        <a href="/projects/repo-standards/cli/#commit-message">Commit messages</a>
        <a href="/projects/repo-standards/cli/#pull-request.commits">Commit history</a>
        <a href="/projects/repo-standards/git-policies/">Git policies</a>
        </main></body></html>""",
        encoding="utf-8",
    )

    violations = verify_site(tmp_path)

    assert not any("missing public contract" in item for item in violations)
    assert not any("api/catalog" in item and "missing" in item for item in violations)
    assert not any("content digest" in item for item in violations)


def test_mounted_site_rejects_a_global_project_fallback(tmp_path: Path) -> None:
    _site(tmp_path / "projects/repo-standards")
    (tmp_path / "404.html").write_text("<html>Unowned global project fallback</html>")

    violations = verify_site(tmp_path)

    assert "site:404.html: unexpected file outside the project mount" in violations


@pytest.mark.parametrize(
    ("relative", "privacy_violation"),
    [
        ("projects/repo-standards/_astro/vendor.js", False),
        ("projects/repo-standards/api/extra.json", True),
        ("_astro/vendor.js", True),
    ],
)
def test_mounted_site_limits_the_vendor_email_exemption_to_project_assets(
    tmp_path: Path, relative: str, *, privacy_violation: bool
) -> None:
    _site(tmp_path / "projects/repo-standards")
    artifact = tmp_path / relative
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("fixture" + "@" + "email.invalid")

    violations = verify_site(tmp_path)

    assert (f"site:{relative}: non-example email address" in violations) is privacy_violation


def test_mounted_site_checks_outside_html_csp_without_project_semantics(tmp_path: Path) -> None:
    _site(tmp_path / "projects/repo-standards")
    (tmp_path / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'\n")
    (tmp_path / "404.html").write_text("<html><script>alert('unsafe')</script></html>")

    violations = verify_site(tmp_path)

    assert "site:404.html: unexpected file outside the project mount" in violations
    assert "site:404.html: inline script is missing from the CSP" in violations
    assert not any(item.startswith("site:404.html: expected") for item in violations)


def test_mounted_site_does_not_follow_a_symbolic_project_parent(tmp_path: Path) -> None:
    site = tmp_path / "site"
    site.mkdir()
    private = tmp_path / "private/repo-standards/api"
    private.mkdir(parents=True)
    (private / "catalog.json").write_text("private fixture marker")
    (site / "projects").symlink_to(private.parent.parent, target_is_directory=True)

    violations = verify_site(site)

    assert "site:projects: links are not publishable" in violations
    assert not any("private fixture marker" in item for item in violations)


def test_site_catalog_links_are_rejected_before_parsing(tmp_path: Path) -> None:
    site = tmp_path / "site"
    _site(site)
    private = tmp_path / "private-catalog.json"
    private.write_text("private fixture marker")
    catalog = site / "api/catalog.json"
    catalog.unlink()
    catalog.symlink_to(private)

    violations = verify_site(site)

    assert "site:api/catalog.json: links are not publishable" in violations
    assert not any("private fixture marker" in item for item in violations)
