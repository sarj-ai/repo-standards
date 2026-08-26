from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import StrEnum
import hashlib
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
from typing import TYPE_CHECKING, Annotated, ClassVar, Literal, Protocol, final
import zipfile

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError
import typer

from repo_standards.core.canonical import canonical_json
from repo_standards.core.models import JSONValue


if TYPE_CHECKING:
    from collections.abc import Iterable

ORGANIZATION_REFERENCE = re.compile(
    rb"(?:@|github\.com/|uses:\s*)sarj-ai/([a-z0-9._-]+)", re.IGNORECASE
)
EMAIL_ADDRESS = re.compile(rb"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
PERSONAL_HOME_PATH = re.compile(
    rf"(?:/{'Users'}/|/{'home'}/|[A-Z]:\\\\{'Users'}\\\\)[a-z0-9._-]+".encode(),
    re.IGNORECASE,
)
INLINE_SCRIPT: re.Pattern[bytes] = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)</script>")
ALLOWED_REPOSITORIES = frozenset({b"repo-standards", b"code-standards", b"standards"})
ALLOWED_EMAILS = frozenset({b"api.github.com@evil.example", b"git@github.com", b"token@github.com"})
SITE_SUFFIXES = frozenset(
    {
        ".css",
        ".html",
        ".ico",
        ".js",
        ".json",
        ".png",
        ".svg",
        ".txt",
        ".webmanifest",
        ".webp",
        ".woff",
        ".woff2",
        ".xml",
    }
)
REQUIRED_SITE_FILES = frozenset(
    {
        "api/v7/catalog.json",
        "api/v7/catalog.schema.json",
        "health.json",
        "index.html",
        "review/index.html",
    }
)
WHEEL_METADATA_FILES = frozenset(
    {"METADATA", "RECORD", "WHEEL", "entry_points.txt", "licenses/LICENSE"}
)
SDIST_ROOT_FILES = frozenset(
    {"LICENSE", "PKG-INFO", "README.md", "pyproject.toml", "pyproject.toml.orig"}
)


class UnsafeArtifactPathError(RuntimeError):
    def __init__(self, path: str) -> None:
        super().__init__(f"unsafe artifact path: {path}")


class UnreadableSdistMemberError(RuntimeError):
    def __init__(self, path: PurePosixPath) -> None:
        super().__init__(f"unreadable source distribution member: {path}")


class WheelMetadataError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("wheel must contain exactly one METADATA file")


@dataclass(frozen=True)
class ArtifactMember:
    path: PurePosixPath
    content: bytes
    symbolic_link: bool = False


@dataclass(frozen=True)
class WheelMetadata:
    values: dict[str, list[str]]
    dist_info: str


class SiteCatalogModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore", frozen=True)


class SiteExample(SiteCatalogModel):
    id: str


class SiteRule(SiteCatalogModel):
    rule_id: str
    slug: str
    title: str
    examples: tuple[SiteExample, ...]


class SiteProvenance(SiteCatalogModel):
    content_digest: str


class SiteSchema(SiteCatalogModel):
    schema_id: str
    document: dict[str, JSONValue]


class SiteCatalog(SiteCatalogModel):
    kind: Literal["repo-standards.catalog"]
    schema_version: Literal[7]
    provenance: SiteProvenance
    rules: tuple[SiteRule, ...]
    schemas: tuple[SiteSchema, ...]


_JSON_OBJECT = TypeAdapter(dict[str, JSONValue])


class _SchemaValidator(Protocol):
    def validate(self, instance: JSONValue) -> None: ...


class HTMLTag(StrEnum):
    H1 = "h1"
    MAIN = "main"
    META = "meta"
    NAV = "nav"
    TITLE = "title"


@final
class PageSemantics(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.main_count = 0
        self.h1_count = 0
        self.h1_text: list[str] = []
        self.title_text: list[str] = []
        self.description = False
        self.breadcrumbs = 0
        self.current_crumbs = 0
        self.rule_navigation = 0
        self.rule_id: str | None = None
        self.code_comparisons = 0
        self.example_kinds: list[str] = []
        self._capture_h1 = False
        self._capture_title = False
        self._in_breadcrumb = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == HTMLTag.MAIN:
            self.main_count += 1
        elif tag == HTMLTag.H1:
            self.h1_count += 1
            self._capture_h1 = True
        elif tag == HTMLTag.TITLE:
            self._capture_title = True
        elif tag == HTMLTag.META and values.get("name") == "description" and values.get("content"):
            self.description = True
        elif tag == HTMLTag.NAV and values.get("aria-label") == "Breadcrumb":
            self.breadcrumbs += 1
            self._in_breadcrumb = True
        elif tag == HTMLTag.NAV and values.get("aria-label") == "Rule navigation":
            self.rule_navigation += 1
        if self._in_breadcrumb and values.get("aria-current") == "page":
            self.current_crumbs += 1
        rule_id = values.get("data-rule-id")
        if "data-rule-page" in values and rule_id:
            self.rule_id = rule_id
        if values.get("data-code-comparison"):
            self.code_comparisons += 1
        classes = set((values.get("class") or "").split())
        if "sarj-code-comparison__side--before" in classes:
            self.example_kinds.append("before")
        if "sarj-code-comparison__side--after" in classes:
            self.example_kinds.append("after")

    def handle_endtag(self, tag: str) -> None:
        if tag == HTMLTag.H1:
            self._capture_h1 = False
        elif tag == HTMLTag.TITLE:
            self._capture_title = False
        elif tag == HTMLTag.NAV and self._in_breadcrumb:
            self._in_breadcrumb = False

    def handle_data(self, data: str) -> None:
        if self._capture_h1:
            self.h1_text.append(data)
        if self._capture_title:
            self.title_text.append(data)


def _safe_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise UnsafeArtifactPathError(raw_path)
    return path


def _scan_identity(name: str, content: bytes) -> list[str]:
    violations: list[str] = []
    violations.extend(
        f"{name}: non-public organization reference"
        for match in ORGANIZATION_REFERENCE.finditer(content)
        if match.group(1).lower() not in ALLOWED_REPOSITORIES
    )
    if PERSONAL_HOME_PATH.search(content):
        violations.append(f"{name}: personal home path")
    return violations


def _scan_emails(name: str, content: bytes) -> list[str]:
    violations: list[str] = []
    for match in EMAIL_ADDRESS.finditer(content):
        candidate = match.group().lower().lstrip(b"/")
        if candidate.endswith(b"@example.invalid") or candidate in ALLOWED_EMAILS:
            continue
        violations.append(f"{name}: non-example email address")
    return violations


def _metadata_values(content: bytes) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    headers = content.split(b"\n\n", maxsplit=1)[0].decode("utf-8")
    for line in headers.splitlines():
        name, separator, value = line.partition(":")
        if separator:
            values.setdefault(name, []).append(value.strip())
    return values


def verify_distributions(
    directory: Path,
) -> list[str]:
    wheels = tuple(directory.glob("*.whl"))
    sdists = tuple(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        return ["distribution directory must contain exactly one wheel and one source distribution"]

    wheel_members = _wheel_members(wheels[0])
    wheel_metadata = _wheel_metadata(wheel_members)
    wheel_names = {str(member.path) for member in wheel_members}
    allowed_wheel_names = {
        name
        for name in wheel_names
        if name.startswith("repo_standards/")
        and (name.endswith(".py") or name == "repo_standards/py.typed")
    }
    allowed_wheel_names.update(
        f"{wheel_metadata.dist_info}/{name}" for name in WHEEL_METADATA_FILES
    )
    violations = [
        f"{wheels[0].name}:{name}: unexpected wheel member"
        for name in sorted(wheel_names - allowed_wheel_names)
    ]
    violations.extend(
        _verify_license(
            wheel_metadata.values,
            wheel_names,
            f"{wheel_metadata.dist_info}/licenses/LICENSE",
        )
    )
    violations.extend(_verify_common(wheel_members, wheels[0].name))

    sdist_members = _sdist_members(sdists[0])
    roots = {member.path.parts[0] for member in sdist_members}
    if len(roots) != 1:
        violations.append("source distribution must contain exactly one root directory")
        return violations
    sdist_root = next(iter(roots))
    sdist_names = {str(member.path) for member in sdist_members}
    allowed_sdist_names = {
        name
        for name in sdist_names
        if name.startswith(f"{sdist_root}/src/repo_standards/")
        and (name.endswith(".py") or name == f"{sdist_root}/src/repo_standards/py.typed")
    }
    allowed_sdist_names.update(f"{sdist_root}/{name}" for name in SDIST_ROOT_FILES)
    violations.extend(
        f"{sdists[0].name}:{name}: unexpected source distribution member"
        for name in sorted(sdist_names - allowed_sdist_names)
    )
    package_info = next(
        (member.content for member in sdist_members if member.path.name == "PKG-INFO"), None
    )
    if package_info is None:
        violations.append("source distribution is missing PKG-INFO")
    else:
        sdist_metadata = _metadata_values(package_info)
        violations.extend(_verify_license(sdist_metadata, sdist_names, f"{sdist_root}/LICENSE"))
    violations.extend(_verify_common(sdist_members, sdists[0].name))
    return violations


def verify_site(directory: Path) -> list[str]:
    if not directory.is_dir():
        return [f"site artifact does not exist: {directory}"]
    violations: list[str] = []
    observed: set[str] = set()
    for path in directory.rglob("*"):
        if path.is_dir():
            continue
        relative_path = path.relative_to(directory)
        artifact_path = _safe_path(relative_path.as_posix())
        observed.add(str(artifact_path))
        if path.is_symlink() or not path.is_file():
            violations.append(f"site:{artifact_path}: links are not publishable")
            continue
        if artifact_path.parts[0] == "pagefind":
            violations.append(f"site:{artifact_path}: search artifacts are not publishable")
        if (
            artifact_path.name not in {"_headers", "_redirects"}
            and artifact_path.suffix.casefold() not in SITE_SUFFIXES
        ):
            violations.append(f"site:{artifact_path}: unexpected static-site file type")
        if artifact_path.name.casefold().endswith(".map"):
            violations.append(f"site:{artifact_path}: source map is not publishable")
        content = path.read_bytes()
        display_name = f"site:{artifact_path}"
        violations.extend(_scan_identity(display_name, content))
        if artifact_path.parts[0] != "_astro":
            violations.extend(_scan_emails(display_name, content))
    violations.extend(
        f"site:{name}: required generated file is missing"
        for name in sorted(REQUIRED_SITE_FILES - observed)
    )
    violations.extend(verify_site_catalog(directory, observed))
    violations.extend(_verify_site_semantics(directory))
    violations.extend(_verify_site_csp(directory))
    return violations


def verify_site_catalog(directory: Path, observed: set[str]) -> list[str]:
    violations = [
        f"site:{name}: legacy API contract is not publishable"
        for name in sorted(observed)
        if name.startswith(
            ("api/v1/", "api/v2/", "api/v3/", "api/v4/", "api/v5/", "api/v6/")
        )
    ]
    catalog_path = directory / "api/v7/catalog.json"
    schema_path = directory / "api/v7/catalog.schema.json"
    if not catalog_path.is_file() or not schema_path.is_file():
        return violations
    try:
        catalog_document = _JSON_OBJECT.validate_json(catalog_path.read_bytes(), strict=True)
        schema_document = _JSON_OBJECT.validate_json(schema_path.read_bytes(), strict=True)
        catalog = SiteCatalog.model_validate(catalog_document)
    except ValidationError as error:
        violations.append(f"site:api/v7/catalog.json: invalid catalog v7: {error}")
        return violations
    if "tombstones" in catalog_document:
        violations.append("site:api/v7/catalog.json: tombstones are not part of catalog v7")
    try:
        _validate_schema(Draft202012Validator(schema_document), catalog_document)
    except JsonSchemaValidationError as error:
        violations.append(f"site:api/v7/catalog.json: schema validation failed: {error.message}")
    embedded = next(
        (
            descriptor.document
            for descriptor in catalog.schemas
            if descriptor.schema_id == "catalog"
        ),
        None,
    )
    if embedded != schema_document:
        violations.append("site:api/v7/catalog.schema.json: must equal the embedded catalog schema")
    schema_id = schema_document.get("$id")
    if not isinstance(schema_id, str) or not schema_id.endswith("/catalog-v7.schema.json"):
        violations.append("site:api/v7/catalog.schema.json: must identify catalog-v7.schema.json")
    unsigned = dict(catalog_document)
    provenance = dict(_JSON_OBJECT.validate_python(catalog_document["provenance"], strict=True))
    provenance["content_digest"] = ""
    unsigned["provenance"] = provenance
    expected_digest = hashlib.sha256(canonical_json(unsigned).encode()).hexdigest()
    if catalog.provenance.content_digest != expected_digest:
        violations.append("site:api/v7/catalog.json: content digest does not match catalog bytes")
    return violations


def _validate_schema(validator: _SchemaValidator, instance: JSONValue) -> None:
    validator.validate(instance)


def _verify_site_csp(directory: Path) -> list[str]:
    headers_path = directory / "_headers"
    if not headers_path.is_file():
        return ["site:_headers: Cloudflare security headers are required"]
    headers = headers_path.read_text(encoding="utf-8")
    violations: list[str] = []
    for path in directory.rglob("*.html"):
        relative = path.relative_to(directory).as_posix()
        document = path.read_bytes()
        if b'http-equiv="content-security-policy"' in document:
            violations.append(f"site:{relative}: CSP must be delivered by the response header only")
        for match in INLINE_SCRIPT.finditer(document):
            script = match.group(1)
            digest = base64.b64encode(hashlib.sha256(script).digest()).decode("ascii")
            if f"'sha256-{digest}'" not in headers:
                violations.append(f"site:{relative}: inline script is missing from the CSP")
    return violations


def _verify_site_semantics(directory: Path) -> list[str]:
    violations: list[str] = []
    catalog_path = directory / "api/v7/catalog.json"
    if not catalog_path.is_file():
        return violations
    payload = SiteCatalog.model_validate_json(catalog_path.read_bytes())
    expected_rules = {item.rule_id: item for item in payload.rules}
    observed_rules: set[str] = set()
    for path in directory.rglob("*.html"):
        relative = path.relative_to(directory).as_posix()
        parser = PageSemantics()
        parser.feed(path.read_text(encoding="utf-8"))
        if parser.main_count != 1:
            violations.append(f"site:{relative}: expected exactly one main landmark")
        if parser.h1_count != 1 or not "".join(parser.h1_text).strip():
            violations.append(f"site:{relative}: expected exactly one nonempty h1")
        if not "".join(parser.title_text).strip() or not parser.description:
            violations.append(f"site:{relative}: title and description are required")
        if parser.rule_id is None:
            if relative.startswith("rules/categories/") and (
                parser.breadcrumbs != 1 or parser.current_crumbs != 1
            ):
                violations.append(f"site:{relative}: category breadcrumb is incomplete")
            continue
        violations.extend(verify_rule_page(relative, parser, expected_rules, observed_rules))
    if observed_rules != set(expected_rules):
        violations.append("site: rendered rule routes differ from the catalog")
    return violations


def verify_rule_page(
    relative: str,
    parser: PageSemantics,
    expected_rules: dict[str, SiteRule],
    observed_rules: set[str],
) -> list[str]:
    if parser.rule_id is None:
        return []
    observed_rules.add(parser.rule_id)
    rule = expected_rules.get(parser.rule_id)
    if rule is None:
        return [f"site:{relative}: unknown rendered rule id"]
    violations: list[str] = []
    if "".join(parser.h1_text).strip() != rule.slug:
        violations.append(f"site:{relative}: rendered slug differs from catalog")
    if parser.breadcrumbs != 1:
        violations.append(f"site:{relative}: rule breadcrumb is incomplete")
    if parser.rule_navigation != 1:
        violations.append(f"site:{relative}: rule navigation is missing")
    expected_examples = len(rule.examples)
    if (
        parser.code_comparisons != expected_examples
        or parser.example_kinds.count("before") != expected_examples
        or parser.example_kinds.count("after") != expected_examples
    ):
        violations.append(f"site:{relative}: example pairs differ from catalog")
    return violations


def _wheel_members(path: Path) -> tuple[ArtifactMember, ...]:
    with zipfile.ZipFile(path) as archive:
        return tuple(
            ArtifactMember(
                _safe_path(info.filename),
                archive.read(info),
                stat.S_ISLNK(info.external_attr >> 16),
            )
            for info in archive.infolist()
            if not info.is_dir()
        )


def _wheel_metadata(members: tuple[ArtifactMember, ...]) -> WheelMetadata:
    metadata_members = [member for member in members if member.path.name == "METADATA"]
    if len(metadata_members) != 1:
        raise WheelMetadataError
    return WheelMetadata(
        values=_metadata_values(metadata_members[0].content),
        dist_info=str(metadata_members[0].path.parent),
    )


def _sdist_members(path: Path) -> tuple[ArtifactMember, ...]:
    members: list[ArtifactMember] = []
    with tarfile.open(path, mode="r:gz") as archive:
        for info in archive.getmembers():
            if info.isdir():
                continue
            artifact_path = _safe_path(info.name)
            if not info.isfile():
                members.append(ArtifactMember(artifact_path, b"", symbolic_link=True))
                continue
            extracted = archive.extractfile(info)
            if extracted is None:
                raise UnreadableSdistMemberError(artifact_path)
            members.append(ArtifactMember(artifact_path, extracted.read()))
    return tuple(members)


def _verify_common(members: Iterable[ArtifactMember], artifact_name: str) -> list[str]:
    violations: list[str] = []
    for member in members:
        display_name = f"{artifact_name}:{member.path}"
        if member.symbolic_link:
            violations.append(f"{display_name}: links are not publishable")
        if member.path.name.casefold().endswith(".map"):
            violations.append(f"{display_name}: source map is not publishable")
        violations.extend(_scan_identity(display_name, member.content))
        violations.extend(_scan_emails(display_name, member.content))
    return violations


def _verify_license(
    metadata: dict[str, list[str]], names: set[str], license_path: str
) -> list[str]:
    violations: list[str] = []
    if metadata.get("License-Expression") != ["MIT"]:
        violations.append("package metadata must declare License-Expression: MIT")
    license_files = metadata.get("License-File", [])
    if "LICENSE" not in license_files:
        violations.append("package metadata must declare License-File: LICENSE")
    if license_path not in names:
        violations.append(f"package artifact is missing {license_path}")
    return violations


def main(
    distributions: Annotated[
        Path | None,
        typer.Option(help="Directory containing one wheel and one source distribution."),
    ] = None,
    site: Annotated[
        Path | None,
        typer.Option(help="Generated static-site directory."),
    ] = None,
) -> None:
    if distributions is None and site is None:
        typer.echo("at least one artifact path is required", err=True)
        raise typer.Exit(code=2)
    violations: list[str] = []
    if distributions is not None:
        violations.extend(verify_distributions(distributions))
    if site is not None:
        violations.extend(verify_site(site))
    if violations:
        sys.stderr.write("\n".join(violations) + "\n")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    typer.run(main)
