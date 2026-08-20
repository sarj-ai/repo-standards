from __future__ import annotations

from pathlib import Path
import re
import tomllib

from pydantic import TypeAdapter

from repo_lint.core.models import JSONValue


REPOSITORY_ROOT = Path(__file__).parents[1]
ORGANIZATION_REFERENCE = re.compile(
    r"(?:@|github\.com/|uses:\s*)sarj-ai/([a-z0-9._-]+)", re.IGNORECASE
)
EMAIL_ADDRESS = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
PERSONAL_HOME_PATH = re.compile(
    rf"(?:/{'Users'}/|/{'home'}/|[A-Z]:\\\\{'Users'}\\\\)[a-z0-9._-]+",
    re.IGNORECASE,
)
ALLOWED_REPOSITORIES = frozenset({"repo-standards", "code-standards", "standards"})
ALLOWED_URL_USERINFO = frozenset(
    {"api.github.com@evil.example", "git@github.com", "token@github.com"}
)
EXCLUDED_DIRECTORIES = frozenset(
    {
        ".astro",
        ".basedpyright",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "dist",
        "node_modules",
    }
)
JSON_OBJECT = TypeAdapter(dict[str, JSONValue])


def test_public_distribution_has_no_legacy_compatibility_surface() -> None:
    project = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    assert project["scripts"] == {"repo-standards": "repo_lint.cli:main"}
    assert not any(path.is_file() for path in (REPOSITORY_ROOT / "compat").rglob("*"))
    publish_source = (REPOSITORY_ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    assert "publish_compat" not in publish_source
    assert "sarj-repo-lint" not in publish_source


def _public_files() -> tuple[Path, ...]:
    return tuple(
        path
        for path in REPOSITORY_ROOT.rglob("*")
        if not EXCLUDED_DIRECTORIES.intersection(path.relative_to(REPOSITORY_ROOT).parts)
        and (path.is_file() or path.is_symlink())
    )


def test_public_tree_contains_only_public_identity_references() -> None:
    violations: list[str] = []
    for path in _public_files():
        if path.is_symlink() or not path.is_file():
            violations.append(f"{path.relative_to(REPOSITORY_ROOT)}: non-regular file")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative_path = path.relative_to(REPOSITORY_ROOT)
        violations.extend(
            f"{relative_path}: non-public organization reference"
            for match in ORGANIZATION_REFERENCE.finditer(content)
            if match.group(1).casefold() not in ALLOWED_REPOSITORIES
        )
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in EMAIL_ADDRESS.finditer(line):
                candidate = match.group().casefold().lstrip("/")
                if candidate.endswith("@example.invalid"):
                    continue
                if candidate in ALLOWED_URL_USERINFO:
                    continue
                violations.append(f"{relative_path}:{line_number}: non-example email address")
        if PERSONAL_HOME_PATH.search(content):
            violations.append(f"{relative_path}: personal home path")
    assert not violations, "\n".join(violations)


def test_public_corpus_selection_has_public_provenance() -> None:
    corpus_path = REPOSITORY_ROOT / "corpus" / "public-oss-v2.json"
    corpus = JSON_OBJECT.validate_json(corpus_path.read_bytes(), strict=True)
    selection = corpus["selection"]
    assert isinstance(selection, dict)
    assert selection["rule"] == "stratified-anchor-v2"
    assert "source_revision" not in selection
    seed = selection["seed"]
    assert isinstance(seed, str)
    assert not re.search(r"[0-9a-f]{40}", seed)
