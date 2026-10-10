from __future__ import annotations

from dataclasses import replace
from datetime import date
import shutil
import subprocess
from typing import TYPE_CHECKING

from pydantic import TypeAdapter
import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.engine import check_baseline, classify_baseline
from repo_standards.core.models import Baseline, FindingsReport, RatchetClassification
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.policy_sarj.makefiles import is_makefile_path, physical_lines
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE = "repository/artifacts/makefile-growth"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(
        (executable, "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _commit(root: Path) -> str:
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".repo-standards").mkdir()
    (tmp_path / ".repo-standards/repository.toml").write_text(_MANIFEST)
    (tmp_path / "Makefile").write_bytes(b"check:\n\ttool check\n")
    _commit(tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"check:\n\ttool check\n", 0),
        (b"check:\r\n\ttool check\r\n", 0),
        (b"check:\n\ttool fix", 0),
        (b"check:\n", 0),
        (b"check:\n\ttool check\n\n", 1),
        (b"check:\n\ttool check\n# explanation\n", 1),
    ],
)
def test_staged_growth_uses_physical_lines(repository: Path, content: bytes, expected: int) -> None:
    (repository / "Makefile").write_bytes(content)
    _git(repository, "add", "Makefile")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "complete"
    assert len(report.diagnostics) == expected
    if expected:
        assert report.diagnostics[0].observed_value == 3
        assert report.diagnostics[0].expected_value == 2


@pytest.mark.parametrize(
    "path", ["GNUmakefile", "nested/Makefile.terraform", "vars.mk", "Makecall"]
)
def test_new_empty_make_artifact_is_a_finding(repository: Path, path: str) -> None:
    target = repository / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"")
    _git(repository, "add", path)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "complete"
    assert [item.path for item in report.diagnostics] == [path]


def test_index_bytes_are_independent_of_unstaged_bytes(repository: Path) -> None:
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# more\n")
    _git(repository, "add", "Makefile")
    (repository / "Makefile").write_bytes(b"")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "complete"
    assert len(report.diagnostics) == 1


def test_cleanup_lowers_the_next_comparison_ceiling(repository: Path) -> None:
    (repository / "Makefile").write_bytes(b"check:\n")
    _commit(repository)
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n")
    _git(repository, "add", "Makefile")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].expected_value == 1


def test_explicit_base_and_cli_match(repository: Path) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# more\n")
    _commit(repository)
    (repository / "README.md").write_text("Readme\n")
    _commit(repository)
    request = RepositoryAnalysisRequest(root=repository, base_revision=base)
    report = analyze_repository(request)
    assert len(report.diagnostics) == 1
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_base_revision == base
    result = CliRunner().invoke(
        app, ["report", str(repository), "--base", base, "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = TypeAdapter(dict[str, object]).validate_json(result.stdout)
    diagnostics = TypeAdapter(list[dict[str, object]]).validate_python(payload["diagnostics"])
    provenance = TypeAdapter(dict[str, object]).validate_python(payload["input_provenance"])
    assert diagnostics[0]["observed"] == 3
    assert provenance["comparison_base_revision"] == base


def test_missing_explicit_base_is_incomplete(repository: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision="f" * 40))
    assert report.completion == "incomplete"


def test_disabled_rule_does_not_resolve_comparison(repository: Path) -> None:
    (repository / ".repo-standards/repository.toml").write_text(
        'repository_id = "example"\ncomponents = []\n'
    )
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision="f" * 40))
    assert report.completion == "complete"
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_base_revision is None


def _allowance(*, expires: str = "2026-10-31", cap: int = 3) -> str:
    return (
        '\n[[makefiles.exceptions]]\npath = "Makefile"\n'
        f'max_lines = {cap}\nowner = "example-team"\nreason = "Required integration"\n'
        'issue = "EXAMPLE-1"\ncreated_on = "2026-10-01"\n'
        f'expires_on = "{expires}"\n'
    )


@pytest.mark.parametrize(
    ("expires", "as_of", "disposition"),
    [
        ("2026-10-31", date(2026, 10, 9), "excepted"),
        ("2026-10-02", date(2026, 10, 9), "active"),
        ("2026-10-31", date(2026, 9, 30), "active"),
    ],
    ids=["valid", "expired", "future"],
)
def test_capped_exception_calendar(
    repository: Path, expires: str, as_of: date, disposition: str
) -> None:
    (repository / ".repo-standards/repository.toml").write_text(
        _MANIFEST + _allowance(expires=expires)
    )
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# required\n")
    _git(repository, "add", ".")
    report = analyze_repository(
        RepositoryAnalysisRequest(root=repository, staged=True, as_of=as_of)
    )
    assert report.completion == "complete"
    assert report.diagnostics[0].disposition == disposition


def test_unused_expired_exception_does_not_block(repository: Path) -> None:
    (repository / ".repo-standards/repository.toml").write_text(
        _MANIFEST + _allowance(expires="2026-10-02")
    )
    _git(repository, "add", ".")
    report = analyze_repository(
        RepositoryAnalysisRequest(root=repository, staged=True, as_of=date(2026, 10, 9))
    )
    assert report.completion == "complete"
    assert report.diagnostics == ()


def test_allowance_parser_rejects_boolean_cap() -> None:
    with pytest.raises(ValueError, match="max_lines"):
        parse_manifest_bytes(
            (_MANIFEST + _allowance().replace("max_lines = 3", "max_lines = true")).encode()
        )


def test_baseline_cannot_authorize_growth(repository: Path) -> None:
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# extra\n")
    _git(repository, "add", "Makefile")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert isinstance(report, FindingsReport)
    diagnostic = replace(report.diagnostics[0], severity="error")
    report = replace(report, diagnostics=(diagnostic,))
    baseline = Baseline(
        repository_id=report.repository_id,
        policy_id=report.policy_id,
        policy_version=report.policy_version,
        scope_digest=report.scope_digest,
        fingerprints=(diagnostic.fingerprint,),
    )
    assert (
        classify_baseline(report, baseline).entries[0].classification is RatchetClassification.NEW
    )
    assert check_baseline(report, baseline) == (diagnostic,)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("MAKEFILE", True),
        ("vendor/Makefile.generated", True),
        ("fixtures/GNUmakefile.test", True),
        ("generated/Rules.MK", True),
        ("Makefile.md", False),
        ("docs/GNUmakefile.MDX", False),
        ("Makefile.rst", False),
        ("Makefile.adoc", False),
        ("Makefile.txt", False),
        ("Makefile.md.mk", True),
        (".env.mcp", False),
        ("Taskfile", False),
        ("custom.make", False),
        ("Makefileish", False),
    ],
)
def test_makefile_path_scope(path: str, expected: bool) -> None:
    assert is_makefile_path(path) is expected


@pytest.mark.parametrize(
    ("content", "lines"),
    [(b"", 0), (b"target:", 1), (b"target:\n", 1), (b"target:\r\n", 1), (b"\n\n", 2)],
)
def test_line_count_does_not_depend_on_final_newline(content: bytes, lines: int) -> None:
    assert physical_lines(content) == lines


@pytest.mark.parametrize("destination", ["makefile", "nested/Makefile", "Copy.mk"])
def test_copy_or_move_destination_is_a_new_path(repository: Path, destination: str) -> None:
    target = repository / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    content = (repository / "Makefile").read_bytes()
    if destination != "Copy.mk":
        (repository / "Makefile").unlink()
        _git(repository, "rm", "--cached", "Makefile")
    target.write_bytes(content)
    _git(repository, "add", "-A")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "complete"
    assert [item.path for item in report.diagnostics] == [destination]


def test_deletion_is_allowed(repository: Path) -> None:
    (repository / "Makefile").unlink()
    _git(repository, "add", "-A")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "complete"
    assert report.diagnostics == ()


@pytest.mark.parametrize(("count", "size"), [(1, 5_242_881), (101, 1)])
@pytest.mark.parametrize("staged", [True, False])
@pytest.mark.parametrize("delete", [True, False])
def test_blob_limits_apply_only_to_surviving_makefiles(
    repository: Path, count: int, size: int, staged: bool, delete: bool
) -> None:
    paths = [repository / "Makefile", *(repository / f"{index}.mk" for index in range(count - 1))]
    for path in paths:
        path.write_bytes(b"#" * size)
    base = _commit(repository)
    if delete:
        for path in paths:
            path.unlink()
    _git(repository, "add", "-A")
    if not staged and delete:
        _commit(repository)
    report = analyze_repository(
        RepositoryAnalysisRequest(root=repository, staged=staged, base_revision=base)
    )
    assert report.completion == ("complete" if delete else "incomplete")
    assert report.diagnostics == ()


def test_local_default_reports_only_last_commit(repository: Path) -> None:
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# extra\n")
    previous = _commit(repository)
    (repository / "README.md").write_text("Readme\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository))
    assert report.completion == "complete"
    assert report.diagnostics == ()
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_basis == "last-commit"
    assert report.input_provenance.comparison_base_revision == previous


def test_staged_ignores_explicit_base(repository: Path) -> None:
    report = analyze_repository(
        RepositoryAnalysisRequest(root=repository, staged=True, base_revision="missing-base")
    )
    assert report.completion == "complete"
    assert report.diagnostics == ()
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_basis == "staged"


def test_root_commit_has_an_empty_comparison(repository: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository))
    assert report.completion == "complete"
    assert [item.path for item in report.diagnostics] == ["Makefile"]
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_basis == "empty"


def test_unborn_index_has_an_empty_comparison(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / ".repo-standards").mkdir()
    (tmp_path / ".repo-standards/repository.toml").write_text(_MANIFEST)
    (tmp_path / "Makefile").write_bytes(b"")
    _git(tmp_path, "add", ".")
    report = analyze_repository(RepositoryAnalysisRequest(root=tmp_path, staged=True))
    assert report.completion == "complete"
    assert [item.path for item in report.diagnostics] == ["Makefile"]


def test_corrupt_head_is_not_an_empty_index_base(repository: Path) -> None:
    ref = _git(repository, "symbolic-ref", "HEAD")
    (repository / ".git" / ref).write_text("f" * 40 + "\n")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "incomplete"


def test_missing_parent_is_not_a_root_commit(repository: Path) -> None:
    parent = _git(repository, "rev-parse", "HEAD")
    (repository / "README.md").write_text("Readme\n")
    head = _commit(repository)
    (repository / ".git/objects" / parent[:2] / parent[2:]).unlink()
    report = analyze_repository(RepositoryAnalysisRequest(root=repository))
    assert report.completion == "incomplete"
    explicit = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=head))
    assert explicit.completion == "complete"
    assert explicit.diagnostics == ()


def test_all_zero_explicit_base_is_empty(repository: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision="0" * 40))
    assert report.completion == "complete"
    assert [item.path for item in report.diagnostics] == ["Makefile"]


@pytest.mark.parametrize("cap", [0, 2])
def test_growth_over_exception_cap_remains_active(repository: Path, cap: int) -> None:
    (repository / ".repo-standards/repository.toml").write_text(_MANIFEST + _allowance(cap=cap))
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# extra\n")
    _git(repository, "add", ".")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "complete"
    assert report.diagnostics[0].disposition == "active"


def test_used_exception_needs_a_date(repository: Path) -> None:
    (repository / ".repo-standards/repository.toml").write_text(_MANIFEST + _allowance())
    (repository / "Makefile").write_bytes(b"check:\n\ttool check\n# extra\n")
    _git(repository, "add", ".")
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, staged=True))
    assert report.completion == "incomplete"
    assert "--as-of" in report.execution_issues[0].message


@pytest.mark.parametrize(
    "change",
    [
        ("max_lines = 3", "max_lines = -1"),
        ('path = "Makefile"', 'path = "./Makefile"'),
        ('path = "Makefile"', 'path = "**/Makefile"'),
        ('owner = "example-team"', 'owner = ""'),
        ('owner = "example-team"', 'owner = "   "'),
        ('reason = "Required integration"', 'reason = "   "'),
        ('issue = "EXAMPLE-1"', 'issue = "   "'),
        ('expires_on = "2026-10-31"', 'expires_on = "2027-01-31"'),
        ('expires_on = "2026-10-31"', 'expires_on = "2026-09-30"'),
        ('expires_on = "2026-10-31"', 'expires_on = "2026-02-30"'),
    ],
    ids=[
        "negative-cap",
        "noncanonical-path",
        "glob-path",
        "empty-owner",
        "blank-owner",
        "blank-reason",
        "blank-issue",
        "overlong-duration",
        "backward-dates",
        "invalid-date",
    ],
)
def test_allowance_requires_scoped_valid_metadata(change: tuple[str, str]) -> None:
    with pytest.raises(ValueError, match="makefiles"):
        parse_manifest_bytes((_MANIFEST + _allowance().replace(*change)).encode())


def test_duplicate_allowance_path_is_invalid() -> None:
    with pytest.raises(ValueError, match="duplicate paths"):
        parse_manifest_bytes((_MANIFEST + _allowance() + _allowance()).encode())


def test_generic_exception_cannot_authorize_growth() -> None:
    generic = (
        f'\n[[exceptions]]\nrule_id = "{_RULE}"\ncomponent_id = "repository"\n'
        'manifest_anchor = "tracked_files.Makefile"\n'
        f'fingerprint = "{"f" * 64}"\n'
        'owner = "example"\nreason = "Required"\nissue = "EXAMPLE-1"\n'
        'created_on = "2026-10-01"\nexpires_on = "2026-10-31"\n'
    )
    with pytest.raises(ValueError, match="capped"):
        parse_manifest_bytes((_MANIFEST + generic).encode())
