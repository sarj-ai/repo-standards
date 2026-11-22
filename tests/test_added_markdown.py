from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING, Literal

import pytest

from repo_standards.core.models import (
    FindingsReport,
    FixtureId,
    MigrationComparison,
    PullRequestTemplate,
)
from repo_standards.core.pull_request_documentation import markdown_only_paths_for_revisions
from repo_standards.policy_sarj.examples import run_rule_example
from repo_standards.repository import (
    RepositoryAnalysisRequest,
    RepositorySnapshot,
    analyze_repository,
    load_repository_snapshot,
)


if TYPE_CHECKING:
    from pathlib import Path


_RULE = "repository/documentation/added-markdown"
_MANIFEST = f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{_RULE}"]\n'


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    return subprocess.run(
        (executable, "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


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
    (tmp_path / "README.md").write_text("Canonical guide\n")
    _commit(tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    "path", ["notes.md", "nested/GUIDE.MD", "guide.mdx", "empty.md", "vendor/doc.md", ".hidden.md"]
)
@pytest.mark.parametrize("staged", [False, True])
def test_new_paths_block_with_exact_comparison(
    repository: Path, path: str, *, staged: bool
) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    target = repository / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("")
    if staged:
        _git(repository, "add", ".")
        target.unlink()
    else:
        _commit(repository)
    report = analyze_repository(
        RepositoryAnalysisRequest(root=repository, base_revision=base, staged=staged)
    )
    assert isinstance(report, FindingsReport)
    assert [(item.rule_id, item.path, item.severity) for item in report.diagnostics] == [
        (_RULE, path, "error")
    ]
    assert not report.diagnostics[0].baselineable
    assert report.input_provenance is not None
    assert report.input_provenance.comparison_base_revision == base
    assert report.input_provenance.comparison_basis == ("staged" if staged else "explicit")


@pytest.mark.parametrize("change", ["edit", "delete", "untracked", "source", "extension-near-miss"])
def test_existing_edits_and_non_additions_pass(repository: Path, change: str) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    match change:
        case "edit":
            (repository / "README.md").write_text("A materially updated guide\n")
        case "delete":
            (repository / "README.md").unlink()
        case _:
            path = {
                "untracked": "notes.md",
                "source": "module.py",
                "extension-near-miss": "guide.md.py",
            }[change]
            (repository / path).write_text("content\n")
    if change != "untracked":
        _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert report.diagnostics == ()


@pytest.mark.parametrize("operation", ["rename", "copy"])
def test_new_destinations_need_review(repository: Path, operation: str) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    (repository / "guide.md").write_bytes((repository / "README.md").read_bytes())
    if operation == "rename":
        (repository / "README.md").unlink()
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert [item.path for item in report.diagnostics] == ["guide.md"]


@pytest.mark.parametrize("trusted", [False, True])
def test_only_base_budget_and_exact_exemptions_apply(repository: Path, *, trusted: bool) -> None:
    manifest = repository / ".repo-standards/repository.toml"
    policy = (
        '\n[documentation]\nentrypoints = ["README.md"]\n'
        'maximum_added_pages = 1\naddition_exemptions = ["required.md"]\n'
    )
    if trusted:
        manifest.write_text(_MANIFEST + policy)
        _commit(repository)
    base = _git(repository, "rev-parse", "HEAD")
    manifest.write_text(_MANIFEST + policy)
    for path in ("required.md", "other.md"):
        (repository / path).write_text("Required content\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert len(report.diagnostics) == (0 if trusted else 1)
    if not trusted:
        assert report.diagnostics[0].observed_value == 2


def test_one_budget_finding_and_branch_base_cover_multiple_commits(repository: Path) -> None:
    base = _git(repository, "rev-parse", "HEAD")
    for path in ("b.md", "a.md"):
        (repository / path).write_text("content\n")
        _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert len(report.diagnostics) == 1
    assert report.diagnostics[0].path == "a.md"
    assert report.diagnostics[0].observed_value == 2


def test_missing_comparison_evidence_is_incomplete(repository: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision="f" * 40))
    assert report.completion == "incomplete"


def test_public_example_executes_the_page_budget_contract() -> None:
    fixture = FixtureId("sarj-documentation-added-markdown")
    assert run_rule_example(fixture, '{"base":[],"head":["docs/notes.md"]}') == (_RULE,)
    assert run_rule_example(fixture, '{"base":["README.md"],"head":["README.md"]}') == ()


def test_snapshot_preserves_legacy_optional_positional_arguments(repository: Path) -> None:
    snapshot = load_repository_snapshot(repository)
    templates = (PullRequestTemplate(".github/pull_request_template.md", "Test evidence"),)
    migration = MigrationComparison(roots=(), base_files=(), head_files=())

    legacy = RepositorySnapshot(
        snapshot.manifest,
        snapshot.baseline,
        snapshot.inspection,
        snapshot.provenance,
        None,
        templates,
        migration,
    )

    assert legacy.pull_request_templates is templates
    assert legacy.migration_comparison is migration
    assert legacy.documentation_comparison is None


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("edit", True),
        ("delete", True),
        ("rename", True),
        ("uppercase-mdx", True),
        ("source-edit", False),
        ("source-mode", False),
        ("source-rename", False),
        ("empty", False),
        ("untracked", False),
    ],
)
def test_markdown_only_review_uses_the_complete_git_change(
    repository: Path,
    change: Literal[
        "edit",
        "delete",
        "rename",
        "uppercase-mdx",
        "source-edit",
        "source-mode",
        "source-rename",
        "empty",
        "untracked",
    ],
    *,
    expected: bool,
) -> None:
    rule = "repository/documentation/markdown-only-change"
    (repository / ".repo-standards/repository.toml").write_text(
        f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{rule}"]\n'
    )
    source = repository / "module.py"
    source.write_text("print('native source')\n")
    base = _commit(repository)
    readme = repository / "README.md"
    readme.write_text("A necessary documentation correction\n")
    match change:
        case "edit":
            pass
        case "delete":
            readme.unlink()
        case "rename":
            readme.rename(repository / "guide.md")
        case "uppercase-mdx":
            readme.rename(repository / "GUIDE.MDX")
        case "source-edit":
            source.write_text("print('changed source')\n")
        case "source-mode":
            source.chmod(0o755)
        case "source-rename":
            source.rename(repository / "module.md")
        case "empty" | "untracked":
            _git(repository, "checkout", "--", "README.md")
            if change == "untracked":
                (repository / "notes.md").write_text("Untracked task notes\n")
    if change not in {"empty", "untracked"}:
        _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "complete"
    assert [item.rule_id for item in report.diagnostics] == ([rule] if expected else [])
    if expected:
        assert report.diagnostics[0].severity == "warning"
        assert not report.diagnostics[0].baselineable


@pytest.mark.parametrize("both_rules", [False, True])
def test_added_page_budget_takes_precedence_only_when_enabled(
    repository: Path, *, both_rules: bool
) -> None:
    rule = "repository/documentation/markdown-only-change"
    rules = [rule, _RULE] if both_rules else [rule]
    (repository / ".repo-standards/repository.toml").write_text(
        'repository_id = "example"\ncomponents = []\nenabled_rules = ['
        + ",".join(f'"{item}"' for item in rules)
        + "]\n"
    )
    base = _commit(repository)
    (repository / "guide.md").write_text("A new page\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert [item.rule_id for item in report.diagnostics] == ([_RULE] if both_rules else [rule])


def test_markdown_only_rule_does_not_guess_a_pr_from_its_last_commit(repository: Path) -> None:
    rule = "repository/documentation/markdown-only-change"
    (repository / ".repo-standards/repository.toml").write_text(
        f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{rule}"]\n'
    )
    _commit(repository)
    (repository / "README.md").write_text("A documentation followup to an earlier source commit\n")
    _commit(repository)
    report = analyze_repository(RepositoryAnalysisRequest(root=repository))
    assert report.completion == "complete"
    assert report.diagnostics == ()


def test_markdown_classifier_retains_the_existing_symlink_rejection(repository: Path) -> None:
    rule = "repository/documentation/markdown-only-change"
    (repository / ".repo-standards/repository.toml").write_text(
        f'repository_id = "example"\ncomponents = []\nenabled_rules = ["{rule}"]\n'
    )
    (repository / "module.py").write_text("print('native source')\n")
    base = _commit(repository)
    readme = repository / "README.md"
    readme.unlink()
    readme.symlink_to("module.py")
    head = _commit(repository)

    assert markdown_only_paths_for_revisions(repository, base=base, head=head) == ()
    report = analyze_repository(RepositoryAnalysisRequest(root=repository, base_revision=base))
    assert report.completion == "incomplete"
    assert [issue.message for issue in report.execution_issues] == [
        "tracked path is a symlink: README.md"
    ]
    assert report.input_provenance is None
    assert report.diagnostics == ()
