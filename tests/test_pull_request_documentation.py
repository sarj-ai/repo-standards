from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

from pydantic import TypeAdapter
import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.pull_request_documentation import analyze_pull_request_documentation


if TYPE_CHECKING:
    from pathlib import Path


runner = CliRunner()


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )
    return completed.stdout.decode().strip()


def _commit(repository: Path) -> str:
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path, *, maximum: int = 0, exemptions: tuple[str, ...] = ()) -> str:
    _git(tmp_path, "init", "--quiet")
    manifest = tmp_path / ".repo-standards" / "repository.toml"
    manifest.parent.mkdir()
    exempt_line = (
        "addition_exemptions = [" + ", ".join(f'"{path}"' for path in exemptions) + "]\n"
        if exemptions
        else ""
    )
    manifest.write_text(
        'repository_id = "fixture"\ncomponents = []\n'
        '[documentation]\nentrypoints = ["README.md"]\n'
        f"maximum_added_pages = {maximum}\n{exempt_line}",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    return _commit(tmp_path)


def test_documentation_budget_rejects_any_new_page_by_default(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "one.md").write_text("# One\n", encoding="utf-8")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", "json"],
    )

    assert result.exit_code == 1
    assert '"added_pages":1' in result.stdout
    assert '"docs/one.md"' in result.stdout


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_cli_rejects_added_readme_content_without_new_pages(
    tmp_path: Path, output_format: str
) -> None:
    base = _repository(tmp_path)
    (tmp_path / "README.md").write_text("# Fixture\nnew content\n", encoding="utf-8")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", output_format],
    )

    assert result.exit_code == 1
    if output_format == "json":
        payload = TypeAdapter(dict[str, object]).validate_json(result.stdout)
        assert payload["content_findings"] == ["README.md"]
        assert payload["summary"] == {
            "satisfied": False,
            "added_pages": 0,
            "exempt_pages": 0,
            "added_content_files": 1,
        }
        assert payload["policy"] == {
            "maximum_added_pages": 0,
            "maximum_added_content_files": 0,
            "source": base,
        }
        assert payload["findings"] == []
    else:
        assert "Added Markdown pages: 0/0" in result.stdout
        assert "README/docs files with added content: 1/0\n  README.md\n" in result.stdout
        assert (
            "Remove the added documentation; express behavior in code, tests and CLI help."
            in result.stdout
        )


def test_documentation_budget_uses_trusted_base_policy_and_exact_exemptions(
    tmp_path: Path,
) -> None:
    base = _repository(tmp_path, maximum=0, exemptions=("CONTRACT.md",))
    (tmp_path / "CONTRACT.md").write_text("# Contract\n", encoding="utf-8")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", "json"],
    )

    assert result.exit_code == 0
    assert '"added_pages":0' in result.stdout
    assert '"exempt_pages":1' in result.stdout


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "nested/readme.MD",
        "docs/guide.txt",
        "nested/DoCs/api.json",
        'docs/odd\tname\n".txt',
        "docs/:(glob)*.txt",
    ],
)
def test_content_additions_are_rejected_in_existing_scoped_files(tmp_path: Path, path: str) -> None:
    _repository(tmp_path)
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("existing\n", encoding="utf-8")
    base = _commit(tmp_path)
    target.write_text("existing\nnew content\n", encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == (path,)
    assert not result.satisfied


@pytest.mark.parametrize("content", ["", "existing\n", "\nexisting\n\t\nsecond\n\u2003\n"])
def test_deletions_and_blank_additions_are_allowed(tmp_path: Path, content: str) -> None:
    _repository(tmp_path)
    target = tmp_path / "README.md"
    target.write_text("existing\nsecond\n", encoding="utf-8")
    base = _commit(tmp_path)
    target.write_text(content, encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ()
    assert result.satisfied


@pytest.mark.parametrize("path", ["nested/README.md", "docs/new.md"])
def test_content_ban_is_independent_of_page_exemptions(tmp_path: Path, path: str) -> None:
    base = _repository(tmp_path, maximum=100, exemptions=(path,))
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_text("new content\n", encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.exempt_pages == (path,)
    assert result.added_content_paths == (path,)
    assert not result.satisfied


@pytest.mark.parametrize(
    "content",
    [
        b"replacement\n",
        b"existing\nexisting\n",
        b"existing\x00hidden",
        b"existing\n\xff",
        b"existing\v",
    ],
)
def test_replacements_duplicates_and_binary_content_are_rejected(
    tmp_path: Path, content: bytes
) -> None:
    _repository(tmp_path)
    target = tmp_path / "README.md"
    target.write_bytes(b"existing\n")
    base = _commit(tmp_path)
    target.write_bytes(content)
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        "README.md",
    )


@pytest.mark.parametrize("source", ["source.txt", "docs/old.txt"])
@pytest.mark.parametrize("copy", [False, True])
def test_moves_and_copies_cannot_import_content_into_docs(
    tmp_path: Path, source: str, copy: bool
) -> None:
    _repository(tmp_path)
    original = tmp_path / source
    original.parent.mkdir(parents=True, exist_ok=True)
    original.write_text("existing content\n", encoding="utf-8")
    base = _commit(tmp_path)
    destination = tmp_path / "docs/new.txt"
    destination.parent.mkdir(exist_ok=True)
    if copy:
        destination.write_bytes(original.read_bytes())
    else:
        _git(tmp_path, "mv", source, "docs/new.txt")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    expected = () if source.startswith("docs/") and not copy else ("docs/new.txt",)
    assert result.added_content_paths == expected


def test_attributes_cannot_hide_readme_content_changes(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    (tmp_path / ".gitattributes").write_text("README.md -diff\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Fixture\nnew content\n", encoding="utf-8")
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        "README.md",
    )


def test_diff_drivers_and_uncommitted_files_cannot_replace_exact_tree_evidence(
    tmp_path: Path,
) -> None:
    _repository(tmp_path)
    (tmp_path / ".gitattributes").write_text("README.md diff=hidden\n", encoding="utf-8")
    base = _commit(tmp_path)
    _git(tmp_path, "config", "diff.hidden.command", "nonexistent-diff-driver")
    _git(tmp_path, "config", "diff.hidden.textconv", "nonexistent-textconv-driver")
    (tmp_path / "README.md").write_text("# Fixture\nnew content\n", encoding="utf-8")
    _commit(tmp_path)
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ("README.md",)


def test_content_ban_cannot_be_disabled_by_head_manifest(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    manifest = tmp_path / ".repo-standards/repository.toml"
    manifest.write_text('repository_id = "fixture"\ncomponents = []\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("new content\n", encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ("README.md",)
    assert not result.satisfied


def test_binary_deletion_and_blank_only_new_files_are_allowed(tmp_path: Path) -> None:
    _repository(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    binary = docs / "image.bin"
    binary.write_bytes(b"existing\0binary")
    base = _commit(tmp_path)
    binary.unlink()
    (docs / "blank.txt").write_text("\t\n\u2003\n", encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ()
    assert result.satisfied


def test_unrelated_changes_preserve_existing_documentation(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    (tmp_path / "source.py").write_text("value = 1\n", encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ()
    assert result.satisfied


def test_non_blob_content_evidence_fails_closed(tmp_path: Path) -> None:
    base = _repository(tmp_path)
    _git(tmp_path, "update-index", "--add", "--cacheinfo", f"160000,{base},docs/module")
    _git(
        tmp_path,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )

    with pytest.raises(ConfigurationError, match="documentation blob evidence"):
        analyze_pull_request_documentation(tmp_path, base=base)


def test_gitmodules_cannot_hide_changed_documentation_gitlinks(tmp_path: Path) -> None:
    initial = _repository(tmp_path)
    _git(tmp_path, "update-index", "--add", "--cacheinfo", f"160000,{initial},docs/module")
    _git(
        tmp_path,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    base = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / ".gitmodules").write_text(
        '[submodule "docs/module"]\n'
        "path = docs/module\nurl = https://example.invalid/module\nignore = all\n",
        encoding="utf-8",
    )
    _git(tmp_path, "add", ".gitmodules")
    _git(tmp_path, "update-index", "--cacheinfo", f"160000,{base},docs/module")
    _git(
        tmp_path,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    assert _git(tmp_path, "rev-parse", "HEAD:docs/module") == base

    with pytest.raises(ConfigurationError, match="documentation blob evidence"):
        analyze_pull_request_documentation(tmp_path, base=base)


@pytest.mark.parametrize("path", ["docs", "nested/DoCs"])
def test_docs_directory_gitlinks_fail_closed(tmp_path: Path, path: str) -> None:
    base = _repository(tmp_path)
    _git(tmp_path, "update-index", "--add", "--cacheinfo", f"160000,{base},{path}")
    _git(
        tmp_path,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )

    with pytest.raises(ConfigurationError, match="documentation blob evidence"):
        analyze_pull_request_documentation(tmp_path, base=base)


@pytest.mark.parametrize("path", ["docs", "nested/DoCs"])
@pytest.mark.parametrize("link_target", ["existing-directory", " "])
def test_docs_directory_symlink_introductions_are_rejected(
    tmp_path: Path, path: str, link_target: str
) -> None:
    base = _repository(tmp_path)
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(link_target)
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == (path,)
    assert not result.satisfied


@pytest.mark.parametrize("path", ["docs", "nested/DoCs"])
def test_docs_symlink_target_changes_cannot_appear_as_content_deletions(
    tmp_path: Path, path: str
) -> None:
    _repository(tmp_path)
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to("existing\nother")
    base = _commit(tmp_path)
    target.unlink()
    target.symlink_to("existing")
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (path,)


def test_readme_regular_file_cannot_turn_into_symlink_with_same_blob(tmp_path: Path) -> None:
    _repository(tmp_path)
    target = tmp_path / "README.md"
    target.write_text("outside-content", encoding="utf-8")
    base = _commit(tmp_path)
    target.unlink()
    target.symlink_to("outside-content")
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        "README.md",
    )


@pytest.mark.parametrize("path", ["docs", "nested/DoCs"])
def test_ordinary_files_named_docs_are_not_directory_content(tmp_path: Path, path: str) -> None:
    base = _repository(tmp_path)
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("ordinary file content\n", encoding="utf-8")
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ()
    assert result.satisfied


def test_documentation_budget_does_not_count_pure_renames(tmp_path: Path) -> None:
    base = _repository(tmp_path, maximum=0)
    _git(tmp_path, "mv", "README.md", "GUIDE.md")
    _commit(tmp_path)

    result = runner.invoke(
        app,
        ["pull-request", "documentation", str(tmp_path), "--base", base, "--format", "json"],
    )

    assert result.exit_code == 0
    assert '"added_pages":0' in result.stdout


@pytest.mark.parametrize("filename", ["package.json", "package-lock.json"])
def test_existing_docs_app_dependency_metadata_updates_are_not_documentation(
    tmp_path: Path, filename: str
) -> None:
    base = _docs_package(tmp_path)
    package = tmp_path / "apps/docs/package.json"
    target = package.with_name(filename)
    target.write_text(
        target.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8"
    )
    _commit(tmp_path)

    result = analyze_pull_request_documentation(tmp_path, base=base)

    assert result.added_content_paths == ()
    assert result.satisfied


def _docs_package(tmp_path: Path) -> str:
    _repository(tmp_path)
    package = tmp_path / "apps/docs/package.json"
    package.parent.mkdir(parents=True)
    package.write_text(
        '{"name":"docs-app","private":true,"dependencies":{"site-framework":"^1.0.0"}}\n',
        encoding="utf-8",
    )
    lock = package.with_name("package-lock.json")
    lock.write_text(
        '{"name":"docs-app","lockfileVersion":3,"packages":'
        '{"":{"name":"docs-app","dependencies":{"site-framework":"^1.0.0"}},'
        '"node_modules/site-framework":{"version":"1.0.0"}}}\n',
        encoding="utf-8",
    )
    return _commit(tmp_path)


@pytest.mark.parametrize("filename", ["package.json", "package-lock.json"])
def test_overflowed_json_numbers_cannot_qualify_for_metadata_maintenance(
    tmp_path: Path, filename: str
) -> None:
    _docs_package(tmp_path)
    target = tmp_path / "apps/docs" / filename
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            '"name":"docs-app"', '"name":"docs-app","config":{"limit":1e999}'
        ),
        encoding="utf-8",
    )
    base = _commit(tmp_path)
    target.write_text(
        target.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8"
    )
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        f"apps/docs/{filename}",
    )


@pytest.mark.parametrize(
    ("filename", "original", "replacement"),
    [
        ("package.json", '"private":true', '"private":false'),
        ("package.json", '"private":true', '"private":1'),
        ("package.json", '"private":true', '"private":true,"description":"new prose"'),
        ("package.json", '"private":true', '"private":true,"scripts":{"build":"changed"}'),
        ("package.json", '"^1.0.0"', '{"description":"prose"}'),
        ("package.json", '"name":"docs-app"', '"name":"docs-app","name":"docs-app"'),
        ("package.json", '"private":true', '"private":NaN'),
        ("package-lock.json", '"lockfileVersion":3', '"lockfileVersion":3.0'),
        ("package-lock.json", '"lockfileVersion":3', '"lockfileVersion":3,"description":"prose"'),
        ("package-lock.json", '"name":"docs-app"', '"name":"other-app"'),
        ("package-lock.json", '"version":"1.0.0"', '"version":"1.0.0","version":"1.0.1"'),
    ],
)
def test_metadata_exception_does_not_allow_prose_config_or_ambiguous_json_changes(
    tmp_path: Path, filename: str, original: str, replacement: str
) -> None:
    base = _docs_package(tmp_path)
    target = tmp_path / "apps/docs" / filename
    target.write_text(
        target.read_text(encoding="utf-8").replace(original, replacement), encoding="utf-8"
    )
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        f"apps/docs/{filename}",
    )


@pytest.mark.parametrize("operation", ["add", "rename", "symlink", "executable"])
def test_metadata_exception_does_not_exempt_new_moved_or_changed_file_types(
    tmp_path: Path, operation: str
) -> None:
    base = _docs_package(tmp_path)
    target = tmp_path / "apps/docs/package.json"
    match operation:
        case "add":
            target = tmp_path / "apps/docs/nested/package.json"
            target.parent.mkdir()
            target.write_text(
                '{"name":"new-app","dependencies":{"framework":"1.0.0"}}\n', encoding="utf-8"
            )
        case "rename":
            target.parent.joinpath("nested").mkdir()
            _git(tmp_path, "mv", "apps/docs/package.json", "apps/docs/nested/package.json")
            target = target.parent / "nested/package.json"
            target.write_text(
                target.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8"
            )
        case "symlink":
            target.unlink()
            target.symlink_to("../../README.md")
        case _:
            target.chmod(0o755)
            target.write_text(
                target.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8"
            )
    _commit(tmp_path)

    assert (
        target.relative_to(tmp_path).as_posix()
        in analyze_pull_request_documentation(tmp_path, base=base).added_content_paths
    )


def test_lockfile_exception_uses_exact_head_package_identity_not_worktree(tmp_path: Path) -> None:
    base = _docs_package(tmp_path)
    package = tmp_path / "apps/docs/package.json"
    original = package.read_text(encoding="utf-8")
    package.write_text(original.replace("docs-app", "renamed-app"), encoding="utf-8")
    lock = package.with_name("package-lock.json")
    lock.write_text(lock.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8")
    _commit(tmp_path)
    package.write_text(original, encoding="utf-8")

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        "apps/docs/package-lock.json",
        "apps/docs/package.json",
    )


def test_lockfile_exception_uses_merge_base_package_identity(tmp_path: Path) -> None:
    initial = _docs_package(tmp_path)
    lock = tmp_path / "apps/docs/package-lock.json"
    lock.write_text(lock.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8")
    head = _commit(tmp_path)
    _git(tmp_path, "checkout", "--quiet", "--detach", initial)
    package = tmp_path / "apps/docs/package.json"
    package.write_text(
        package.read_text(encoding="utf-8").replace("docs-app", "new-main-app"), encoding="utf-8"
    )
    base = _commit(tmp_path)

    assert (
        analyze_pull_request_documentation(tmp_path, base=base, head=head).added_content_paths == ()
    )


def test_lockfile_exception_rejects_nonobject_legacy_resolution_entries(tmp_path: Path) -> None:
    base = _docs_package(tmp_path)
    lock = tmp_path / "apps/docs/package-lock.json"
    source = lock.read_text(encoding="utf-8").replace('"lockfileVersion":3', '"lockfileVersion":2')
    lock.write_text(source, encoding="utf-8")
    base = _commit(tmp_path)
    lock.write_text(
        source.replace('"packages":', '"dependencies":{"prose":"added content"},"packages":'),
        encoding="utf-8",
    )
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        "apps/docs/package-lock.json",
    )


@pytest.mark.parametrize("filename", ["package.json", "package-lock.json"])
def test_dependency_metadata_exception_rejects_binary_json_encodings(
    tmp_path: Path, filename: str
) -> None:
    base = _docs_package(tmp_path)
    target = tmp_path / "apps/docs" / filename
    content = target.read_text(encoding="utf-8").replace("1.0.0", "1.0.1")
    target.write_bytes(content.encode("utf-16"))
    _commit(tmp_path)

    assert analyze_pull_request_documentation(tmp_path, base=base).added_content_paths == (
        f"apps/docs/{filename}",
    )
