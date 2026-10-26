from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Literal

from pydantic import RootModel
import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    git_index_identity,
    inspect_repository,
    load_repository_snapshot,
    parse_project_metadata,
    parse_workspace_metadata,
    read_tracked_blob_contents,
)
from repo_standards.core.models import InventoryKind, RuleId
from repo_standards.policy_sarj import SarjPolicy


_MANIFEST = b"""\
repository_id = "example-repository"
[[components]]
id = "application"
kind = "service"
path = "apps/application"
owner = "@example/alpha"
"""


def _git(repository: Path, *arguments: str) -> None:
    git_executable = shutil.which("git")
    assert git_executable is not None
    subprocess.run(
        [git_executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
    )


def _committed_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".repo-standards").mkdir()
    (repository / ".repo-standards" / "repository.toml").write_bytes(_MANIFEST)
    (repository / "apps" / "application").mkdir(parents=True)
    (repository / "apps" / "application" / "package.json").write_text(
        '{"name":"@example/application","private":true}', encoding="utf-8"
    )
    (repository / "packages" / "shared").mkdir(parents=True)
    (repository / "package.json").write_text(
        '{"private":true,"workspaces":["apps/*","packages/*"]}', encoding="utf-8"
    )
    (repository / "iac").mkdir()
    (repository / "iac" / "main.tf").write_text("terraform {}\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    return repository


def test_deep_json_is_classified_without_crashing() -> None:
    content = b"[" * 2_000 + b"]" * 2_000
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_project_metadata("package.json", content)


def test_immutable_inventory_reuse_tracks_commits_without_caching_the_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _committed_repository(tmp_path)
    executable = shutil.which("git")
    assert executable is not None
    binary = tmp_path / "bin"
    binary.mkdir()
    trace = tmp_path / "git-reads"
    shim = binary / "git"
    shim.write_text(
        "#!/bin/sh\n"
        "for argument do\n"
        f'  if [ "$argument" = ls-tree ]; then echo tree >> {shlex.quote(str(trace))}; fi\n'
        "done\n"
        f'exec {shlex.quote(executable)} "$@"\n'
    )
    shim.chmod(0o700)
    monkeypatch.setenv("PATH", str(binary), prepend=os.pathsep)
    first = inspect_repository(repository)
    assert read_tracked_blob_contents(repository, ("package.json",))[0].content.startswith(b"{")
    assert inspect_repository(repository) == first
    assert trace.read_text().splitlines() == ["tree"]

    (repository / "new.txt").write_text("staged\n")
    _git(repository, "add", "new.txt")
    staged = git_index_identity(repository)
    assert (
        inspect_repository(repository, identity=staged).tracked_file_count
        == first.tracked_file_count + 1
    )
    assert inspect_repository(repository) == first

    (repository / "later.txt").write_text("later\n")
    _git(repository, "add", "later.txt")
    with pytest.raises(ConfigurationError, match="index changed"):
        inspect_repository(repository, identity=staged)
    _git(
        repository,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "next",
    )
    second = inspect_repository(repository)
    assert second.tracked_file_count == first.tracked_file_count + 2
    assert trace.read_text().splitlines() == ["tree", "tree"]


@pytest.mark.parametrize(
    "content",
    [
        b'{"name": 42}',
        b'{"private": "yes"}',
        b'{"workspaces": false}',
    ],
)
def test_invalid_npm_metadata_types_are_classified(content: bytes) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_project_metadata("package.json", content)


@pytest.mark.parametrize(
    "content",
    [
        b'{"name":"first","name":"second"}',
        b'{"private":true,"private":false}',
        b'{"workspaces":["apps/*"],"workspaces":["outside/*"]}',
        b'{"workspaces":{"packages":["apps/*"],"packages":["outside/*"]}}',
        b'{"custom":NaN}',
        b'{"custom":1e999}',
    ],
)
def test_ambiguous_npm_metadata_is_not_trusted(content: bytes) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_project_metadata("package.json", content)
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("package.json", content)


def test_workspace_metadata_is_typed_without_expanding_globs() -> None:
    npm = parse_workspace_metadata(
        "package.json", b'{"workspaces":{"packages":["apps/*","packages/*"]}}'
    )
    python = parse_workspace_metadata(
        "pyproject.toml",
        b'[tool.uv.workspace]\nmembers = ["packages/*"]\nexclude = ["packages/old"]\n',
    )
    pnpm = parse_workspace_metadata(
        "pnpm-workspace.yaml",
        b"packages:\n  - packages/*\n  - '!packages/retired'\n",
    )
    assert npm is not None
    assert npm.member_patterns == ("apps/*", "packages/*")
    assert python is not None
    assert python.member_patterns == ("packages/*",)
    assert python.exclude_patterns == ("packages/old",)
    assert pnpm is not None
    assert pnpm.member_patterns == ("packages/*",)
    assert pnpm.exclude_patterns == ("packages/retired",)
    assert parse_workspace_metadata("pnpm-workspace.yaml", b"catalog:\n  react: 19.0.0\n") is None


@pytest.mark.parametrize(
    "content",
    [
        b"packages: [apps/*]\npackages: [outside/*]\n",
        b"packages: [apps/*]\n'packages': [outside/*]\n",
        b'packages: [apps/*]\n"pack\\u0061ges": [outside/*]\n',
        b"defaults: &defaults {packages: [apps/*], packages: [outside/*]}\n<<: *defaults\n",
        b"? &key packages\n: [apps/*]\n? *key\n: [outside/*]\n",
    ],
)
def test_pnpm_workspace_rejects_repeated_package_selectors(content: bytes) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("pnpm-workspace.yaml", content)


def test_pnpm_workspace_preserves_native_merge_overrides() -> None:
    workspace = parse_workspace_metadata(
        "pnpm-workspace.yaml",
        b"defaults: &defaults {packages: [packages/*]}\n<<: *defaults\npackages: [apps/*]\n",
    )
    assert workspace is not None
    assert workspace.member_patterns == ("apps/*",)


def test_workspace_metadata_rejects_unsafe_patterns() -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("package.json", b'{"workspaces":["../outside"]}')
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("pnpm-workspace.yaml", b"packages:\n  - ../outside\n")


@pytest.mark.parametrize("pattern", ["!../outside", "!/absolute", "!", "!packages/\\n"])
def test_exclusion_only_workspace_still_validates_its_patterns(pattern: str) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("pnpm-workspace.yaml", f'packages: ["{pattern}"]\n'.encode())


@pytest.mark.parametrize("control", ["\\n", "\\r", "\\t", "\\u007f"])
def test_workspace_globs_reject_filename_controls(control: str) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata(
            "package.json", f'{{"workspaces":["packages/{control}*"]}}'.encode()
        )


@pytest.mark.parametrize(
    "pattern",
    ["{apps,packages}/*", "@(apps|packages)/*", "!(packages/retired)"],
)
def test_workspace_metadata_rejects_unsupported_globs(pattern: str) -> None:
    with pytest.raises(ConfigurationError, match="metadata is malformed"):
        parse_workspace_metadata("pnpm-workspace.yaml", f"packages:\n  - '{pattern}'\n".encode())


def test_snapshot_joins_manifest_and_inventory_from_one_git_tree(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    snapshot = load_repository_snapshot(repository)

    assert snapshot.manifest.repository_id == "example-repository"
    assert snapshot.provenance.mode == "git-tree"
    assert len(snapshot.provenance.source_revision) in {40, 64}
    assert len(snapshot.provenance.tree_digest) in {40, 64}
    assert len(snapshot.provenance.manifest_digest) == 64
    assert snapshot.provenance.manifest_object_id is not None
    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.packages[0].object_id
    assert snapshot.inspection.workspaces[0].member_patterns == ("apps/*", "packages/*")
    assert snapshot.inspection.terraform_modules == ("iac",)
    assert InventoryKind.TERRAFORM_MODULE in {
        unit.kind for unit in snapshot.inspection.inventory_units
    }

    dirty_manifest = _MANIFEST.replace(b"example-repository", b"dirty-repository")
    (repository / ".repo-standards" / "repository.toml").write_bytes(dirty_manifest)
    repeated = load_repository_snapshot(repository)
    assert repeated.manifest.repository_id == "example-repository"
    assert repeated.provenance == snapshot.provenance
    assert repeated.inspection == snapshot.inspection


@pytest.mark.parametrize(
    "filename", ["override.tf", "z_override.tf", "main.tf.json", "r\u00e9seau.tf"]
)
def test_terraform_digest_tracks_filenames_without_binding_the_module_directory(
    tmp_path: Path, filename: str
) -> None:
    repository = _committed_repository(tmp_path)

    def module_digest() -> str | None:
        [unit] = (
            unit
            for unit in inspect_repository(repository).inventory_units
            if unit.kind is InventoryKind.TERRAFORM_MODULE
        )
        return unit.content_digest

    def commit() -> None:
        _git(
            repository,
            "-c",
            "user.name=Inventory Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "rename",
        )

    original = module_digest()
    _git(repository, "mv", "iac/main.tf", f"iac/{filename}")
    commit()
    renamed = module_digest()
    assert renamed is not None
    assert renamed != original

    _git(repository, "mv", "iac", "infrastructure")
    commit()
    assert module_digest() == renamed


def test_inventory_retains_overlapping_kinds_case_and_posix_parents(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    paths = (
        ".github/workflows/CloudBuild.yaml",
        ".github/workflows/Dockerfile.yml",
        ".github/workflows/cloudbuild-\u00e9.yaml",
        ".github/workflows/cloudbuild-uppercase.YAML",
        "Dockerfile.production",
        "infra/dev/main.tf.json",
        "main.tf",
    )
    for path in paths:
        destination = repository / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("value = 1\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "inventory",
    )
    inspected = inspect_repository(repository)
    assert inspected.workflow_paths == paths[:3]
    assert inspected.cloudbuild_paths == (paths[0], paths[2])
    assert inspected.dockerfile_paths == (paths[1], paths[4])
    assert inspected.terraform_modules == (".", "iac", "infra/dev")


def test_documentation_entrypoint_must_exist_but_its_blob_need_not_be_read(
    tmp_path: Path,
) -> None:
    repository = _committed_repository(tmp_path)
    manifest = repository / ".repo-standards" / "repository.toml"
    manifest.write_bytes(_MANIFEST + b'\n[documentation]\nentrypoints = ["README.md"]\n')
    _git(repository, "add", ".repo-standards/repository.toml")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "declare documentation",
    )

    with pytest.raises(ConfigurationError, match="documentation entrypoint is absent"):
        load_repository_snapshot(repository)

    (repository / "README.md").write_text("x" * 1_048_577, encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "add documentation",
    )

    assert load_repository_snapshot(repository).manifest.documentation is not None


def test_snapshot_can_select_the_exact_staged_index(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    manifest = repository / ".repo-standards" / "repository.toml"
    manifest.write_bytes(_MANIFEST.replace(b"example-repository", b"staged-repository"))
    _git(repository, "add", str(manifest.relative_to(repository)))
    identity = git_index_identity(repository)
    manifest.write_bytes(_MANIFEST.replace(b"example-repository", b"unstaged-repository"))

    snapshot = load_repository_snapshot(repository, identity=identity)
    repeated = load_repository_snapshot(repository, identity=identity)

    assert snapshot.manifest.repository_id == "staged-repository"
    assert snapshot.provenance.mode == "git-index"
    assert (
        snapshot.provenance.source_revision
        == load_repository_snapshot(repository).provenance.source_revision
    )
    assert len(snapshot.provenance.tree_digest) == 64
    assert repeated.provenance == snapshot.provenance
    assert repeated.manifest == snapshot.manifest


@pytest.mark.parametrize("relative", [False, True])
def test_staged_snapshot_honors_the_selected_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, relative: bool
) -> None:
    repository = _committed_repository(tmp_path)
    ordinary_index = repository / ".git/index"
    ordinary_bytes = ordinary_index.read_bytes()
    selected_index = repository / ".git/pending-index"
    monkeypatch.setenv("GIT_INDEX_FILE", ".git/pending-index" if relative else str(selected_index))
    # Git resolves relative index selections after -C selects the repository.
    monkeypatch.chdir(tmp_path)
    _git(repository, "read-tree", "HEAD")
    manifest = repository / ".repo-standards/repository.toml"
    manifest.write_bytes(_MANIFEST.replace(b"example-repository", b"pending-repository"))
    _git(repository, "add", ".repo-standards/repository.toml")
    selected_bytes = selected_index.read_bytes()
    manifest.write_bytes(_MANIFEST.replace(b"example-repository", b"unstaged-repository"))

    snapshot = load_repository_snapshot(repository, identity=git_index_identity(repository))

    assert snapshot.manifest.repository_id == "pending-repository"
    assert load_repository_snapshot(repository).manifest.repository_id == "example-repository"
    assert ordinary_index.read_bytes() == ordinary_bytes
    assert selected_index.read_bytes() == selected_bytes
    assert not ordinary_index.with_suffix(".lock").exists()
    assert not selected_index.with_suffix(".lock").exists()


def test_selected_index_preserves_deletions_and_rejects_later_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _committed_repository(tmp_path)
    monkeypatch.setenv("GIT_INDEX_FILE", str(repository / ".git/pending-index"))
    _git(repository, "read-tree", "HEAD")
    _git(repository, "rm", "--cached", "apps/application/package.json")
    identity = git_index_identity(repository)
    selected = inspect_repository(repository, identity=identity)
    assert "apps/application/package.json" not in {item.path for item in selected.packages}
    assert "apps/application/package.json" in {
        item.path for item in inspect_repository(repository).packages
    }
    (repository / "new.txt").write_text("staged\n")
    _git(repository, "add", "new.txt")
    with pytest.raises(ConfigurationError, match="index changed"):
        inspect_repository(repository, identity=identity)


def test_unborn_selected_index_keeps_unrelated_git_environment_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    selected_index = repository / ".git/pending-index"
    monkeypatch.setenv("GIT_INDEX_FILE", str(selected_index))
    (repository / ".repo-standards").mkdir()
    (repository / ".repo-standards/repository.toml").write_bytes(_MANIFEST)
    _git(repository, "add", ".")
    selected_bytes = selected_index.read_bytes()
    for variable in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_GLOBAL",
    ):
        monkeypatch.setenv(variable, str(tmp_path / "unrelated"))

    snapshot = load_repository_snapshot(repository, identity=git_index_identity(repository))

    assert snapshot.manifest.repository_id == "example-repository"
    assert snapshot.provenance.source_revision == "0" * 40
    assert not (repository / ".git/index").exists()
    assert selected_index.read_bytes() == selected_bytes


@pytest.mark.parametrize("content", [b"", b"invalid index"])
def test_invalid_selected_index_never_falls_back_to_ordinary_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    repository = _committed_repository(tmp_path)
    selected_index = repository / ".git/pending-index"
    selected_index.write_bytes(content)
    monkeypatch.setenv("GIT_INDEX_FILE", str(selected_index))
    with pytest.raises(ConfigurationError, match="cannot enumerate Git index"):
        git_index_identity(repository)
    assert load_repository_snapshot(repository).manifest.repository_id == "example-repository"
    assert selected_index.read_bytes() == content


def test_native_partial_commit_hook_checks_its_pending_index(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    _git(repository, "config", "core.hooksPath", str(repository / ".git/hooks"))
    manifest = repository / ".repo-standards/repository.toml"
    manifest.write_bytes(
        _MANIFEST.replace(
            b'repository_id = "example-repository"',
            b'repository_id = "example-repository"\n'
            b'enabled_rules = ["repository/artifacts/local-residue"]',
        )
    )
    _git(repository, "add", ".repo-standards/repository.toml")
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "enable policy",
    )
    (repository / "cache.pyc").write_bytes(b"inert private fixture; never imported")
    _git(repository, "add", "cache.pyc")
    (repository / "package.json").write_text('{"private":true}\n', encoding="utf-8")
    receipt = tmp_path / "hook-receipt.json"
    source = Path(__file__).resolve().parents[2] / "src"
    hook = repository / ".git/hooks/pre-commit"
    hook.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(source)!r})\n"
        "from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository\n"
        "report = analyze_repository(RepositoryAnalysisRequest(root=Path.cwd(), staged=True))\n"
        f"Path({str(receipt)!r}).write_text(json.dumps({{"
        "'index': os.environ.get('GIT_INDEX_FILE'), 'completion': report.completion, "
        "'paths': [item.path for item in report.diagnostics]}))\n",
        encoding="utf-8",
    )
    hook.chmod(0o700)
    _git(
        repository,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--only",
        "package.json",
        "--quiet",
        "-m",
        "partial commit",
    )
    observed = (
        RootModel[dict[str, object]].model_validate_json(receipt.read_text(encoding="utf-8")).root
    )
    assert observed["index"]
    assert observed["index"] != str(repository / ".git/index")
    assert observed["completion"] == "complete"
    assert observed["paths"] == []


def test_snapshot_can_select_an_unborn_staged_index(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    manifest = repository / ".repo-standards" / "repository.toml"
    manifest.parent.mkdir()
    manifest.write_bytes(_MANIFEST)
    _git(repository, "add", ".repo-standards/repository.toml")

    snapshot = load_repository_snapshot(repository, identity=git_index_identity(repository))

    assert snapshot.manifest.repository_id == "example-repository"
    assert snapshot.provenance.mode == "git-index"
    assert snapshot.provenance.source_revision == "0" * 40


def test_staged_index_rejects_symlinks(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "linked.py").symlink_to("apps/application/package.json")
    _git(repository, "add", "linked.py")

    with pytest.raises(ConfigurationError, match="symlink"):
        git_index_identity(repository)


def test_committed_tree_rejects_symlinks(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "linked.py").symlink_to("apps/application/package.json")
    _git(repository, "add", "linked.py")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "symlink",
    )

    with pytest.raises(ConfigurationError, match="symlink"):
        load_repository_snapshot(repository)


@pytest.mark.parametrize(
    ("evidence", "content"),
    [
        pytest.param("package-lock.json", "\n", id="newline-lock"),
        pytest.param("index.js", "// ownership decoy\n", id="line-comment-entrypoint"),
        pytest.param("index.cjs", "/* ownership decoy */\n", id="block-comment-entrypoint"),
        pytest.param("uv.lock", "# ownership decoy\n", id="hash-comment-lock"),
        pytest.param("main.py", "# ownership decoy\n", id="python-comment-entrypoint"),
    ],
)
def test_exact_tree_marks_comment_only_ownership_evidence_insubstantial(
    tmp_path: Path, evidence: str, content: str
) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "package.json").write_text('{"private":true}', encoding="utf-8")
    package = repository / "packages" / "fake"
    package.mkdir()
    manifest = "package.json" if evidence.endswith((".js", ".cjs", ".json")) else "pyproject.toml"
    manifest_content = (
        '{"name":"fake"}' if manifest == "package.json" else '[project]\nname="fake"\n'
    )
    (package / manifest).write_text(manifest_content, encoding="utf-8")
    (package / evidence).write_text(content, encoding="utf-8")
    verifier = "src/verify-plan.cjs" if manifest == "package.json" else "src/verify_plan.py"
    (package / "src").mkdir()
    (package / verifier).write_text("export {}\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "evidence",
    )

    snapshot = load_repository_snapshot(repository)
    tracked = next(
        item for item in snapshot.inspection.tracked_files if item.path.endswith(evidence)
    )

    assert not tracked.substantive
    expected_rules = [RuleId("repository/artifacts/bespoke-iac-verifiers")]
    if verifier == "src/verify-plan.cjs":
        expected_rules.append(RuleId("repository/artifacts/untyped-javascript"))
    assert [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.path == f"packages/fake/{verifier}"
    ] == expected_rules


@pytest.mark.parametrize(
    ("tree_mode", "evidence", "content"),
    [
        pytest.param("committed", "package-lock.json", " " * 1_048_577, id="committed-lock"),
        pytest.param(
            "staged",
            "index.cjs",
            f"/*{' ' * 1_048_573}*/",
            id="staged-entrypoint",
        ),
    ],
)
def test_oversized_ownership_decoys_fail_closed_in_the_exact_tree(
    tmp_path: Path,
    tree_mode: Literal["committed", "staged"],
    evidence: str,
    content: str,
) -> None:
    repository = _committed_repository(tmp_path)
    (repository / "package.json").write_text('{"private":true}', encoding="utf-8")
    package = repository / "packages" / "fake"
    package.mkdir()
    (package / "package.json").write_text('{"name":"fake"}', encoding="utf-8")
    (package / evidence).write_text(content, encoding="utf-8")
    (package / "src").mkdir()
    verifier = package / "src" / "verify-plan.cjs"
    verifier.write_text("export {}\n", encoding="utf-8")
    _git(repository, "add", ".")
    identity = git_index_identity(repository) if tree_mode == "staged" else None
    if tree_mode == "committed":
        _git(
            repository,
            "-c",
            "user.name=Repository Lint",
            "-c",
            "user.email=repository-lint@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "oversized ownership decoy",
        )
    (package / evidence).write_text("substantive dirty bytes\n", encoding="utf-8")

    snapshot = load_repository_snapshot(repository, identity=identity)
    tracked = next(
        item for item in snapshot.inspection.tracked_files if item.path.endswith(evidence)
    )

    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.issues == ()
    assert not tracked.substantive
    assert [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.path == "packages/fake/src/verify-plan.cjs"
    ] == [
        RuleId("repository/artifacts/bespoke-iac-verifiers"),
        RuleId("repository/artifacts/untyped-javascript"),
    ]


@pytest.mark.parametrize("ownership", ["workspace", "entrypoint"])
def test_oversized_lock_does_not_brick_independently_owned_package(
    tmp_path: Path, ownership: Literal["workspace", "entrypoint"]
) -> None:
    repository = _committed_repository(tmp_path)
    if ownership == "entrypoint":
        (repository / "package.json").write_text('{"private":true}', encoding="utf-8")
    relative_package = "packages/owned" if ownership == "workspace" else "vendor/owned"
    package_root = repository / relative_package
    package_root.mkdir(parents=True)
    (package_root / "package.json").write_text('{"name":"owned"}', encoding="utf-8")
    oversized_lock = package_root / "package-lock.json"
    oversized_lock.write_text(" " * 1_048_577, encoding="utf-8")
    if ownership == "entrypoint":
        (package_root / "index.cjs").write_text("export {}\n", encoding="utf-8")
    (package_root / "src").mkdir()
    verifier = package_root / "src" / "verify-plan.cjs"
    verifier.write_text("export {}\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "large legitimate lockfile",
    )

    snapshot = load_repository_snapshot(repository)
    lock_evidence = next(
        item
        for item in snapshot.inspection.tracked_files
        if item.path == oversized_lock.relative_to(repository).as_posix()
    )

    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.issues == ()
    assert not lock_evidence.substantive
    assert [
        item.rule_id
        for item in SarjPolicy.evaluate_repository(snapshot)
        if item.path == verifier.relative_to(repository).as_posix()
    ] == [RuleId("repository/artifacts/untyped-javascript")]


def test_unrelated_oversized_blob_does_not_affect_inspection(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    unrelated = repository / "assets" / "payload.txt"
    unrelated.parent.mkdir()
    unrelated.write_text("x" * 1_048_577, encoding="utf-8")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "unrelated large blob",
    )

    snapshot = load_repository_snapshot(repository)

    assert snapshot.inspection.completion == "complete"
    assert snapshot.inspection.issues == ()


def test_selected_blob_reader_ignores_dirty_worktree_bytes(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    selected = read_tracked_blob_contents(repository, ("package.json",))
    assert selected[0].content == b'{"private":true,"workspaces":["apps/*","packages/*"]}'

    (repository / "package.json").write_text('{"private":false}', encoding="utf-8")
    repeated = read_tracked_blob_contents(repository, ("package.json",))
    assert repeated == selected


def test_selected_blob_reader_rejects_absent_and_duplicate_paths(tmp_path: Path) -> None:
    repository = _committed_repository(tmp_path)
    with pytest.raises(ConfigurationError, match="absent"):
        read_tracked_blob_contents(repository, ("missing.json",))
    with pytest.raises(ConfigurationError, match="unique"):
        read_tracked_blob_contents(repository, ("package.json", "package.json"))


@pytest.mark.parametrize(
    ("paths", "message"),
    [
        (("Fixture.json", "fixture.json"), "collide after normalization"),
        (("noncanonical\\fixture.json",), "invalid repository-relative path"),
    ],
)
def test_committed_path_boundaries_survive_direct_blob_sorting(
    tmp_path: Path, paths: tuple[str, ...], message: str
) -> None:
    repository = _committed_repository(tmp_path)
    blob = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD:package.json"],
        text=True,
        timeout=10,
    ).strip()
    # Write the index directly so case-insensitive filesystems
    # cannot collapse the deliberately invalid tracked-tree paths.
    for path in paths:
        _git(repository, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}")
    _git(
        repository,
        "-c",
        "user.name=Repository Lint",
        "-c",
        "user.email=repository-lint@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "invalid tree fixture",
    )
    with pytest.raises(ConfigurationError, match=message):
        inspect_repository(repository)
