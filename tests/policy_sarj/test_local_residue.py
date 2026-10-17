from __future__ import annotations

from dataclasses import replace
from datetime import date
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.canonical import with_fingerprint
from repo_standards.core.engine import apply_exceptions
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import (
    Component,
    ComponentId,
    ExceptionRecord,
    GitObjectId,
    InputProvenance,
    Manifest,
    RepositoryId,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedFileEvidence,
)
from repo_standards.core.parser import parse_baseline_bytes
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path

    from repo_standards.core.models import Diagnostic


_RULE_ID = RuleId("repository/artifacts/local-residue")
_RUNNER = CliRunner()


def _snapshot(*paths: str) -> RepositorySnapshot:
    tracked = tuple(
        TrackedFileEvidence(path=path, object_id=f"{index + 1:040x}")
        for index, path in enumerate(paths)
    )
    return RepositorySnapshot(
        manifest=Manifest(repository_id=RepositoryId("example-repository"), components=()),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            tracked_file_count=len(tracked),
            packages=(),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=tracked,
        ),
        provenance=InputProvenance(
            mode="git-tree",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            manifest_path=".repo-standards/repository.toml",
            manifest_object_id=GitObjectId("c" * 40),
            manifest_digest="d" * 64,
        ),
    )


def _findings(snapshot: RepositorySnapshot) -> tuple[Diagnostic, ...]:
    return tuple(
        finding
        for finding in SarjPolicy.evaluate_repository(snapshot)
        if finding.rule_id == _RULE_ID
    )


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("module.pyc", id="python-bytecode"),
        pytest.param("module.pyo", id="legacy-optimized-bytecode"),
        pytest.param("tsconfig.tsbuildinfo", id="typescript-build-cache"),
        pytest.param(".DS_Store", id="macos-metadata"),
        pytest.param("Thumbs.db", id="windows-thumbnail-cache"),
        pytest.param(".eslintcache", id="eslint-default-cache"),
        pytest.param(".coverage", id="coverage-default-data"),
        pytest.param("pkg/__pycache__/module.cpython-315.pyc", id="python-cache-directory"),
        pytest.param("vendor/APP.PYC", id="vendor-name-no-exemption"),
        pytest.param("fixtures/INPUT.PYO", id="fixture-name-no-exemption"),
        pytest.param("node_modules/TSConfig.TSBUILDINFO", id="dependency-name-no-exemption"),
        pytest.param("dist/.ds_store", id="distribution-name-no-exemption"),
        pytest.param("docs/THUMBS.DB", id="nested-uppercase-metadata"),
        pytest.param("tools/.ESLintCache", id="nested-case-insensitive-eslint-cache"),
        pytest.param("fixtures/.COVERAGE", id="nested-case-insensitive-coverage-data"),
        pytest.param("café/[id].pyc", id="unicode-literal-brackets"),
        pytest.param(".pyc", id="extension-only-file"),
    ],
)
def test_cache_and_metadata_conventions_are_warning_review_candidates(path: str) -> None:
    findings = _findings(_snapshot(path))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.path == finding.observed == path
    assert finding.rule_version == 1
    assert finding.severity == "warning"
    assert finding.evidence_level == "verified"
    assert finding.location is not None
    assert finding.location.path == path
    assert finding.location.line == 1
    assert finding.remediation is not None
    assert "review" in finding.remediation.summary.lower()


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("module.py", id="python-source"),
        pytest.param("module.pyi", id="python-type-stub"),
        pytest.param("src/app.ts", id="typescript-source"),
        pytest.param("runtime/module.pyd", id="python-extension-runtime"),
        pytest.param("runtime/lib.so", id="native-library"),
        pytest.param("runtime/tool.exe", id="executable-runtime"),
        pytest.param("runtime/tool.jar", id="jvm-runtime"),
        pytest.param("vendor/package.zip", id="archive"),
        pytest.param("uv.lock", id="dependency-lock"),
        pytest.param("data/requests.log", id="log-data"),
        pytest.param("fixtures/input.tmp", id="temporary-looking-fixture"),
        pytest.param("fixtures/input.bak", id="backup-looking-fixture"),
        pytest.param("fixtures/input.orig", id="patch-original-fixture"),
        pytest.param("fixtures/input.rej", id="patch-rejection-fixture"),
        pytest.param("fixtures/input.swp", id="swap-looking-data"),
        pytest.param("module.pyc.txt", id="bytecode-name-document"),
        pytest.param("module.pyo.json", id="bytecode-name-data"),
        pytest.param("cache.tsbuildinfo.map", id="source-map"),
        pytest.param(".DS_Store.json", id="metadata-name-json"),
        pytest.param("prefixThumbs.db", id="thumbnail-basename-prefix"),
        pytest.param("Thumbs.db.backup", id="thumbnail-basename-suffix"),
        pytest.param(".eslintcache.json", id="eslint-cache-json-fixture"),
        pytest.param("eslintcache", id="eslint-basename-without-dot"),
        pytest.param("data.cache", id="generic-cache-data"),
        pytest.param(".coverage.db", id="coverage-database-fixture"),
        pytest.param(".coverage.host.123.abc", id="parallel-coverage-file"),
        pytest.param("data.coverage", id="coverage-looking-data-extension"),
        pytest.param(".coveragerc", id="coverage-configuration"),
        pytest.param(".eslintcache/input.ts", id="eslint-cache-directory-segment"),
        pytest.param(".coverage/input.py", id="coverage-directory-segment"),
        pytest.param(".DS_Store/input.py", id="metadata-directory-segment"),
        pytest.param("cache.pyc/input.ts", id="bytecode-directory-segment"),
        pytest.param("Thumb\u017f.db", id="unicode-confusable-not-ascii-convention"),
        pytest.param(".DS_\uff33tore", id="fullwidth-confusable"),
    ],
)
def test_other_languages_runtime_assets_and_near_misses_remain_out_of_scope(path: str) -> None:
    assert _findings(_snapshot(path)) == ()


def test_repeated_unsorted_evidence_is_deduplicated_without_mutating_snapshot() -> None:
    snapshot = _snapshot("z.pyc", "Thumbs.db", "a.pyo", "z.pyc")
    first = _findings(snapshot)
    second = _findings(snapshot)
    reversed_evidence = replace(
        snapshot,
        inspection=replace(
            snapshot.inspection,
            tracked_files=tuple(reversed(snapshot.inspection.tracked_files)),
        ),
    )
    assert first == second == _findings(reversed_evidence)
    assert [finding.path for finding in first] == ["Thumbs.db", "a.pyo", "z.pyc"]
    assert len(snapshot.inspection.tracked_files) == 4


def test_empty_cache_and_nearest_component_still_have_one_exact_location() -> None:
    snapshot = _snapshot("applications/app/tool/cache.tsbuildinfo")
    snapshot = replace(
        snapshot,
        manifest=replace(
            snapshot.manifest,
            components=(
                Component(ComponentId("app"), "application", "applications/app", "@app"),
                Component(ComponentId("tool"), "tool", "applications/app/tool", "@tool"),
            ),
        ),
        inspection=replace(
            snapshot.inspection,
            tracked_files=tuple(
                replace(tracked, substantive=False) for tracked in snapshot.inspection.tracked_files
            ),
        ),
    )
    findings = _findings(snapshot)
    assert len(findings) == 1
    assert findings[0].component_id == "tool"
    assert findings[0].manifest_anchor == "tracked_files.applications/app/tool/cache.tsbuildinfo"


def test_review_fingerprint_tracks_filename_instead_of_cache_content() -> None:
    snapshot = _snapshot("fixtures/input.pyc")
    original = with_fingerprint(_findings(snapshot)[0])
    changed_content = replace(
        snapshot,
        inspection=replace(
            snapshot.inspection,
            tracked_files=(replace(snapshot.inspection.tracked_files[0], object_id="f" * 40),),
        ),
    )
    changed = with_fingerprint(_findings(changed_content)[0])
    renamed = with_fingerprint(_findings(_snapshot("fixtures/renamed.pyc"))[0])
    assert original.fingerprint == changed.fingerprint
    assert original.fingerprint != renamed.fingerprint


@pytest.mark.parametrize(
    "fixture_path",
    [
        pytest.param("fixtures/legacy.pyc", id="bytecode-fixture"),
        pytest.param("fixtures/.eslintcache", id="eslint-cache-fixture"),
        pytest.param("fixtures/.coverage", id="coverage-data-fixture"),
    ],
)
def test_intentional_fixture_uses_existing_exact_reviewed_exception(fixture_path: str) -> None:
    snapshot = _snapshot(fixture_path, "fixtures/other.pyc")
    findings = tuple(with_fingerprint(finding) for finding in _findings(snapshot))
    fixture = next(finding for finding in findings if finding.path == fixture_path)
    exception = ExceptionRecord(
        rule_id=_RULE_ID,
        component_id=fixture.component_id,
        manifest_anchor=fixture.manifest_anchor,
        fingerprint=fixture.fingerprint,
        owner="@runtime",
        reason="The parser must reject this exact malformed cache or coverage data fixture.",
        issue="https://example.invalid/issues/123",
        created_on="2026-10-17",
        expires_on="2026-11-17",
    )
    manifest = replace(snapshot.manifest, exceptions=(exception,))
    reviewed = apply_exceptions(findings, manifest, date(2026, 10, 17))
    assert {finding.path: finding.disposition for finding in reviewed} == {
        fixture_path: "excepted",
        "fixtures/other.pyc": "active",
    }
    with pytest.raises(ConfigurationError, match="do not match current findings"):
        apply_exceptions(
            tuple(finding for finding in findings if finding.path != fixture.path),
            manifest,
            date(2026, 10, 17),
        )
    with pytest.raises(ConfigurationError, match="expired"):
        apply_exceptions(findings, manifest, date(2026, 11, 18))


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(
        [executable, "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        timeout=10,
        env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "LC_ALL": "C"},
    )
    return result.stdout.decode().strip()


def _repository(root: Path) -> None:
    (root / ".repo-standards").mkdir()
    (root / ".repo-standards/repository.toml").write_text(
        'repository_id = "example-repository"\ncomponents = []\n', encoding="utf-8"
    )
    (root / ".gitignore").write_text("*.pyc\n.eslintcache\n.coverage\n", encoding="utf-8")
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )


@pytest.mark.parametrize("filename", ["cache.pyc", ".eslintcache", ".coverage"])
def test_forced_tracked_ignored_cache_uses_selected_index_then_cleans(
    tmp_path: Path, filename: str
) -> None:
    _repository(tmp_path)
    request = RepositoryAnalysisRequest(
        root=tmp_path, enabled_rule_ids=(str(_RULE_ID),), staged=True
    )
    initial = analyze_repository(request)
    assert initial.completion == "complete"
    assert initial.diagnostics == ()
    (tmp_path / filename).write_bytes(b"this inert fixture is never imported")
    untracked = analyze_repository(request)
    assert untracked.completion == "complete"
    assert untracked.diagnostics == ()
    _git(tmp_path, "add", "--force", "--", filename)
    enabled = analyze_repository(request)
    assert enabled.completion == "complete"
    assert [
        (finding.rule_id, finding.path, finding.severity) for finding in enabled.diagnostics
    ] == [(_RULE_ID, filename, "warning")]
    assert analyze_repository(replace(request, staged=False)).diagnostics == ()
    disabled = analyze_repository(replace(request, enabled_rule_ids=()))
    assert disabled.completion == "complete"
    assert disabled.diagnostics == ()
    _git(tmp_path, "rm", "--cached", filename)
    clean = analyze_repository(request)
    assert clean.completion == "complete"
    assert clean.diagnostics == ()
    assert (tmp_path / filename).is_file()


@pytest.mark.parametrize("filename", ["cache.pyc", ".eslintcache", ".coverage"])
def test_native_warning_ratchet_blocks_only_forced_tracked_cache_then_recovers(
    tmp_path: Path, filename: str
) -> None:
    _repository(tmp_path)
    manifest = tmp_path / ".repo-standards/repository.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8") + f'enabled_rules = ["{_RULE_ID}"]\n',
        encoding="utf-8",
    )
    _git(tmp_path, "add", "--", ".repo-standards/repository.toml")
    baseline = _RUNNER.invoke(app, ["baseline", str(tmp_path), "--staged", "--ratchet-warnings"])
    assert baseline.exit_code == 0, baseline.stdout
    parsed = parse_baseline_bytes(baseline.stdout.encode())
    assert parsed.fingerprints == ()
    assert parsed.include_warnings is True
    (tmp_path / ".repo-standards/baseline.json").write_text(baseline.stdout, encoding="utf-8")
    _git(tmp_path, "add", "--", ".repo-standards/baseline.json")
    arguments = [
        "check",
        str(tmp_path),
        "--mode",
        "ratchet",
        "--staged",
        "--ratchet-warnings",
        "--format",
        "json",
    ]
    before = _RUNNER.invoke(app, arguments)
    assert before.exit_code == 0, before.stdout
    (tmp_path / filename).write_bytes(b"never execute or deserialize this inert fixture")
    _git(tmp_path, "add", "--force", "--", filename)
    probe = _RUNNER.invoke(app, arguments)
    assert probe.exit_code == 1, probe.stdout
    assert '"completion":"complete"' in probe.stdout
    assert '"severity":"warning"' in probe.stdout
    assert '"new":1' in probe.stdout
    assert '"errors":0' in probe.stdout
    _git(tmp_path, "rm", "--cached", filename)
    after = _RUNNER.invoke(app, arguments)
    assert after.exit_code == 0, after.stdout
    assert '"diagnostics":[]' in after.stdout
