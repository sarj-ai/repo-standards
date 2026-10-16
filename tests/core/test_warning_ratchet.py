from __future__ import annotations

from dataclasses import dataclass, replace
import json
import shutil
import subprocess
from typing import TYPE_CHECKING

from jsonschema import validate
from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- generic native JSON output codec validates the existing wire object.
import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.canonical import with_fingerprint
from repo_standards.core.engine import baseline_from_report, check_baseline
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import (
    MAX_REPOSITORY_INPUT_BYTES,
    FindingsReport,
    JSONValue,
    Mode,
)
from repo_standards.core.parser import parse_baseline_bytes
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE_ID = "repository/artifacts/untyped-javascript"
_MANIFEST = f'repository_id = "ratchet-example"\ncomponents = []\nenabled_rules = ["{_RULE_ID}"]\n'
_RUNNER = CliRunner()
_JSON_OBJECT = TypeAdapter(dict[str, JSONValue])


def parse_json_object(content: bytes) -> dict[str, JSONValue]:
    return _JSON_OBJECT.validate_json(content, strict=True)


def _git(root: Path, *arguments: str) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run([git, "-C", str(root), *arguments], check=True, capture_output=True, timeout=10)


def _commit(root: Path) -> None:
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


def _repository(root: Path, *, javascript: bool = True) -> Path:
    (root / ".repo-standards").mkdir()
    (root / ".repo-standards/repository.toml").write_text(_MANIFEST, encoding="utf-8")
    (root / ("app.js" if javascript else "app.ts")).write_text("export {};\n", encoding="utf-8")
    _git(root, "init", "--quiet")
    _commit(root)
    return root


def _baseline(root: Path, *, include_warnings: bool) -> str:
    arguments = ["baseline", str(root)]
    if include_warnings:
        arguments.append("--ratchet-warnings")
    result = _RUNNER.invoke(app, arguments)
    assert result.exit_code == 0, result.stdout
    baseline = parse_baseline_bytes(result.stdout.encode())
    assert baseline.include_warnings is include_warnings
    (root / ".repo-standards/baseline.json").write_text(result.stdout, encoding="utf-8")
    _commit(root)
    return result.stdout


@dataclass(frozen=True, slots=True)
class _CheckResult:
    exit_code: int
    stdout: str


def _check(root: Path, *, include_warnings: bool = False, staged: bool = False) -> _CheckResult:
    arguments = ["check", str(root), "--mode", "ratchet", "--format", "json"]
    if include_warnings:
        arguments.append("--ratchet-warnings")
    if staged:
        arguments.append("--staged")
    result = _RUNNER.invoke(app, arguments)
    return _CheckResult(exit_code=result.exit_code, stdout=result.stdout)


def test_default_baseline_and_ratchet_preserve_error_only_behavior(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    payload = parse_json_object(_baseline(root, include_warnings=False).encode())
    assert payload["fingerprints"] == []
    checked = _check(root)
    assert checked.exit_code == 0, checked.stdout
    assert '"warnings":1' in checked.stdout
    assert '"new":0' in checked.stdout
    assert '"include_warnings":false' in checked.stdout


def test_opted_in_ratchet_blocks_a_new_warning_from_a_zero_baseline(tmp_path: Path) -> None:
    root = _repository(tmp_path, javascript=False)
    payload = parse_json_object(_baseline(root, include_warnings=True).encode())
    assert payload["fingerprints"] == []
    (root / "app.js").write_text("export {};\n", encoding="utf-8")
    _commit(root)
    checked = _check(root, include_warnings=True)
    assert checked.exit_code == 1, checked.stdout
    assert '"severity":"warning"' in checked.stdout
    assert '"errors":0' in checked.stdout
    assert '"new":1' in checked.stdout
    assert '"include_warnings":true' in checked.stdout


def test_opted_in_known_warning_passes_and_resolved_fingerprint_fails_closed(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    payload = parse_json_object(_baseline(root, include_warnings=True).encode())
    fingerprints = payload["fingerprints"]
    assert isinstance(fingerprints, list)
    assert len(fingerprints) == 1
    checked = _check(root, include_warnings=True)
    assert checked.exit_code == 0, checked.stdout
    assert '"known":1' in checked.stdout
    (root / "app.js").unlink()
    _commit(root)
    checked = _check(root, include_warnings=True)
    assert checked.exit_code == 2, checked.stdout
    assert "resolved fingerprints" in checked.stdout


@pytest.mark.parametrize("baseline_warnings", [False, True])
def test_baseline_comparison_requires_the_exact_warning_setting(
    tmp_path: Path, baseline_warnings: bool
) -> None:
    root = _repository(tmp_path)
    _baseline(root, include_warnings=baseline_warnings)
    checked = _check(root, include_warnings=not baseline_warnings)
    assert checked.exit_code == 2, checked.stdout
    assert "include_warnings" in checked.stdout


def test_staged_warning_gate_does_not_read_unstaged_or_untracked_bytes(tmp_path: Path) -> None:
    root = _repository(tmp_path, javascript=False)
    _baseline(root, include_warnings=True)
    (root / "new.js").write_text("export {};\n", encoding="utf-8")
    assert _check(root, include_warnings=True, staged=True).exit_code == 0
    _git(root, "add", "new.js")
    assert _check(root, include_warnings=True).exit_code == 0
    assert _check(root, include_warnings=True, staged=True).exit_code == 1


def test_native_baseline_creation_has_the_same_staged_git_authority(tmp_path: Path) -> None:
    root = _repository(tmp_path, javascript=False)
    (root / "new.js").write_text("export {};\n", encoding="utf-8")
    _git(root, "add", "new.js")
    committed = _RUNNER.invoke(app, ["baseline", str(root), "--ratchet-warnings"])
    staged = _RUNNER.invoke(app, ["baseline", str(root), "--ratchet-warnings", "--staged"])
    assert committed.exit_code == staged.exit_code == 0
    assert parse_baseline_bytes(committed.stdout.encode()).fingerprints == ()
    assert len(parse_baseline_bytes(staged.stdout.encode()).fingerprints) == 1
    assert not (root / ".repo-standards/baseline.json").exists()


@pytest.mark.parametrize("field", ["policy_version", "scope_digest"])
def test_stale_policy_or_scope_baselines_are_rejected(tmp_path: Path, field: str) -> None:
    root = _repository(tmp_path)
    baseline = parse_json_object(_baseline(root, include_warnings=True).encode())
    baseline[field] = 1 if field == "policy_version" else "0" * 64
    (root / ".repo-standards/baseline.json").write_text(json.dumps(baseline), encoding="utf-8")
    _commit(root)
    checked = _check(root, include_warnings=True)
    assert checked.exit_code == 2, checked.stdout
    assert "does not match" in checked.stdout


def test_reviewed_artifact_changes_require_a_new_scope_baseline(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _baseline(root, include_warnings=True)
    (root / ".repo-standards/repository.toml").write_text(
        _MANIFEST
        + '\n[[javascript.artifacts]]\npath = "app.js"\nkind = "runtime"\n'
        + 'reason = "Required runtime source."\n',
        encoding="utf-8",
    )
    _commit(root)
    checked = _check(root, include_warnings=True)
    assert checked.exit_code == 2, checked.stdout
    assert "scope does not match" in checked.stdout


def test_warning_opt_in_rejects_contradictory_check_mode_and_api_request(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    cli = _RUNNER.invoke(app, ["check", str(root), "--ratchet-warnings", "--format", "json"])
    assert cli.exit_code == 2, cli.stdout
    assert "ratchet" in cli.stdout
    api = analyze_repository(RepositoryAnalysisRequest(root=root, include_warnings=True))
    assert api.completion == "incomplete"
    assert "ratchet" in api.execution_issues[0].message


def test_warning_setting_is_a_strict_optional_baseline_boolean(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    baseline = parse_json_object(_baseline(root, include_warnings=False).encode())
    baseline = {key: value for key, value in baseline.items() if key != "include_warnings"}
    assert parse_baseline_bytes(json.dumps(baseline).encode()).include_warnings is False
    malformed_values: tuple[JSONValue, ...] = (0, 1, "true", None, [])
    for malformed in malformed_values:
        baseline["include_warnings"] = malformed
        with pytest.raises(ConfigurationError, match="boolean"):
            parse_baseline_bytes(json.dumps(baseline).encode())


def test_native_baseline_has_a_machine_discoverable_json_schema(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    payload = parse_json_object(_baseline(root, include_warnings=True).encode())
    schema = _RUNNER.invoke(app, ["schema", "baseline"])
    assert schema.exit_code == 0, schema.stdout
    validate(payload, parse_json_object(schema.stdout.encode()))


def test_warning_ratchet_api_returns_explicit_comparison_metadata(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    _baseline(root, include_warnings=True)
    report = analyze_repository(
        RepositoryAnalysisRequest(
            root=root,
            baseline_path=".repo-standards/baseline.json",
            mode=Mode.RATCHET,
            include_warnings=True,
        )
    )
    assert report.completion == "complete"
    assert report.ratchet is not None
    assert report.ratchet.include_warnings is True
    assert len(report.ratchet.entries) == 1
    assert report.ratchet.entries[0].classification.value == "known"


def test_incomplete_baseline_creation_is_structured_and_does_not_write(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / ".repo-standards/repository.toml").write_text("malformed [\n", encoding="utf-8")
    _commit(root)
    result = _RUNNER.invoke(app, ["baseline", str(root), "--ratchet-warnings"])
    assert result.exit_code == 2, result.stdout
    assert '"completion":"incomplete"' in result.stdout
    assert not (root / ".repo-standards/baseline.json").exists()


def test_native_baseline_helper_rejects_duplicate_and_invalid_findings(tmp_path: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=_repository(tmp_path)))
    assert isinstance(report, FindingsReport)
    finding = report.diagnostics[0]
    duplicate = replace(report, diagnostics=(finding, finding))
    with pytest.raises(ConfigurationError, match="duplicate"):
        baseline_from_report(duplicate, include_warnings=True)
    invalid = replace(report, diagnostics=(replace(finding, fingerprint="0" * 64),))
    with pytest.raises(ConfigurationError, match="invalid diagnostic"):
        baseline_from_report(invalid, include_warnings=True)
    with pytest.raises(ConfigurationError, match="invalid report"):
        baseline_from_report(replace(report, scope_digest="not-a-digest"))
    with pytest.raises(ConfigurationError, match="invalid report"):
        baseline_from_report(replace(report, policy_version=True))


def test_native_baseline_helper_cannot_cap_uncappable_or_excepted_findings(tmp_path: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=_repository(tmp_path)))
    assert isinstance(report, FindingsReport)
    finding = report.diagnostics[0]
    uncappable = replace(report, diagnostics=(replace(finding, baselineable=False),))
    baseline = baseline_from_report(uncappable, include_warnings=True)
    assert baseline.fingerprints == ()
    assert len(check_baseline(uncappable, baseline, include_warnings=True)) == 1
    excepted = replace(report, diagnostics=(replace(finding, disposition="excepted"),))
    assert baseline_from_report(excepted, include_warnings=True).fingerprints == ()


def test_native_baseline_helper_rejects_incomplete_analysis(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / ".repo-standards/repository.toml").write_text("invalid [\n", encoding="utf-8")
    _commit(root)
    report = analyze_repository(RepositoryAnalysisRequest(root=root))
    assert report.completion == "incomplete"
    with pytest.raises(ConfigurationError, match="incomplete"):
        baseline_from_report(report, include_warnings=True)


def test_native_baseline_creation_respects_its_parser_size_boundary(tmp_path: Path) -> None:
    report = analyze_repository(RepositoryAnalysisRequest(root=_repository(tmp_path)))
    assert isinstance(report, FindingsReport)
    finding = report.diagnostics[0]
    findings = tuple(
        with_fingerprint(
            replace(
                finding,
                path=f"fixtures/{index}.js",
                observed=f"fixtures/{index}.js",
                manifest_anchor=f"tracked_files.fixtures/{index}.js",
            )
        )
        for index in range(16_000)
    )
    oversized = replace(report, diagnostics=findings)
    with pytest.raises(ConfigurationError, match="size"):
        baseline_from_report(oversized, include_warnings=True)


@pytest.mark.parametrize(
    "extra_bytes",
    [
        pytest.param(0, id="exact-reader-bound"),
        pytest.param(1, id="one-byte-over-reader-bound"),
    ],
)
def test_native_baseline_cli_wire_size_includes_its_trailing_newline(
    tmp_path: Path, extra_bytes: int
) -> None:
    root = _repository(tmp_path, javascript=False)
    initial = _RUNNER.invoke(app, ["baseline", str(root), "--ratchet-warnings"])
    assert initial.exit_code == 0
    repository_id_length = (
        MAX_REPOSITORY_INPUT_BYTES
        - len(initial.stdout.encode())
        + len("ratchet-example")
        + extra_bytes
    )
    manifest = _MANIFEST.replace("ratchet-example", "a" * repository_id_length)
    assert len(manifest.encode()) < MAX_REPOSITORY_INPUT_BYTES
    (root / ".repo-standards/repository.toml").write_text(manifest, encoding="utf-8")
    _commit(root)
    result = _RUNNER.invoke(app, ["baseline", str(root), "--ratchet-warnings"])
    if extra_bytes:
        assert result.exit_code == 2
        assert "size limit" in result.stdout
    else:
        assert result.exit_code == 0
        assert result.stdout.endswith("\n")
        assert len(result.stdout.encode()) == MAX_REPOSITORY_INPUT_BYTES
        assert parse_baseline_bytes(result.stdout.encode()).include_warnings is True
