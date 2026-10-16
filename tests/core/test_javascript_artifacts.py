from __future__ import annotations

from dataclasses import replace
import json
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from repo_standards.cli import app
from repo_standards.core.canonical import scope_digest
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import (
    git_index_identity,
    load_calibration_snapshot,
    load_repository_snapshot,
)
from repo_standards.core.models import (
    Component,
    ComponentId,
    GitObjectId,
    InputProvenance,
    Manifest,
    Mode,
    RepositoryInspection,
    RepositorySnapshot,
    RuleId,
    TrackedFileEvidence,
)
from repo_standards.core.parser import parse_manifest_bytes
from repo_standards.policy_sarj import SarjPolicy
from repo_standards.repository import RepositoryAnalysisRequest, analyze_repository


if TYPE_CHECKING:
    from pathlib import Path


_RULE_ID = RuleId("repository/artifacts/untyped-javascript")
_BASE = 'repository_id = "example-repository"\ncomponents = []\n'


def _artifact(
    path: str = "eslint.config.mjs",
    *,
    kind: str = "tool-config",
    reason: str = "The external tool loads this exact runtime artifact.",
    source: str | None = None,
) -> str:
    fields = {"path": path, "kind": kind, "reason": reason}
    if source is not None:
        fields["source"] = source
    return (
        "\n[[javascript.artifacts]]\n"
        + "\n".join(
            f"{key} = {json.dumps(value, ensure_ascii=False)}" for key, value in fields.items()
        )
        + "\n"
    )


def _manifest(artifact: str = "", *, enabled: bool = False) -> bytes:
    activation = f'enabled_rules = ["{_RULE_ID}"]\n' if enabled else ""
    return (_BASE + activation + artifact).encode()


def _snapshot(*paths: str, manifest: Manifest | None = None) -> RepositorySnapshot:
    return RepositorySnapshot(
        manifest=manifest or parse_manifest_bytes(_manifest()),
        baseline=None,
        inspection=RepositoryInspection(
            completion="complete",
            source_revision="a" * 40,
            tree_digest="b" * 40,
            tracked_file_count=len(paths),
            packages=(),
            workflow_paths=(),
            cloudbuild_paths=(),
            dockerfile_paths=(),
            terraform_modules=(),
            issues=(),
            tracked_files=tuple(
                TrackedFileEvidence(path=path, object_id=f"{index + 1:040x}")
                for index, path in enumerate(paths)
            ),
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


@pytest.mark.parametrize(
    "path",
    [
        "index.js",
        "ui.jsx",
        "module.mjs",
        "loader.cjs",
        "INDEX.JS",
        "ui.JSX",
        "nested/MODULE.MjS",
        "loader.CJS",
        ".config.js",
        "scripts/generate.mjs",
        "eslint.config.mjs",
        ".dependency-cruiser.mjs",
        "vendor/client.js",
        "generated/client.mjs",
        "fixtures/input.cjs",
        "tests/parser.test.jsx",
        "node_modules/tracked/index.js",
        "dist/app.js",
        "docs/example.mjs",
        "café/app.js",
    ],
)
def test_every_tracked_javascript_extension_needs_a_declaration(path: str) -> None:
    findings = [
        item for item in SarjPolicy.evaluate_repository(_snapshot(path)) if item.rule_id == _RULE_ID
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.path == path
    assert finding.severity == "warning"
    assert finding.rule_version == 1
    assert finding.evidence_level == "verified"
    assert "declar" in finding.message
    assert finding.remediation is not None
    assert "rename" not in finding.remediation.summary.casefold()


@pytest.mark.parametrize(
    "path",
    [
        "index.ts",
        "ui.tsx",
        "module.mts",
        "loader.cts",
        "types.d.ts",
        "bundle.js.map",
        "bundle.mjs.map",
        "index.js.bak",
        "script.py",
        "index.json",
        "legacy.mjs/index.ts",
        "javascript",
        "ui.jsx.txt",
        "main.sh",
        "MAIN.TS",
        "café/schema.proto",
    ],
)
def test_typed_sources_maps_and_other_languages_are_out_of_scope(path: str) -> None:
    assert _RULE_ID not in {
        item.rule_id for item in SarjPolicy.evaluate_repository(_snapshot(path))
    }


@pytest.mark.parametrize("kind", ["tool-config", "vendor", "fixture", "runtime"])
def test_declared_runtime_artifacts_are_exact_and_preserve_sibling_findings(kind: str) -> None:
    manifest = parse_manifest_bytes(_manifest(_artifact(kind=kind)))
    findings = SarjPolicy.evaluate_repository(
        _snapshot("eslint.config.mjs", "other.js", manifest=manifest)
    )
    assert [(item.rule_id, item.path) for item in findings] == [(_RULE_ID, "other.js")]
    assert manifest.javascript_artifacts[0].kind.value == kind
    assert manifest.javascript_artifacts[0].reason.strip()


@pytest.mark.parametrize(
    "source", ["src/client.ts", "scripts/generate.py", "schema.proto", "schema.json", "Cargo.toml"]
)
def test_generated_artifacts_accept_non_javascript_generation_inputs(source: str) -> None:
    manifest = parse_manifest_bytes(
        _manifest(_artifact("client.mjs", kind="generated", source=source))
    )
    assert SarjPolicy.evaluate_repository(_snapshot("client.mjs", source, manifest=manifest)) == ()


@pytest.mark.parametrize(
    "path",
    [
        "*.js",
        "src/**/app.mjs",
        "src/app?.js",
        "src/[ab].js",
        "../app.js",
        "/app.js",
        "./app.js",
        "src/../app.js",
        "src//app.js",
        "src/./app.js",
        "app.js/",
        "C:\\app.js",
        "src\\app.js",
        "app.js\n",
        "app.js\x00",
        "cafe\u0301/app.js",
    ],
)
def test_artifact_declarations_reject_non_exact_paths(path: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(_manifest(_artifact(path)))


@pytest.mark.parametrize(
    "path", ["source.ts", "source.tsx", "source.mts", "source.cts", "app.js.map", "schema.json"]
)
def test_non_javascript_artifact_declarations_are_invalid(path: str) -> None:
    with pytest.raises(ConfigurationError, match="JavaScript"):
        parse_manifest_bytes(_manifest(_artifact(path)))


@pytest.mark.parametrize("kind", ["config", "GENERATED", "", "generated ", "tool_config"])
def test_artifact_kinds_are_closed_and_exact(kind: str) -> None:
    with pytest.raises(ConfigurationError, match="kind"):
        parse_manifest_bytes(_manifest(_artifact(kind=kind)))


@pytest.mark.parametrize("reason", ["", " ", "\t\n", "\u2003", "\u200b", "\ufeff"])
def test_artifact_reason_requires_text(reason: str) -> None:
    with pytest.raises(ConfigurationError, match="reason"):
        parse_manifest_bytes(_manifest(_artifact(reason=reason)))


@pytest.mark.parametrize(
    "source",
    [
        None,
        "client.mjs",
        "input.js",
        "input.jsx",
        "input.CJS",
        "input.MJS",
        "../generator.py",
        "*.py",
        "./generator.py",
    ],
)
def test_generated_declarations_reject_missing_javascript_and_non_exact_inputs(
    source: str | None,
) -> None:
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(_manifest(_artifact("client.mjs", kind="generated", source=source)))


@pytest.mark.parametrize("kind", ["tool-config", "runtime", "fixture", "vendor"])
def test_only_generated_artifacts_can_declare_a_source(kind: str) -> None:
    with pytest.raises(ConfigurationError, match="source"):
        parse_manifest_bytes(_manifest(_artifact(kind=kind, source="input.ts")))


@pytest.mark.parametrize(
    "section",
    [
        '[javascript]\nartifacts = "all"',
        '[javascript]\nartifacts = ["app.js"]',
        '[javascript]\nexclude = ["*.js"]',
        "[javascript]\nartifacts = []\nunknown = true",
        '[[javascript.artifacts]]\npath = "app.js"\nkind = "runtime"',
        '[[javascript.artifacts]]\npath = 42\nkind = "runtime"\nreason = "needed"',
        '[[javascript.artifacts]]\npath = "app.js"\nkind = true\nreason = "needed"',
        '[[javascript.artifacts]]\npath = "app.js"\nkind = "runtime"\nreason = 42',
        (
            '[[javascript.artifacts]]\npath = "app.js"\nkind = "runtime"\n'
            'reason = "needed"\nextra = true'
        ),
    ],
)
def test_javascript_contract_rejects_malformed_or_unknown_fields(section: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(_manifest(section))


def test_duplicate_declarations_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="duplicate"):
        parse_manifest_bytes(_manifest(_artifact() + _artifact(kind="runtime")))


def test_empty_javascript_contract_keeps_default_manifest_behavior() -> None:
    plain = parse_manifest_bytes(_manifest())
    explicit_empty = parse_manifest_bytes(_manifest("[javascript]\nartifacts = []\n"))
    assert plain.javascript_artifacts == explicit_empty.javascript_artifacts == ()
    assert scope_digest(plain) == scope_digest(explicit_empty)


def test_declaration_changes_invalidate_baseline_scope_but_order_does_not() -> None:
    plain = parse_manifest_bytes(_manifest())
    first = parse_manifest_bytes(_manifest(_artifact() + _artifact("fixture.js", kind="fixture")))
    second = parse_manifest_bytes(_manifest(_artifact("fixture.js", kind="fixture") + _artifact()))
    revised = parse_manifest_bytes(_manifest(_artifact(reason="A reviewed runtime requirement.")))
    assert scope_digest(first) == scope_digest(second)
    assert len({scope_digest(plain), scope_digest(first), scope_digest(revised)}) == 3


def test_rule_is_deterministic_and_declarations_do_not_disable_other_rules() -> None:
    manifest = parse_manifest_bytes(_manifest(_artifact("iac/verify-plan.mjs", kind="runtime")))
    snapshot = _snapshot("other.js", "iac/verify-plan.mjs", manifest=manifest)
    first = SarjPolicy.evaluate_repository(snapshot)
    second = SarjPolicy.evaluate_repository(
        replace(
            snapshot,
            inspection=replace(
                snapshot.inspection,
                tracked_files=tuple(reversed(snapshot.inspection.tracked_files)),
            ),
        )
    )
    assert first == second
    assert {(item.rule_id, item.path) for item in first} == {
        (_RULE_ID, "other.js"),
        (RuleId("repository/artifacts/bespoke-iac-verifiers"), "iac/verify-plan.mjs"),
    }


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(
        [executable, "-C", str(root), *arguments], check=True, capture_output=True, timeout=10
    )
    return result.stdout.decode().strip()


def _repository(root: Path, *, artifact: str = "", enabled: bool = False) -> Path:
    (root / ".repo-standards").mkdir()
    (root / ".repo-standards/repository.toml").write_bytes(_manifest(artifact, enabled=enabled))
    (root / "app.js").write_text("export {};\n", encoding="utf-8")
    (root / "input.py").write_text("print('generator is not executed')\n", encoding="utf-8")
    _git(root, "init", "--quiet")
    _commit(root)
    return root


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


@pytest.mark.parametrize("calibration", [False, True])
@pytest.mark.parametrize(
    "artifact",
    [
        pytest.param(_artifact("absent.js"), id="missing-runtime-artifact"),
        pytest.param(
            _artifact("app.js", kind="generated", source="absent.py"),
            id="missing-generation-input",
        ),
    ],
)
def test_declaration_paths_must_exist_in_the_selected_tree(
    tmp_path: Path, calibration: bool, artifact: str
) -> None:
    root = _repository(tmp_path, artifact=artifact)

    def load_selected_snapshot() -> None:
        if calibration:
            load_calibration_snapshot(root, _manifest(artifact))
        else:
            load_repository_snapshot(root)

    with pytest.raises(ConfigurationError, match="tracked"):
        load_selected_snapshot()


def test_working_files_cannot_satisfy_committed_or_staged_declarations(tmp_path: Path) -> None:
    root = _repository(
        tmp_path, artifact=_artifact("app.js", kind="generated", source="untracked.py")
    )
    (root / "untracked.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="tracked"):
        load_repository_snapshot(root)
    with pytest.raises(ConfigurationError, match="tracked"):
        load_repository_snapshot(root, identity=git_index_identity(root))
    _git(root, "add", "untracked.py")
    assert load_repository_snapshot(
        root, identity=git_index_identity(root)
    ).manifest.javascript_artifacts
    with pytest.raises(ConfigurationError, match="tracked"):
        load_repository_snapshot(root)


def test_deleted_or_renamed_artifacts_cannot_leave_stale_allowances(tmp_path: Path) -> None:
    root = _repository(tmp_path, artifact=_artifact("app.js", kind="generated", source="input.py"))
    assert load_repository_snapshot(root).manifest.javascript_artifacts
    (root / "app.js").rename(root / "renamed.js")
    _commit(root)
    with pytest.raises(ConfigurationError, match="tracked"):
        load_repository_snapshot(root)


@pytest.mark.parametrize("path", ["app.js", "input.py"])
def test_artifact_and_generator_symlinks_fail_closed(tmp_path: Path, path: str) -> None:
    root = _repository(tmp_path, artifact=_artifact("app.js", kind="generated", source="input.py"))
    (root / path).unlink()
    (root / path).symlink_to("target.txt")
    (root / "target.txt").write_text("runtime target\n", encoding="utf-8")
    _commit(root)
    with pytest.raises(ConfigurationError, match="symlink"):
        load_repository_snapshot(root)
    with pytest.raises(ConfigurationError, match="symlink"):
        load_repository_snapshot(root, identity=git_index_identity(root))


def test_new_rule_is_opt_in_warning_with_no_implicit_activation(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    disabled = analyze_repository(RepositoryAnalysisRequest(root=root))
    enabled = analyze_repository(
        RepositoryAnalysisRequest(root=root, enabled_rule_ids=(str(_RULE_ID),))
    )
    assert disabled.completion == enabled.completion == "complete"
    assert disabled.diagnostics == ()
    assert [(item.rule_id, item.severity, item.path) for item in enabled.diagnostics] == [
        (_RULE_ID, "warning", "app.js")
    ]
    assert enabled.mode is Mode.STRICT


def test_manifest_activation_and_declaration_are_independent(tmp_path: Path) -> None:
    root = _repository(
        tmp_path, artifact=_artifact("app.js", kind="generated", source="input.py"), enabled=True
    )
    result = analyze_repository(RepositoryAnalysisRequest(root=root))
    assert result.completion == "complete"
    assert result.diagnostics == ()


def test_declaration_is_exact_case_even_though_extension_match_is_insensitive(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, artifact=_artifact("APP.JS"))
    with pytest.raises(ConfigurationError, match="tracked"):
        load_repository_snapshot(root)


def test_artifact_count_is_bounded_and_accepts_the_exact_limit() -> None:
    records = "".join(_artifact(f"fixtures/{index}.js", kind="fixture") for index in range(1_000))
    assert len(parse_manifest_bytes(_manifest(records)).javascript_artifacts) == 1_000
    with pytest.raises(ConfigurationError, match="at most 1000"):
        parse_manifest_bytes(_manifest(records + _artifact("fixtures/overflow.js")))


def test_repeated_tracking_evidence_cannot_duplicate_javascript_findings() -> None:
    findings = SarjPolicy.evaluate_repository(_snapshot("app.js", "app.js", "other.mjs"))
    assert [(item.rule_id, item.path) for item in findings] == [
        (_RULE_ID, "app.js"),
        (_RULE_ID, "other.mjs"),
    ]


def test_nested_component_owns_the_finding_without_exempting_its_javascript() -> None:
    snapshot = _snapshot("applications/app/tool/main.js")
    manifest = replace(
        snapshot.manifest,
        components=(
            Component(ComponentId("parent"), "application", "applications/app", "@app"),
            Component(ComponentId("child"), "tool", "applications/app/tool", "@tool"),
        ),
    )
    findings = [
        item
        for item in SarjPolicy.evaluate_repository(replace(snapshot, manifest=manifest))
        if item.rule_id == _RULE_ID
    ]
    assert len(findings) == 1
    assert findings[0].component_id == "child"
    assert findings[0].location is not None
    assert findings[0].location.path == "applications/app/tool/main.js"
    assert findings[0].location.line == 1


def test_generator_and_javascript_contents_are_never_executed(tmp_path: Path) -> None:
    artifact = _artifact("app.js", kind="generated", source="input.py")
    root = _repository(tmp_path, artifact=artifact)
    marker = root / "executed.txt"
    (root / "input.py").write_text(
        "from pathlib import Path\nPath('executed.txt').write_text('unsafe')\n",
        encoding="utf-8",
    )
    (root / "app.js").write_text("throw new Error('must not execute');\n", encoding="utf-8")
    _commit(root)
    assert load_repository_snapshot(root).manifest.javascript_artifacts
    assert load_calibration_snapshot(root, _manifest(artifact)).manifest.javascript_artifacts
    assert not marker.exists()


def test_removed_generation_input_invalidates_a_declaration(tmp_path: Path) -> None:
    root = _repository(tmp_path, artifact=_artifact("app.js", kind="generated", source="input.py"))
    (root / "input.py").unlink()
    _commit(root)
    with pytest.raises(ConfigurationError, match="source must name a tracked"):
        load_repository_snapshot(root)


@pytest.mark.parametrize("command", ["check", "report"])
def test_strict_and_report_show_warnings_without_error_promotion(
    tmp_path: Path, command: str
) -> None:
    root = _repository(tmp_path, enabled=True)
    result = CliRunner().invoke(app, [command, str(root), "--format", "json"])
    assert result.exit_code == 0, result.stdout
    assert '"severity":"warning"' in result.stdout
    assert '"warnings":1' in result.stdout
    assert '"errors":0' in result.stdout
