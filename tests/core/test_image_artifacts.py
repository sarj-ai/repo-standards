from __future__ import annotations

from dataclasses import replace
import json
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from repo_standards.core.canonical import scope_digest
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.inspection import git_index_identity, load_repository_snapshot
from repo_standards.core.models import (
    GitObjectId,
    InputProvenance,
    Manifest,
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


_RULE_ID = RuleId("repository/artifacts/undeclared-images")
_BASE = 'repository_id = "example-repository"\ncomponents = []\n'


def _artifact(
    path: str = "public/logo.png",
    *,
    kind: str = "application",
    reason: str = "The application renders this brand asset.",
) -> str:
    return (
        "\n[[images.artifacts]]\n"
        + "\n".join(
            f"{key} = {json.dumps(value, ensure_ascii=False)}"
            for key, value in {"path": path, "kind": kind, "reason": reason}.items()
        )
        + "\n"
    )


def _manifest(records: str = "", *, enabled: bool = False) -> bytes:
    activation = f'enabled_rules = ["{_RULE_ID}"]\n' if enabled else ""
    return (_BASE + activation + records).encode()


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
        "before.png",
        "docs/review/after.JPG",
        "public/preview.jpeg",
        "tests/frame.gif",
        "fixtures/page.webp",
        "generated/output.avif",
        "vendor/icon.svg",
        "public/favicon.ico",
        "sample.bmp",
        "scan.tif",
        "scan.tiff",
        "animation.apng",
        "drawing.svgz",
        "camera.heic",
        "camera.heif",
        "sample.jxl",
        "café/logo.PNG",
    ],
)
def test_undeclared_images_have_no_directory_or_case_exemptions(path: str) -> None:
    findings = SarjPolicy.evaluate_repository(
        _snapshot(path), enabled_rule_ids=frozenset({_RULE_ID})
    )
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.rule_version, finding.severity, finding.path) == (
        _RULE_ID,
        1,
        "warning",
        path,
    )
    assert finding.evidence_level == "verified"
    assert finding.remediation is not None
    assert "attach" in " ".join(finding.remediation.steps).lower()


@pytest.mark.parametrize("kind", ["application", "documentation", "fixture"])
def test_declared_image_purposes_preserve_assets_and_report_undeclared_siblings(kind: str) -> None:
    manifest = parse_manifest_bytes(_manifest(_artifact(kind=kind)))
    findings = SarjPolicy.evaluate_repository(
        _snapshot("public/logo.png", "public/review.png", manifest=manifest),
        enabled_rule_ids=frozenset({_RULE_ID}),
    )
    assert [item.path for item in findings] == ["public/review.png"]
    assert manifest.image_artifacts[0].kind.value == kind


@pytest.mark.parametrize("path", ["image.png.txt", "images.png/source.ts", "image", "report.pdf"])
def test_non_image_paths_are_not_classified_by_directory_or_content_names(path: str) -> None:
    assert (
        SarjPolicy.evaluate_repository(_snapshot(path), enabled_rule_ids=frozenset({_RULE_ID}))
        == ()
    )


@pytest.mark.parametrize(
    "path",
    [
        "../logo.png",
        "/logo.png",
        "./logo.png",
        "a//logo.png",
        "a/../logo.png",
        "a\\logo.png",
        "logo.png\n",
        "cafe\u0301/logo.png",
        "README.md",
    ],
)
def test_image_declarations_require_canonical_image_paths(path: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(_manifest(_artifact(path)))


@pytest.mark.parametrize("kind", ["screenshot", "review", "generated", "vendor", "", "APPLICATION"])
def test_review_evidence_is_not_a_durable_image_purpose(kind: str) -> None:
    with pytest.raises(ConfigurationError, match="kind"):
        parse_manifest_bytes(_manifest(_artifact(kind=kind)))


@pytest.mark.parametrize("reason", ["", " \t\n", "\x00"])
def test_declarations_require_a_visible_reason(reason: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(_manifest(_artifact(reason=reason)))


def test_declarations_are_unique_strict_and_exact_without_glob_expansion() -> None:
    with pytest.raises(ConfigurationError, match="duplicate"):
        parse_manifest_bytes(_manifest(_artifact() + _artifact()))
    with pytest.raises(ConfigurationError):
        parse_manifest_bytes(_manifest(_artifact() + 'owner = "unknown-field"\n'))
    literal = "fixtures/[ab]*.png"
    manifest = parse_manifest_bytes(_manifest(_artifact(literal, kind="fixture")))
    findings = SarjPolicy.evaluate_repository(
        _snapshot(literal, "fixtures/a.png", manifest=manifest),
        enabled_rule_ids=frozenset({_RULE_ID}),
    )
    assert [item.path for item in findings] == ["fixtures/a.png"]


def test_image_permissions_are_bound_to_baseline_scope_and_stable_under_reordering() -> None:
    plain = parse_manifest_bytes(_manifest())
    declared = parse_manifest_bytes(_manifest(_artifact()))
    assert scope_digest(plain) != scope_digest(declared)
    other = _artifact("docs/diagram.svg", kind="documentation")
    assert scope_digest(parse_manifest_bytes(_manifest(_artifact() + other))) == scope_digest(
        parse_manifest_bytes(_manifest(other + _artifact()))
    )
    changed = parse_manifest_bytes(_manifest(_artifact(reason="A different contract.")))
    assert scope_digest(changed) != scope_digest(declared)


def test_image_and_local_residue_findings_remain_distinct_and_deterministic() -> None:
    snapshot = _snapshot("review.png", ".DS_Store", "second.png")
    first = SarjPolicy.evaluate_repository(snapshot)
    reversed_snapshot = replace(
        snapshot,
        inspection=replace(
            snapshot.inspection, tracked_files=tuple(reversed(snapshot.inspection.tracked_files))
        ),
    )
    assert first == SarjPolicy.evaluate_repository(reversed_snapshot)
    assert {(item.rule_id, item.path) for item in first} == {
        (_RULE_ID, "review.png"),
        (_RULE_ID, "second.png"),
        (RuleId("repository/artifacts/local-residue"), ".DS_Store"),
    }


def _git(root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(
        [executable, "-C", str(root), *arguments], check=True, capture_output=True, timeout=10
    )
    return result.stdout.decode().strip()


def _repository(root: Path, *, records: str = "", enabled: bool = False) -> Path:
    (root / ".repo-standards").mkdir()
    (root / ".repo-standards/repository.toml").write_bytes(_manifest(records, enabled=enabled))
    (root / "public").mkdir()
    (root / "public/logo.png").write_bytes(b"\x89PNG\r\n\x1a\nfixture")
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
    return root


def test_rule_activation_is_explicit(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    disabled = analyze_repository(RepositoryAnalysisRequest(root=root))
    enabled = analyze_repository(
        RepositoryAnalysisRequest(root=root, enabled_rule_ids=(str(_RULE_ID),))
    )
    assert disabled.diagnostics == ()
    assert [(item.rule_id, item.severity, item.path) for item in enabled.diagnostics] == [
        (_RULE_ID, "warning", "public/logo.png")
    ]


def test_declarations_do_not_implicitly_activate_the_image_rule(tmp_path: Path) -> None:
    root = _repository(tmp_path, records=_artifact())
    (root / "public/review.png").write_bytes(b"review evidence")
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
        "undeclared review image",
    )
    assert analyze_repository(RepositoryAnalysisRequest(root=root)).diagnostics == ()
    enabled = analyze_repository(
        RepositoryAnalysisRequest(root=root, enabled_rule_ids=(str(_RULE_ID),))
    )
    assert [item.path for item in enabled.diagnostics] == ["public/review.png"]


@pytest.mark.parametrize("selection", ["tree", "index"])
@pytest.mark.parametrize(
    ("invalid", "error"),
    [
        ("missing", "tracked regular file"),
        ("directory", "tracked regular file"),
        ("symlink", "tracked path is a symlink"),
        ("case", "tracked regular file"),
    ],
)
def test_declarations_must_name_a_regular_file_in_the_selected_git_snapshot(
    tmp_path: Path, selection: str, invalid: str, error: str
) -> None:
    path = "public/LOGO.PNG" if invalid == "case" else "public/missing.png"
    root = _repository(tmp_path, records=_artifact(path))
    target = root / path
    if invalid == "directory":
        target.mkdir()
        (target / "source.py").write_text("# fixture\n", encoding="utf-8")
    elif invalid == "symlink":
        target.symlink_to("logo.png")
    _git(root, "add", ".")
    if selection == "tree":
        _git(
            root,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "invalid declaration fixture",
        )
    with pytest.raises(ConfigurationError, match=error):
        load_repository_snapshot(
            root, identity=git_index_identity(root) if selection == "index" else None
        )


def test_staged_manifest_and_images_ignore_unstaged_permissions_and_untracked_images(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path, enabled=True)
    manifest = root / ".repo-standards/repository.toml"
    manifest.write_bytes(_manifest(_artifact(), enabled=True))
    (root / "public/review.png").write_bytes(b"temporary screenshot")
    before = load_repository_snapshot(root, identity=git_index_identity(root))
    assert before.manifest.image_artifacts == ()
    assert [item.path for item in SarjPolicy.evaluate_repository(before)] == ["public/logo.png"]
    _git(root, "add", ".repo-standards/repository.toml")
    after = load_repository_snapshot(root, identity=git_index_identity(root))
    assert SarjPolicy.evaluate_repository(after) == ()
    assert load_repository_snapshot(root).manifest.image_artifacts == ()
    _git(root, "add", "public/review.png")
    staged = load_repository_snapshot(root, identity=git_index_identity(root))
    assert [item.path for item in SarjPolicy.evaluate_repository(staged)] == ["public/review.png"]
