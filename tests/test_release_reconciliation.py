from __future__ import annotations

import hashlib
import io
import tarfile
from typing import TYPE_CHECKING
import zipfile

import pytest

from release_reconciliation import (
    Artifact,
    ReconciliationPlan,
    RegistrySide,
    ReleaseState,
    ReleaseStateError,
    parse_github_registry_side,
    parse_pypi_registry_side,
    reconciliation_plan,
    render_release_readme,
    verify_distribution_release_identity,
    verify_installed_distributions,
)


if TYPE_CHECKING:
    from pathlib import Path


VERSION = "3.0.0"
HEAD_SHA = "a" * 40
TAG_SHA = "b" * 40
WHEEL = Artifact(f"repo_standards-{VERSION}-py3-none-any.whl", "1" * 64)
SDIST = Artifact(f"repo_standards-{VERSION}.tar.gz", "2" * 64)


def _side(source_sha: str = TAG_SHA) -> RegistrySide:
    return RegistrySide((SDIST, WHEEL), source_sha)


def _state(
    *,
    tag_sha: str | None = TAG_SHA,
    github: RegistrySide | None = None,
    pypi: RegistrySide | None = None,
) -> ReleaseState:
    return ReleaseState(VERSION, HEAD_SHA, tag_sha, github, pypi)


def test_new_release_anchors_head_before_building() -> None:
    assert reconciliation_plan(_state(tag_sha=None)) == ReconciliationPlan(
        artifact_source="build",
        create_tag=True,
        create_github_release=True,
        prepare_artifacts=True,
        publish_pypi=True,
        source_sha=HEAD_SHA,
    )


def test_failed_initial_release_rebuilds_only_the_anchored_tag() -> None:
    plan = reconciliation_plan(_state())
    assert plan.artifact_source == "build"
    assert plan.create_tag is False
    assert plan.source_sha == TAG_SHA


@pytest.mark.parametrize(
    ("github", "pypi", "artifact_source", "expected_publish", "expected_release"),
    [
        (_side(), None, "github", "true", "false"),
        (None, _side(), "pypi", "false", "true"),
        (_side(), _side(), "none", "false", "false"),
    ],
)
def test_partial_states_reuse_exact_published_artifacts(
    github: RegistrySide | None,
    pypi: RegistrySide | None,
    artifact_source: str,
    expected_publish: str,
    expected_release: str,
) -> None:
    plan = reconciliation_plan(_state(github=github, pypi=pypi))
    assert plan.artifact_source == artifact_source
    assert str(plan.publish_pypi).lower() == expected_publish
    assert str(plan.create_github_release).lower() == expected_release
    assert plan.source_sha == TAG_SHA


def test_published_side_without_tag_is_refused() -> None:
    with pytest.raises(ReleaseStateError, match="immutable release tag"):
        reconciliation_plan(_state(tag_sha=None, pypi=_side()))


@pytest.mark.parametrize("label", ["github", "pypi"])
def test_published_source_must_match_tag(label: str) -> None:
    values = {label: _side(source_sha="c" * 40)}
    with pytest.raises(ReleaseStateError, match="source does not match"):
        reconciliation_plan(_state(**values))  # type: ignore[arg-type]


def test_cross_registry_hash_mismatch_is_refused() -> None:
    different = RegistrySide((SDIST, Artifact(WHEEL.name, "3" * 64)), TAG_SHA)
    with pytest.raises(ReleaseStateError, match="artifact hashes differ"):
        reconciliation_plan(_state(github=_side(), pypi=different))


def test_incomplete_or_extra_artifact_sets_are_refused() -> None:
    with pytest.raises(ReleaseStateError, match="exactly the wheel and source distribution"):
        reconciliation_plan(_state(github=RegistrySide((WHEEL,), TAG_SHA)))


def test_release_readme_is_rendered_to_exact_source_and_version() -> None:
    source = """steps:
      - uses: sarj-ai/repo-standards@1111111111111111111111111111111111111111 # v2.0.0
"""
    rendered = render_release_readme(source, source_sha=TAG_SHA, version=VERSION)
    assert rendered.count(f"uses: sarj-ai/repo-standards@{TAG_SHA} # v{VERSION}") == 1
    assert "v2.0.0" not in rendered


def test_release_readme_requires_one_unambiguous_action_pin() -> None:
    with pytest.raises(ReleaseStateError, match="exactly one"):
        render_release_readme("# no action\n", source_sha=TAG_SHA, version=VERSION)


def test_built_package_documents_must_embed_the_exact_release_identity(tmp_path: Path) -> None:
    pin = f"uses: sarj-ai/repo-standards@{TAG_SHA} # v{VERSION}"
    wheel = tmp_path / f"repo_standards-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr(f"repo_standards-{VERSION}.dist-info/METADATA", pin)
    sdist = tmp_path / f"repo_standards-{VERSION}.tar.gz"
    content = pin.encode()
    with tarfile.open(sdist, mode="w:gz") as archive:
        info = tarfile.TarInfo(f"repo_standards-{VERSION}/README.md")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))

    verify_distribution_release_identity(tmp_path, source_sha=TAG_SHA, version=VERSION)


def test_installed_distribution_verifier_checks_both_artifacts_and_writes_checksums(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "dist/packages/repo-standards"
    directory.mkdir(parents=True)
    wheel = directory / WHEEL.name
    sdist = directory / SDIST.name
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    commands: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...]) -> str:
        commands.append(command)
        return f"{VERSION}\n" if command[-1] == "--version" else ""

    checksum = tmp_path / "dist/SHA256SUMS"
    verify_installed_distributions(
        directory,
        version=VERSION,
        smoke_root=tmp_path / "smoke",
        checksum_path=checksum,
        run_command=run,
    )

    assert len(commands) == 8
    assert sum(command[:2] == ("uv", "venv") for command in commands) == 2
    assert sum(command[:3] == ("uv", "pip", "install") for command in commands) == 2
    assert checksum.read_text(encoding="utf-8").splitlines() == [
        f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  packages/repo-standards/{wheel.name}",
        f"{hashlib.sha256(sdist.read_bytes()).hexdigest()}  packages/repo-standards/{sdist.name}",
    ]


def test_installed_distribution_verifier_rejects_extra_packages(tmp_path: Path) -> None:
    directory = tmp_path / "packages"
    directory.mkdir()
    (directory / WHEEL.name).write_bytes(b"wheel")
    (directory / SDIST.name).write_bytes(b"sdist")
    (directory / "unexpected.whl").write_bytes(b"extra")

    with pytest.raises(ReleaseStateError, match="exactly the expected"):
        verify_installed_distributions(
            directory,
            version=VERSION,
            smoke_root=tmp_path / "smoke",
            checksum_path=tmp_path / "SHA256SUMS",
            run_command=lambda _command: "",
        )


def test_installed_distribution_verifier_rejects_missing_release_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(ReleaseStateError, match="release directory does not exist"):
        verify_installed_distributions(
            tmp_path / "missing",
            version=VERSION,
            smoke_root=tmp_path / "smoke",
            checksum_path=tmp_path / "SHA256SUMS",
            run_command=lambda _command: "",
        )


def test_installed_distribution_verifier_rejects_wrong_installed_version(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "packages"
    directory.mkdir()
    (directory / WHEEL.name).write_bytes(b"wheel")
    (directory / SDIST.name).write_bytes(b"sdist")

    with pytest.raises(ReleaseStateError, match="installed version differs"):
        verify_installed_distributions(
            directory,
            version=VERSION,
            smoke_root=tmp_path / "smoke",
            checksum_path=tmp_path / "SHA256SUMS",
            run_command=lambda command: "9.9.9\n" if command[-1] == "--version" else "",
        )


def test_github_snapshot_preserves_source_sorted_artifacts_and_ignores_other_named_assets() -> None:
    document: dict[str, object] = {
        "target_commitish": TAG_SHA,
        "assets": [
            {
                "name": WHEEL.name,
                "digest": f"sha256:{WHEEL.sha256}",
                "browser_download_url": "wheel",
            },
            {"name": "SHA256SUMS"},
            {"name": "unrelated.txt"},
            {
                "name": SDIST.name,
                "digest": f"sha256:{SDIST.sha256}",
                "browser_download_url": "sdist",
            },
        ],
    }
    assert parse_github_registry_side(document, VERSION) == RegistrySide(
        tuple(
            sorted(
                (
                    Artifact(WHEEL.name, WHEEL.sha256, "wheel"),
                    Artifact(SDIST.name, SDIST.sha256, "sdist"),
                )
            )
        ),
        TAG_SHA,
    )


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"assets": []}, "target is missing"),
        ({"target_commitish": TAG_SHA}, "assets are missing"),
        ({"target_commitish": TAG_SHA, "assets": [None]}, "malformed asset"),
        ({"target_commitish": TAG_SHA, "assets": [dict[str, object]()]}, "malformed asset"),
        ({"target_commitish": TAG_SHA, "assets": []}, "missing SHA256SUMS"),
        ({"target_commitish": TAG_SHA, "assets": [{"name": WHEEL.name}]}, "digest is unavailable"),
        (
            {"target_commitish": TAG_SHA, "assets": [{"name": WHEEL.name, "digest": "sha256:123"}]},
            "URL is unavailable",
        ),
    ],
)
def test_github_snapshot_rejects_incomplete_publication_evidence(
    document: dict[str, object], message: str
) -> None:
    with pytest.raises(ReleaseStateError, match=message):
        parse_github_registry_side(document, VERSION)


def test_pypi_snapshot_preserves_source_sorted_artifacts_and_ignores_unrelated_files() -> None:
    document: dict[str, object] = {
        "info": {"description": f"- uses: sarj-ai/repo-standards@{TAG_SHA} # v{VERSION}\n"},
        "urls": [
            None,
            {},
            {"filename": "unrelated.txt"},
            {"filename": WHEEL.name, "digests": {"sha256": WHEEL.sha256}, "url": "wheel"},
            {"filename": SDIST.name, "digests": {"sha256": SDIST.sha256}, "url": "sdist"},
        ],
    }
    assert parse_pypi_registry_side(document, VERSION) == RegistrySide(
        tuple(
            sorted(
                (
                    Artifact(WHEEL.name, WHEEL.sha256, "wheel"),
                    Artifact(SDIST.name, SDIST.sha256, "sdist"),
                )
            )
        ),
        TAG_SHA,
    )


@pytest.mark.parametrize(
    ("artifact", "message"),
    [
        ({"filename": WHEEL.name}, "digest is unavailable"),
        ({"filename": WHEEL.name, "digests": {}}, "digest is unavailable"),
        ({"filename": WHEEL.name, "digests": {"sha256": WHEEL.sha256}}, "URL is unavailable"),
    ],
)
def test_pypi_snapshot_rejects_incomplete_artifact_evidence(
    artifact: dict[str, object], message: str
) -> None:
    document: dict[str, object] = {
        "info": {"description": f"- uses: sarj-ai/repo-standards@{TAG_SHA} # v{VERSION}\n"},
        "urls": [artifact],
    }
    with pytest.raises(ReleaseStateError, match=message):
        parse_pypi_registry_side(document, VERSION)
