from __future__ import annotations

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
    reconciliation_plan,
    render_release_readme,
    verify_release_documents,
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


def test_release_readme_is_rendered_to_exact_source_and_version(tmp_path: Path) -> None:
    del tmp_path
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

    verify_release_documents(tmp_path, source_sha=TAG_SHA, version=VERSION)
