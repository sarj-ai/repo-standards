from __future__ import annotations

from io import BytesIO
import tarfile
from typing import TYPE_CHECKING
import zipfile

import pytest

from repo_standards.verify_release_artifacts import verify_distributions


if TYPE_CHECKING:
    from pathlib import Path


_METADATA = b"License-Expression: MIT\nLicense-File: LICENSE\n\n"
_DIST_INFO = "repo_standards-1.0.0.dist-info"
_ROOT = "repo_standards-1.0.0"


def _archives(directory: Path, wheel: dict[str, bytes], sdist: dict[str, bytes]) -> None:
    with zipfile.ZipFile(directory / "package.whl", "w") as archive:
        for name, content in wheel.items():
            archive.writestr(name, content)
    with tarfile.open(directory / "package.tar.gz", "w:gz") as archive:
        for name, content in sdist.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, BytesIO(content))


def test_distribution_verification_accepts_public_package_members(tmp_path: Path) -> None:
    _archives(
        tmp_path,
        {
            "repo_standards/__init__.py": b"",
            "repo_standards/py.typed": b"",
            f"{_DIST_INFO}/METADATA": _METADATA,
            f"{_DIST_INFO}/licenses/LICENSE": b"MIT",
        },
        {
            f"{_ROOT}/src/repo_standards/__init__.py": b"",
            f"{_ROOT}/src/repo_standards/py.typed": b"",
            f"{_ROOT}/PKG-INFO": _METADATA,
            f"{_ROOT}/LICENSE": b"MIT",
        },
    )

    assert verify_distributions(tmp_path) == []


@pytest.mark.parametrize(
    ("sdist", "expected"),
    [
        pytest.param(
            {
                f"{_ROOT}/PKG-INFO": _METADATA,
                f"{_ROOT}/LICENSE": b"MIT",
                f"{_ROOT}/secret.txt": b"",
            },
            [f"package.tar.gz:{_ROOT}/secret.txt: unexpected source distribution member"],
            id="unexpected-source-member",
        ),
        pytest.param(
            {f"{_ROOT}/LICENSE": b"MIT"},
            ["source distribution is missing PKG-INFO"],
            id="missing-source-metadata",
        ),
        pytest.param(
            {f"{_ROOT}/PKG-INFO": _METADATA, "other/LICENSE": b"MIT"},
            ["source distribution must contain exactly one root directory"],
            id="multiple-source-roots",
        ),
    ],
)
def test_distribution_verification_preserves_both_artifact_failures(
    tmp_path: Path, sdist: dict[str, bytes], expected: list[str]
) -> None:
    _archives(
        tmp_path,
        {
            f"{_DIST_INFO}/METADATA": _METADATA,
            f"{_DIST_INFO}/licenses/LICENSE": b"MIT",
            "secret.txt": b"",
        },
        sdist,
    )

    assert verify_distributions(tmp_path) == [
        "package.whl:secret.txt: unexpected wheel member",
        *expected,
    ]
