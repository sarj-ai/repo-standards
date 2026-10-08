from __future__ import annotations

import hashlib
import io
from threading import Barrier
from typing import TYPE_CHECKING

import pytest

import release_reconciliation as release


if TYPE_CHECKING:
    from pathlib import Path
    from urllib.request import Request


@pytest.mark.parametrize("failed", [False, True])
def test_registry_inspection_overlaps_all_reads_and_propagates_failure(
    monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    barrier = Barrier(3)
    finished: list[str] = []

    def request(url: str, *, token: str | None = None) -> dict[str, object] | None:
        if "pypi.org" in url:
            assert token is None
        barrier.wait(timeout=5)
        finished.append(url)
        if failed and "pypi.org" in url:
            message = "registry outage"
            raise OSError(message)
        return None

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- intercept release bootstrap HTTP boundary
        release, "_request_json", request
    )
    if failed:
        with pytest.raises(OSError, match="outage"):
            release.inspect_release(
                version="1.0.0", repository="example/repository", head_sha="a" * 40
            )
    else:
        state = release.inspect_release(
            version="1.0.0", repository="example/repository", head_sha="a" * 40
        )
        assert state.tag_sha is None
        assert state.github is None
        assert state.pypi is None
    assert len(finished) == 3


@pytest.mark.parametrize("bad_digest", [False, True])
def test_downloads_overlap_and_only_publish_files_after_all_hashes_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_digest: bool
) -> None:
    barrier = Barrier(2)
    contents = {"wheel.whl": b"wheel", "sdist.tar.gz": b"sdist"}
    side = release.RegistrySide(
        tuple(
            release.Artifact(
                name, hashlib.sha256(content).hexdigest(), "https://files.pythonhosted.org/" + name
            )
            for name, content in contents.items()
        ),
        "a" * 40,
    )

    def open_url(request: Request, *, timeout: int) -> io.BytesIO:
        assert timeout == 60
        barrier.wait(timeout=5)
        name = request.full_url.rsplit("/", 1)[1]
        return io.BytesIO(b"wrong" if bad_digest and name == "wheel.whl" else contents[name])

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- stub HTTP around real digest validation
        release, "urlopen", open_url
    )
    directory = tmp_path / "dist/packages/repo-standards"
    if bad_digest:
        with pytest.raises(release.ReleaseStateError, match="digest differs"):
            release.download_artifacts(side, directory)
        assert not directory.exists()
        assert not (tmp_path / "dist/SHA256SUMS").exists()
    else:
        (tmp_path / "dist").mkdir()
        release.download_artifacts(side, directory)
        assert {path.name: path.read_bytes() for path in directory.iterdir()} == contents
        assert (tmp_path / "dist/SHA256SUMS").read_text().splitlines() == [
            f"{artifact.sha256}  packages/repo-standards/{artifact.name}"
            for artifact in side.artifacts
        ]


@pytest.mark.parametrize(
    ("name", "url"),
    [
        ("../escape.whl", "https://files.pythonhosted.org/wheel"),
        ("nested\\escape.whl", "https://files.pythonhosted.org/wheel"),
        ("wheel.whl", "http://files.pythonhosted.org/wheel"),
        ("wheel.whl", "https://other.example/wheel"),
        ("wheel.whl", "https://token@" + "files.pythonhosted.org/wheel"),
    ],
)
def test_invalid_second_artifact_blocks_all_network_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, url: str
) -> None:
    def open_url(_request: Request, *, timeout: int) -> io.BytesIO:
        pytest.fail(f"invalid artifact must fail before transport (timeout {timeout})")

    monkeypatch.setattr(  # sarj-noqa: SARJ445 -- prove validation precedes all HTTP reads
        release, "urlopen", open_url
    )
    side = release.RegistrySide(
        (
            release.Artifact("safe.whl", "a" * 64, "https://files.pythonhosted.org/safe.whl"),
            release.Artifact(name, "b" * 64, url),
        ),
        "a" * 40,
    )
    directory = tmp_path / "dist/packages/repo-standards"
    with pytest.raises(release.ReleaseStateError, match="approved registry artifact"):
        release.download_artifacts(side, directory)
    assert not directory.exists()
