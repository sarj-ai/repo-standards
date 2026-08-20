from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
from typing import BinaryIO, Literal, cast, final
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_ACTION_PIN = re.compile(
    r"(?m)^(?P<indent>\s*- uses: sarj-ai/repo-standards@)[^\s]+\s+#\s+v[^\s]+$"
)
_HTTP_NOT_FOUND = 404
ArtifactSource = Literal["build", "github", "none", "pypi"]


class ReleaseStateError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class Artifact:
    name: str
    sha256: str
    url: str = ""


@dataclass(frozen=True)
class RegistrySide:
    artifacts: tuple[Artifact, ...]
    source_sha: str


@dataclass(frozen=True)
class ReleaseState:
    version: str
    head_sha: str
    tag_sha: str | None = None
    github: RegistrySide | None = None
    pypi: RegistrySide | None = None


@dataclass(frozen=True)
class ReconciliationPlan:
    artifact_source: ArtifactSource
    create_tag: bool
    create_github_release: bool
    prepare_artifacts: bool
    publish_pypi: bool
    source_sha: str


def expected_artifact_names(version: str) -> frozenset[str]:
    _validate_version(version)
    return frozenset(
        {
            f"repo_standards-{version}-py3-none-any.whl",
            f"repo_standards-{version}.tar.gz",
        }
    )


def reconciliation_plan(state: ReleaseState) -> ReconciliationPlan:
    _validate_version(state.version)
    _validate_sha(state.head_sha, "head")
    if state.tag_sha is None:
        if state.github is not None or state.pypi is not None:
            msg = "published artifacts require an immutable release tag"
            raise ReleaseStateError(msg)
        return ReconciliationPlan(
            artifact_source="build",
            create_tag=True,
            create_github_release=True,
            prepare_artifacts=True,
            publish_pypi=True,
            source_sha=state.head_sha,
        )

    _validate_sha(state.tag_sha, "tag")
    if state.github is not None:
        _validate_side(state, "GitHub", state.github)
    if state.pypi is not None:
        _validate_side(state, "PyPI", state.pypi)
    if state.github is not None and state.pypi is not None:
        if _digest_map(state.github) != _digest_map(state.pypi):
            msg = "PyPI and GitHub release artifact hashes differ"
            raise ReleaseStateError(msg)
        return ReconciliationPlan(
            artifact_source="none",
            create_tag=False,
            create_github_release=False,
            prepare_artifacts=False,
            publish_pypi=False,
            source_sha=state.tag_sha,
        )
    if state.github is not None:
        return ReconciliationPlan(
            artifact_source="github",
            create_tag=False,
            create_github_release=False,
            prepare_artifacts=True,
            publish_pypi=True,
            source_sha=state.tag_sha,
        )
    if state.pypi is not None:
        return ReconciliationPlan(
            artifact_source="pypi",
            create_tag=False,
            create_github_release=True,
            prepare_artifacts=True,
            publish_pypi=False,
            source_sha=state.tag_sha,
        )
    return ReconciliationPlan(
        artifact_source="build",
        create_tag=False,
        create_github_release=True,
        prepare_artifacts=True,
        publish_pypi=True,
        source_sha=state.tag_sha,
    )


def render_release_readme(readme: str, *, source_sha: str, version: str) -> str:
    _validate_sha(source_sha, "source")
    _validate_version(version)
    replacement = rf"\g<indent>{source_sha} # v{version}"
    rendered, replacements = _ACTION_PIN.subn(replacement, readme)
    if replacements != 1:
        msg = "README must contain exactly one pinned repo-standards Action"
        raise ReleaseStateError(msg)
    return rendered


def verify_release_documents(directory: Path, *, source_sha: str, version: str) -> None:
    expected = f"uses: sarj-ai/repo-standards@{source_sha} # v{version}"
    wheel = _exact_file(directory, f"repo_standards-{version}-py3-none-any.whl")
    sdist = _exact_file(directory, f"repo_standards-{version}.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            msg = "wheel must contain exactly one METADATA document"
            raise ReleaseStateError(msg)
        wheel_document = archive.read(metadata_names[0]).decode()
    with tarfile.open(sdist, mode="r:gz") as archive:
        readme_names = [name for name in archive.getnames() if name.endswith("/README.md")]
        if len(readme_names) != 1:
            msg = "source distribution must contain exactly one README"
            raise ReleaseStateError(msg)
        extracted = archive.extractfile(readme_names[0])
        if extracted is None:
            msg = "source distribution README is unreadable"
            raise ReleaseStateError(msg)
        sdist_document = extracted.read().decode()
    if expected not in wheel_document or expected not in sdist_document:
        msg = "release artifacts do not identify their exact source SHA and version"
        raise ReleaseStateError(msg)


def _validate_side(state: ReleaseState, label: str, side: RegistrySide) -> None:
    if side.source_sha != state.tag_sha:
        msg = f"{label} source does not match the immutable release tag"
        raise ReleaseStateError(msg)
    expected = expected_artifact_names(state.version)
    observed = {artifact.name for artifact in side.artifacts}
    if observed != expected or len(observed) != len(side.artifacts):
        msg = f"{label} must contain exactly the wheel and source distribution"
        raise ReleaseStateError(msg)
    for artifact in side.artifacts:
        if not re.fullmatch(r"[0-9a-f]{64}", artifact.sha256):
            msg = f"{label} artifact has an invalid SHA-256 digest"
            raise ReleaseStateError(msg)


def _digest_map(side: RegistrySide) -> dict[str, str]:
    return {artifact.name: artifact.sha256 for artifact in side.artifacts}


def _validate_sha(value: str, label: str) -> None:
    if _COMMIT.fullmatch(value) is None:
        msg = f"{label} SHA must be a full lowercase Git commit SHA"
        raise ReleaseStateError(msg)


def _validate_version(version: str) -> None:
    if _VERSION.fullmatch(version) is None:
        msg = "release version must be an exact major.minor.patch version"
        raise ReleaseStateError(msg)


def _exact_file(directory: Path, name: str) -> Path:
    path = directory / name
    if not path.is_file():
        msg = f"missing release artifact: {name}"
        raise ReleaseStateError(msg)
    return path


def inspect_release(  # ruff: ignore[too-many-branches,too-many-locals,too-many-statements] -- one registry snapshot
    *, version: str, repository: str, head_sha: str
) -> ReleaseState:
    _validate_version(version)
    _validate_sha(head_sha, "head")
    # This dependency-free bootstrap runs before the project environment exists.
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    api = f"https://api.github.com/repos/{repository}"
    tag_document = _request_json(f"{api}/git/ref/tags/v{version}", token=token)
    tag_sha = (
        None
        if tag_document is None
        else _nested_string(tag_document, object_key="object", value_key="sha")
    )
    release_document = _request_json(f"{api}/releases/tags/v{version}", token=token)
    github = None
    if release_document is not None:
        target = release_document.get("target_commitish")
        if not isinstance(target, str):
            msg = "GitHub release target is missing"
            raise ReleaseStateError(msg)
        assets = release_document.get("assets")
        if not isinstance(assets, list):
            msg = "GitHub release assets are missing"
            raise ReleaseStateError(msg)
        package_assets: list[Artifact] = []
        checksum_present = False
        for raw_object in cast("list[object]", assets):
            raw = cast("dict[str, object]", raw_object) if isinstance(raw_object, dict) else None
            name_object = None if raw is None else raw.get("name")
            if raw is None or not isinstance(name_object, str):
                msg = "GitHub release contains malformed asset metadata"
                raise ReleaseStateError(msg)
            name = name_object
            checksum_present = checksum_present or name == "SHA256SUMS"
            if name not in expected_artifact_names(version):
                continue
            digest = raw.get("digest")
            url = raw.get("browser_download_url")
            if not isinstance(digest, str) or not digest.startswith("sha256:"):
                msg = "GitHub release asset digest is unavailable"
                raise ReleaseStateError(msg)
            if not isinstance(url, str):
                msg = "GitHub release asset URL is unavailable"
                raise ReleaseStateError(msg)
            package_assets.append(Artifact(name, digest.removeprefix("sha256:"), url))
        if not checksum_present:
            msg = "GitHub release is missing SHA256SUMS"
            raise ReleaseStateError(msg)
        github = RegistrySide(tuple(sorted(package_assets)), target)

    pypi_document = _request_json(f"https://pypi.org/pypi/repo-standards/{version}/json")
    pypi = None
    if pypi_document is not None:
        info_object = pypi_document.get("info")
        urls = pypi_document.get("urls")
        if not isinstance(info_object, dict) or not isinstance(urls, list):
            msg = "PyPI release metadata is malformed"
            raise ReleaseStateError(msg)
        info = cast("dict[str, object]", info_object)
        description = info.get("description")
        if not isinstance(description, str):
            msg = "PyPI release description is missing"
            raise ReleaseStateError(msg)
        pypi_source = _source_sha_from_readme(description, version)
        package_files: list[Artifact] = []
        for raw_object in cast("list[object]", urls):
            raw = cast("dict[str, object]", raw_object) if isinstance(raw_object, dict) else None
            if raw is None:
                continue
            filename = raw.get("filename")
            if not isinstance(filename, str) or filename not in expected_artifact_names(version):
                continue
            digests_object = raw.get("digests")
            url = raw.get("url")
            if not isinstance(digests_object, dict):
                msg = "PyPI artifact digest is unavailable"
                raise ReleaseStateError(msg)
            digests = cast("dict[str, object]", digests_object)
            sha256 = digests.get("sha256")
            if not isinstance(sha256, str):
                msg = "PyPI artifact digest is unavailable"
                raise ReleaseStateError(msg)
            if not isinstance(url, str):
                msg = "PyPI artifact URL is unavailable"
                raise ReleaseStateError(msg)
            package_files.append(Artifact(filename, sha256, url))
        pypi = RegistrySide(tuple(sorted(package_files)), pypi_source)
    return ReleaseState(version, head_sha, tag_sha, github, pypi)


def _request_json(url: str, *, token: str | None = None) -> dict[str, object] | None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "repo-standards-release"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    try:
        with cast(
            "BinaryIO",
            urlopen(  # ruff: ignore[suspicious-url-open-usage] -- same exact URL
                Request(url, headers=headers),  # ruff: ignore[suspicious-url-open-usage]
                timeout=30,
            ),
        ) as response:
            document = cast("object", json.load(response))
    except HTTPError as error:
        if error.code == _HTTP_NOT_FOUND:
            return None
        raise
    if not isinstance(document, dict):
        msg = f"expected a JSON object from {url}"
        raise ReleaseStateError(msg)
    return cast("dict[str, object]", document)


def _source_sha_from_readme(document: str, version: str) -> str:
    matches = _ACTION_PIN.findall(document)
    line = re.search(
        rf"uses: sarj-ai/repo-standards@(?P<sha>[0-9a-f]{{40}}) # v{re.escape(version)}(?:\s|$)",
        document,
    )
    if len(matches) != 1 or line is None:
        msg = "PyPI description does not identify its exact release SHA/version"
        raise ReleaseStateError(msg)
    return line.group("sha")


def _nested_string(
    document: dict[str, object], *, object_key: str, value_key: str
) -> str:
    nested_object = document.get(object_key)
    if not isinstance(nested_object, dict):
        msg = "GitHub tag response is malformed"
        raise ReleaseStateError(msg)
    nested = cast("dict[str, object]", nested_object)
    value = nested.get(value_key)
    if not isinstance(value, str):
        msg = "GitHub tag response is malformed"
        raise ReleaseStateError(msg)
    return value


def download_artifacts(side: RegistrySide, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for artifact in side.artifacts:
        destination = directory / artifact.name
        parsed = urlsplit(artifact.url)
        if parsed.scheme != "https" or parsed.hostname not in {
            "github.com",
            "files.pythonhosted.org",
        }:
            msg = f"artifact URL is not an approved HTTPS registry URL: {artifact.name}"
            raise ReleaseStateError(msg)
        request = Request(  # ruff: ignore[suspicious-url-open-usage] -- exact HTTPS hosts allowed above
            artifact.url,
            headers={"User-Agent": "repo-standards-release"},
        )
        with cast(
            "BinaryIO",
            urlopen(request, timeout=60),  # ruff: ignore[suspicious-url-open-usage]
        ) as response:
            content = response.read()
        digest = hashlib.sha256(content).hexdigest()
        if digest != artifact.sha256:
            msg = f"downloaded artifact digest differs: {artifact.name}"
            raise ReleaseStateError(msg)
        destination.write_bytes(content)
        lines.append(f"{digest}  packages/repo-standards/{artifact.name}\n")
    checksum_path = directory.parents[1] / "SHA256SUMS"
    checksum_path.write_text("".join(lines), encoding="utf-8")


@final
class Arguments(argparse.Namespace):
    def __init__(self) -> None:
        super().__init__()
        self.command = ""
        self.directory = Path()
        self.github_output = Path()
        self.head_sha = ""
        self.readme = Path()
        self.repository = ""
        self.source = ""
        self.source_sha = ""
        self.version = ""


def main() -> None:
    arguments = _parser().parse_args(namespace=Arguments())
    try:
        _run(arguments)
    except ReleaseStateError as error:
        sys.stderr.write(f"release reconciliation refused: {error}\n")
        raise SystemExit(2) from error


def _run(arguments: Arguments) -> None:
    if arguments.command == "inspect":
        state = inspect_release(
            version=arguments.version,
            repository=arguments.repository,
            head_sha=arguments.head_sha,
        )
        plan = reconciliation_plan(state)
        _write_outputs(plan, state.version, arguments.github_output)
    elif arguments.command == "prepare-readme":
        source = arguments.readme.read_text(encoding="utf-8")
        arguments.readme.write_text(
            render_release_readme(
                source,
                source_sha=arguments.source_sha,
                version=arguments.version,
            ),
            encoding="utf-8",
        )
    elif arguments.command == "download":
        state = inspect_release(
            version=arguments.version,
            repository=arguments.repository,
            head_sha=arguments.source_sha,
        )
        plan = reconciliation_plan(state)
        if plan.source_sha != arguments.source_sha or plan.artifact_source != arguments.source:
            msg = "release state changed before artifact reconciliation"
            raise ReleaseStateError(msg)
        side = state.github if arguments.source == "github" else state.pypi
        if side is None:
            msg = "requested artifact source is unavailable"
            raise ReleaseStateError(msg)
        download_artifacts(side, arguments.directory)
    elif arguments.command == "verify-documents":
        verify_release_documents(
            arguments.directory,
            source_sha=arguments.source_sha,
            version=arguments.version,
        )


def _write_outputs(plan: ReconciliationPlan, version: str, path: Path) -> None:
    values = {
        "artifact_source": plan.artifact_source,
        "create_tag": str(plan.create_tag).lower(),
        "prepare_artifacts": str(plan.prepare_artifacts).lower(),
        "publish_primary": str(plan.publish_pypi).lower(),
        "release": str(plan.create_github_release).lower(),
        "source_sha": plan.source_sha,
        "version": version,
    }
    with path.open("a", encoding="utf-8") as output:
        for name, value in values.items():
            output.write(f"{name}={value}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--version", required=True)
    inspect.add_argument("--repository", required=True)
    inspect.add_argument("--head-sha", required=True)
    inspect.add_argument("--github-output", type=Path, required=True)
    prepare = commands.add_parser("prepare-readme")
    prepare.add_argument("--readme", type=Path, required=True)
    prepare.add_argument("--version", required=True)
    prepare.add_argument("--source-sha", required=True)
    download = commands.add_parser("download")
    download.add_argument("--source", choices=("github", "pypi"), required=True)
    download.add_argument("--version", required=True)
    download.add_argument("--repository", required=True)
    download.add_argument("--source-sha", required=True)
    download.add_argument("--directory", type=Path, required=True)
    verify = commands.add_parser("verify-documents")
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--source-sha", required=True)
    return parser


if __name__ == "__main__":
    main()
