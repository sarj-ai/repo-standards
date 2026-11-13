from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
from io import BufferedIOBase
import json
import math
import os
from pathlib import Path
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import] -- fixed release commands only
import sys
import tarfile
import time
from typing import TYPE_CHECKING, ClassVar, Literal, NewType, TypedDict, TypeGuard, assert_never
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile


type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None

if TYPE_CHECKING:
    from collections.abc import Callable


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_ACTION_PIN = re.compile(
    r"(?m)^(?P<indent>\s*- uses: sarj-ai/repo-standards@)[^\s]+\s+#\s+v[^\s]+$"
)
_HTTP_NOT_FOUND = 404
_PROCESS_TIMEOUT_SECONDS = 300
SourceCommit = NewType("SourceCommit", str)


class ReleaseStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstalledArtifactTiming:
    label: str
    seconds: float


@dataclass(frozen=True, order=True)
class Artifact:
    name: str
    sha256: str
    url: str


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
class NewRelease:
    kind: ClassVar[Literal["new-release"]] = "new-release"
    source_sha: SourceCommit


@dataclass(frozen=True)
class TaggedReleaseWithoutArtifacts:
    kind: ClassVar[Literal["tagged-without-artifacts"]] = "tagged-without-artifacts"
    source_sha: SourceCommit


@dataclass(frozen=True)
class PublishPyPIFromGitHub:
    kind: ClassVar[Literal["publish-pypi"]] = "publish-pypi"
    source_sha: SourceCommit


@dataclass(frozen=True)
class RestoreGitHubFromPyPI:
    kind: ClassVar[Literal["restore-github"]] = "restore-github"
    source_sha: SourceCommit


@dataclass(frozen=True)
class CompleteRelease:
    kind: ClassVar[Literal["complete"]] = "complete"
    source_sha: SourceCommit


type ReconciliationPlan = (
    NewRelease
    | TaggedReleaseWithoutArtifacts
    | PublishPyPIFromGitHub
    | RestoreGitHubFromPyPI
    | CompleteRelease
)


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
        return NewRelease(SourceCommit(state.head_sha))

    _validate_sha(state.tag_sha, "tag")
    if state.github is not None:
        _validate_side(state, "GitHub", state.github)
    if state.pypi is not None:
        _validate_side(state, "PyPI", state.pypi)
    if state.github is not None and state.pypi is not None:
        if _digest_map(state.github) != _digest_map(state.pypi):
            msg = "PyPI and GitHub release artifact hashes differ"
            raise ReleaseStateError(msg)
        return CompleteRelease(SourceCommit(state.tag_sha))
    if state.github is not None:
        return PublishPyPIFromGitHub(SourceCommit(state.tag_sha))
    if state.pypi is not None:
        return RestoreGitHubFromPyPI(SourceCommit(state.tag_sha))
    return TaggedReleaseWithoutArtifacts(SourceCommit(state.tag_sha))


def render_release_readme(readme: str, *, source_sha: str, version: str) -> str:
    _validate_sha(source_sha, "source")
    _validate_version(version)
    replacement = rf"\g<indent>{source_sha} # v{version}"
    rendered, replacements = _ACTION_PIN.subn(replacement, readme)
    if replacements != 1:
        msg = "README must contain exactly one pinned repo-standards Action"
        raise ReleaseStateError(msg)
    return rendered


def verify_distribution_release_identity(directory: Path, *, source_sha: str, version: str) -> None:
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


def inspect_release(*, version: str, repository: str, head_sha: str) -> ReleaseState:
    _validate_version(version)
    _validate_sha(head_sha, "head")
    # This dependency-free bootstrap runs before the project environment exists.
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    api = f"https://api.github.com/repos/{repository}"
    with ThreadPoolExecutor(max_workers=3) as executor:
        tag_request = executor.submit(_request_json, f"{api}/git/ref/tags/v{version}", token=token)
        release_request = executor.submit(
            _request_json, f"{api}/releases/tags/v{version}", token=token
        )
        pypi_request = executor.submit(
            _request_json, f"https://pypi.org/pypi/repo-standards/{version}/json"
        )
        tag_document = tag_request.result()
        release_document = release_request.result()
        pypi_document = pypi_request.result()
    tag_sha = (
        None
        if tag_document is None
        else _nested_string(tag_document, object_key="object", value_key="sha")
    )
    github = (
        None if release_document is None else parse_github_registry_side(release_document, version)
    )
    pypi = None if pypi_document is None else parse_pypi_registry_side(pypi_document, version)
    return ReleaseState(version, head_sha, tag_sha, github, pypi)


def _json_object(value: object) -> TypeGuard[dict[str, JsonValue]]:
    return _object_container(value) and all(
        isinstance(key, str) and _json_value(item) for key, item in value.items()
    )


def _object_container(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _json_array(value: object) -> TypeGuard[list[JsonValue]]:
    return _array_container(value) and all(_json_value(item) for item in value)


def _array_container(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _json_value(value: object) -> TypeGuard[JsonValue]:
    match value:
        case None | str() | bool() | int():
            return True
        case float():
            return math.isfinite(value)
        case _:
            return _json_array(value) or _json_object(value)


def parse_github_registry_side(document: dict[str, JsonValue], version: str) -> RegistrySide:
    target = document.get("target_commitish")
    if not isinstance(target, str):
        msg = "GitHub release target is missing"
        raise ReleaseStateError(msg)
    assets = document.get("assets")
    if not _json_array(assets):
        msg = "GitHub release assets are missing"
        raise ReleaseStateError(msg)
    package_assets: list[Artifact] = []
    checksum_present = False
    for raw_object in assets:
        if not _json_object(raw_object):
            msg = "GitHub release contains malformed asset metadata"
            raise ReleaseStateError(msg)
        raw = raw_object
        name = raw.get("name")
        if not isinstance(name, str):
            msg = "GitHub release contains malformed asset metadata"
            raise ReleaseStateError(msg)
        checksum_present = checksum_present or name == "SHA256SUMS"
        if name in expected_artifact_names(version):
            package_assets.append(_github_artifact(raw, name))
    if not checksum_present:
        msg = "GitHub release is missing SHA256SUMS"
        raise ReleaseStateError(msg)
    return RegistrySide(tuple(sorted(package_assets)), target)


def _github_artifact(raw: dict[str, JsonValue], name: str) -> Artifact:
    digest = raw.get("digest")
    url = raw.get("browser_download_url")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        msg = "GitHub release asset digest is unavailable"
        raise ReleaseStateError(msg)
    if not isinstance(url, str):
        msg = "GitHub release asset URL is unavailable"
        raise ReleaseStateError(msg)
    return Artifact(name, digest.removeprefix("sha256:"), url)


def parse_pypi_registry_side(document: dict[str, JsonValue], version: str) -> RegistrySide:
    info_object = document.get("info")
    urls = document.get("urls")
    if not _json_object(info_object) or not _json_array(urls):
        msg = "PyPI release metadata is malformed"
        raise ReleaseStateError(msg)
    info = info_object
    description = info.get("description")
    if not isinstance(description, str):
        msg = "PyPI release description is missing"
        raise ReleaseStateError(msg)
    pypi_source = _source_sha_from_readme(description, version)
    package_files: list[Artifact] = []
    for raw_object in urls:
        if not _json_object(raw_object):
            continue
        raw = raw_object
        filename = raw.get("filename")
        if isinstance(filename, str) and filename in expected_artifact_names(version):
            package_files.append(_pypi_artifact(raw, filename))
    return RegistrySide(tuple(sorted(package_files)), pypi_source)


def _pypi_artifact(raw: dict[str, JsonValue], filename: str) -> Artifact:
    digests_object = raw.get("digests")
    url = raw.get("url")
    if not _json_object(digests_object):
        msg = "PyPI artifact digest is unavailable"
        raise ReleaseStateError(msg)
    digests = digests_object
    sha256 = digests.get("sha256")
    if not isinstance(sha256, str):
        msg = "PyPI artifact digest is unavailable"
        raise ReleaseStateError(msg)
    if not isinstance(url, str):
        msg = "PyPI artifact URL is unavailable"
        raise ReleaseStateError(msg)
    return Artifact(filename, sha256, url)


def _request_json(url: str, *, token: str | None = None) -> dict[str, JsonValue] | None:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "repo-standards-release"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    try:
        opened: object = urlopen(  # ruff: ignore[suspicious-url-open-usage] -- fixed registry URL. # pyright: ignore[reportAny] -- binary response validation follows.
            Request(url, headers=headers),  # ruff: ignore[suspicious-url-open-usage] -- fixed GitHub/PyPI metadata URLs only.
            timeout=30,
        )
        with _binary_stream(opened) as stream:
            document: object = json.load(stream)  # pyright: ignore[reportAny] -- recursively validate decoded metadata before any release decision.
    except HTTPError as error:
        if error.code == _HTTP_NOT_FOUND:
            return None
        raise
    if not _json_object(document):
        msg = f"expected a JSON object from {url}"
        raise ReleaseStateError(msg)
    return document


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


def _nested_string(document: dict[str, JsonValue], *, object_key: str, value_key: str) -> str:
    nested_object = document.get(object_key)
    if not _json_object(nested_object):
        msg = "GitHub tag response is malformed"
        raise ReleaseStateError(msg)
    nested = nested_object
    value = nested.get(value_key)
    if not isinstance(value, str):
        msg = "GitHub tag response is malformed"
        raise ReleaseStateError(msg)
    return value


def download_artifacts(side: RegistrySide, directory: Path) -> None:
    # Validate every URL/name before any network request or destination write.
    for artifact in side.artifacts:
        parsed = urlsplit(artifact.url)
        safe_name = Path(artifact.name).name == artifact.name and artifact.name not in {
            "",
            ".",
            "..",
        }
        if (
            not safe_name
            or "\\" in artifact.name
            or parsed.scheme != "https"
            or parsed.hostname not in {"github.com", "files.pythonhosted.org"}
            or (parsed.username, parsed.password) != (None, None)
        ):
            msg = f"artifact URL or filename is not an approved registry artifact: {artifact.name}"
            raise ReleaseStateError(msg)
    with ThreadPoolExecutor(max_workers=2) as executor:
        downloads = list(executor.map(_download_artifact, side.artifacts))
    # All hashes must pass before writing either artifact or its checksum receipt.
    directory.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for artifact, content in zip(side.artifacts, downloads, strict=True):
        (directory / artifact.name).write_bytes(content)
        lines.append(f"{artifact.sha256}  packages/repo-standards/{artifact.name}\n")
    checksum_path = directory.parents[1] / "SHA256SUMS"
    checksum_path.write_text("".join(lines), encoding="utf-8")


def _download_artifact(artifact: Artifact) -> bytes:
    request = Request(  # ruff: ignore[suspicious-url-open-usage] -- caller validates HTTPS registry host
        artifact.url, headers={"User-Agent": "repo-standards-release"}
    )
    opened: object = urlopen(request, timeout=60)  # ruff: ignore[suspicious-url-open-usage] -- prevalidated HTTPS registry URL. # pyright: ignore[reportAny] -- validate the standard-library response class below.
    with _binary_stream(opened) as stream:
        content = stream.read()
    if hashlib.sha256(content).hexdigest() != artifact.sha256:
        msg = f"downloaded artifact digest differs: {artifact.name}"
        raise ReleaseStateError(msg)
    return content


def _binary_stream(value: object) -> BufferedIOBase:
    if not isinstance(value, BufferedIOBase):
        msg = "registry transport returned an unsupported binary response"
        raise ReleaseStateError(msg)
    return value


def verify_installed_distributions(
    directory: Path,
    *,
    version: str,
    smoke_root: Path,
    checksum_path: Path,
    run_command: Callable[[tuple[str, ...]], str] | None = None,
) -> None:
    _validate_version(version)
    if not directory.is_dir():
        msg = f"release directory does not exist: {directory}"
        raise ReleaseStateError(msg)
    if not checksum_path.parent.is_dir():
        msg = f"checksum directory does not exist: {checksum_path.parent}"
        raise ReleaseStateError(msg)
    expected_names = expected_artifact_names(version)
    observed_names = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    }
    if observed_names != expected_names:
        msg = "release directory must contain exactly the expected wheel and source distribution"
        raise ReleaseStateError(msg)

    execute = _run_release_command if run_command is None else run_command
    artifacts = (
        ("wheel", directory / f"repo_standards-{version}-py3-none-any.whl"),
        ("sdist", directory / f"repo_standards-{version}.tar.gz"),
    )
    with ThreadPoolExecutor(max_workers=len(artifacts)) as executor:
        futures = [
            executor.submit(
                _verify_installed_artifact,
                artifact,
                (f"{label}-{python_version}", python_version),
                version,
                smoke_root,
                execute,
            )
            for label, artifact in artifacts
            for python_version in ("3.14", "3.15")
        ]
        timings = [future.result() for future in futures]
    for timing in timings:
        sys.stdout.write(f"{timing.label} clean install and imports: {timing.seconds:.2f}s\n")

    if not checksum_path.exists():
        lines: list[str] = []
        for name in sorted(expected_names):
            artifact = directory / name
            relative = artifact.relative_to(checksum_path.parent)
            lines.append(f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {relative}\n")
        checksum_path.write_text("".join(lines), encoding="utf-8")


def _verify_installed_artifact(
    artifact: Path,
    target: tuple[str, str],
    version: str,
    smoke_root: Path,
    execute: Callable[[tuple[str, ...]], str],
) -> InstalledArtifactTiming:
    started = time.monotonic()
    label, python_version = target
    environment = smoke_root / label
    python = environment / "bin" / "python"
    executable = environment / "bin" / "repo-standards"
    execute(("uv", "venv", "--python", python_version, str(environment)))
    execute(("uv", "pip", "install", "--python", str(python), str(artifact)))
    installed_version = execute((str(executable), "--version")).strip()
    if installed_version != version:
        msg = f"{label} installed version differs: {installed_version!r}"
        raise ReleaseStateError(msg)
    execute(
        (
            str(python),
            "-c",
            (
                "import repo_standards, repo_standards.catalog, "
                "repo_standards.pull_request, repo_standards.repository"
            ),
        )
    )
    return InstalledArtifactTiming(label, time.monotonic() - started)


def _run_release_command(command: tuple[str, ...]) -> str:
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- fixed trusted command tuple
            command,
            capture_output=True,
            check=True,
            text=True,
            timeout=_PROCESS_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        msg = f"release smoke command failed: {command[0]}"
        raise ReleaseStateError(msg) from error
    return completed.stdout


@dataclass(frozen=True)
class InspectRelease:
    kind: ClassVar[Literal["inspect"]] = "inspect"
    version: str
    repository: str
    head_sha: str
    github_output: Path


@dataclass(frozen=True)
class PrepareReadme:
    kind: ClassVar[Literal["prepare-readme"]] = "prepare-readme"
    readme: Path
    source_sha: str
    version: str


@dataclass(frozen=True)
class DownloadRelease:
    kind: ClassVar[Literal["download"]] = "download"
    source: Literal["github", "pypi"]
    version: str
    repository: str
    source_sha: str
    directory: Path


@dataclass(frozen=True)
class VerifyReleaseIdentity:
    kind: ClassVar[Literal["verify-release-identity"]] = "verify-release-identity"
    directory: Path
    version: str
    source_sha: str


@dataclass(frozen=True)
class VerifyInstalledRelease:
    kind: ClassVar[Literal["verify-installed"]] = "verify-installed"
    directory: Path
    version: str
    smoke_root: Path
    checksum: Path


type ReleaseCommand = (
    InspectRelease
    | PrepareReadme
    | DownloadRelease
    | VerifyReleaseIdentity
    | VerifyInstalledRelease
)


class Arguments(argparse.Namespace):
    command: str = ""
    version: str | None = None
    repository: str | None = None
    head_sha: str | None = None
    source_sha: str | None = None
    source: str | None = None
    github_output: Path | None = None
    readme: Path | None = None
    directory: Path | None = None
    smoke_root: Path | None = None
    checksum: Path | None = None


def main() -> None:
    arguments = _parser().parse_args(namespace=Arguments())
    try:
        _run(_command(arguments))
    except ReleaseStateError as error:
        sys.stderr.write(f"release reconciliation refused: {error}\n")
        raise SystemExit(2) from error


def _command(arguments: Arguments) -> ReleaseCommand:
    match arguments.command:
        case "inspect":
            return InspectRelease(
                _text_argument(arguments.version, "version"),
                _text_argument(arguments.repository, "repository"),
                _text_argument(arguments.head_sha, "head_sha"),
                _path_argument(arguments.github_output, "github_output"),
            )
        case "prepare-readme":
            return PrepareReadme(
                _path_argument(arguments.readme, "readme"),
                _text_argument(arguments.source_sha, "source_sha"),
                _text_argument(arguments.version, "version"),
            )
        case "download":
            source = _text_argument(arguments.source, "source")
            if source not in {"github", "pypi"}:
                msg = "invalid release artifact source"
                raise ReleaseStateError(msg)
            if source == "github":
                return DownloadRelease(
                    "github",
                    _text_argument(arguments.version, "version"),
                    _text_argument(arguments.repository, "repository"),
                    _text_argument(arguments.source_sha, "source_sha"),
                    _path_argument(arguments.directory, "directory"),
                )
            return DownloadRelease(
                "pypi",
                _text_argument(arguments.version, "version"),
                _text_argument(arguments.repository, "repository"),
                _text_argument(arguments.source_sha, "source_sha"),
                _path_argument(arguments.directory, "directory"),
            )
        case "verify-release-identity":
            return VerifyReleaseIdentity(
                _path_argument(arguments.directory, "directory"),
                _text_argument(arguments.version, "version"),
                _text_argument(arguments.source_sha, "source_sha"),
            )
        case "verify-installed":
            return VerifyInstalledRelease(
                _path_argument(arguments.directory, "directory"),
                _text_argument(arguments.version, "version"),
                _path_argument(arguments.smoke_root, "smoke_root"),
                _path_argument(arguments.checksum, "checksum"),
            )
        case _:
            msg = "unknown release command"
            raise ReleaseStateError(msg)


def _text_argument(value: str | None, name: str) -> str:
    if not isinstance(value, str):
        msg = f"missing release argument: {name}"
        raise ReleaseStateError(msg)
    return value


def _path_argument(value: Path | None, name: str) -> Path:
    if not isinstance(value, Path):
        msg = f"missing release path: {name}"
        raise ReleaseStateError(msg)
    return value


def _run(arguments: ReleaseCommand) -> None:
    match arguments:
        case InspectRelease():
            state = inspect_release(
                version=arguments.version,
                repository=arguments.repository,
                head_sha=arguments.head_sha,
            )
            plan = reconciliation_plan(state)
            _write_outputs(plan, state.version, arguments.github_output)
        case PrepareReadme():
            source = arguments.readme.read_text(encoding="utf-8")
            arguments.readme.write_text(
                render_release_readme(
                    source, source_sha=arguments.source_sha, version=arguments.version
                ),
                encoding="utf-8",
            )
        case DownloadRelease():
            state = inspect_release(
                version=arguments.version,
                repository=arguments.repository,
                head_sha=arguments.source_sha,
            )
            plan = reconciliation_plan(state)
            match plan:
                case PublishPyPIFromGitHub():
                    expected_source = "github"
                case RestoreGitHubFromPyPI():
                    expected_source = "pypi"
                case NewRelease() | TaggedReleaseWithoutArtifacts() | CompleteRelease():
                    msg = "release state changed before artifact reconciliation"
                    raise ReleaseStateError(msg)
                case _:
                    assert_never(plan)
            if plan.source_sha != arguments.source_sha or expected_source != arguments.source:
                msg = "release state changed before artifact reconciliation"
                raise ReleaseStateError(msg)
            side = state.github if arguments.source == "github" else state.pypi
            if side is None:
                msg = "requested artifact source is unavailable"
                raise ReleaseStateError(msg)
            download_artifacts(side, arguments.directory)
        case VerifyReleaseIdentity():
            verify_distribution_release_identity(
                arguments.directory, source_sha=arguments.source_sha, version=arguments.version
            )
        case VerifyInstalledRelease():
            verify_installed_distributions(
                arguments.directory,
                version=arguments.version,
                smoke_root=arguments.smoke_root,
                checksum_path=arguments.checksum,
            )
        case _:
            assert_never(arguments)


class PlanOutputs(TypedDict):
    artifact_source: str
    create_tag: str
    prepare_artifacts: str
    publish_primary: str
    release: str
    source_sha: str
    version: str


def plan_outputs(plan: ReconciliationPlan, version: str) -> PlanOutputs:
    # These strings are the existing GitHub Actions protocol, derived once from
    # the closed plan. They are never accepted back as a release decision.
    match plan:
        case NewRelease():
            source, tag, prepare, publish, release = "build", True, True, True, True
        case TaggedReleaseWithoutArtifacts():
            source, tag, prepare, publish, release = "build", False, True, True, True
        case PublishPyPIFromGitHub():
            source, tag, prepare, publish, release = "github", False, True, True, False
        case RestoreGitHubFromPyPI():
            source, tag, prepare, publish, release = "pypi", False, True, False, True
        case CompleteRelease():
            source, tag, prepare, publish, release = "none", False, False, False, False
        case _:
            assert_never(plan)
    return {
        "artifact_source": source,
        "create_tag": str(tag).lower(),
        "prepare_artifacts": str(prepare).lower(),
        "publish_primary": str(publish).lower(),
        "release": str(release).lower(),
        "source_sha": plan.source_sha,
        "version": version,
    }


def _write_outputs(plan: ReconciliationPlan, version: str, path: Path) -> None:
    with path.open("a", encoding="utf-8") as output:
        for name, value in plan_outputs(plan, version).items():
            output.write(f"{name}={value}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(  # sarj-noqa: SARJ533 -- pre-install CLI; typed decode.
    )
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
    verify = commands.add_parser("verify-release-identity")
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--source-sha", required=True)
    installed = commands.add_parser("verify-installed")
    installed.add_argument("--directory", type=Path, required=True)
    installed.add_argument("--version", required=True)
    installed.add_argument("--smoke-root", type=Path, required=True)
    installed.add_argument("--checksum", type=Path, required=True)
    return parser


if __name__ == "__main__":
    main()
