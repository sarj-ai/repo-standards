from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from io import BytesIO
import os
from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed Git metadata query only
import tempfile
import threading
import tomllib
from types import MappingProxyType
from typing import ClassVar, NamedTuple

from pydantic import BaseModel, ConfigDict

from .canonical import canonical_path
from .errors import ConfigurationError
from .models import (
    GitObjectId,
    InputProvenance,
    InventoryKind,
    InventoryUnit,
    PackageEvidence,
    RepositoryInspection,
    RepositorySnapshot,
    TrackedFileEvidence,
    WorkspaceEvidence,
)
from .parser import parse_baseline_bytes, parse_manifest_bytes


_MAX_FILES = 100_000
_MAX_TREE_OUTPUT_BYTES = 33_554_432
_MAX_PATH_BYTES = 4_096
_MAX_TOTAL_PATH_BYTES = 16_777_216
_MAX_METADATA_BYTES = 1_048_576
_MAX_METADATA_FILES = 1_000
_MAX_TOTAL_METADATA_BYTES = 67_108_864
_MAX_SELECTED_BLOB_BYTES = 5_242_880
_MAX_TOTAL_SELECTED_BLOB_BYTES = 20_971_520
_MAX_SELECTED_BLOBS = 100
_GIT_TREE_FIELD_COUNT = 3
_GIT_ENVIRONMENT = MappingProxyType(
    {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
)


ProjectCoordinate = PackageEvidence


@dataclass(frozen=True, slots=True)
class GitIdentity:
    source_revision: str
    tree_digest: str


@dataclass(frozen=True, slots=True)
class TrackedBlob:
    path: str
    object_id: str


@dataclass(frozen=True, slots=True)
class TrackedBlobContent:
    path: str
    object_id: str
    content: bytes


class _TreeRecord(NamedTuple):
    blob: TrackedBlob
    encoded_path_size: int


class _MetadataBatch(NamedTuple):
    contents: dict[str, bytes]
    issues: list[str]


class _NpmWorkspaces(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", strict=True)

    packages: list[object] | None = None


class _NpmPackage(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", strict=True)

    name: str | None = None
    private: bool | None = None
    workspaces: list[object] | _NpmWorkspaces | None = None


def read_tracked_blob_contents(
    root: Path,
    paths: tuple[str, ...],
    *,
    identity: GitIdentity | None = None,
) -> tuple[TrackedBlobContent, ...]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    if identity is None:
        identity = git_identity(resolved)
    if len(paths) > _MAX_SELECTED_BLOBS:
        ConfigurationError.fail("selected blob count exceeds the 100-file safety limit")
    canonical = tuple(canonical_path(path) for path in paths)
    if canonical != paths or len(canonical) != len(set(canonical)):
        ConfigurationError.fail("selected blob paths must be unique and canonical")
    by_path = {blob.path: blob for blob in _tracked_files(resolved, identity.tree_digest)}
    try:
        selected = tuple(by_path[path] for path in canonical)
    except KeyError:
        ConfigurationError.fail("a selected path is absent from the exact Git tree")
    contents = _read_bounded_blob_batch(
        resolved,
        selected,
        max_file_bytes=_MAX_SELECTED_BLOB_BYTES,
        max_total_bytes=_MAX_TOTAL_SELECTED_BLOB_BYTES,
    )
    return tuple(
        TrackedBlobContent(blob.path, blob.object_id, _required_content(contents, blob))
        for blob in selected
    )


def inspect_repository(root: Path, *, identity: GitIdentity | None = None) -> RepositoryInspection:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    if identity is None:
        identity = git_identity(resolved)
    blobs = _tracked_files(resolved, identity.tree_digest)
    return _inspection_from_blobs(resolved, identity, blobs)


def load_repository_snapshot(
    root: Path,
    *,
    manifest_path: str = ".repo-standards/repository.toml",
    baseline_path: str | None = None,
    identity: GitIdentity | None = None,
) -> RepositorySnapshot:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    if identity is None:
        identity = git_identity(resolved)
    blobs = _tracked_files(resolved, identity.tree_digest)
    by_path = {blob.path: blob for blob in blobs}
    canonical_manifest = canonical_path(manifest_path)
    manifest_blob = by_path.get(canonical_manifest)
    if manifest_blob is None:
        ConfigurationError.fail("manifest is absent from the selected Git tree")
    selected = [manifest_blob]
    canonical_baseline: str | None = None
    baseline_blob: TrackedBlob | None = None
    if baseline_path is not None:
        canonical_baseline = canonical_path(baseline_path)
        baseline_blob = by_path.get(canonical_baseline)
        if baseline_blob is None:
            ConfigurationError.fail("baseline is absent from the selected Git tree")
        selected.append(baseline_blob)
    contents, issues = _read_metadata_batch(resolved, tuple(selected))
    if issues:
        ConfigurationError.fail("selected policy input exceeds the per-file safety limit")
    manifest_content = _required_content(contents, manifest_blob)
    baseline_content = (
        _required_content(contents, baseline_blob) if baseline_blob is not None else None
    )
    inspection = _inspection_from_blobs(resolved, identity, blobs)
    if inspection.completion != "complete":
        ConfigurationError.fail("repository inspection is incomplete")
    return RepositorySnapshot(
        manifest=parse_manifest_bytes(manifest_content),
        baseline=(parse_baseline_bytes(baseline_content) if baseline_content is not None else None),
        inspection=inspection,
        provenance=InputProvenance(
            mode="git-tree",
            source_revision=identity.source_revision,
            tree_digest=identity.tree_digest,
            manifest_path=canonical_manifest,
            manifest_object_id=GitObjectId(manifest_blob.object_id),
            manifest_digest=_content_digest(manifest_content),
            baseline_path=canonical_baseline,
            baseline_object_id=(
                GitObjectId(baseline_blob.object_id) if baseline_blob is not None else None
            ),
            baseline_digest=(
                _content_digest(baseline_content) if baseline_content is not None else None
            ),
        ),
    )


def _inspection_from_blobs(
    root: Path, identity: GitIdentity, blobs: tuple[TrackedBlob, ...]
) -> RepositoryInspection:
    tracked = tuple(blob.path for blob in blobs)
    issues: list[str] = []
    metadata_blobs = tuple(
        blob for blob in blobs if Path(blob.path).name in {"package.json", "pyproject.toml"}
    )
    if len(metadata_blobs) > _MAX_METADATA_FILES:
        ConfigurationError.fail(
            f"repository exceeds the {_MAX_METADATA_FILES} metadata-file safety limit"
        )
    contents, read_issues = _read_metadata_batch(root, metadata_blobs)
    issues.extend(read_issues)
    packages: list[PackageEvidence] = []
    workspaces: list[WorkspaceEvidence] = []
    for blob in metadata_blobs:
        content = contents.get(blob.object_id)
        project = _inspect_project(blob, content, issues)
        if project is not None:
            packages.append(project)
        workspace = _inspect_workspace(blob, content, issues)
        if workspace is not None:
            workspaces.append(workspace)
    terraform_modules = _terraform_module_units(blobs)
    workflow_blobs = tuple(
        blob
        for blob in blobs
        if blob.path.startswith(".github/workflows/") and blob.path.endswith((".yaml", ".yml"))
    )
    cloudbuild_blobs = tuple(
        blob
        for blob in blobs
        if Path(blob.path).name.casefold().startswith("cloudbuild")
        and blob.path.endswith((".yaml", ".yml"))
    )
    dockerfile_blobs = tuple(
        blob for blob in blobs if Path(blob.path).name.casefold().startswith("dockerfile")
    )
    inventory_units = [
        InventoryUnit(
            kind=InventoryKind.PACKAGE,
            path=project.path,
            object_id=project.object_id,
            content_digest=project.content_digest,
        )
        for project in packages
    ]
    inventory_units.extend(
        InventoryUnit(
            kind=InventoryKind.WORKSPACE,
            path=workspace.path,
            object_id=workspace.object_id,
            content_digest=workspace.content_digest,
        )
        for workspace in workspaces
    )
    inventory_units.extend(
        _blob_inventory_unit(kind, blob)
        for kind, selected in (
            (InventoryKind.GITHUB_WORKFLOW, workflow_blobs),
            (InventoryKind.CLOUD_BUILD, cloudbuild_blobs),
            (InventoryKind.DOCKERFILE, dockerfile_blobs),
        )
        for blob in selected
    )
    inventory_units.extend(terraform_modules)
    return RepositoryInspection(
        completion="incomplete" if issues else "complete",
        source_revision=identity.source_revision,
        tree_digest=identity.tree_digest,
        tracked_file_count=len(tracked),
        packages=tuple(sorted(packages, key=lambda item: (item.path, item.ecosystem))),
        workflow_paths=tuple(blob.path for blob in workflow_blobs),
        cloudbuild_paths=tuple(blob.path for blob in cloudbuild_blobs),
        dockerfile_paths=tuple(blob.path for blob in dockerfile_blobs),
        terraform_modules=tuple(item.path for item in terraform_modules),
        issues=tuple(sorted(issues)),
        tracked_files=tuple(TrackedFileEvidence(blob.path, blob.object_id) for blob in blobs),
        workspaces=tuple(sorted(workspaces, key=lambda item: (item.path, item.ecosystem))),
        inventory_units=tuple(sorted(inventory_units, key=lambda item: (item.path, item.kind))),
    )


def git_identity(root: Path) -> GitIdentity:
    git_executable = shutil.which("git")
    if git_executable is None:
        ConfigurationError.fail("Git executable is unavailable")
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed Git identity query
            [
                git_executable,
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "-C",
                str(root),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            check=True,
            capture_output=True,
            timeout=30,
            text=True,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot resolve the inspected Git revision")
    commit = result.stdout.strip()
    try:
        tree_result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - immutable Git identity query
            [
                git_executable,
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "-C",
                str(root),
                "rev-parse",
                "--verify",
                f"{commit}^{{tree}}",
            ],
            check=True,
            capture_output=True,
            timeout=30,
            text=True,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot resolve the inspected Git tree")
    return GitIdentity(source_revision=commit, tree_digest=tree_result.stdout.strip())


def _tracked_files(root: Path, tree_digest: str) -> tuple[TrackedBlob, ...]:
    git_executable = shutil.which("git")
    if git_executable is None:
        ConfigurationError.fail("Git executable is unavailable")
    payload = _git_tree_payload(root, git_executable, tree_digest)
    try:
        records = tuple(item for item in payload.decode("utf-8").split("\0") if item)
    except UnicodeDecodeError:
        ConfigurationError.fail("tracked paths must be UTF-8")
    if len(records) > _MAX_FILES:
        ConfigurationError.fail("repository exceeds the 100000 tracked-file safety limit")
    blobs: list[TrackedBlob] = []
    path_bytes = 0
    for record in records:
        blob, encoded_path_size = _parse_tree_record(record)
        path_bytes += encoded_path_size
        if path_bytes > _MAX_TOTAL_PATH_BYTES:
            ConfigurationError.fail("tracked paths exceed the 16 MiB aggregate safety limit")
        blobs.append(blob)
    canonical = tuple(canonical_path(blob.path) for blob in blobs)
    if canonical != tuple(blob.path for blob in blobs):
        ConfigurationError.fail("tracked paths must already be canonical")
    if len(canonical) != len(set(canonical)) or len(canonical) != len(
        {p.casefold() for p in canonical}
    ):
        ConfigurationError.fail("tracked paths collide after normalization")
    by_path = {blob.path: blob for blob in blobs}
    return tuple(by_path[path] for path in sorted(canonical))


def _parse_tree_record(record: str) -> _TreeRecord:
    metadata, separator, path = record.partition("\t")
    fields = metadata.split()
    if separator != "\t" or len(fields) != _GIT_TREE_FIELD_COUNT:
        ConfigurationError.fail("Git tree output is malformed")
    mode, object_type, object_id = fields
    if mode == "120000":
        ConfigurationError.fail(f"tracked path is a symlink: {path}")
    if object_type != "blob":
        ConfigurationError.fail(f"tracked path is not a regular file: {path}")
    encoded_path_size = len(path.encode("utf-8"))
    if encoded_path_size > _MAX_PATH_BYTES:
        ConfigurationError.fail("tracked path exceeds the 4096-byte safety limit")
    return _TreeRecord(TrackedBlob(path=path, object_id=object_id), encoded_path_size)


def _git_tree_payload(root: Path, git_executable: str, tree_digest: str) -> bytes:
    command = [
        git_executable,
        "--no-replace-objects",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "-C",
        str(root),
        "ls-tree",
        "-rz",
        "--full-tree",
        tree_digest,
    ]
    try:
        process: subprocess.Popen[bytes] = subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed trusted Git executable and arguments
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_GIT_ENVIRONMENT,
        )
    except OSError:
        ConfigurationError.fail("cannot enumerate tracked files with Git")
    stream = process.stdout
    if stream is None:
        process.kill()
        ConfigurationError.fail("cannot read tracked-file enumeration output")
    output = bytearray()
    read_failed = threading.Event()

    def read_bounded_output() -> None:
        descriptor = stream.fileno()
        try:
            while chunk := os.read(descriptor, 65_536):
                remaining = _MAX_TREE_OUTPUT_BYTES + 1 - len(output)
                output.extend(chunk[:remaining])
                if len(output) > _MAX_TREE_OUTPUT_BYTES:
                    process.kill()
                    return
        except OSError:
            read_failed.set()
            process.kill()

    reader = threading.Thread(target=read_bounded_output, daemon=True)
    reader.start()
    reader.join(timeout=30)
    if reader.is_alive():
        process.kill()
        reader.join(timeout=1)
        ConfigurationError.fail("Git tree enumeration timed out")
    try:
        return_code = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        ConfigurationError.fail("Git tree enumeration timed out")
    if len(output) > _MAX_TREE_OUTPUT_BYTES:
        ConfigurationError.fail("Git tree output exceeds the 32 MiB safety limit")
    if read_failed.is_set() or return_code != 0:
        ConfigurationError.fail("cannot enumerate tracked files with Git")
    return bytes(output)


def _inspect_project(
    blob: TrackedBlob, content: bytes | None, issues: list[str]
) -> ProjectCoordinate | None:
    relative = blob.path
    if content is None:
        return None
    try:
        return replace(
            parse_project_metadata(relative, content),
            object_id=blob.object_id,
            content_digest=_content_digest(content),
        )
    except ConfigurationError:
        issues.append(f"metadata is malformed: {relative}")
        return None


def _inspect_workspace(
    blob: TrackedBlob, content: bytes | None, issues: list[str]
) -> WorkspaceEvidence | None:
    if content is None:
        return None
    try:
        workspace = parse_workspace_metadata(blob.path, content)
    except ConfigurationError:
        if f"metadata is malformed: {blob.path}" not in issues:
            issues.append(f"metadata is malformed: {blob.path}")
        return None
    if workspace is None:
        return None
    return replace(
        workspace,
        object_id=blob.object_id,
        content_digest=_content_digest(content),
    )


def parse_project_metadata(relative: str, content: bytes) -> ProjectCoordinate:
    try:
        if relative.endswith("package.json"):
            return _npm_project(relative, content)
        if relative.endswith("pyproject.toml"):
            return _python_project(relative, content)
    except (
        ConfigurationError,
        RecursionError,
        UnicodeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ):
        ConfigurationError.fail(f"metadata is malformed: {relative}")
    return ConfigurationError.fail(f"unsupported project metadata: {relative}")


def parse_workspace_metadata(relative: str, content: bytes) -> WorkspaceEvidence | None:
    try:
        if relative.endswith("package.json"):
            return _npm_workspace(relative, content)
        if relative.endswith("pyproject.toml"):
            return _python_workspace(relative, content)
    except (
        ConfigurationError,
        RecursionError,
        UnicodeError,
        ValueError,
        tomllib.TOMLDecodeError,
    ):
        ConfigurationError.fail(f"metadata is malformed: {relative}")
    return ConfigurationError.fail(f"unsupported project metadata: {relative}")


def _required_content(contents: dict[str, bytes], blob: TrackedBlob) -> bytes:
    content = contents.get(blob.object_id)
    if content is None:
        ConfigurationError.fail("selected Git blob could not be read")
    return content


def _content_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _blob_inventory_unit(kind: InventoryKind, blob: TrackedBlob) -> InventoryUnit:
    return InventoryUnit(
        kind=kind,
        path=blob.path,
        object_id=blob.object_id,
        content_digest=None,
    )


def _terraform_module_units(blobs: tuple[TrackedBlob, ...]) -> tuple[InventoryUnit, ...]:
    by_directory: dict[str, list[str]] = {}
    for blob in blobs:
        if not blob.path.endswith((".tf", ".tf.json")):
            continue
        parent = Path(blob.path).parent
        directory = "." if parent == Path() else parent.as_posix()
        by_directory.setdefault(directory, []).append(blob.object_id)
    return tuple(
        InventoryUnit(
            kind=InventoryKind.TERRAFORM_MODULE,
            path=directory,
            object_id=None,
            content_digest=_content_digest("\n".join(sorted(object_ids)).encode("ascii")),
        )
        for directory, object_ids in sorted(by_directory.items())
    )


def _read_metadata_batch(root: Path, blobs: tuple[TrackedBlob, ...]) -> _MetadataBatch:
    if not blobs:
        return _MetadataBatch({}, [])
    git_executable = shutil.which("git")
    if git_executable is None:
        ConfigurationError.fail("Git executable is unavailable")
    unique = {blob.object_id: blob for blob in blobs}
    ordered = tuple(unique[object_id] for object_id in sorted(unique))
    object_input = b"".join(f"{blob.object_id}\n".encode() for blob in ordered)
    try:
        size_result = _run_git_batch(
            root,
            git_executable,
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            object_input,
        )
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot query tracked metadata sizes")
    sizes = _parse_batch_sizes(size_result.stdout, ordered)
    eligible: list[TrackedBlob] = []
    issues: list[str] = []
    total = 0
    for blob in ordered:
        size = sizes[blob.object_id]
        if size > _MAX_METADATA_BYTES:
            affected = sorted(item.path for item in blobs if item.object_id == blob.object_id)
            issues.extend(f"metadata exceeds 1 MiB: {path}" for path in affected)
            continue
        total += size
        eligible.append(blob)
    if total > _MAX_TOTAL_METADATA_BYTES:
        ConfigurationError.fail("repository metadata exceeds the 64 MiB aggregate safety limit")
    if not eligible:
        return _MetadataBatch({}, issues)
    eligible_input = b"".join(f"{blob.object_id}\n".encode() for blob in eligible)
    try:
        blob_result = _run_git_batch(root, git_executable, "--batch", eligible_input)
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot read tracked metadata batch")
    return _MetadataBatch(_parse_batch_contents(blob_result.stdout, eligible, sizes), issues)


def _read_bounded_blob_batch(
    root: Path,
    blobs: tuple[TrackedBlob, ...],
    *,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, bytes]:
    if not blobs:
        return {}
    git_executable = shutil.which("git")
    if git_executable is None:
        ConfigurationError.fail("Git executable is unavailable")
    unique = {blob.object_id: blob for blob in blobs}
    ordered = tuple(unique[object_id] for object_id in sorted(unique))
    object_input = b"".join(f"{blob.object_id}\n".encode() for blob in ordered)
    try:
        size_result = _run_git_batch(
            root,
            git_executable,
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            object_input,
        )
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot query selected Git blob sizes")
    sizes = _parse_batch_sizes(size_result.stdout, ordered)
    if any(size > max_file_bytes for size in sizes.values()):
        ConfigurationError.fail("a selected Git blob exceeds the per-file safety limit")
    if sum(sizes.values()) > max_total_bytes:
        ConfigurationError.fail("selected Git blobs exceed the aggregate safety limit")
    try:
        blob_result = _run_git_batch(root, git_executable, "--batch", object_input)
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot read selected Git blobs")
    return _parse_batch_contents(blob_result.stdout, list(ordered), sizes)


def _run_git_batch(
    root: Path, git_executable: str, mode: str, object_input: bytes
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryFile() as batch_input:
        batch_input.write(object_input)
        batch_input.seek(0)
        return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed trusted Git executable and bounded immutable input
            [
                git_executable,
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "-C",
                str(root),
                "cat-file",
                mode,
            ],
            check=True,
            capture_output=True,
            stdin=batch_input,
            timeout=30,
            env=_GIT_ENVIRONMENT,
        )


def _parse_batch_sizes(payload: bytes, blobs: tuple[TrackedBlob, ...]) -> dict[str, int]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError:
        ConfigurationError.fail("Git metadata-size output is malformed")
    if len(lines) != len(blobs):
        ConfigurationError.fail("Git metadata-size output is incomplete")
    sizes: dict[str, int] = {}
    for line, blob in zip(lines, blobs, strict=True):
        fields = line.split()
        if (
            len(fields) != _GIT_TREE_FIELD_COUNT
            or fields[0] != blob.object_id
            or fields[1] != "blob"
        ):
            ConfigurationError.fail("Git metadata-size output is malformed")
        try:
            sizes[blob.object_id] = int(fields[2])
        except ValueError:
            ConfigurationError.fail("Git metadata size is malformed")
    return sizes


def _parse_batch_contents(
    payload: bytes, blobs: list[TrackedBlob], sizes: dict[str, int]
) -> dict[str, bytes]:
    stream = BytesIO(payload)
    contents: dict[str, bytes] = {}
    for blob in blobs:
        header = stream.readline(256)
        try:
            fields = header.decode("ascii").split()
        except UnicodeDecodeError:
            ConfigurationError.fail("Git metadata header is malformed")
        expected_size = sizes[blob.object_id]
        if (
            len(fields) != _GIT_TREE_FIELD_COUNT
            or fields[0] != blob.object_id
            or fields[1] != "blob"
            or fields[2] != str(expected_size)
        ):
            ConfigurationError.fail("Git metadata header is malformed")
        content = stream.read(expected_size)
        if len(content) != expected_size or stream.read(1) != b"\n":
            ConfigurationError.fail("Git metadata batch is truncated")
        contents[blob.object_id] = content
    if stream.read(1):
        ConfigurationError.fail("Git metadata batch has unexpected trailing bytes")
    return contents


def _npm_project(relative: str, content: bytes) -> ProjectCoordinate:
    package = _NpmPackage.model_validate_json(content)
    return ProjectCoordinate(
        ecosystem="npm",
        path=relative,
        name=package.name,
        private=package.private,
        workspace_root=package.workspaces is not None,
    )


def _npm_workspace(relative: str, content: bytes) -> WorkspaceEvidence | None:
    workspaces = _NpmPackage.model_validate_json(content).workspaces
    if workspaces is None:
        return None
    match workspaces:
        case list():
            patterns = _workspace_patterns(
                workspaces,
                f"package workspaces: {relative}",
            )
        case _NpmWorkspaces():
            patterns = _workspace_patterns(
                workspaces.packages, f"package workspaces.packages: {relative}"
            )
    return WorkspaceEvidence(
        ecosystem="npm",
        path=relative,
        member_patterns=patterns,
        exclude_patterns=(),
    )


def _python_project(relative: str, content: bytes) -> ProjectCoordinate:
    raw = _erase_parser_type(tomllib.loads(content.decode("utf-8")))
    if not isinstance(raw, dict):
        ConfigurationError.fail(f"Python metadata must be a table: {relative}")
    project = raw.get("project")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    tool = raw.get("tool")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    name: str | None = None
    if isinstance(project, dict):
        observed = project.get("name")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
        name = observed if isinstance(observed, str) else None
    workspace_root = False
    if isinstance(tool, dict):
        uv = tool.get("uv")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
        workspace_root = isinstance(uv, dict) and "workspace" in uv
    return ProjectCoordinate(
        ecosystem="python",
        path=relative,
        name=name,
        private=None,
        workspace_root=workspace_root,
    )


def _python_workspace(relative: str, content: bytes) -> WorkspaceEvidence | None:
    raw = _erase_parser_type(tomllib.loads(content.decode("utf-8")))
    if not isinstance(raw, dict):
        ConfigurationError.fail(f"Python metadata must be a table: {relative}")
    tool = raw.get("tool")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    if not isinstance(tool, dict):
        return None
    uv = tool.get("uv")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    if not isinstance(uv, dict):
        return None
    workspace = uv.get(  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
        "workspace"
    )
    if workspace is None:
        return None
    if not isinstance(workspace, dict):
        ConfigurationError.fail(f"tool.uv.workspace must be a table: {relative}")
    members = _erase_parser_type(
        workspace.get(  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            "members"
        )
    )
    excludes = _erase_parser_type(
        workspace.get(  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            "exclude", []
        )
    )
    return WorkspaceEvidence(
        ecosystem="python",
        path=relative,
        member_patterns=_workspace_patterns(members, f"tool.uv.workspace.members: {relative}"),
        exclude_patterns=_workspace_patterns(excludes, f"tool.uv.workspace.exclude: {relative}"),
    )


def _workspace_patterns(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        ConfigurationError.fail(f"{context} must be an array")
    patterns: list[str] = []
    for item in value:  # pyright: ignore[reportUnknownVariableType]
        if not isinstance(item, str) or not item:
            ConfigurationError.fail(f"{context} entries must be non-empty strings")
        if "\\" in item or item.startswith("/") or "\x00" in item or ".." in Path(item).parts:
            ConfigurationError.fail(f"{context} contains an unsafe pattern")
        patterns.append(item)
    return tuple(patterns)


def _erase_parser_type(value: object) -> object:
    return value
