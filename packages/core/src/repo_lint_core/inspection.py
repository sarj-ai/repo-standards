"""Read-only discovery of repository layout facts from tracked files."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import json
from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed Git metadata query only
import tempfile
import tomllib
from types import MappingProxyType

from .canonical import canonical_path
from .errors import ConfigurationError


_MAX_FILES = 100_000
_MAX_METADATA_BYTES = 1_048_576
_MAX_METADATA_FILES = 1_000
_MAX_TOTAL_METADATA_BYTES = 104_857_600
_GIT_TREE_FIELD_COUNT = 3
_GIT_ENVIRONMENT = MappingProxyType(
    {"GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1", "LC_ALL": "C"}
)


@dataclass(frozen=True, slots=True)
class ProjectCoordinate:
    """One inert package coordinate observed in tracked metadata."""

    ecosystem: str
    path: str
    name: str | None
    private: bool | None
    workspace_root: bool


@dataclass(frozen=True, slots=True)
class GitIdentity:
    """Exact Git commit and tree selected for inspection."""

    source_revision: str
    tree_digest: str


@dataclass(frozen=True, slots=True)
class TrackedBlob:
    """One immutable regular-file object selected from the inspected tree."""

    path: str
    object_id: str


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
    """Deterministic bootstrap facts that require no repository manifest."""

    completion: str
    source_revision: str
    tree_digest: str
    tracked_file_count: int
    projects: tuple[ProjectCoordinate, ...]
    workflow_paths: tuple[str, ...]
    cloudbuild_paths: tuple[str, ...]
    dockerfile_paths: tuple[str, ...]
    terraform_roots: tuple[str, ...]
    issues: tuple[str, ...]


def inspect_repository(root: Path, *, identity: GitIdentity | None = None) -> RepositoryInspection:
    """Inspect tracked inert metadata without importing or executing target code."""
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    if identity is None:
        identity = git_identity(resolved)
    blobs = _tracked_files(resolved, identity.tree_digest)
    tracked = tuple(blob.path for blob in blobs)
    issues: list[str] = []
    metadata_blobs = tuple(
        blob for blob in blobs if Path(blob.path).name in {"package.json", "pyproject.toml"}
    )
    if len(metadata_blobs) > _MAX_METADATA_FILES:
        ConfigurationError.fail(
            f"repository exceeds the {_MAX_METADATA_FILES} metadata-file safety limit"
        )
    contents, read_issues = _read_metadata_batch(resolved, metadata_blobs)
    issues.extend(read_issues)
    projects = tuple(
        project
        for blob in metadata_blobs
        if (project := _inspect_project(blob, contents.get(blob.object_id), issues)) is not None
    )
    terraform_roots = sorted(
        {
            "." if Path(path).parent == Path() else Path(path).parent.as_posix()
            for path in tracked
            if path.endswith((".tf", ".tf.json"))
        }
    )
    return RepositoryInspection(
        completion="incomplete" if issues else "complete",
        source_revision=identity.source_revision,
        tree_digest=identity.tree_digest,
        tracked_file_count=len(tracked),
        projects=tuple(sorted(projects, key=lambda item: (item.path, item.ecosystem))),
        workflow_paths=tuple(
            path
            for path in tracked
            if path.startswith(".github/workflows/") and path.endswith((".yaml", ".yml"))
        ),
        cloudbuild_paths=tuple(
            path
            for path in tracked
            if Path(path).name.casefold().startswith("cloudbuild")
            and path.endswith((".yaml", ".yml"))
        ),
        dockerfile_paths=tuple(
            path for path in tracked if Path(path).name.casefold().startswith("dockerfile")
        ),
        terraform_roots=tuple(terraform_roots),
        issues=tuple(sorted(issues)),
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
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed trusted Git executable and arguments
            [
                git_executable,
                "--no-replace-objects",
                "-C",
                str(root),
                "ls-tree",
                "-rz",
                "--full-tree",
                tree_digest,
            ],
            check=True,
            capture_output=True,
            timeout=30,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot enumerate tracked files with Git")
    try:
        records = tuple(item for item in result.stdout.decode("utf-8").split("\0") if item)
    except UnicodeDecodeError:
        ConfigurationError.fail("tracked paths must be UTF-8")
    if len(records) > _MAX_FILES:
        ConfigurationError.fail("repository exceeds the 100000 tracked-file safety limit")
    blobs: list[TrackedBlob] = []
    for record in records:
        metadata, separator, path = record.partition("\t")
        fields = metadata.split()
        if separator != "\t" or len(fields) != _GIT_TREE_FIELD_COUNT:
            ConfigurationError.fail("Git tree output is malformed")
        mode, object_type, object_id = fields
        if mode == "120000":
            ConfigurationError.fail(f"tracked path is a symlink: {path}")
        if object_type != "blob":
            ConfigurationError.fail(f"tracked path is not a regular file: {path}")
        blobs.append(TrackedBlob(path=path, object_id=object_id))
    paths = [blob.path for blob in blobs]
    canonical = tuple(canonical_path(path) for path in paths)
    if len(canonical) != len(set(canonical)) or len(canonical) != len(
        {p.casefold() for p in canonical}
    ):
        ConfigurationError.fail("tracked paths collide after normalization")
    by_path = {blob.path: blob for blob in blobs}
    return tuple(by_path[path] for path in sorted(canonical))


def _inspect_project(
    blob: TrackedBlob, content: bytes | None, issues: list[str]
) -> ProjectCoordinate | None:
    relative = blob.path
    if content is None:
        return None
    try:
        return parse_project_metadata(relative, content)
    except ConfigurationError:
        issues.append(f"metadata is malformed: {relative}")
        return None


def parse_project_metadata(relative: str, content: bytes) -> ProjectCoordinate:
    """Parse one inert package manifest and normalize parser failures."""
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
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ):
        ConfigurationError.fail(f"metadata is malformed: {relative}")
    return ConfigurationError.fail(f"unsupported project metadata: {relative}")


def _read_metadata_batch(
    root: Path, blobs: tuple[TrackedBlob, ...]
) -> tuple[dict[str, bytes], list[str]]:
    if not blobs:
        return {}, []
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
        ConfigurationError.fail("repository metadata exceeds the 100 MiB aggregate safety limit")
    if not eligible:
        return {}, issues
    eligible_input = b"".join(f"{blob.object_id}\n".encode() for blob in eligible)
    try:
        blob_result = _run_git_batch(root, git_executable, "--batch", eligible_input)
    except (OSError, subprocess.SubprocessError):
        ConfigurationError.fail("cannot read tracked metadata batch")
    return _parse_batch_contents(blob_result.stdout, eligible, sizes), issues


def _run_git_batch(
    root: Path, git_executable: str, mode: str, object_input: bytes
) -> subprocess.CompletedProcess[bytes]:
    """Run finite Git batch input without relying on platform-specific pipe EOF behavior."""
    with tempfile.TemporaryFile() as batch_input:
        batch_input.write(object_input)
        batch_input.seek(0)
        return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed trusted Git executable and bounded immutable input
            [
                git_executable,
                "--no-replace-objects",
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
    raw: object = json.loads(content.decode("utf-8"))  # pyright: ignore[reportAny]
    if not isinstance(raw, dict):
        ConfigurationError.fail(f"package metadata must be an object: {relative}")
    name = raw.get("name")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    private = raw.get("private")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    workspaces = raw.get("workspaces")  # pyright: ignore[reportUnknownMemberType,reportUnknownVariableType]
    if name is not None and not isinstance(name, str):
        ConfigurationError.fail(f"package name must be a string: {relative}")
    if private is not None and not isinstance(private, bool):
        ConfigurationError.fail(f"package private must be a boolean: {relative}")
    if workspaces is not None and not isinstance(workspaces, (list, dict)):
        ConfigurationError.fail(f"package workspaces must be an array or object: {relative}")
    return ProjectCoordinate(
        ecosystem="npm",
        path=relative,
        name=name if isinstance(name, str) else None,
        private=private if isinstance(private, bool) else None,
        workspace_root=workspaces is not None,
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


def _erase_parser_type(value: object) -> object:
    """Contain permissive stdlib parser types behind an object boundary."""
    return value
