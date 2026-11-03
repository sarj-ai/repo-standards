from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from typing import TYPE_CHECKING

from repo_standards._git_environment import GIT_NO_PAGER_ENVIRONMENT
from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import GitObjectId, Manifest
from repo_standards.core.parser import parse_manifest_bytes


if TYPE_CHECKING:
    from pathlib import Path


MANIFEST_PATH = ".repo-standards/repository.toml"
MAXIMUM_MANIFEST_BYTES = 1024 * 1024
_OBJECT_ID = re.compile(r"[0-9a-f]{40}\Z")
_SIZE = re.compile(rb"[0-9]+\Z")
_GIT_TIMEOUT = timedelta(seconds=10)


@dataclass(frozen=True, slots=True)
class TrustedBaseManifest:
    base_sha: GitObjectId
    manifest: Manifest | None


def load_trusted_base_manifest(root: Path, base_sha: GitObjectId) -> TrustedBaseManifest:
    if _OBJECT_ID.fullmatch(base_sha) is None:
        ConfigurationError.fail("trusted base object ID is malformed")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        ConfigurationError.fail("repository root must be a directory")
    _git(root=resolved, arguments=("cat-file", "-e", f"{base_sha}^{{commit}}"))
    object_id = _manifest_object_id(resolved, base_sha)
    if object_id is None:
        return TrustedBaseManifest(base_sha=base_sha, manifest=None)
    size_output = _git(root=resolved, arguments=("cat-file", "-s", object_id))
    encoded_size = size_output.strip()
    if _SIZE.fullmatch(encoded_size) is None:
        ConfigurationError.fail("Git returned a malformed trusted manifest size")
    if int(encoded_size) > MAXIMUM_MANIFEST_BYTES:
        ConfigurationError.fail("trusted manifest exceeds the 1 MiB safety limit")
    content = _git(root=resolved, arguments=("cat-file", "blob", object_id))
    if len(content) > MAXIMUM_MANIFEST_BYTES:
        ConfigurationError.fail("trusted manifest exceeds the 1 MiB safety limit")
    return TrustedBaseManifest(
        base_sha=base_sha,
        manifest=parse_manifest_bytes(_without_v6_base_marker(content)),
    )


def _manifest_object_id(root: Path, base_sha: GitObjectId) -> str | None:
    payload = _git(
        root=root, arguments=("ls-tree", "--full-tree", "-z", base_sha, "--", MANIFEST_PATH)
    )
    if not payload:
        return None
    record = payload.removesuffix(b"\0")
    metadata, separator, path = record.partition(b"\t")
    if not payload.endswith(b"\0") or b"\0" in record or separator != b"\t":
        ConfigurationError.fail("Git returned malformed trusted manifest tree evidence")
    try:
        mode, kind, raw_object_id = metadata.split()
        object_id = raw_object_id.decode("ascii")
    except ValueError, UnicodeError:
        ConfigurationError.fail("Git returned malformed trusted manifest tree evidence")
    if (
        mode not in {b"100644", b"100755"}
        or kind != b"blob"
        or path != MANIFEST_PATH.encode("utf-8")
        or _OBJECT_ID.fullmatch(object_id) is None
    ):
        ConfigurationError.fail("trusted manifest must be a regular blob in the exact base tree")
    return object_id


def _without_v6_base_marker(content: bytes) -> bytes:
    lines = content.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.lstrip().startswith(b"["):
            break
        if re.fullmatch(rb"[ \t]*schema_version[ \t]*=[ \t]*6[ \t]*(?:#.*)?(?:\r?\n)?", line):
            return b"".join((*lines[:index], *lines[index + 1 :]))
    return content


def _git(
    *,
    root: Path,
    arguments: tuple[str, ...],
) -> bytes:
    executable = shutil.which("git")
    if executable is None:
        ConfigurationError.fail("Git is required to load trusted pull-request policy")
    try:
        completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - argv is fixed and bounded
            [
                executable,
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "-C",
                str(root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            timeout=_GIT_TIMEOUT.total_seconds(),
            env=GIT_NO_PAGER_ENVIRONMENT,
        )
    except OSError, subprocess.TimeoutExpired:
        ConfigurationError.fail("Git could not load trusted pull-request policy")
    if completed.returncode != 0:
        ConfigurationError.fail("Git could not load trusted pull-request policy")
    return completed.stdout
