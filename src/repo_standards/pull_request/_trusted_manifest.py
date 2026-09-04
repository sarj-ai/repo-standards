from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed read-only Git queries
from types import MappingProxyType
from typing import TYPE_CHECKING

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
_GIT_ENVIRONMENT = MappingProxyType(
    {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
)


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
    object_spec = f"{base_sha}:{MANIFEST_PATH}"
    size_output = _git(
        root=resolved,
        arguments=("cat-file", "-s", object_spec),
        absent_ok=True,
    )
    if size_output is None:
        return TrustedBaseManifest(base_sha=base_sha, manifest=None)
    encoded_size = size_output.strip()
    if _SIZE.fullmatch(encoded_size) is None:
        ConfigurationError.fail("Git returned a malformed trusted manifest size")
    if int(encoded_size) > MAXIMUM_MANIFEST_BYTES:
        ConfigurationError.fail("trusted manifest exceeds the 1 MiB safety limit")
    content = _git(root=resolved, arguments=("show", object_spec))
    if content is None:
        ConfigurationError.fail("trusted manifest disappeared during analysis")
    if len(content) > MAXIMUM_MANIFEST_BYTES:
        ConfigurationError.fail("trusted manifest exceeds the 1 MiB safety limit")
    return TrustedBaseManifest(
        base_sha=base_sha,
        manifest=parse_manifest_bytes(content),
    )


def _git(
    *,
    root: Path,
    arguments: tuple[str, ...],
    absent_ok: bool = False,
) -> bytes | None:
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
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired):
        ConfigurationError.fail("Git could not load trusted pull-request policy")
    if completed.returncode != 0:
        if absent_ok:
            return None
        ConfigurationError.fail("trusted manifest is absent from the exact base tree")
    return completed.stdout
