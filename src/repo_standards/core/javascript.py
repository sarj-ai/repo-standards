from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import ConfigurationError


if TYPE_CHECKING:
    from .models import JavaScriptArtifact


JAVASCRIPT_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs")


def is_javascript_path(path: str) -> bool:
    return path.lower().endswith(JAVASCRIPT_SUFFIXES)


def validate_javascript_artifacts(
    artifacts: tuple[JavaScriptArtifact, ...], tracked_paths: frozenset[str]
) -> None:
    for artifact in artifacts:
        if artifact.path not in tracked_paths:
            ConfigurationError.fail(
                f"javascript artifact must name a tracked regular file: {artifact.path}"
            )
        if artifact.source is not None and artifact.source not in tracked_paths:
            ConfigurationError.fail(
                f"javascript artifact source must name a tracked regular file: {artifact.source}"
            )
