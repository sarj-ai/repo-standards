from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import ConfigurationError


if TYPE_CHECKING:
    from .models import ImageArtifact


IMAGE_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".avif",
    ".svg",
    ".svgz",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".apng",
    ".heic",
    ".heif",
    ".jxl",
)


def is_image_path(path: str) -> bool:
    return path.lower().endswith(IMAGE_SUFFIXES)


def validate_image_artifacts(
    artifacts: tuple[ImageArtifact, ...], tracked_paths: frozenset[str]
) -> None:
    for artifact in artifacts:
        if artifact.path not in tracked_paths:
            ConfigurationError.fail(
                f"image artifact must name a tracked regular file: {artifact.path}"
            )
