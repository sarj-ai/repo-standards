from __future__ import annotations

from importlib.metadata import version
from pathlib import Path  # ruff: ignore[typing-only-standard-library-import] -- Typer resolves this CLI path annotation at runtime.

from pydantic import TypeAdapter  # ruff: ignore[banned-api] -- validate the CLI's existing open machine envelope, not a new domain payload.
import typer

from repo_standards._machine import CommandEnvelope  # ruff: ignore[import-private-name] -- this package's CI validates its installed machine contract; copying the envelope would hide drift.


def main(report_path: Path) -> None:
    report = TypeAdapter(CommandEnvelope).validate_json(report_path.read_bytes(), strict=True)
    if report["completion"] != "complete":
        message = "Installed CLI smoke report did not complete."
        raise ValueError(message)
    if report["tool"]["version"] != version("repo-standards"):
        message = "Installed CLI smoke report version differs from its distribution."
        raise ValueError(message)


if __name__ == "__main__":
    typer.run(main)
