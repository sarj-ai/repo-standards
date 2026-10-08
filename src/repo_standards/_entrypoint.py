from __future__ import annotations

from importlib import metadata
import sys


def main() -> None:
    # A version probe needs installed metadata, without constructing every
    # command, schema and repository parser. All other arguments use Typer.
    if sys.argv[1:] == ["--version"]:
        try:
            installed = metadata.version("repo-standards")
        except metadata.PackageNotFoundError:
            installed = "unknown"
        sys.stdout.write(f"{installed}\n")
        return
    from repo_standards.cli import main as cli_main  # ruff: ignore[import-outside-top-level] -- defer the full command graph until needed.

    cli_main()
