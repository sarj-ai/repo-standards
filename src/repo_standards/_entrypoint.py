from __future__ import annotations

import sys

from repo_standards._machine import capabilities_payload, installed_version


def main() -> None:
    # Machine metadata does not need the command, schema or analysis graph.
    # Every other argument combination retains the original Typer parser.
    if sys.argv[1:] == ["--version"]:
        sys.stdout.write(f"{installed_version()}\n")
        return
    if sys.argv[1:] == ["capabilities"]:
        from repo_standards.core.canonical import canonical_json  # ruff: ignore[import-outside-top-level] -- version probes do not need JSON serialization.

        sys.stdout.write(f"{canonical_json(capabilities_payload())}\n")
        return
    from repo_standards.cli import main as cli_main  # ruff: ignore[import-outside-top-level] -- defer the full command graph until needed.

    cli_main()
