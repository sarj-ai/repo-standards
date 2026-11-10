from __future__ import annotations

from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Annotated

import typer

from release_reconciliation import ReleaseStateError, render_release_readme


app = typer.Typer(add_completion=False)


def render_package_readme(readme: str, *, source_sha: str, version: str) -> str:
    if "sarj-ai/repo-standards@" not in readme.casefold():
        readme = (
            f"{readme.rstrip()}\n\n## GitHub Action\n\n```yaml\n"
            f"- uses: sarj-ai/repo-standards@{source_sha} # v{version}\n```\n"
        )
    return render_release_readme(readme, source_sha=source_sha, version=version)


@app.command()
def prepare(
    readme: Annotated[Path, typer.Option(help="Package README to render.")],
    source_sha: Annotated[str, typer.Option(help="Exact source commit SHA.")],
    version: Annotated[
        str | None, typer.Option(help="Defaults to the installed project version.")
    ] = None,
) -> None:
    try:
        rendered = render_package_readme(
            readme.read_text(encoding="utf-8"),
            source_sha=source_sha,
            version=version if version is not None else distribution_version("repo-standards"),
        )
    except ReleaseStateError as error:
        raise typer.BadParameter(str(error)) from error
    readme.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    app()
