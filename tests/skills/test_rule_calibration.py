from __future__ import annotations

import json
from pathlib import Path
import shutil
import stat
import subprocess  # ruff: ignore[suspicious-subprocess-import] - fixed local fixture only
import sys

from pydantic import TypeAdapter


_SCRIPT = (
    Path(__file__).parents[2] / ".agents/skills/repo-rule-authoring/scripts/calibrate_rules.py"
)
_MANIFEST = """\
schema_version = 3
repository_id = "calibration-fixture"
components = []

[documentation]
entrypoints = ["README.md"]
"""
_JSON_OBJECT = TypeAdapter(dict[str, object])
_JSON_OBJECTS = TypeAdapter(list[dict[str, object]])


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed Git fixture
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "private-consumer-name"
    repository.mkdir()
    (repository / "docs").mkdir()
    (repository / "README.md").write_text("# Entry\n", encoding="utf-8")
    (repository / "docs/orphan.md").write_text("# Orphan\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Rule Calibration",
        "-c",
        "user.email=rule-calibration@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
    )
    manifest = tmp_path / "sidecar.toml"
    manifest.write_text(_MANIFEST, encoding="utf-8")
    manifest.chmod(0o600)
    corpus = tmp_path / "private-corpus.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sources": [
                    {
                        "report_name": "<private-corpus-01>",
                        "visibility": "private",
                        "path": str(repository),
                        "commit": _git(repository, "rev-parse", "HEAD"),
                        "manifest_path": str(manifest),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    corpus.chmod(0o600)
    return repository, corpus


def _run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed helper invocation
        [sys.executable, str(_SCRIPT), *arguments],
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_calibration_isolated_worker_redacts_private_report(  # ruff: ignore[too-many-locals]
    tmp_path: Path,
) -> None:
    repository, corpus = _fixture(tmp_path)
    private_output = tmp_path / "private.json"
    public_output = tmp_path / "public.json"

    _run(
        "evaluate",
        "--corpus",
        str(corpus),
        "--rule",
        "repository/documentation/reachability",
        "--fixtures-passed",
        "--private-output",
        str(private_output),
        "--public-output",
        str(public_output),
    )

    public = public_output.read_text(encoding="utf-8")
    assert str(repository) not in public
    assert "private-consumer-name" not in public
    assert "docs/orphan.md" not in public
    public_payload = _JSON_OBJECT.validate_json(public)
    public_private = _JSON_OBJECT.validate_python(public_payload["private"])
    assert public_private["findings"] == 1
    assert public_private["report_name"] == "<private-corpus>"
    assert stat.S_IMODE(private_output.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_output.stat().st_mode) == 0o600

    private = _JSON_OBJECT.validate_json(private_output.read_bytes())
    private_sources = _JSON_OBJECTS.validate_python(private["sources"])
    private_findings = _JSON_OBJECTS.validate_python(private_sources[0]["findings"])
    finding_id = str(private_findings[0]["finding_id"])
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps({"schema_version": 1, "labels": {finding_id: "tp"}}),
        encoding="utf-8",
    )
    labels.chmod(0o600)
    classified_private = tmp_path / "classified-private.json"
    classified_public = tmp_path / "classified-public.json"

    _run(
        "evaluate",
        "--corpus",
        str(corpus),
        "--rule",
        "repository/documentation/reachability",
        "--fixtures-passed",
        "--labels",
        str(labels),
        "--private-output",
        str(classified_private),
        "--public-output",
        str(classified_public),
    )

    classified = _JSON_OBJECT.validate_json(classified_public.read_bytes())
    classified_private_payload = _JSON_OBJECT.validate_python(classified["private"])
    assert classified["decision"] == "ship-warning"
    assert classified_private_payload["tp"] == 1
    assert classified_private_payload["fp"] == 0


def test_calibration_refuses_broad_private_overlay_permissions(tmp_path: Path) -> None:
    _repository, corpus = _fixture(tmp_path)
    corpus.chmod(0o644)

    completed = _run("verify", "--corpus", str(corpus), check=False)

    assert completed.returncode != 0
    assert "mode 0600" in completed.stderr
