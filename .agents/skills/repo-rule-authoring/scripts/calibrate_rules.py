from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess  # ruff: ignore[suspicious-subprocess-import] - child isolation is a core calibration control
import sys
import time
from typing import Annotated, NoReturn

import typer

from repo_standards.core.inspection import load_calibration_snapshot
from repo_standards.policy_sarj.policy import SarjPolicy


_PRIVATE_MODE = 0o600
_SOURCE_TIMEOUT_SECONDS = 120
_FULL_SHA_LENGTH = 40
_GIT = shutil.which("git", path=os.defpath)
app = typer.Typer(add_completion=False, help="Evaluate pending rules against pinned local corpora.")


def _fail(message: str) -> NoReturn:
    raise SystemExit(message)


def _private_file(path: Path, *, label: str) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        _fail(f"{label} must be an absolute regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != _PRIVATE_MODE:
        _fail(f"{label} must have mode 0600")


def _object(path: Path) -> dict[str, object]:
    _private_file(path, label="corpus overlay")
    try:
        value: object = json.loads(path.read_bytes())
    except (OSError, ValueError):
        _fail("corpus overlay must be valid JSON")
    if not isinstance(value, dict):
        _fail("corpus overlay must be a JSON object")
    return {str(key): item for key, item in value.items()}


def _sources(corpus: dict[str, object]) -> list[dict[str, str]]:
    if corpus.get("schema_version") != 1:
        _fail("corpus schema_version must be 1")
    raw = corpus.get("sources")
    if not isinstance(raw, list) or not raw:
        _fail("corpus sources must be a non-empty array")
    sources: list[dict[str, str]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            _fail(f"corpus source {index} must be an object")
        source = {str(key): value for key, value in item.items() if isinstance(value, str)}
        required = {"report_name", "visibility", "path", "commit", "manifest_path"}
        if set(source) != required:
            _fail(f"corpus source {index} must contain exactly {sorted(required)}")
        if source["visibility"] not in {"private", "public"}:
            _fail(f"corpus source {index} visibility must be private or public")
        if source["visibility"] == "private" and not source["report_name"].startswith(
            "<private-corpus-"
        ):
            _fail(f"private corpus source {index} must use an opaque report name")
        if len(source["commit"]) != _FULL_SHA_LENGTH or any(
            char not in "0123456789abcdef" for char in source["commit"]
        ):
            _fail(f"corpus source {index} commit must be lowercase full SHA-1")
        root = Path(source["path"])
        manifest = Path(source["manifest_path"])
        if not root.is_absolute() or not root.is_dir():
            _fail(f"corpus source {index} path must be an absolute local directory")
        _private_file(manifest, label=f"corpus source {index} manifest")
        sources.append(source)
    return sources


def _labels(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    payload = _object(path)
    if payload.get("schema_version") != 1 or set(payload) != {"schema_version", "labels"}:
        _fail("classification ledger must contain schema_version and labels")
    raw = payload["labels"]
    if not isinstance(raw, dict):
        _fail("classification labels must be a JSON object")
    labels = {str(key): value for key, value in raw.items() if isinstance(value, str)}
    if len(labels) != len(raw) or any(value not in {"tp", "fp"} for value in labels.values()):
        _fail("classification labels must be tp or fp")
    return labels


def _git_head(root: Path) -> str:
    if _GIT is None:
        _fail("git is unavailable")
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed Git plumbing command, no shell
        [_GIT, "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    return result.stdout.strip()


def _verify(sources: list[dict[str, str]]) -> None:
    for source in sources:
        if _git_head(Path(source["path"])) != source["commit"]:
            _fail(f"corpus pin mismatch: {source['report_name']}")


def _finding_id(rule_id: str, path: str, anchor: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{path}\0{anchor}".encode()).hexdigest()


def _worker(root: Path, manifest_path: Path, rule_id: str) -> int:
    snapshot = load_calibration_snapshot(root, manifest_path.read_bytes())
    diagnostics = (
        *SarjPolicy.evaluate(snapshot.manifest),
        *SarjPolicy.evaluate_repository(snapshot),
    )
    selected = [item for item in diagnostics if item.rule_id == rule_id]
    payload = {
        "tracked_files": snapshot.inspection.tracked_file_count,
        "content_files": len(snapshot.content),
        "content_bytes": sum(len(item.content) for item in snapshot.content),
        "findings": [
            {
                "finding_id": _finding_id(str(item.rule_id), item.path, item.manifest_anchor),
                "rule_id": str(item.rule_id),
                "path": item.path,
                "anchor": item.manifest_anchor,
                "message": item.message,
            }
            for item in selected
        ],
    }
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def _run_source(source: dict[str, str], rule_id: str) -> dict[str, object]:
    started = time.perf_counter()
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed self-worker command, no shell
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "_worker",
            "--root",
            source["path"],
            "--manifest",
            source["manifest_path"],
            "--rule",
            rule_id,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=_SOURCE_TIMEOUT_SECONDS,
        env={"PATH": os.defpath, "LC_ALL": "C", "PYTHONHASHSEED": "0"},
    )
    if result.returncode != 0:
        _fail(f"corpus evaluation failed: {source['report_name']}")
    try:
        payload: object = json.loads(result.stdout)
    except ValueError:
        _fail(f"corpus worker returned invalid JSON: {source['report_name']}")
    if not isinstance(payload, dict):
        _fail(f"corpus worker returned invalid payload: {source['report_name']}")
    return {**payload, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)}


def _write_json(path: Path, payload: object, *, private: bool) -> None:
    if not path.is_absolute() or path.is_symlink() or path.exists():
        _fail("report destination must be a new absolute non-symlink path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _PRIVATE_MODE)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    finally:
        if private:
            path.chmod(_PRIVATE_MODE)


def _evaluate(  # ruff: ignore[too-many-arguments] - explicit report boundaries are security inputs
    *,
    rule_id: str,
    fixtures_passed: bool,
    private_output: Path,
    public_output: Path,
    sources: list[dict[str, str]],
    labels: dict[str, str],
) -> None:
    results = [(source, _run_source(source, rule_id)) for source in sources]
    findings = [
        finding
        for _source, result in results
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    ]
    finding_ids = {
        str(finding.get("finding_id")) for finding in findings if finding.get("finding_id")
    }
    if set(labels) - finding_ids:
        _fail("classification ledger contains findings outside this evaluation")
    tp_count = sum(labels.get(finding_id) == "tp" for finding_id in finding_ids)
    fp_count = sum(labels.get(finding_id) == "fp" for finding_id in finding_ids)
    unclassified_count = len(finding_ids - set(labels))
    private_payload = {
        "schema_version": 1,
        "rule_id": rule_id,
        "sources": [
            {
                "report_name": source["report_name"],
                **result,
                "findings": [
                    {**finding, "classification": labels.get(str(finding["finding_id"]))}
                    for finding in result.get("findings", [])
                    if isinstance(finding, dict)
                ],
            }
            for source, result in results
        ],
    }
    public_sources = [
        {
            "report_name": source["report_name"],
            "findings": len(result.get("findings", [])),
            "tracked_files": result.get("tracked_files", 0),
            "content_bytes": result.get("content_bytes", 0),
            "elapsed_ms": result.get("elapsed_ms", 0),
        }
        for source, result in results
        if source["visibility"] == "public"
    ]
    decision = (
        "ship-warning"
        if fixtures_passed and fp_count == 0 and unclassified_count == 0
        else "revise"
    )
    public_payload = {
        "schema_version": 1,
        "rule_id": rule_id,
        "decision": decision,
        "private": {
            "report_name": "<private-corpus>",
            "findings": len(finding_ids),
            "tp": tp_count,
            "fp": fp_count,
            "unclassified": unclassified_count,
        },
        "public_sources": public_sources,
        "unclassified": unclassified_count,
    }
    _write_json(private_output, private_payload, private=True)
    _write_json(public_output, public_payload, private=False)


@app.command()
def verify(corpus: Annotated[Path, typer.Option(exists=True, dir_okay=False)]) -> None:
    """Verify permissions, source pins, and sidecar manifests without analysis."""
    sources = _sources(_object(corpus))
    _verify(sources)


@app.command()
def evaluate(  # ruff: ignore[too-many-arguments] - explicit CLI options are the public contract
    corpus: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    rule: Annotated[str, typer.Option()],
    private_output: Annotated[Path, typer.Option()],
    public_output: Annotated[Path, typer.Option()],
    labels: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    *,
    fixtures_passed: Annotated[bool, typer.Option()] = False,
) -> None:
    """Evaluate one immutable rule ID in isolated child processes."""
    sources = _sources(_object(corpus))
    _verify(sources)
    _evaluate(
        rule_id=rule,
        fixtures_passed=fixtures_passed,
        private_output=private_output,
        public_output=public_output,
        sources=sources,
        labels=_labels(labels),
    )


@app.command(name="_worker", hidden=True)
def worker(
    root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    manifest: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    rule: Annotated[str, typer.Option()],
) -> None:
    """Run one internal isolated evaluation worker."""
    raise typer.Exit(_worker(root, manifest, rule))


if __name__ == "__main__":
    app()
