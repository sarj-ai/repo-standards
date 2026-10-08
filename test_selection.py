"""Select reviewed PR test cohorts; exact main and unknown changes run every test."""

from __future__ import annotations

import argparse  # ruff: ignore[banned-api] -- dependency-free developer and CI entry point.
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] -- fixed Git and Python argv only.
import sys
import tomllib


_PARALLEL_FILE_THRESHOLD = 8
_VERSION_TESTS = (
    "tests/test_public_api.py",
    "tests/test_release_distributions.py",
    "tests/test_catalog.py",
    "tests/test_cli.py",
)
_CONTRACTS = ("tests/test_public_content.py", "tests/test_test_selection.py")
_DOCS_TESTS = (
    "tests/test_catalog.py",
    "tests/test_cli.py",
    "tests/test_public_api.py",
    "tests/test_release_site_contract.py",
    "tests/test_distribution_fast_paths.py",
    "tests/test_action_contract.py",
    "tests/test_documentation_action_contract.py",
    "tests/test_pull_request_commits_packaging_contract.py",
)
_TOOL_TESTS = {
    "ci_artifacts.py": ("tests/test_ci_artifacts.py",),
    "release_reconciliation.py": (
        "tests/test_release_reconciliation.py",
        "tests/test_distribution_fast_paths.py",
    ),
    "src/repo_standards/verify_release_artifacts.py": (
        "tests/test_release_distributions.py",
        "tests/test_release_site_contract.py",
        "tests/test_distribution_fast_paths.py",
        "tests/test_public_api.py",
    ),
}


@dataclass(frozen=True)
class TestPlan:
    tests: tuple[str, ...]
    reason: str
    total_files: int


def select_tests(root: Path, *, base: str = "") -> TestPlan:
    all_tests = tuple(
        sorted(path.relative_to(root).as_posix() for path in (root / "tests").rglob("test_*.py"))
    )

    def full(reason: str) -> TestPlan:
        return TestPlan(all_tests, reason, len(all_tests))

    if not base or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]*", base) is None:
        return full("full validation requested or invalid base")
    try:
        changes = _changed_paths(root, base)
    except OSError, subprocess.SubprocessError:
        return full("Git evidence unavailable")
    if changes is None:
        return full("deletion, rename or unsupported Git change")
    if not changes:
        return full("no changed files; full validation")
    selected = set(_CONTRACTS)
    for path in changes:
        if path in all_tests and path != "tests/test_test_selection.py":
            selected.add(path)
        elif path.startswith(("apps/docs/", ".github/deploy/")):
            selected.update(_DOCS_TESTS)
        elif path in {"pyproject.toml", "uv.lock"} and _version_only(root, base, path):
            selected.update(_VERSION_TESTS)
        elif path in _TOOL_TESTS:
            selected.update(_TOOL_TESTS[path])
        else:
            return full(f"shared or unclassified change: {path}")
    if not selected.issubset(all_tests):
        return full("reviewed cohort is missing a required contract")
    return TestPlan(tuple(sorted(selected)), "reviewed PR cohort", len(all_tests))


def _without_version(source: str, path: str) -> object:
    document = tomllib.loads(source)
    if path == "pyproject.toml":
        project = document["project"]
        if not isinstance(project, dict) or project.get("name") != "repo-standards":
            message = "unexpected project identity"
            raise ValueError(message)
        del project["version"]
    else:
        packages = document["package"]
        if not isinstance(packages, list) or any(
            not isinstance(package, dict) for package in packages
        ):
            message = "invalid package records"
            raise ValueError(message)
        owned = [
            package
            for package in packages
            if package.get("name") == "repo-standards"
            and package.get("source") == {"editable": "."}
        ]
        if len(owned) != 1:
            message = "missing or ambiguous editable package"
            raise ValueError(message)
        del owned[0]["version"]
    return document


def _version_only(root: Path, base: str, path: str) -> bool:
    try:
        ancestor = _git(root, "merge-base", "HEAD", base).strip()
        previous = _without_version(_git(root, "show", f"{ancestor}:{path}"), path)
        current = _without_version((root / path).read_text(), path)
    except OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError:
        return False
    return previous == current


def _changed_paths(root: Path, base: str) -> list[str] | None:
    ancestor = _git(root, "merge-base", "HEAD", base).strip()
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", ancestor) is None:
        return None
    records = _git(root, "diff", "--name-status", "-z", "--find-renames", ancestor, "--").split(
        "\0"
    )
    changes: list[str] = []
    while records and records[0]:
        status = records.pop(0)
        if status not in {"A", "M"} or not records:
            return None
        changes.append(records.pop(0))
    changes.extend(
        path
        for path in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0")
        if path
    )
    return changes


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- argv-only read-only Git.
        (shutil.which("git") or "git", *arguments),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout


class _Arguments(argparse.Namespace):
    base: str = ""
    run: bool = False
    jobs: int = 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Reviewed docs, delivery-tool and test-only changes use explicit cohorts. "
        "Shared source/config, deletions, renames and unavailable Git evidence run every test. "
        "Main, schedules and publication always use full validation. "
        "Preview with --base origin/main; add --run to execute, or --jobs 1 for serial debugging.",
    )
    parser.add_argument(
        "--base", default="", help="reviewed base revision; omitted means all tests"
    )
    parser.add_argument("--run", action="store_true", help="execute the selected tests")
    parser.add_argument("--jobs", type=int, choices=(1, 2, 4), default=2)
    args = _Arguments()
    parser.parse_args(namespace=args)
    root = Path(__file__).resolve().parent
    plan = select_tests(root, base=args.base)
    sys.stdout.write(json.dumps(asdict(plan), sort_keys=True) + "\n")
    sys.stdout.flush()
    if not args.run:
        return 0
    parallel = (
        ("-n", str(args.jobs), "--dist", "worksteal")
        if args.jobs > 1 and len(plan.tests) >= _PARALLEL_FILE_THRESHOLD
        else ()
    )
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] -- bounded installed pytest invocation.
        (sys.executable, "-m", "pytest", *parallel, *plan.tests),
        cwd=root,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
