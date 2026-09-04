from __future__ import annotations

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - local Git fixture only
from typing import NamedTuple

import pytest

from repo_standards.core.errors import ConfigurationError
from repo_standards.core.models import RepositoryId
from repo_standards.core.pull_request_commits import (
    TransitionExemption,
    TransitionExemptionId,
    analyze_pull_request_commits,
)


class RepositoryFixture(NamedTuple):
    path: Path
    base_revision: str


def _git(repository: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    completed = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture
        [executable, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _commit(repository: Path, message: str) -> str:
    path = repository / "change.txt"
    path.write_text(path.read_text(encoding="utf-8") + message + "\n", encoding="utf-8")
    _git(repository, "add", "change.txt")
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=repository-standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _commit_new_file(repository: Path, path: str, message: str) -> str:
    (repository / path).write_text(message + "\n", encoding="utf-8")
    _git(repository, "add", path)
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=repository-standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> RepositoryFixture:
    _git(tmp_path, "init", "--quiet")
    (tmp_path / "change.txt").write_text("base\n", encoding="utf-8")
    return RepositoryFixture(tmp_path, _commit(tmp_path, "base"))


@pytest.mark.parametrize("count", range(6))
def test_at_or_below_default_limit_passes(tmp_path: Path, count: int) -> None:
    repository, base = _repository(tmp_path)
    for index in range(count):
        _commit(repository, f"change {index + 1}")

    result = analyze_pull_request_commits(repository, base=base)

    assert result.commit_count == count
    assert result.satisfied
    assert result.disposition == "within-limit"


def test_six_ordinary_commits_fail(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    for index in range(6):
        _commit(repository, f"change {index + 1}")

    result = analyze_pull_request_commits(repository, base=base)

    assert result.commit_count == 6
    assert not result.satisfied
    assert result.disposition == "over-limit"
    assert result.numbering_issue == "missing-marker"


def test_complete_numbered_series_passes(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    for index in range(1, 7):
        _commit(repository, f"({index}/6) reviewable step {index}")

    result = analyze_pull_request_commits(repository, base=base)

    assert result.satisfied
    assert result.disposition == "numbered-series"
    assert result.numbering_issue is None


@pytest.mark.parametrize(
    ("subjects", "issue"),
    [
        (
            ["(1/6) step", "(2/6) step", "(3/6) step", "(4/6) step", "(5/6) step", "step"],
            "missing-marker",
        ),
        (
            ["(1/6) step", "(2/6) step", "(2/6) step", "(4/6) step", "(5/6) step", "(6/6) step"],
            "duplicate-index",
        ),
        (
            ["(1/7) step", "(2/7) step", "(3/7) step", "(4/7) step", "(5/7) step", "(6/7) step"],
            "wrong-total",
        ),
        (
            ["(01/6) step", "(2/6) step", "(3/6) step", "(4/6) step", "(5/6) step", "(6/6) step"],
            "malformed-marker",
        ),
        (
            ["(1/6)  step", "(2/6) step", "(3/6) step", "(4/6) step", "(5/6) step", "(6/6) step"],
            "malformed-marker",
        ),
        (
            ["(6/6) step", "(5/6) step", "(4/6) step", "(3/6) step", "(2/6) step", "(1/6) step"],
            "out-of-order",
        ),
    ],
)
def test_malformed_numbered_series_fails(
    tmp_path: Path,
    subjects: list[str],
    issue: str,
) -> None:
    repository, base = _repository(tmp_path)
    for subject in subjects:
        _commit(repository, subject)

    result = analyze_pull_request_commits(repository, base=base)

    assert not result.satisfied
    assert result.numbering_issue == issue


def test_merge_commit_is_excluded_but_side_branch_commits_are_counted(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(repository, "checkout", "-q", "-b", "side")
    for index in range(3):
        _commit_new_file(repository, f"side-{index}.txt", f"side {index + 1}")
    _git(repository, "checkout", "-q", "-b", "feature", base)
    for index in range(3):
        _commit_new_file(repository, f"feature-{index}.txt", f"feature {index + 1}")
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=repository-standards@example.invalid",
        "merge",
        "--quiet",
        "--no-ff",
        "side",
        "-m",
        "merge side",
    )

    result = analyze_pull_request_commits(repository, base=base)

    assert result.commit_count == 6
    assert not result.satisfied


def test_exact_transition_exemption_passes(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(repository, "branch", "preview", base)
    for index in range(6):
        _commit(repository, f"promoted {index + 1}")
    head = _git(repository, "rev-parse", "HEAD")
    _git(repository, "branch", "dev", head)
    head_ref = f"automation/promote-dev-{head[:12]}"

    result = analyze_pull_request_commits(
        repository,
        base=base,
        head=head,
        base_ref="preview",
        head_ref=head_ref,
        repository_id="sarj-ai/bulbul",
        transition_exemptions=(
            TransitionExemption(
                exemption_id=TransitionExemptionId("bulbul-dev-preview"),
                repository_id=RepositoryId("sarj-ai/bulbul"),
                source_ref="dev",
                base_ref="preview",
                head_prefix="automation/promote-dev-",
            ),
        ),
    )

    assert result.satisfied
    assert result.disposition == "transition-exemption"
    assert result.exemption_id == "bulbul-dev-preview"


def test_transition_snapshot_allows_source_advance(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(repository, "branch", "preview", base)
    for index in range(6):
        _commit(repository, f"promoted {index + 1}")
    snapshot = _git(repository, "rev-parse", "HEAD")
    _commit(repository, "source advanced")
    _git(repository, "branch", "dev", "HEAD")

    result = analyze_pull_request_commits(
        repository,
        base=base,
        head=snapshot,
        base_ref="preview",
        head_ref=f"automation/promote-dev-{snapshot[:12]}",
        repository_id="sarj-ai/bulbul",
        transition_exemptions=(
            TransitionExemption(
                exemption_id=TransitionExemptionId("bulbul-dev-preview"),
                repository_id=RepositoryId("sarj-ai/bulbul"),
                source_ref="dev",
                base_ref="preview",
                head_prefix="automation/promote-dev-",
            ),
        ),
    )

    assert result.satisfied
    assert result.disposition == "transition-exemption"


def test_transition_snapshot_with_extra_commit_is_not_exempt(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(repository, "branch", "preview", base)
    for index in range(6):
        _commit(repository, f"promoted {index + 1}")
    snapshot = _git(repository, "rev-parse", "HEAD")
    _git(repository, "branch", "dev", snapshot)
    head = _commit(repository, "unattested extra change")

    result = analyze_pull_request_commits(
        repository,
        base=base,
        head=head,
        base_ref="preview",
        head_ref=f"automation/promote-dev-{snapshot[:12]}",
        repository_id="sarj-ai/bulbul",
        transition_exemptions=(
            TransitionExemption(
                exemption_id=TransitionExemptionId("bulbul-dev-preview"),
                repository_id=RepositoryId("sarj-ai/bulbul"),
                source_ref="dev",
                base_ref="preview",
                head_prefix="automation/promote-dev-",
            ),
        ),
    )

    assert not result.satisfied
    assert result.exemption_id is None


@pytest.mark.parametrize("changed", ["repository", "base", "head"])
def test_transition_lookalikes_do_not_pass(tmp_path: Path, changed: str) -> None:
    repository, base = _repository(tmp_path)
    _git(repository, "branch", "preview", base)
    for index in range(6):
        _commit(repository, f"promoted {index + 1}")
    head = _git(repository, "rev-parse", "HEAD")
    _git(repository, "branch", "dev", head)
    repository_id = "sarj-ai/bulbul" if changed != "repository" else "fork/bulbul"
    base_ref = "preview" if changed != "base" else "main"
    head_ref = (
        f"automation/promote-dev-{head[:12]}"
        if changed != "head"
        else f"automation/promote-dev-{'0' * 12}"
    )

    result = analyze_pull_request_commits(
        repository,
        base=base,
        head=head,
        base_ref=base_ref,
        head_ref=head_ref,
        repository_id=repository_id,
        transition_exemptions=(
            TransitionExemption(
                exemption_id=TransitionExemptionId("bulbul-dev-preview"),
                repository_id=RepositoryId("sarj-ai/bulbul"),
                source_ref="dev",
                base_ref="preview",
                head_prefix="automation/promote-dev-",
            ),
        ),
    )

    assert not result.satisfied
    assert result.exemption_id is None


def test_unrelated_histories_are_incomplete(tmp_path: Path) -> None:
    repository, base = _repository(tmp_path)
    _git(repository, "checkout", "--orphan", "unrelated")
    _git(repository, "rm", "-q", "-f", "change.txt")
    (repository / "other.txt").write_text("other\n", encoding="utf-8")
    _git(repository, "add", "other.txt")
    _git(
        repository,
        "-c",
        "user.name=Repository Standards",
        "-c",
        "user.email=repository-standards@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "unrelated",
    )

    with pytest.raises(ConfigurationError, match="common history"):
        analyze_pull_request_commits(repository, base=base)


def test_unsafe_revision_is_rejected(tmp_path: Path) -> None:
    repository, _base = _repository(tmp_path)

    with pytest.raises(ConfigurationError, match="unsafe"):
        analyze_pull_request_commits(repository, base="--all")
