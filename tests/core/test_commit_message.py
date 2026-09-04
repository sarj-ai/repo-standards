from __future__ import annotations

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - isolated Git fixture

import pytest

from repo_standards.core.commit_message import (
    analyze_commit_header,
    check_commit_message_file,
    check_local_commit_message_file,
)
from repo_standards.core.errors import ConfigurationError


@pytest.mark.parametrize(
    "header",
    [
        "feat: add search",
        "fix(api): handle empty input",
        "feat!: remove legacy endpoint",
        "(1/7) docs: explain deployment",
        "[SARJ-437] fix(parser): preserve العربية",
        "(2/7) [NO-TICKET] test: cover promotion",
    ],
)
def test_managed_conventional_headers_pass(header: str) -> None:
    assert analyze_commit_header(header).satisfied


@pytest.mark.parametrize(
    "header",
    [
        "update parser",
        "feature: add search",
        "feat:",
        "[sarj-1] feat: lowercase ticket",
        "(01/2) feat: padded marker",
        "feat(@api): unsupported scope",
        "feat:   ",
        "feat: bad\x00header",
    ],
)
def test_semantic_or_unsafe_headers_fail_without_replacement(header: str) -> None:
    result = analyze_commit_header(header)
    assert not result.satisfied
    assert result.replacement_header is None


def test_safe_fix_only_normalizes_structure_and_type(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    body = "\n\nBody stays byte-for-byte.\n\nRefs: SARJ-1\n"
    path.write_text(f"(1/2) [SARJ-1] FeAt (api) ! :   Preserve العربية  {body}")

    result = check_commit_message_file(path, fix_safe=True)

    assert result.satisfied
    assert result.fix_applied
    assert path.read_text() == f"(1/2) [SARJ-1] feat(api)!: Preserve العربية  {body}"
    assert check_commit_message_file(path, fix_safe=True).fix_applied is False


def test_semantic_failure_never_mutates_file(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    original = b"choose a type\n\nBody\n"
    path.write_bytes(original)

    result = check_commit_message_file(path, fix_safe=True)

    assert not result.satisfied
    assert path.read_bytes() == original


def test_crlf_suffix_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_bytes(b"FIX : repair\r\n\r\nBody\r\n")

    check_commit_message_file(path, fix_safe=True)

    assert path.read_bytes() == b"fix: repair\r\n\r\nBody\r\n"


def test_non_utf8_and_symlinks_fail_closed(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid"
    invalid.write_bytes(b"feat: \xff")
    with pytest.raises(ConfigurationError, match="UTF-8"):
        check_commit_message_file(invalid)

    target = tmp_path / "target"
    target.write_text("feat: valid")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ConfigurationError, match="regular file"):
        check_commit_message_file(link)


@pytest.mark.parametrize("prefix", ["fixup! ", "squash! ", "amend! "])
def test_local_hook_allows_temporary_autosquash_messages_but_strict_analysis_does_not(
    tmp_path: Path,
    prefix: str,
) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text(f"{prefix}feat: add search\n")

    assert check_local_commit_message_file(path, root=tmp_path).satisfied
    assert not check_commit_message_file(path).satisfied


@pytest.mark.parametrize("subject", ["amend!", "amend! ", "Amend! feat: add search"])
def test_local_hook_rejects_noncanonical_or_empty_amend_subjects(
    tmp_path: Path,
    subject: str,
) -> None:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text(subject + "\n")

    assert not check_local_commit_message_file(path, root=tmp_path).satisfied


def test_local_hook_allows_a_structurally_proven_merge_only(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture command
        (git, "init", "-q"), cwd=tmp_path, check=True, env={}
    )
    message_path = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture query
        (git, "rev-parse", "--git-path", "COMMIT_EDITMSG"),
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env={},
        text=True,
    ).stdout.strip()
    message = Path(message_path)
    if not message.is_absolute():
        message = tmp_path / message
    message.write_text("Merge branch 'feature'\n")
    merge_head = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture query
        (git, "rev-parse", "--git-path", "MERGE_HEAD"),
        cwd=tmp_path,
        check=True,
        capture_output=True,
        env={},
        text=True,
    ).stdout.strip()
    marker = Path(merge_head)
    if not marker.is_absolute():
        marker = tmp_path / marker
    marker.write_text("0" * 40 + "\n")

    assert check_local_commit_message_file(message, root=tmp_path).satisfied
    marker.unlink()
    assert not check_local_commit_message_file(message, root=tmp_path).satisfied


def test_merge_state_does_not_bypass_message_file_safety(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture command
        (git, "init", "-q"), cwd=tmp_path, check=True, env={}
    )
    git_dir = tmp_path / ".git"
    (git_dir / "MERGE_HEAD").write_text("0" * 40 + "\n")
    message = git_dir / "COMMIT_EDITMSG"
    message.write_bytes(b"Merge branch 'feature'\x00\n")

    assert not check_local_commit_message_file(message, root=tmp_path).satisfied
    message.unlink()
    with pytest.raises(ConfigurationError, match="cannot read commit message"):
        check_local_commit_message_file(message, root=tmp_path)


def test_merge_state_cannot_exempt_another_repository_message(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for root in (first, second):
        subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed fixture command
            (git, "init", "-q"), cwd=root, check=True, env={}
        )
    (first / ".git" / "MERGE_HEAD").write_text("0" * 40 + "\n")
    message = second / ".git" / "COMMIT_EDITMSG"
    message.write_text("Merge branch 'feature'\n")

    assert not check_local_commit_message_file(message, root=first).satisfied
