from __future__ import annotations

import pytest

from repo_standards.core.subject import subject_advisories


@pytest.mark.parametrize(
    ("header", "allow_plain", "expected"),
    [
        pytest.param("fix: " + "x" * 72, False, False, id="content-at-target"),
        pytest.param("fix: " + "x" * 73, False, True, id="content-over-target"),
        pytest.param(
            "(1/12) [SARJ-123456] fix(api: v1)!: " + "x" * 72,
            False,
            False,
            id="prefixes-and-colon-scope-are-structure",
        ),
        pytest.param("[SARJ-123] " + "x" * 72, True, False, id="plain-title-prefix"),
        pytest.param("x" * 73, True, True, id="plain-title-over-target"),
        pytest.param("fix: " + "ع" * 72, False, False, id="unicode-codepoints"),
        pytest.param(
            "Merge branch " + "x" * 100, False, False, id="merge-description-is-not-rewritten"
        ),
        pytest.param(
            "fixup! fix: " + "x" * 100, False, False, id="temporary-message-owned-by-syntax"
        ),
        pytest.param("FIX: " + "x" * 100, False, False, id="type-case-owned-by-syntax"),
        pytest.param("fix(@api): " + "x" * 100, False, False, id="invalid-scope-owned-by-syntax"),
        pytest.param("fix: " + "x" * 100 + "\x00", False, False, id="controls-owned-by-syntax"),
    ],
)
def test_subject_advice_counts_only_descriptive_content(
    header: str, allow_plain: bool, *, expected: bool
) -> None:
    warnings = subject_advisories(header, allow_plain=allow_plain)

    assert bool(warnings) is expected
    if warnings:
        assert len(warnings) == 1
        assert warnings[0].code == "subject.too-long"
        assert "essential identifiers" in warnings[0].remediation
