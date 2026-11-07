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
        pytest.param("gh-123: " + "x" * 72, True, False, id="github-issue-prefix"),
        pytest.param("bpo-123: " + "x" * 72, True, False, id="legacy-issue-prefix"),
        pytest.param(
            "[3.14] GH-123: " + "x" * 72 + " (gh-456)",
            True,
            False,
            id="backport-issue-and-source-references",
        ),
        pytest.param("gh-0: " + "x" * 72, True, True, id="zero-issue-prefix"),
        pytest.param("bpo-01: " + "x" * 72, True, True, id="leading-zero-issue-prefix"),
        pytest.param("gh-\u0661: " + "x" * 72, True, True, id="non-ascii-issue-prefix"),
        pytest.param("gh-123 " + "x" * 72, True, True, id="missing-issue-delimiter"),
        pytest.param("Use gh-123: " + "x" * 72, True, True, id="embedded-issue-reference"),
        pytest.param("[3.14] " + "x" * 72, True, True, id="branch-without-issue-prefix"),
        pytest.param("gh-123: bpo-456: " + "x" * 72, True, True, id="only-one-issue-prefix"),
        pytest.param(
            "fix: gh-123: " + "x" * 72,
            False,
            True,
            id="commit-description-retains-leading-issue-text",
        ),
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


@pytest.mark.parametrize(
    ("suffix", "warns"),
    [
        pytest.param(" (#123)", False, id="issue-reference"),
        pytest.param(" (GH-123)", False, id="github-reference"),
        pytest.param(" (gh-123)", False, id="lowercase-github-reference"),
        pytest.param(" (Gh-123)", False, id="mixed-case-github-reference"),
        pytest.param(" (#1) (GH-2)", False, id="reference-chain"),
        pytest.param(" (#1)  (GH-2) ", False, id="reference-chain-spacing"),
        pytest.param(" (v2)", True, id="ordinary-parenthetical"),
        pytest.param(" (#0)", True, id="zero-is-not-a-reference"),
        pytest.param(" (GH-01)", True, id="leading-zero-is-not-a-reference"),
        pytest.param(" (gh-01)", True, id="lowercase-leading-zero-is-not-a-reference"),
        pytest.param(" (#\u0661)", True, id="non-ascii-number"),
        pytest.param(" `(#1)`", True, id="quoted-reference-literal"),
        pytest.param(" (#1) detail", True, id="nonterminal-reference"),
        pytest.param(" (GH-2) detail)", True, id="unmatched-parenthetical"),
    ],
)
def test_terminal_references_do_not_spend_the_descriptive_budget(
    suffix: str, *, warns: bool
) -> None:
    assert bool(subject_advisories("fix: " + "x" * 72 + suffix)) is warns


def test_reference_exclusion_preserves_a_genuinely_long_description() -> None:
    warnings = subject_advisories("fix: " + "x" * 73 + " (#1) (GH-2)")

    assert len(warnings) == 1
    assert warnings[0].message == "The descriptive subject has 73 characters; target 72."


def test_issue_prefix_exclusion_preserves_a_genuinely_long_title() -> None:
    warnings = subject_advisories("[3.14] gh-123: " + "x" * 73 + " (gh-456)", allow_plain=True)

    assert len(warnings) == 1
    assert warnings[0].message == "The descriptive subject has 73 characters; target 72."
