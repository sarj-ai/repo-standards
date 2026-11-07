import pytest

from repo_standards.core.pull_request_body import (
    missing_required_body_sections,
    missing_template_sections,
)


REQUIRED = ("What & why", "QA impact / blast radius", "Manual test checklist")


@pytest.mark.parametrize(
    ("opening", "candidate"),
    [("````markdown", "```"), ("~~~~", "~~~"), ("```", "```text"), ("~~~", "~~~text")],
)
def test_short_or_nonclosing_fence_cannot_expose_example_headings(
    opening: str, candidate: str
) -> None:
    body = f"{opening}\n{candidate}\n## What & why\nExample only.\n"

    assert missing_template_sections(body, ("What & why",)) == ("What & why",)
    assert missing_required_body_sections(body, ("What & why",)) == ("What & why",)


@pytest.mark.parametrize("closing", ["````", "`````", "   ````  \t"])
def test_equal_or_longer_fence_exposes_the_following_real_heading(closing: str) -> None:
    body = f"````markdown\n## Example\n{closing}\n## What & why\nActual evidence.\n"

    assert missing_required_body_sections(body, ("What & why",)) == ()


@pytest.mark.parametrize("heading", ["## C#", "## C# ###"])
def test_hash_in_heading_text_is_preserved_and_optional_closing_hashes_are_removed(
    heading: str,
) -> None:
    body = f"{heading}\nUpdate the C# contract.\n"

    assert missing_template_sections(body, ("C#",)) == ()
    assert missing_required_body_sections(body, ("C#",)) == ()


def test_backtick_inside_fence_info_does_not_start_a_code_block() -> None:
    assert missing_template_sections("```invalid`info\n## What & why\n", ("What & why",)) == ()


def test_empty_heading_closes_the_previous_section() -> None:
    body = "## What & why\n##\nContent belongs to the empty section.\n"

    assert missing_required_body_sections(body, ("What & why",)) == ("What & why",)


def test_html_comment_text_inside_code_does_not_hide_real_sections() -> None:
    body = "```html\n<!-- This is example source.\n```\n## What & why\nReal evidence.\n"

    assert missing_required_body_sections(body, ("What & why",)) == ()
    assert missing_template_sections(body, ("What & why",)) == ()


@pytest.mark.parametrize("marker", ["-", "1."])
def test_list_code_examples_cannot_supply_required_sections(marker: str) -> None:
    indent = " " * (len(marker) + 1)
    body = f"{marker} ```markdown\n{indent}## What & why\n{indent}Example only.\n{indent}```\n"

    assert missing_required_body_sections(body, ("What & why",)) == ("What & why",)
    assert missing_template_sections(body, ("What & why",)) == ("What & why",)


@pytest.mark.parametrize("marker", ["-", "1."])
def test_comments_in_list_code_do_not_hide_following_real_sections(marker: str) -> None:
    indent = " " * (len(marker) + 1)
    body = (
        f"{marker} ```html\n{indent}<!-- Example source.\n{indent}```\n## What & why\nEvidence.\n"
    )

    assert missing_required_body_sections(body, ("What & why",)) == ()
    assert missing_template_sections(body, ("What & why",)) == ()


def test_fence_text_inside_an_html_comment_does_not_hide_real_sections() -> None:
    body = "<!--\n```markdown\n## Example\n-->\n## What & why\nReal evidence.\n"

    assert missing_required_body_sections(body, ("What & why",)) == ()


def test_body_sections_require_non_comment_content() -> None:
    body = """
## What & why
<!-- fill this in -->

## QA impact / blast radius
N/A

## Manual test checklist
- [x] Opened the page
"""

    assert missing_required_body_sections(body, REQUIRED) == ("What & why",)


def test_body_sections_ignore_headings_inside_fences_and_accept_nested_content() -> None:
    body = """
```markdown
## What & why
not real evidence
```

What & why
==========
### Detail
Small documentation correction.

## QA impact / blast radius
None.

Manual test checklist
---------------------
- [x] Read the rendered document.
"""

    assert missing_required_body_sections(body, REQUIRED) == ()


def test_template_sections_need_headings_but_not_content() -> None:
    template = """
## **What & why**
<!-- Explain the change. -->

## qa impact / BLAST RADIUS:

<!--
## Manual test checklist
-->

```markdown
## Manual test checklist
```
"""

    assert missing_template_sections(template, REQUIRED) == ("Manual test checklist",)


@pytest.mark.parametrize(
    "separator", ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
)
def test_literal_separators_cannot_create_required_headings(separator: str) -> None:
    body = f"Example text{separator}## What & why{separator}Evidence."

    assert missing_template_sections(body, ("What & why",)) == ("What & why",)
    assert missing_required_body_sections(body, ("What & why",)) == ("What & why",)


@pytest.mark.parametrize("ending", ["\r", "\n", "\r\n"])
def test_markdown_line_endings_expose_required_headings(ending: str) -> None:
    body = ending.join(("Intro.", "## What & why", "Evidence."))

    assert missing_template_sections(body, ("What & why",)) == ()
    assert missing_required_body_sections(body, ("What & why",)) == ()


@pytest.mark.parametrize("indent", ["    ", "\t", " \t", "  \t", "   \t"])
@pytest.mark.parametrize("heading", ["## What & why", "What & why\n----", "What & why\n\t----"])
def test_indented_code_cannot_supply_a_heading(indent: str, heading: str) -> None:
    body = f"{indent}{heading}\nEvidence."

    assert missing_template_sections(body, ("What & why",)) == ("What & why",)
    assert missing_required_body_sections(body, ("What & why",)) == ("What & why",)


@pytest.mark.parametrize(
    ("body", "missing"),
    [
        ("## Parent\n### Child\nEvidence.\n", ()),
        ("## Parent\n### Child\n## Peer\nEvidence.\n", ("Parent", "Child")),
        ("## Parent\n### Child\n### Peer\nEvidence.\n", ("Child",)),
        ("## Parent\n### Child\n## Parent\nEvidence.\n", ("Child",)),
        ("## Parent\n### Child\n<!-- Evidence. -->\n", ("Parent", "Child")),
    ],
)
def test_section_content_obeys_ancestor_and_peer_boundaries(
    body: str, missing: tuple[str, ...]
) -> None:
    assert missing_required_body_sections(body, ("Parent", "Child")) == missing


@pytest.mark.parametrize("indent", ["\t", " \t", "  \t", "   \t"])
def test_indented_code_fence_does_not_hide_a_real_heading(indent: str) -> None:
    body = f"{indent}```markdown\n\n## What & why\nEvidence.\n"

    assert missing_template_sections(body, ("What & why",)) == ()
    assert missing_required_body_sections(body, ("What & why",)) == ()


def test_tab_indented_setext_underline_is_code() -> None:
    body = "What & why\n\t----\nEvidence."

    assert missing_template_sections(body, ("What & why",)) == ("What & why",)
    assert missing_required_body_sections(body, ("What & why",)) == ("What & why",)


_MERGE_RISK = """\
## Merge Risk

**Merge risk: medium**
**Alignment:** good ✅
**Impact:** medium 👀
**Verification:** decent 👀
**Rollback cost:** low ✅
**Error detection:** good ✅
"""


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("**Merge risk: medium**", ""),
        ("**Alignment:** good ✅", ""),
        ("**Impact:** medium 👀", "**Impact:** 2"),
        ("**Verification:** decent 👀", "**Verification:** low ✅"),
        ("**Rollback cost:** low ✅", "**Rollback cost:** low ⚠️"),
        ("**Error detection:** good ✅", "**Error detection:** unknown"),
        ("**Alignment:** good ✅", "**Alignment:** good ✅\n**Alignment:** poor ⚠️"),
        ("**Alignment:** good ✅", "<!-- **Alignment:** good ✅ -->"),
        ("**Alignment:** good ✅", "```text\n**Alignment:** good ✅\n```"),
        ("**Merge risk: medium**", "**Merge risk: 2**"),
        ("**Alignment:** good ✅", "**Alignment:** good ✅\nThe change matches the issue."),
        ("## Merge Risk", "## Merge Risk\n\n## Merge Risk"),
    ],
)
def test_merge_risk_requires_the_original_verdict_ratings(old: str, new: str) -> None:
    assert missing_required_body_sections(_MERGE_RISK.replace(old, new), ("Merge Risk",)) == (
        "Merge Risk",
    )


def test_merge_risk_accepts_ratings_without_explanations() -> None:
    assert missing_required_body_sections(_MERGE_RISK, ("Merge Risk",)) == ()
    assert (
        missing_required_body_sections(
            _MERGE_RISK.replace("**Error detection:** good ✅", "**Error detection:** N/A ✅"),
            ("Merge Risk",),
        )
        == ()
    )


def test_merge_risk_does_not_borrow_ratings_from_other_sections() -> None:
    body = _MERGE_RISK.replace("**Alignment:** good ✅\n", "")
    body += "\n## Evidence\n**Alignment:** good ✅\n"

    assert missing_required_body_sections(body, ("Merge Risk",)) == ("Merge Risk",)
