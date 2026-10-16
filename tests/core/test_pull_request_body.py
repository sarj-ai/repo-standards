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
