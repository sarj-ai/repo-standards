from repo_standards.core.pull_request_body import missing_required_body_sections


REQUIRED = ("What & why", "QA impact / blast radius", "Manual test checklist")


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
