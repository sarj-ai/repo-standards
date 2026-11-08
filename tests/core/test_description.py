from __future__ import annotations

import pytest

from repo_standards.core.description import (
    DescriptionMetrics,
    analyze_description,
    without_bot_footer,
)


FOOTER = (
    "<!-- codesmith:footer -->\n---\n"
    '<a href="https://backend.blacksmith.sh/track/enable-autofix?pr_number=1"><picture>'
    '<source media="(prefers-color-scheme: dark)" srcset="https://assets.invalid/dark.svg">'
    '<img alt="Autofix with [code]smith" src="https://assets.invalid/dark.png"></picture></a>\n'
    '<sup><a href="https://app.blacksmith.sh/pr/1">Open in [code]smith</a> · Need help on this'
    " PR? Tag <code>@codesmith</code> with what you need.</sup>\n\n"
    "<!-- codesmith:autofix:disabled -->\n<!-- /codesmith:footer -->"
)
UNCLOSED = "Fix.\n\n<!-- codesmith:footer -->\nHidden prose.\n"
FENCED = "```text\n<!-- codesmith:footer -->\n```\n\nShown.\n<!-- /codesmith:footer -->\n"
QUOTED = "> <!-- codesmith:footer -->\n> Hidden.\n> <!-- /codesmith:footer -->\n"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(f"Fix.\n\n{FOOTER}", "Fix.\n\n", id="footer-present"),
        pytest.param(
            f"Fix.\r\n\r\n{FOOTER.replace(chr(10), chr(13) + chr(10))}\r\nAfter.",
            "Fix.\r\n\r\nAfter.",
            id="crlf-footer-keeps-trailing-content",
        ),
        pytest.param(f"{FOOTER}\n\nAfter.\n", "\nAfter.\n", id="content-after-close-counts"),
        pytest.param(f"{FOOTER}\n{FOOTER}", f"{FOOTER}", id="only-one-footer"),
        pytest.param(UNCLOSED, UNCLOSED, id="unclosed-marker-strips-nothing"),
        pytest.param(FENCED, FENCED, id="fenced-marker-strips-nothing"),
        pytest.param(QUOTED, QUOTED, id="nested-marker-strips-nothing"),
        pytest.param(
            "<!-- codesmith:footer --> x\nHidden.\n<!-- /codesmith:footer -->",
            "<!-- codesmith:footer --> x\nHidden.\n<!-- /codesmith:footer -->",
            id="marker-must-stand-alone",
        ),
    ],
)
def test_only_a_complete_top_level_bot_footer_is_removed(body: str, expected: str) -> None:
    assert without_bot_footer(body) == expected


@pytest.mark.parametrize(
    ("body", "prose", "examples", "invalid"),
    [
        pytest.param("", 0, 0, 0, id="empty-self-evident-change"),
        pytest.param("Fix retries.", 12, 0, 0, id="short-plain-outcome"),
        pytest.param("**Fix** `retries`.", 12, 0, 0, id="inline-formatting-counts-content"),
        pytest.param("First.\n\nSecond.", 14, 0, 0, id="paragraphs-keep-a-separator"),
        pytest.param("## Fix\n\n- A\n- B", 7, 0, 0, id="headings-and-list-markers"),
        pytest.param(
            "[CI](https://ci.invalid/long/report)", 2, 0, 0, id="link-label-without-destination"
        ),
        pytest.param(
            "[CI][report]\n\n[report]: https://ci.invalid/report",
            2,
            0,
            0,
            id="reference-link-label",
        ),
        pytest.param("![Before](https://images.invalid/result.png)", 6, 0, 0, id="image-alt-text"),
        pytest.param(
            '<a href="https://ci.invalid/report">CI</a>', 2, 0, 0, id="automation-anchor-label"
        ),
        pytest.param(
            "<details><summary>CI</summary>Passed</details>", 8, 0, 0, id="html-visible-text"
        ),
        pytest.param(
            "<!-- instructions -->\nFix.", 4, 0, 0, id="hidden-instructions-still-raw-bounded"
        ),
        pytest.param("&lt;div&gt; &amp; done", 12, 0, 0, id="escaped-html-stays-visible"),
        pytest.param("```python\nvalue = 1\n```", 0, 1, 0, id="typed-example"),
        pytest.param("~~~sql\nSELECT 1;\n~~~~", 0, 1, 0, id="tilde-fence-with-longer-close"),
        pytest.param("````text\n```\n````", 0, 1, 0, id="longer-fence-can-show-backticks"),
        pytest.param("> ```python\n> value = 1\n> ```", 0, 1, 0, id="quoted-example"),
        pytest.param("- ```python\n  value = 1\n  ```", 0, 1, 0, id="list-example"),
        pytest.param("```python\r\nvalue = 1\r\n```", 0, 1, 0, id="crlf-example"),
        pytest.param(
            "Fix.\n\n```diff\n-old\n+new\n```\n\nTested.", 12, 1, 0, id="outcome-example-validation"
        ),
        pytest.param("```py\na\n```\n\n~~~sql\nb\n~~~", 0, 2, 0, id="multiple-compact-examples"),
        pytest.param("```\nvalue = 1\n```", 0, 0, 1, id="missing-language"),
        pytest.param("```python\nvalue = 1", 0, 0, 1, id="unclosed-example"),
        pytest.param(
            "```python\nvalue = 1\n> ```", 0, 0, 1, id="quoted-line-cannot-close-root-fence"
        ),
        pytest.param("```python\n```", 0, 0, 1, id="empty-example"),
        pytest.param("```python\n \t\n```", 0, 0, 1, id="whitespace-example"),
        pytest.param("```{.python}\nvalue = 1\n```", 0, 0, 1, id="non-github-language-syntax"),
        pytest.param("```.\nvalue = 1\n```", 0, 0, 1, id="punctuation-is-not-a-language"),
        pytest.param("```+\nvalue = 1\n```", 0, 0, 1, id="operator-is-not-a-language"),
        pytest.param("    value = 1\n", 9, 0, 0, id="indented-code-uses-prose-budget"),
    ],
)
def test_description_measures_prose_and_code_contracts(
    body: str, prose: int, examples: int, invalid: int
) -> None:
    assert analyze_description(body) == DescriptionMetrics(
        prose_characters=prose, code_examples=examples, invalid_code_examples=invalid
    )


@pytest.mark.parametrize(
    "language", ["python", "SQL", "typescript", "diff", "c++", "c#", "bash", "1c"]
)
def test_example_language_ids_do_not_require_a_language_allowlist(language: str) -> None:
    assert analyze_description(f"```{language}\nexample\n```") == DescriptionMetrics(
        prose_characters=0, code_examples=1, invalid_code_examples=0
    )
