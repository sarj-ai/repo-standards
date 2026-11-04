from __future__ import annotations

import pytest

from repo_standards.core.description import DescriptionMetrics, analyze_description


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
