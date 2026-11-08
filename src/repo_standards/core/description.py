from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import re
from typing import TYPE_CHECKING, override

from markdown_it import MarkdownIt


if TYPE_CHECKING:
    from collections.abc import Sequence

    from markdown_it.token import Token


_LANGUAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+#.-]*\Z")
_LINE_END = re.compile(r"(?<=\n)|(?<=\r)(?!\n)")
_BOT_FOOTER_OPEN = "<!-- codesmith:footer -->"
_BOT_FOOTER_CLOSE = "<!-- /codesmith:footer -->"


@dataclass(frozen=True, slots=True)
class DescriptionMetrics:
    prose_characters: int
    code_examples: int
    invalid_code_examples: int


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    @override
    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _html_text(value: str) -> str:
    parser = _HTMLText()
    parser.feed(value)
    parser.close()
    return "".join(parser.parts)


def without_bot_footer(body: str) -> str:
    start: int | None = None
    for token in _markdown().parse(body):
        if token.type != "html_block" or token.level or token.map is None:
            continue
        marker = token.content.strip()
        if start is None and marker == _BOT_FOOTER_OPEN:
            start = token.map[0]
        elif start is not None and marker == _BOT_FOOTER_CLOSE:
            lines = _LINE_END.split(body)
            return "".join(lines[:start] + lines[token.map[1] :])
    return body


def _markdown() -> MarkdownIt:
    return MarkdownIt("commonmark").enable(["table", "strikethrough"])


def analyze_description(body: str) -> DescriptionMetrics:
    tokens = _markdown().parse(body)
    prose: list[str] = []
    examples = 0
    invalid = 0
    for token in tokens:
        if token.type == "fence":
            language = token.info.split(maxsplit=1)
            content_lines = token.content.count("\n") + int(
                bool(token.content) and not token.content.endswith("\n")
            )
            closed = token.map is not None and token.map[1] - token.map[0] == content_lines + 2
            if (
                closed
                and language
                and _LANGUAGE_ID.fullmatch(language[0]) is not None
                and token.content.strip()
            ):
                examples += 1
            else:
                invalid += 1
        elif token.type == "inline" and token.children is not None:
            prose.append(_inline_text(token.children))
        elif token.type == "html_block":
            prose.append(_html_text(token.content))
        elif token.type == "code_block":
            prose.append(token.content.rstrip())
    return DescriptionMetrics(
        prose_characters=len("\n".join(part for part in prose if part).strip()),
        code_examples=examples,
        invalid_code_examples=invalid,
    )


def _inline_text(tokens: Sequence[Token]) -> str:
    parts: list[str] = []
    for token in tokens:
        if token.children is not None:
            parts.append(_inline_text(token.children))
        elif token.type in {"text", "code_inline"}:
            parts.append(token.content)
        elif token.type in {"softbreak", "hardbreak"}:
            parts.append("\n")
        elif token.type == "html_inline":
            parts.append(_html_text(token.content))
    return "".join(parts)
