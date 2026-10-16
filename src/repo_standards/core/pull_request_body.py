from __future__ import annotations

from dataclasses import dataclass
import re
from typing import NamedTuple


_ATX_HEADING = re.compile(r"^ {0,3}(?P<marks>#{1,6})(?:[ \t]+(?P<title>.*?))?[ \t]*$")
_ATX_CLOSING = re.compile(r"[ \t]+#+[ \t]*$")
_SETEXT_HEADING = re.compile(r"^ {0,3}(?P<marks>=+|-+)[ \t]*$")
_SETEXT_TEXT = re.compile(r"^ {0,3}[^ \t]")
_FENCE = re.compile(r"^ {0,3}(?P<marks>`{3,}|~{3,})(?P<tail>.*)$")
_HEADING_DECORATION = re.compile(r"[*_`]+")


@dataclass(frozen=True, slots=True)
class _Heading:
    title: str
    level: int
    content_start: int
    line_index: int


class _CommentLine(NamedTuple):
    text: str
    continues: bool


def missing_required_body_sections(
    body: str,
    required_sections: tuple[str, ...],
) -> tuple[str, ...]:
    lines = _markdown_lines(body)
    headings = _headings(lines)
    filled = _filled_sections(lines, headings)
    return tuple(
        required for required in required_sections if _normalized_title(required) not in filled
    )


def missing_template_sections(
    template: str,
    required_sections: tuple[str, ...],
) -> tuple[str, ...]:
    titles = {heading.title for heading in _headings(_markdown_lines(template))}
    return tuple(
        required for required in required_sections if _normalized_title(required) not in titles
    )


def _markdown_lines(body: str) -> list[str]:
    lines: list[str] = []
    fence: str | None = None
    comment = False
    for line in re.split(r"\r\n?|\n", body):
        if not comment and (matched := _FENCE.match(line)) is not None:
            fence = _fence_state(matched, fence)
            lines.append(line)
            continue
        if fence is not None:
            lines.append(line)
            continue
        stripped = _strip_line_comments(line, comment=comment)
        comment = stripped.continues
        lines.append(stripped.text)
    return lines


def _strip_line_comments(line: str, *, comment: bool) -> _CommentLine:
    parts: list[str] = []
    cursor = 0
    while cursor < len(line):
        delimiter = "-->" if comment else "<!--"
        boundary = line.find(delimiter, cursor)
        if not comment:
            parts.append(line[cursor:] if boundary < 0 else line[cursor:boundary])
        if boundary < 0:
            break
        comment = not comment
        cursor = boundary + len(delimiter)
    return _CommentLine("".join(parts), comment)


def _fence_state(matched: re.Match[str], fence: str | None) -> str | None:
    marks, tail = matched.group("marks", "tail")
    if fence is None:
        return None if marks[0] == "`" and "`" in tail else marks
    if marks[0] == fence[0] and len(marks) >= len(fence) and not tail.strip():
        return None
    return fence


def _headings(lines: list[str]) -> tuple[_Heading, ...]:
    headings: list[_Heading] = []
    fence: str | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        if (fence_match := _FENCE.match(line)) is not None:
            fence = _fence_state(fence_match, fence)
            index += 1
            continue
        if fence is not None:
            index += 1
            continue
        heading = _heading_at(lines, index)
        if heading is None:
            index += 1
            continue
        headings.append(heading)
        index = heading.content_start
    return tuple(headings)


def _heading_at(lines: list[str], index: int) -> _Heading | None:
    line = lines[index]
    if (atx := _ATX_HEADING.match(line)) is not None:
        return _Heading(
            title=_normalized_title(_ATX_CLOSING.sub("", atx.group("title") or "")),
            level=len(atx.group("marks")),
            content_start=index + 1,
            line_index=index,
        )
    if index + 1 >= len(lines) or not line.strip() or _SETEXT_TEXT.match(line) is None:
        return None
    if (setext := _SETEXT_HEADING.match(lines[index + 1])) is None:
        return None
    return _Heading(
        title=_normalized_title(line),
        level=1 if setext.group("marks").startswith("=") else 2,
        content_start=index + 2,
        line_index=index,
    )


def _filled_sections(lines: list[str], headings: tuple[_Heading, ...]) -> frozenset[str]:
    active: list[_Heading] = []
    filled: set[str] = set()
    for index, heading in enumerate(headings):
        while active and active[-1].level >= heading.level:
            active.pop()
        active.append(heading)
        end = headings[index + 1].line_index if index + 1 < len(headings) else len(lines)
        if any(line.strip() for line in lines[heading.content_start : end]):
            filled.update(ancestor.title for ancestor in active)
    return frozenset(filled)


def _normalized_title(value: str) -> str:
    undecorated = _HEADING_DECORATION.sub("", value).strip().removesuffix(":")
    return " ".join(undecorated.casefold().split())
