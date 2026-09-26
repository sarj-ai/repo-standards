from __future__ import annotations

from dataclasses import dataclass
import re


_HTML_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_ATX_HEADING = re.compile(r"^[ \t]{0,3}(?P<marks>#{1,6})[ \t]+(?P<title>.*?)[ \t]*#*[ \t]*$")
_SETEXT_HEADING = re.compile(r"^[ \t]{0,3}(?P<marks>=+|-+)[ \t]*$")
_FENCE = re.compile(r"^[ \t]{0,3}(?P<marks>`{3,}|~{3,})")
_HEADING_DECORATION = re.compile(r"[*_`]+")


@dataclass(frozen=True, slots=True)
class _Heading:
    title: str
    level: int
    content_start: int
    line_index: int


def missing_required_body_sections(
    body: str,
    required_sections: tuple[str, ...],
) -> tuple[str, ...]:
    lines = _HTML_COMMENT.sub("", body).splitlines()
    headings = _headings(lines)
    missing: list[str] = []
    for required in required_sections:
        expected = _normalized_title(required)
        matching = tuple(heading for heading in headings if heading.title == expected)
        if not matching or not any(_has_content(lines, heading, headings) for heading in matching):
            missing.append(required)
    return tuple(missing)


def _headings(lines: list[str]) -> tuple[_Heading, ...]:
    headings: list[_Heading] = []
    fence: str | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        if (fence_match := _FENCE.match(line)) is not None:
            marks = fence_match.group("marks")
            if fence is None:
                fence = marks[0]
            elif marks[0] == fence:
                fence = None
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
            title=_normalized_title(atx.group("title")),
            level=len(atx.group("marks")),
            content_start=index + 1,
            line_index=index,
        )
    if index + 1 >= len(lines) or not line.strip():
        return None
    if (setext := _SETEXT_HEADING.match(lines[index + 1])) is None:
        return None
    return _Heading(
        title=_normalized_title(line),
        level=1 if setext.group("marks").startswith("=") else 2,
        content_start=index + 2,
        line_index=index,
    )


def _has_content(
    lines: list[str],
    heading: _Heading,
    headings: tuple[_Heading, ...],
) -> bool:
    end = len(lines)
    for candidate in headings:
        if candidate.line_index > heading.line_index and candidate.level <= heading.level:
            end = candidate.line_index
            break
    heading_lines = {
        index
        for candidate in headings
        for index in range(candidate.line_index, candidate.content_start)
    }
    content = "\n".join(
        line
        for index, line in enumerate(lines[heading.content_start : end], heading.content_start)
        if index not in heading_lines
    )
    return bool(content.strip())


def _normalized_title(value: str) -> str:
    undecorated = _HEADING_DECORATION.sub("", value).strip().removesuffix(":")
    return " ".join(undecorated.casefold().split())
