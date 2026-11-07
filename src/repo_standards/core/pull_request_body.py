from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, NamedTuple

from markdown_it import MarkdownIt


_ATX_HEADING = re.compile(r"^ {0,3}(?P<marks>#{1,6})(?:[ \t]+(?P<title>.*?))?[ \t]*$")
_ATX_CLOSING = re.compile(r"[ \t]+#+[ \t]*$")
_SETEXT_HEADING = re.compile(r"^ {0,3}(?P<marks>=+|-+)[ \t]*$")
_SETEXT_TEXT = re.compile(r"^ {0,3}[^ \t]")
_HEADING_DECORATION = re.compile(r"[*_`]+")
MERGE_RISK_SECTION = "Merge Risk"
_QUALITY_VERDICTS = frozenset({"poor ⚠️", "decent 👀", "good ✅"})
_MERGE_RISK_VERDICTS: Final[dict[str, frozenset[str]]] = {
    "merge risk": frozenset({"low", "medium", "high"}),
    "alignment": _QUALITY_VERDICTS,
    "impact": frozenset({"large ⚠️", "medium 👀", "small ✅"}),
    "verification": _QUALITY_VERDICTS,
    "rollback cost": frozenset({"high ⚠️", "medium 👀", "low ✅"}),
    "error detection": _QUALITY_VERDICTS | {"n/a ✅"},
}


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
    if not required_sections:
        return ()
    code_lines = _code_lines(body)
    lines = _markdown_lines(body, code_lines)
    headings = _headings(lines, code_lines)
    filled = _filled_sections(lines, headings)
    if "merge risk" in filled and not _complete_merge_risk(lines, headings, code_lines):
        filled -= {"merge risk"}
    return tuple(
        required for required in required_sections if _normalized_title(required) not in filled
    )


def _complete_merge_risk(
    lines: list[str], headings: tuple[_Heading, ...], code_lines: frozenset[int]
) -> bool:
    sections = tuple(heading for heading in headings if heading.title == "merge risk")
    if len(sections) != 1:
        return False
    section = sections[0]
    end = next(
        (
            heading.line_index
            for heading in headings
            if heading.line_index > section.line_index and heading.level <= section.level
        ),
        len(lines),
    )
    seen: set[str] = set()
    for index in range(section.content_start, end):
        if index in code_lines:
            return False
        line = _HEADING_DECORATION.sub("", lines[index]).strip()
        if not line:
            continue
        label, separator, value = line.partition(":")
        key = _normalized_title(label)
        if (
            not separator
            or key in seen
            or _normalized_title(value) not in _MERGE_RISK_VERDICTS.get(key, frozenset())
        ):
            return False
        seen.add(key)
    return seen == _MERGE_RISK_VERDICTS.keys()


def missing_template_sections(
    template: str,
    required_sections: tuple[str, ...],
) -> tuple[str, ...]:
    if not required_sections:
        return ()
    code_lines = _code_lines(template)
    titles = {
        heading.title for heading in _headings(_markdown_lines(template, code_lines), code_lines)
    }
    return tuple(
        required for required in required_sections if _normalized_title(required) not in titles
    )


def _code_lines(body: str) -> frozenset[int]:
    return frozenset(
        line
        for token in MarkdownIt("commonmark").parse(body)
        if token.type in {"fence", "code_block"} and token.map is not None
        for line in range(*token.map)
    )


def _markdown_lines(body: str, code_lines: frozenset[int]) -> list[str]:
    lines: list[str] = []
    comment = False
    for index, line in enumerate(re.split(r"\r\n?|\n", body)):
        if index in code_lines:
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


def _headings(lines: list[str], code_lines: frozenset[int]) -> tuple[_Heading, ...]:
    headings: list[_Heading] = []
    index = 0
    while index < len(lines):
        if index in code_lines:
            index += 1
            continue
        heading = _heading_at(lines, index, code_lines)
        if heading is None:
            index += 1
            continue
        headings.append(heading)
        index = heading.content_start
    return tuple(headings)


def _heading_at(lines: list[str], index: int, code_lines: frozenset[int]) -> _Heading | None:
    line = lines[index]
    if (atx := _ATX_HEADING.match(line)) is not None:
        return _Heading(
            title=_normalized_title(_ATX_CLOSING.sub("", atx.group("title") or "")),
            level=len(atx.group("marks")),
            content_start=index + 1,
            line_index=index,
        )
    if (
        index + 1 >= len(lines)
        or index + 1 in code_lines
        or not line.strip()
        or _SETEXT_TEXT.match(line) is None
    ):
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
