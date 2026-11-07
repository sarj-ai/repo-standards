from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

from .commit_message import descriptive_subject


MAXIMUM_SUBJECT_CHARACTERS = 72
_ISSUE_PREFIX = re.compile(
    r"^(?:\[[1-9][0-9]*\.[0-9]+\] )?(?:gh|bpo)-[1-9][0-9]*: ", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class SubjectAdvisory:
    code: Literal["subject.too-long"]
    message: str
    remediation: str


def subject_advisories(header: str, *, allow_plain: bool = False) -> tuple[SubjectAdvisory, ...]:
    if allow_plain:
        header = _ISSUE_PREFIX.sub("", header, count=1)
    description = descriptive_subject(header, allow_plain=allow_plain)
    if description is None:
        return ()
    characters = _descriptive_characters(description)
    if characters <= MAXIMUM_SUBJECT_CHARACTERS:
        return ()
    return (
        SubjectAdvisory(
            code="subject.too-long",
            message=(
                f"The descriptive subject has {characters} characters; "
                f"target {MAXIMUM_SUBJECT_CHARACTERS}."
            ),
            remediation="Move detail to the body; retain the outcome and essential identifiers.",
        ),
    )


def _descriptive_characters(description: str) -> int:
    subject = description.strip()
    end = len(subject)
    while end and subject[end - 1] == ")":
        start = subject.rfind(" (", 0, end)
        if start < 0:
            break
        reference = subject[start + 2 : end - 1]
        if reference.startswith("#"):
            number = reference[1:]
        elif reference[:3].upper() == "GH-":
            number = reference[3:]
        else:
            break
        if not number or number[0] == "0" or not number.isascii() or not number.isdecimal():
            break
        end = start
        while end and subject[end - 1].isspace():
            end -= 1
    return end
