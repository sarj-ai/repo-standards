from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .commit_message import descriptive_subject


MAXIMUM_SUBJECT_CHARACTERS = 72


@dataclass(frozen=True, slots=True)
class SubjectAdvisory:
    code: Literal["subject.too-long"]
    message: str
    remediation: str


def subject_advisories(header: str, *, allow_plain: bool = False) -> tuple[SubjectAdvisory, ...]:
    description = descriptive_subject(header, allow_plain=allow_plain)
    if description is None:
        return ()
    characters = len(description.strip())
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
