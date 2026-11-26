from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache, partial
import html
from pathlib import PurePosixPath
import posixpath
import re
from typing import TYPE_CHECKING
import unicodedata
from urllib.parse import unquote

from repo_standards.core.canonical import nearest_component
from repo_standards.core.models import ComponentId, Diagnostic, Remediation, RuleId, SourceLocation
from repo_standards.policy_sarj.makefiles import is_makefile_path


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from repo_standards.core.models import GeneratedDocument, RepositorySnapshot, RuleDefinition


MARKDOWN_ONLY_RULE_ID = RuleId("repository/documentation/markdown-only-change")
ADDED_MARKDOWN_RULE_ID = RuleId("repository/documentation/added-markdown")
MARKDOWN_WORD_GROWTH_RULE_ID = RuleId("repository/documentation/markdown-word-growth")
GENERATED_DOCUMENTATION_RULE_ID = RuleId("repository/documentation/generated-sources")
LOCAL_LINKS_RULE_ID = RuleId("repository/documentation/local-links")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_CODE_SPAN = re.compile(r"(`+)(.+?)\1")
_LINK_TARGETS = re.compile(r"(?:\]\(|^ {0,3}\[[^\]^][^\]]*\]:)\s*(?:<([^>]+)>|([^)\s]+))")
_NON_RELATIVE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|[#/])")
_LINE_FRAGMENT = re.compile(r"l\d+(?:c\d+)?(?:-l\d+(?:c\d+)?)?")
_ATX_HEADING = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
_SETEXT_UNDERLINE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
_INLINE_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_HTML_TAG = re.compile(r"<[^>]*>")
_FILENAME_LINK = re.compile(r"\[(`?)([\w.-]+\.md)\1\]\(<?([^)>\s#?]+\.md)(?=[#>)\s])")
_HTML_ID = re.compile(r"""\b(?:id|name)\s*=\s*["']?([^"'\s>]+)""")
MAKE_TARGETS_RULE_ID = RuleId("repository/documentation/make-targets")
_SHELL_FENCES = frozenset({"bash", "console", "sh", "shell", "zsh"})
_MAKE_ENTRIES = ("GNUmakefile", "makefile", "Makefile")
_MAKE_TARGET = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_MAKE_DIRECTORY = re.compile(r"[A-Za-z0-9_./-]+")
_MAKE_ARGUMENT_OPTIONS = ("-f", "--file", "--makefile", "-I", "--include-dir", "-o", "-W")
_ASSIGNMENT = re.compile(
    r"(?:(?:export|override|private)\s+)*([^\s:#=$]+)\s*(:{1,3}|[+?!])?=\s*(.*)"
)
_DIRECTIVE = re.compile(r"(?:ifn?eq|ifn?def|else|endif|export|unexport|vpath|undefine)\b")
_DEFINE = re.compile(r"(?:(?:export|override)\s+)*define\b")
_INCLUDE = re.compile(r"(-|s)?include\s+(.*)")
_RULE = re.compile(r"([^:=#]+?)\s*::?(?!=)")
_REFERENCE = re.compile(r"\$[({]([^\s(){}:$]+)[)}]")
_SELF_DIRECTORY = "$(dir $(lastword $(MAKEFILE_LIST)))"
_MAX_MAKE_DEPTH = 8


def added_markdown_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    if comparison is None or len(comparison.added_pages) <= comparison.maximum_added_pages:
        return ()
    path = comparison.added_pages[0]
    component = nearest_component(path, snapshot.manifest.components)
    return (
        Diagnostic(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            severity=rule.severity,
            evidence_level="verified",
            component_id=component.component_id if component else ComponentId("repository"),
            subject_kind="documentation",
            observed=str(len(comparison.added_pages)),
            expected=str(comparison.maximum_added_pages),
            observed_value=len(comparison.added_pages),
            expected_value=comparison.maximum_added_pages,
            message=(
                f"Added {len(comparison.added_pages)} Markdown paths; the trusted base allows "
                f"{comparison.maximum_added_pages}. Review whether another page is necessary."
            ),
            path=path,
            manifest_anchor=f"tracked_files.{path}",
            location=SourceLocation(path, line=1),
            remediation=Remediation(
                summary="Prefer updating an existing canonical document or native CLI help.",
                steps=(
                    "Keep audit reports, rehearsal notes and task logs outside application source.",
                    "Retain required documentation; do not rename it merely to avoid review.",
                    "Review necessary additions using the existing documentation page budget.",
                ),
                validation=("Rerun the same Git comparison after reviewing the added paths.",),
            ),
            baselineable=False,
        ),
    )


def markdown_only_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    if comparison is None or not comparison.markdown_only_paths:
        return ()
    path = comparison.markdown_only_paths[0]
    component = nearest_component(path, snapshot.manifest.components)
    return (
        Diagnostic(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            severity=rule.severity,
            evidence_level="verified",
            component_id=component.component_id if component else ComponentId("repository"),
            subject_kind="documentation",
            observed="Markdown-only change",
            expected="Review whether this needs a standalone pull request",
            message=(
                "This Git comparison changes only Markdown files. "
                "Review the value of a standalone documentation PR."
            ),
            path=path,
            manifest_anchor=f"tracked_files.{path}",
            location=SourceLocation(path, line=1),
            remediation=Remediation(
                summary="Keep necessary documentation with the change it explains when practical.",
                steps=(
                    "Retain required guides, operational contracts and useful corrections.",
                    "Keep task logs outside source; do not rename files to bypass review.",
                ),
                validation=("Compare the full pull request with its explicit base using --base.",),
            ),
            baselineable=False,
        ),
    )


def markdown_word_growth_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    if comparison is None or comparison.added_words <= comparison.maximum_added_words:
        return ()
    return (
        Diagnostic(
            rule_id=rule.rule_id,
            rule_version=rule.version,
            severity=rule.severity,
            evidence_level="verified",
            component_id=ComponentId("repository"),
            subject_kind="documentation",
            observed=str(comparison.added_words),
            expected=str(comparison.maximum_added_words),
            observed_value=comparison.added_words,
            expected_value=comparison.maximum_added_words,
            message=(
                f"Tracked Markdown grew by {comparison.added_words} net words; the trusted "
                f"base allows {comparison.maximum_added_words}."
            ),
            path=snapshot.provenance.manifest_path,
            manifest_anchor="documentation.maximum_added_words",
            remediation=Remediation(
                summary="Trim or replace existing Markdown so the net growth fits the budget.",
                steps=(
                    "Delete stale, duplicated or history text and link the canonical page.",
                    "Move checkable instructions into rules, tests or native CLI help.",
                    "Keep required contracts; do not rename or reformat text to hide growth.",
                ),
                validation=("Rerun the same Git comparison and require no active findings.",),
            ),
            baselineable=False,
        ),
    )


def generated_documentation_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    comparison = snapshot.documentation_comparison
    policy = snapshot.manifest.documentation
    if comparison is None or policy is None:
        return ()
    tracked = frozenset(item.path for item in snapshot.inspection.tracked_files)
    changed = comparison.changed_paths
    source_changes = frozenset(changed).difference(
        *(_paths_under(changed, item.path) for item in policy.generated)
    )
    diagnostics: list[Diagnostic] = []
    for index, document in enumerate(policy.generated):
        finding = partial(_generated_diagnostic, rule, document, index)
        edited = [path for path in _paths_under(changed, document.path) if path in tracked]
        if not _paths_under(tracked, document.source):
            diagnostics.append(
                finding(document.source, f"Generator source {document.source} is not tracked.")
            )
        elif not _paths_under(tracked, document.path):
            diagnostics.append(
                finding(document.path, f"Generated {document.path} is declared but not tracked.")
            )
        elif edited and not _paths_under(source_changes, document.source):
            diagnostics.append(
                finding(edited[0], f"Generated {edited[0]} changed without {document.source}.")
            )
    return (
        *diagnostics,
        *_undeclared_diagnostics(rule, comparison.linguist_generated, policy.generated),
    )


def _paths_under(paths: Iterable[str], prefix: str) -> list[str]:
    return sorted(path for path in paths if path == prefix or path.startswith(f"{prefix}/"))


def _generated_diagnostic(
    rule: RuleDefinition, document: GeneratedDocument, index: int, path: str, message: str
) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="generated-documentation",
        observed=path,
        expected=f"{document.path} regenerated from {document.source}",
        message=message,
        path=path,
        manifest_anchor=f"documentation.generated[{index}]",
        remediation=Remediation(
            summary=f"Regenerate {document.path} with `{document.command}`.",
            steps=(
                "Change the generator source or its inputs, not the generated output.",
                "Commit the regenerated output together with the source change.",
                "Update or remove the documentation.generated entry when the generator moves.",
            ),
            validation=("Rerun the same Git comparison and require no active findings.",),
        ),
        baselineable=False,
    )


def local_link_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    tracked = {item.path for item in snapshot.inspection.tracked_files}
    targets = tracked | {str(parent) for path in tracked for parent in PurePosixPath(path).parents}
    pages = {
        text.path: text.content for text in snapshot.tracked_texts if text.path.endswith(".md")
    }
    anchors = cache(_anchors)
    return tuple(
        _local_link_diagnostic(rule, path=path, finding=finding)
        for path, content in pages.items()
        for finding in (
            *_broken_links(path, content, targets, pages, anchors),
            *_misnamed_links(path, content, targets),
        )
    )


@dataclass(frozen=True, slots=True)
class _LinkFinding:
    line: int
    target: str
    expected: str
    message: str
    anchor: str


def _broken_links(
    path: str,
    content: str,
    targets: set[str],
    pages: dict[str, str],
    anchors: Callable[[str], frozenset[str]],
) -> Iterator[_LinkFinding]:
    for target, line in _relative_links(content).items():
        resolved = _resolve(path, target)
        if resolved not in targets:
            message = f"Link {target} does not resolve to a tracked path."
            yield _LinkFinding(line, target, "a tracked file or directory", message, target)
        elif (page := pages.get(resolved)) is not None and _missing_anchor(target, page, anchors):
            message = f"Link {target} names no heading anchor in {resolved}."
            yield _LinkFinding(line, target, f"a heading anchor in {resolved}", message, target)


def _misnamed_links(path: str, content: str, targets: set[str]) -> Iterator[_LinkFinding]:
    for number, line in _prose_lines(content):
        spans = [match.span() for match in _CODE_SPAN.finditer(line)]
        for match in _FILENAME_LINK.finditer(line):
            name, target = match.group(2), match.group(3)
            resolved = _resolve(path, target)
            basename = posixpath.basename(resolved)
            if (
                resolved in targets
                and name.lower() != basename.lower()
                and not any(start < match.start() < end for start, end in spans)
            ):
                message = f"Link text {name} names a different file than {target}."
                yield _LinkFinding(number, target, basename, message, f"{target}.text")


def _prose_lines(content: str) -> Iterator[tuple[int, str]]:
    fence = ""
    for number, line in enumerate(content.splitlines(), start=1):
        if marker := _FENCE.match(line):
            opened = marker.group(1)
            if not fence:
                fence = opened
            elif opened[0] == fence[0] and len(opened) >= len(fence):
                fence = ""
            yield number, ""
        elif not fence:
            yield number, line


def _relative_links(content: str) -> dict[str, int]:
    links: dict[str, int] = {}
    for number, line in _prose_lines(content):
        for match in _LINK_TARGETS.finditer(_CODE_SPAN.sub("", line)):
            target = match.group(1) or match.group(2)
            if not _NON_RELATIVE.match(target):
                links.setdefault(target, number)
    return links


def _resolve(page: str, target: str) -> str:
    path = unquote(target.split("#", 1)[0].split("?", 1)[0])
    return posixpath.normpath(posixpath.join(posixpath.dirname(page), path)) if path else "."


def _missing_anchor(target: str, page: str, anchors: Callable[[str], frozenset[str]]) -> bool:
    fragment = _fragment(target)
    return fragment is not None and fragment not in anchors(page)


def _fragment(target: str) -> str | None:
    path, _, fragment = target.partition("#")
    fragment = unquote(fragment).lower()
    if "?" in path or not fragment or ":~:" in fragment or _LINE_FRAGMENT.fullmatch(fragment):
        return None
    return fragment


def _anchors(content: str) -> frozenset[str]:
    anchors = {match.group(1).lower() for match in _HTML_ID.finditer(content)}
    counts: dict[str, int] = {}
    previous = ""
    for _, line in _prose_lines(content):
        if heading := _ATX_HEADING.match(line):
            text = heading.group(1) or ""
        elif previous.strip() and _SETEXT_UNDERLINE.match(line):
            text = previous
        else:
            previous = line
            continue
        previous = ""
        rendered = html.unescape(_HTML_TAG.sub("", _INLINE_LINK.sub(r"\1", text)))
        for slug in {_slug(rendered), _slug(rendered.replace("_", ""))}:
            count = counts.get(slug, 0)
            counts[slug] = count + 1
            anchors.add(f"{slug}-{count}" if count else slug)
    return frozenset(anchors)


def _slug(text: str) -> str:
    kept = (
        character
        for character in text.strip().lower()
        if character in " -_" or unicodedata.category(character)[0] in "LMN"
    )
    return "".join(kept).replace(" ", "-")


def _local_link_diagnostic(rule: RuleDefinition, *, path: str, finding: _LinkFinding) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="documentation-link",
        observed=finding.target,
        expected=finding.expected,
        message=finding.message,
        path=path,
        manifest_anchor=f"tracked_files.{path}.links.{finding.anchor}",
        location=SourceLocation(path, line=finding.line),
        remediation=Remediation(
            summary="Point the link and its text at the tracked page or heading, or remove it.",
            steps=(
                "Update the link when its page or heading moved; remove it when it was deleted.",
                "Use an absolute URL for content outside this repository.",
            ),
            validation=("Rerun repo-standards and require no active findings.",),
        ),
    )


def _undeclared_diagnostics(
    rule: RuleDefinition, paths: tuple[str, ...], generated: tuple[GeneratedDocument, ...]
) -> tuple[Diagnostic, ...]:
    declared = frozenset(path for item in generated for path in _paths_under(paths, item.path))
    return tuple(_undeclared_diagnostic(rule, path) for path in paths if path not in declared)


def _undeclared_diagnostic(rule: RuleDefinition, path: str) -> Diagnostic:
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="generated-documentation",
        observed=path,
        expected=f"a documentation.generated entry covering {path}",
        message=f"{path} is linguist-generated but has no declared generator.",
        path=path,
        manifest_anchor="documentation.generated",
        remediation=Remediation(
            summary=f"Declare the generator of {path} under documentation.generated.",
            steps=(
                "Add a documentation.generated entry whose path covers the output.",
                "Remove linguist-generated from .gitattributes when the page is hand-maintained.",
            ),
            validation=("Rerun the same Git comparison and require no active findings.",),
        ),
        baselineable=False,
    )


def is_make_source(path: str) -> bool:
    return is_makefile_path(path) or path.rpartition("/")[2].startswith("Make")


def make_target_diagnostics(
    snapshot: RepositorySnapshot, *, rule: RuleDefinition
) -> tuple[Diagnostic, ...]:
    tracked = {item.path for item in snapshot.inspection.tracked_files}
    tracked |= {str(parent) for path in tracked for parent in PurePosixPath(path).parents}
    targets = _directory_targets(snapshot)
    return tuple(
        _make_target_diagnostic(rule, path=page.path, line=line, directory=directory, target=target)
        for page in snapshot.tracked_texts
        if page.path.endswith(".md")
        for (directory, target), line in _make_invocations(page.content).items()
        if _missing_target(
            target, _make_candidates(page.path, directory, targets), targets, tracked
        )
    )


def _directory_targets(snapshot: RepositorySnapshot) -> dict[str, frozenset[str] | None]:
    sources = {
        item.path: item.content for item in snapshot.tracked_texts if is_make_source(item.path)
    }
    entries = [path for path in sources if path.rpartition("/")[2] in _MAKE_ENTRIES]
    directories = {_directory(posixpath.dirname(path)) for path in entries}
    return {directory: _make_targets(directory, sources) for directory in directories}


def _make_candidates(
    page: str, directory: str | None, targets: dict[str, frozenset[str] | None]
) -> set[str]:
    if directory is None:
        return set(targets)
    paths = (directory, posixpath.join(posixpath.dirname(page), directory))
    return {_directory(posixpath.normpath(path)) for path in paths} & set(targets)


def _missing_target(
    target: str,
    candidates: set[str],
    targets: dict[str, frozenset[str] | None],
    tracked: set[str],
) -> bool:
    resolved = [targets[candidate] for candidate in candidates]
    defined = [item for item in resolved if item is not None]
    if not resolved or len(defined) < len(resolved):
        return False
    return not any(_defines(item, target) for item in defined) and not any(
        posixpath.join(candidate, target) in tracked for candidate in candidates
    )


def _directory(path: str) -> str:
    return "" if path in {"", "."} else path


def _make_invocations(content: str) -> dict[tuple[str | None, str], int]:
    found: dict[tuple[str | None, str], int] = {}
    for number, command in _shell_commands(content):
        for segment in re.split(r"&&|\|\|?|;", command):
            for invocation in _make_invocation(segment.split()):
                found.setdefault(invocation, number)
    return found


def _shell_commands(content: str) -> Iterator[tuple[int, str]]:
    fence = ""
    shell = False
    for number, line in enumerate(content.splitlines(), start=1):
        if marker := _FENCE.match(line):
            opened = marker.group(1)
            if not fence:
                fence = opened
                shell = line[marker.end() :].strip().partition(" ")[0].lower() in _SHELL_FENCES
            elif opened[0] == fence[0] and len(opened) >= len(fence):
                fence = ""
        elif not fence:
            yield from ((number, match.group(2)) for match in _CODE_SPAN.finditer(line))
        elif shell:
            yield number, line


def _make_invocation(words: list[str]) -> tuple[tuple[str | None, str], ...]:
    if "--" in words:
        words = words[words.index("--") + 1 :]
    while words and (words[0] == "$" or "=" in words[0]):
        words = words[1:]
    if not words or words[0] != "make":
        return ()
    directory: str | None = None
    targets: list[str] = []
    remaining = iter(words[1:])
    for word in remaining:
        if word.startswith("#"):
            break
        if word.startswith(_MAKE_ARGUMENT_OPTIONS):
            return ()
        if word.startswith(("-C", "--directory=")):
            path = word.removeprefix("--directory=").removeprefix("-C") or next(remaining, "")
            if not _MAKE_DIRECTORY.fullmatch(path):
                return ()
            directory = posixpath.join(directory or "", path)
        elif _MAKE_TARGET.fullmatch(word):
            targets.append(word)
    return tuple((directory, target) for target in targets)


def _make_targets(directory: str, sources: dict[str, str]) -> frozenset[str] | None:
    entry = next(
        (path for name in _MAKE_ENTRIES if (path := posixpath.join(directory, name)) in sources),
        None,
    )
    makefiles = _Makefiles(directory, sources)
    if entry is None or not makefiles.read(entry, depth=0):
        return None
    return frozenset(makefiles.targets)


@dataclass(slots=True)
class _Makefiles:
    directory: str
    sources: dict[str, str]
    targets: set[str] = field(default_factory=set[str])
    variables: dict[str, str | None] = field(default_factory=dict[str, str | None])

    def read(self, path: str, *, depth: int) -> bool:
        relative = posixpath.relpath(posixpath.dirname(path) or ".", self.directory or ".")
        self_directory = "" if relative == "." else f"{relative}/"
        define = False
        for raw in re.sub(r"\\\n[ \t]*", " ", self.sources[path]).splitlines():
            if define:
                define = not raw.strip().startswith("endef")
                continue
            line = raw.split("#", 1)[0].strip().replace(_SELF_DIRECTORY, self_directory)
            if raw.startswith("\t") or not line:
                continue
            if _DEFINE.match(line):
                define = True
            elif not self._read_line(line, depth=depth):
                return False
        return True

    def _read_line(self, line: str, *, depth: int) -> bool:
        if assignment := _ASSIGNMENT.fullmatch(line):
            name, operator, value = assignment.groups()
            same = self.variables.get(name, value) == value
            self.variables[name] = value if operator != "+" and same else None
            return True
        if include := _INCLUDE.fullmatch(line):
            names = self._expand(include.group(2))
            return (
                names is not None
                and depth < _MAX_MAKE_DEPTH
                and all(
                    self._include(name, include.group(1), depth=depth) for name in names.split()
                )
            )
        if rule := _RULE.match(line):
            names = self._expand(rule.group(1))
            self.targets.update(names.split() if names else ())
            return names is not None
        return bool(_DIRECTIVE.match(line)) or "$" not in line

    def _include(self, name: str, optional: str | None, *, depth: int) -> bool:
        path = posixpath.normpath(posixpath.join(self.directory, name))
        if path in self.sources:
            return self.read(path, depth=depth + 1)
        return optional is not None

    def _expand(self, text: str) -> str | None:
        for _ in range(_MAX_MAKE_DEPTH):
            if "$" not in text:
                return text
            names: list[str] = _REFERENCE.findall(text)
            if not names or any(self.variables.get(name) is None for name in names):
                return None
            text = _REFERENCE.sub(lambda match: self.variables.get(match.group(1)) or "", text)
        return None


def _defines(targets: frozenset[str], target: str) -> bool:
    return target in targets or any(
        len(target) > len(prefix) + len(suffix)
        and target.startswith(prefix)
        and target.endswith(suffix)
        for pattern in targets
        if "%" in pattern
        for prefix, _, suffix in (pattern.partition("%"),)
    )


def _make_target_diagnostic(
    rule: RuleDefinition, *, path: str, line: int, directory: str | None, target: str
) -> Diagnostic:
    command = f"make {target}" if directory is None else f"make -C {directory} {target}"
    return Diagnostic(
        rule_id=rule.rule_id,
        rule_version=rule.version,
        severity=rule.severity,
        evidence_level="verified",
        component_id=ComponentId("repository"),
        subject_kind="documentation-command",
        observed=command,
        expected="a target defined by the tracked Makefile",
        message=f"`{command}` names no target in the tracked Makefiles.",
        path=path,
        manifest_anchor=f"tracked_files.{path}.make.{command}",
        location=SourceLocation(path, line=line),
        remediation=Remediation(
            summary="Name the current target or remove the stale command.",
            steps=(
                "Update the command when the target was renamed or moved to another Makefile.",
                "Remove the step when the target was deleted.",
            ),
            validation=("Rerun repo-standards and require no active findings.",),
        ),
    )
