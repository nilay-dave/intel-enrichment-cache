"""Fail when a markdown table has rows of differing width.

Sigma field modifiers are written with a pipe, as in `CommandLine|contains`, and
a pipe inside a table cell ends the cell. Putting real Sigma syntax in a
documentation table silently produces a table with the wrong number of columns,
which renders as a mess on the page and looks fine in the diff.

That happened in docs/false-positives.md, whose central table is a list of
Sigma selections. The fix is to escape the pipe; this is the check that says
when it was forgotten.

Usage:
    python tools/check_tables.py [paths...]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# A pipe that is not preceded by a backslash. Splitting on this is what a
# markdown renderer does, so counting it is counting real columns.
UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
SEPARATOR = re.compile(r"^\s*\|?[\s:|-]+\|[\s:|-]*$")


def columns(row: str) -> int:
    stripped = row.strip()
    cells = UNESCAPED_PIPE.split(stripped)
    # A row written |a|b| has an empty cell at each end; drop them.
    if cells and not cells[0].strip():
        cells = cells[1:]
    if cells and not cells[-1].strip():
        cells = cells[:-1]
    return len(cells)


def check(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    findings: list[str] = []
    table: list[tuple[int, str]] = []
    in_fence = False

    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if UNESCAPED_PIPE.search(line) and line.strip().startswith("|"):
            table.append((number, line))
            continue
        if table:
            findings.extend(_inspect(path, table))
            table = []
    if table:
        findings.extend(_inspect(path, table))
    return findings


def _inspect(path: Path, table: list[tuple[int, str]]) -> list[str]:
    if len(table) < 2:
        return []
    header_line, header = table[0]
    expected = columns(header)
    findings = []
    for number, row in table[1:]:
        if SEPARATOR.match(row):
            width = columns(row)
            if width != expected:
                findings.append(
                    f"{path}:{number}: separator has {width} columns, header on line {header_line} has {expected}"
                )
            continue
        width = columns(row)
        if width != expected:
            findings.append(
                f"{path}:{number}: row has {width} columns, header on line {header_line} has {expected}. "
                f"An unescaped pipe inside a cell ends it; write it as a backslash pipe."
            )
    return findings


def tracked_markdown() -> list[Path]:
    try:
        result = subprocess.run(["git", "ls-files", "-z", "*.md"], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return sorted(Path(".").rglob("*.md"))
    return [Path(name) for name in result.stdout.split("\0") if name]


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or tracked_markdown()
    findings = [f for path in paths if path.is_file() for f in check(path)]
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"\n{len(findings)} malformed table row(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
