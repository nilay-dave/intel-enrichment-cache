"""Fail when a number published in the README no longer matches a measured one.

Every figure in the README and in docs/ that this tool knows about is tagged in
the source with an HTML comment so the check is explicit rather than a regex hunt
through prose:

    <!--number:audit.blind_technique_pct-->66.7<!--/number-->

The value between the markers must equal the value at that dotted path in
docs/metrics.json, which tools/collect_metrics.py regenerates from executed
code. CI runs collect_metrics.py and then this script, so a number that drifts
breaks the build rather than quietly misleading a reader.

Usage:
    python tools/check_numbers.py [--readme README.md] [--metrics docs/metrics.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Hyphens are allowed in a path segment because this project's metrics are keyed
# by check id and every check id is hyphenated. Without them every published
# firing rate matched ANY_MARKER and not PATTERN, which the loud failure below
# would have reported as an unparseable marker rather than letting it pass
# unchecked, but a correct path should not need working around.
PATTERN = re.compile(r"<!--number:([a-zA-Z0-9_.\-\[\]]+)-->(.*?)<!--/number-->", re.DOTALL)
# Any opening marker at all. A marker that does not match PATTERN, for example
# because its path contains a character the resolver cannot address, used to be
# skipped in silence, so a tagged number went unchecked while the run still
# reported success.
ANY_MARKER = re.compile(r"<!--number:([^>]*)-->")
# A published figure is rounded for a reader, so the check allows the larger of
# an absolute and a relative tolerance. Absolute alone is right for a percentage
# and wrong for a duration: 713 seconds published against 712.742 measured is
# correct rounding, not drift, and demanding 712.742 in a README would be
# absurd precision presented as rigour.
ABSOLUTE_TOLERANCE = 0.05
RELATIVE_TOLERANCE = 0.005


def tolerance_for(measured: float) -> float:
    return max(ABSOLUTE_TOLERANCE, abs(measured) * RELATIVE_TOLERANCE)


def resolve(payload: dict, dotted: str):
    """Walk a dotted path, supporting [index] for lists."""
    node = payload
    for part in dotted.split("."):
        match = re.fullmatch(r"([a-zA-Z0-9_\-]+)\[(\d+)\]", part)
        if match:
            node = node[match.group(1)][int(match.group(2))]
        else:
            node = node[part]
    return node


def normalise(value) -> str:
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def documents(readme: Path) -> list[Path]:
    """The README plus every markdown file under docs/."""
    found = [readme] if readme.exists() else []
    docs = ROOT / "docs"
    if docs.is_dir():
        found.extend(sorted(docs.rglob("*.md")))
    return found


def check(readme: Path, metrics: Path) -> list[str]:
    if not metrics.exists():
        return [f"{metrics} does not exist. Run tools/collect_metrics.py first."]

    payload = json.loads(metrics.read_text(encoding="utf-8"))
    failures: list[str] = []
    checked = 0

    for document in documents(readme):
        # Resolved first. A relative path passed on the command line is not a
        # subpath of ROOT as written, and relative_to raised rather than
        # reporting a finding, so the tool crashed on the one invocation a
        # person would type by hand.
        try:
            where = document.resolve().relative_to(ROOT)
        except ValueError:
            where = document
        text = document.read_text(encoding="utf-8")

        parsed = {m.group(1) for m in PATTERN.finditer(text)}
        for marker in ANY_MARKER.finditer(text):
            path = marker.group(1)
            if path not in parsed:
                failures.append(
                    f"{where}: the marker {path!r} cannot be read as a metrics path, so its number was never checked"
                )

        for match in PATTERN.finditer(text):
            path, published = match.group(1), match.group(2).strip()
            checked += 1
            try:
                measured = resolve(payload, path)
            except (KeyError, IndexError, TypeError):
                failures.append(f"{where}: {path} is not present in {metrics.name}")
                continue

            published_clean = published.replace(",", "").replace("%", "").strip()
            try:
                published_number = float(published_clean)
                measured_number = float(measured)
                if abs(published_number - measured_number) > tolerance_for(measured_number):
                    failures.append(f"{where}: {path} says {published}, measured {normalise(measured)}")
            except (TypeError, ValueError):
                if published != str(measured):
                    failures.append(f"{where}: {path} says {published!r}, measured {measured!r}")

    if checked == 0:
        failures.append("no tagged numbers found in the README or docs, the check is not wired up")
    else:
        print(f"checked {checked} published numbers across {len(documents(readme))} documents")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readme", type=Path, default=ROOT / "README.md")
    parser.add_argument("--metrics", type=Path, default=ROOT / "docs" / "metrics.json")
    args = parser.parse_args()

    failures = check(args.readme, args.metrics)
    for failure in failures:
        print(f"  FAIL  {failure}", file=sys.stderr)
    if failures:
        print(
            f"\n{len(failures)} number(s) out of date. Run make report and update the document.",
            file=sys.stderr,
        )
        return 1
    print("all published numbers match measured values")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
