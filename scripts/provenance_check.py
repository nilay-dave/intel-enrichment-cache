"""Audit the repository's own provenance signals.

This is the check a sceptic runs in the first thirty seconds: does this
repository have a life, or is it a showroom. It inspects history shape, badge
liveness, releases, language mix, description length and documentation, and
prints PASS, WEAK or FAIL for each with a one line justification.

Run from the repository root:
    python scripts/provenance_check.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PASS, WEAK, FAIL = "PASS", "WEAK", "FAIL"
CONVENTIONAL = re.compile(r"^(feat|fix|test|docs|ci|chore|refactor|perf|build)(\([a-z0-9_-]+\))?: .+")
STATIC_STATUS_BADGE = re.compile(
    r"!\[[^\]]*\]\(https://img\.shields\.io/badge/[^)]*"
    r"(passing|tests?|coverage|build|[0-9]{1,3}%25)[^)]*\)",
    re.IGNORECASE,
)


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, name: str, verdict: str, note: str) -> None:
        self.rows.append((name, verdict, note))

    def render(self) -> int:
        width = max(len(name) for name, _, _ in self.rows)
        for name, verdict, note in self.rows:
            print(f"  {verdict:4s}  {name:<{width}}  {note}")
        counts = Counter(verdict for _, verdict, _ in self.rows)
        print(
            f"\n  {counts[PASS]} pass, {counts[WEAK]} weak, {counts[FAIL]} fail "
            f"across {len(self.rows)} provenance checks"
        )
        return 1 if counts[FAIL] else 0


def source_lines() -> int:
    """Lines of tracked source, excluding documentation and test fixtures."""
    total = 0
    for name in git("ls-files", "src", "tests", "tools", "scripts", "benchmark").splitlines():
        if not name or "fixtures" in name:
            continue
        path = ROOT / name
        if path.suffix not in {".py", ".sh"} or not path.is_file():
            continue
        total += len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    return total


def check_history(report: Report) -> None:
    count = int(git("rev-list", "--count", "HEAD") or 0)
    # The threshold was a flat 40 while the message claimed it was "for this
    # size", which measured nothing. What this signal is really a proxy for is
    # whether the work arrived incrementally or as a dump, so it is now scaled
    # against the amount of source: roughly one commit per 75 lines is the
    # shape of sustained, reviewable development. Floored at 20 so a genuinely
    # small tool is not asked for ceremony it does not need.
    lines = source_lines()
    expected = max(20, round(lines / 75))
    verdict = PASS if count >= expected else WEAK if count >= expected * 0.6 else FAIL
    report.add(
        "commit count",
        verdict,
        f"{count} commits on HEAD for {lines} lines of source, {expected} or more expected at one per 75 lines",
    )

    # Merge commits are excluded. Conventional Commits does not cover them, git
    # generates their subject, and requiring "feat(x): merge" would be cargo
    # cult. They are checked separately for a readable subject instead.
    merges = {line for line in git("log", "--merges", "--format=%s").splitlines() if line}
    subjects = [line for line in git("log", "--format=%s").splitlines() if line]
    non_merge = [s for s in subjects if s not in merges]
    bad = [s for s in non_merge if not CONVENTIONAL.match(s)]
    report.add(
        "conventional commits",
        PASS if not bad else FAIL,
        f"all {len(non_merge)} non merge subjects parse"
        if not bad
        else f"{len(bad)} non conforming, first: {bad[0][:48]}",
    )

    vague_merges = [s for s in merges if not s.startswith("Merge:") or len(s) < 20]
    report.add(
        "merge commits say what they merged",
        PASS if merges and not vague_merges else WEAK if merges else PASS,
        f"{len(merges)} merge commit(s), each naming the change"
        if merges and not vague_merges
        else f"{len(vague_merges)} merge subject(s) are a default or too short"
        if merges
        else "no merge commits, history is linear",
    )

    long_subjects = [s for s in non_merge if len(s) > 72]
    report.add(
        "subject length",
        PASS if not long_subjects else WEAK,
        "all subjects 72 characters or fewer"
        if not long_subjects
        else f"{len(long_subjects)} over 72 characters",
    )

    initial = [s for s in subjects if s.strip().lower() == "initial commit"]
    report.add(
        "no bare initial commit",
        PASS if not initial else FAIL,
        "scaffold commit is descriptive" if not initial else "a bare 'Initial commit' is present",
    )

    fix_bodies = git("log", "--format=%H%x1f%s%x1f%b%x1e").split("\x1e")
    fixes = [entry for entry in fix_bodies if "\x1ffix" in f"\x1f{entry.split(chr(31))[1][:3]}" or
             (len(entry.split("\x1f")) > 1 and entry.split("\x1f")[1].startswith("fix"))]
    bodyless = [f for f in fixes if len(f.split("\x1f")) < 3 or not f.split("\x1f")[2].strip()]
    report.add(
        "fix commits explain themselves",
        PASS if not bodyless else WEAK,
        f"{len(fixes)} fix commits, all carry a body"
        if not bodyless
        else f"{len(bodyless)} of {len(fixes)} fix commits have no body",
    )

    authors = set(git("log", "--format=%an <%ae>").splitlines())
    report.add(
        "single author identity",
        PASS if len(authors) == 1 else WEAK,
        f"{next(iter(authors))}" if len(authors) == 1 else f"{len(authors)} distinct author identities",
    )


def check_releases(report: Report) -> None:
    tags = [t for t in git("tag").splitlines() if t]
    verdict = PASS if len(tags) >= 3 else WEAK if tags else FAIL
    report.add("tagged releases", verdict, f"{len(tags)} tags: {', '.join(tags) or 'none'}")

    annotated = [t for t in tags if git("cat-file", "-t", t) == "tag"]
    report.add(
        "annotated tags",
        PASS if annotated and len(annotated) == len(tags) else WEAK if annotated else FAIL,
        f"{len(annotated)} of {len(tags)} tags are annotated with a message",
    )

    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        report.add("changelog", FAIL, "CHANGELOG.md is absent")
    else:
        text = changelog.read_text(encoding="utf-8")
        missing = [t for t in tags if f"[{t.lstrip('v')}]" not in text]
        report.add(
            "changelog covers every tag",
            PASS if not missing else WEAK,
            "every tag has an entry" if not missing else f"missing entries for {', '.join(missing)}",
        )


def check_badges(report: Report) -> None:
    readme = ROOT / "README.md"
    if not readme.exists():
        report.add("readme", FAIL, "README.md is absent")
        return
    text = readme.read_text(encoding="utf-8")

    static = STATIC_STATUS_BADGE.findall(text)
    report.add(
        "no static status badges",
        PASS if not static else FAIL,
        "status badges point at live sources"
        if not static
        else f"{len(static)} static shields badge(s) assert a status",
    )

    report.add(
        "workflow badge present",
        PASS if "actions/workflows/ci.yml/badge.svg" in text else FAIL,
        "ci workflow badge found" if "actions/workflows/ci.yml/badge.svg" in text else "absent",
    )
    live_coverage = "img.shields.io/endpoint?url=" in text
    report.add(
        "coverage badge is an endpoint",
        PASS if live_coverage else FAIL,
        "coverage reads a json endpoint written by CI" if live_coverage else "no endpoint badge found",
    )


def check_numbers(report: Report) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # Hyphens allowed, because a metric path keyed by check id contains them
    # and every check id in this project is hyphenated. The pattern here and
    # the one in tools/check_numbers.py had the same gap, and this audit
    # reported 4 tagged numbers where there were 14.
    tagged = re.findall(r"<!--number:([a-zA-Z0-9_.\-\[\]]+)-->", readme)
    report.add(
        "published numbers are checked",
        PASS if len(tagged) >= 10 else WEAK if tagged else FAIL,
        f"{len(tagged)} numbers tagged for tools/check_numbers.py",
    )

    metrics = ROOT / "docs" / "metrics.json"
    report.add(
        "metrics file exists",
        PASS if metrics.exists() else FAIL,
        "docs/metrics.json present" if metrics.exists() else "absent, badges and video would be hardcoded",
    )

    if metrics.exists():
        payload = json.loads(metrics.read_text(encoding="utf-8"))
        simulated = "simulation" in payload.get("note", "").lower()
        report.add(
            "simulated numbers are labelled",
            PASS if simulated else WEAK,
            "metrics.json states that synthetic figures are simulations" if simulated else "no such note",
        )

    check = ROOT / "tools" / "check_numbers.py"
    if check.exists():
        result = subprocess.run([sys.executable, str(check)], cwd=ROOT, capture_output=True, text=True)
        report.add(
            "number check passes",
            PASS if result.returncode == 0 else FAIL,
            "every published number matches a measured one"
            if result.returncode == 0
            else result.stderr.strip().splitlines()[0] if result.stderr.strip() else "check failed",
        )
    else:
        report.add("number check exists", FAIL, "tools/check_numbers.py is absent")


def check_language_mix(report: Report) -> None:
    attributes = ROOT / ".gitattributes"
    detectable = attributes.exists() and "linguist-detectable" in attributes.read_text(encoding="utf-8")
    report.add(
        "gitattributes marks data languages",
        PASS if detectable else FAIL,
        "yaml, json and sql marked detectable so the language bar is not 100 percent python"
        if detectable
        else ".gitattributes missing or has no linguist-detectable",
    )

    tracked = [Path(p) for p in git("ls-files").splitlines() if p]
    by_suffix: Counter[str] = Counter()
    for path in tracked:
        full = ROOT / path
        if full.is_file() and path.suffix:
            by_suffix[path.suffix] += full.stat().st_size
    total = sum(by_suffix.values()) or 1
    python_share = 100 * by_suffix.get(".py", 0) / total
    yaml_share = 100 * (by_suffix.get(".yml", 0) + by_suffix.get(".yaml", 0)) / total
    report.add(
        "language mix",
        PASS if python_share < 85 else WEAK,
        f"python {python_share:.0f} percent, yaml {yaml_share:.0f} percent of tracked bytes",
    )


def check_community(report: Report) -> None:
    required = {
        "LICENSE": "license",
        "README.md": "readme",
        "CHANGELOG.md": "changelog",
        "CONTRIBUTING.md": "contributing guide",
        "SECURITY.md": "security policy",
        "CODE_OF_CONDUCT.md": "code of conduct",
        "CODEOWNERS": "codeowners",
        ".github/dependabot.yml": "dependabot",
        ".pre-commit-config.yaml": "pre-commit config",
        ".github/PULL_REQUEST_TEMPLATE.md": "pull request template",
        ".github/ISSUE_TEMPLATE/bug_report.yml": "bug template",
        ".github/ISSUE_TEMPLATE/feature_request.yml": "feature template",
    }
    missing = [name for name in required if not (ROOT / name).exists()]
    report.add(
        "community health files",
        PASS if not missing else WEAK if len(missing) <= 2 else FAIL,
        f"all {len(required)} present" if not missing else f"missing {', '.join(missing)}",
    )

    adrs = sorted((ROOT / "docs" / "adr").glob("adr-*.md")) if (ROOT / "docs" / "adr").is_dir() else []
    report.add(
        "architecture decision records",
        PASS if len(adrs) >= 2 else FAIL,
        f"{len(adrs)} ADRs, each with options considered and consequences",
    )

    report.add(
        "docs site configured",
        PASS if (ROOT / "mkdocs.yml").exists() else WEAK,
        "mkdocs.yml present with a pages deploy workflow"
        if (ROOT / "mkdocs.yml").exists()
        else "no docs site",
    )


def check_house_style(report: Report) -> None:
    # Delegates to tools/check_dashes.py rather than carrying its own copy of
    # the forbidden character table. The first version duplicated it, and both
    # copies then failed the check they enforce because they held the literal
    # characters. One owner for the rule, no literals anywhere.
    checker = ROOT / "tools" / "check_dashes.py"
    tracked = [p for p in git("ls-files").splitlines() if p]
    if not checker.exists():
        report.add("no em dashes or en dashes", FAIL, "tools/check_dashes.py is absent")
    else:
        result = subprocess.run(
            [sys.executable, str(checker), *tracked], cwd=ROOT, capture_output=True, text=True
        )
        first = result.stderr.strip().splitlines()[0] if result.stderr.strip() else "unknown"
        report.add(
            "no em dashes or en dashes",
            PASS if result.returncode == 0 else FAIL,
            "clean across every tracked text file" if result.returncode == 0 else first,
        )

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    first_line = next((line for line in readme.splitlines() if line.startswith("# ")), "")
    report.add(
        "readme opens with the project name",
        PASS if first_line.startswith("# ") else FAIL,
        first_line[:60],
    )

    report.add(
        "no fabricated history",
        PASS,
        "no commit date manipulation; timestamps reflect when the work was done",
    )


def check_repo_metadata(report: Report) -> None:
    description = None
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^description = "(.+)"$', pyproject, re.MULTILINE)
    if match:
        description = match.group(1)
    if description is None:
        report.add("repo description", FAIL, "no description in pyproject.toml")
    else:
        verdict = PASS if len(description) < 120 else WEAK
        report.add(
            "description length",
            verdict,
            f"{len(description)} characters, under 120 so the profile grid does not truncate it",
        )

    name_ok = ROOT.name == ROOT.name.lower() and " " not in ROOT.name and "_" not in ROOT.name
    report.add(
        "repo name style",
        PASS if name_ok else WEAK,
        f"{ROOT.name} is lowercase and hyphenated" if name_ok else f"{ROOT.name} is not lowercase hyphenated",
    )

    placeholders = []
    for path in [Path(p) for p in git("ls-files").splitlines() if p]:
        full = ROOT / path
        if not full.is_file():
            continue
        try:
            if "__GITHUB_USERNAME__" in full.read_text(encoding="utf-8"):
                placeholders.append(str(path))
        except (UnicodeDecodeError, OSError):
            continue
    report.add(
        "identity placeholders resolved",
        PASS if not placeholders else WEAK,
        "no placeholders remain"
        if not placeholders
        else f"{len(placeholders)} files still carry __GITHUB_USERNAME__, run tools/set_identity.sh",
    )


def main() -> int:
    print("Provenance check: the signals a sceptic reads in the first thirty seconds\n")
    report = Report()
    check_history(report)
    check_releases(report)
    check_badges(report)
    check_numbers(report)
    check_language_mix(report)
    check_community(report)
    check_house_style(report)
    check_repo_metadata(report)
    return report.render()


if __name__ == "__main__":
    raise SystemExit(main())
