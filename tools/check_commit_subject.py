"""Fail a commit whose subject line exceeds 72 characters.

Runs as a commit-msg hook. The 72 character limit keeps `git log --oneline`
readable in a terminal and keeps the subject readable in GitHub's commit list
without truncation.

Eight subjects in this repository's early history exceed the limit. They are
left alone rather than rewritten, because rewriting history to tidy prose
invalidates every existing clone and commit reference for no functional gain.
The hook stops the count growing.

Usage, as a hook:
    python tools/check_commit_subject.py .git/COMMIT_EDITMSG
"""

from __future__ import annotations

import sys
from pathlib import Path

LIMIT = 72


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_commit_subject.py <commit message file>", file=sys.stderr)
        return 2

    lines = Path(argv[0]).read_text(encoding="utf-8").splitlines()
    subject = next((line for line in lines if line.strip() and not line.startswith("#")), "")

    if len(subject) > LIMIT:
        print(
            f"commit subject is {len(subject)} characters, limit is {LIMIT}:\n  {subject}",
            file=sys.stderr,
        )
        return 1
    if subject.endswith("."):
        print(f"commit subject should not end with a period:\n  {subject}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
