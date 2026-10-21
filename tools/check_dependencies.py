"""Fail when a declared dependency is not actually used.

An unused dependency in pyproject.toml is a claim the code does not support. It
costs a user an install, it widens the supply chain surface for nothing, and if
it also appears in the README's tech stack table it is a capability the project
advertises and does not have.

Some dependencies are legitimately not imported anywhere. pyarrow is pandas's
parquet engine: nothing imports it, pandas raises ImportError without it. Those
are declared in INDIRECT below with the reason, so "not imported" and "not
needed" stay distinguishable.

Usage:
    python tools/check_dependencies.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEARCH = ("src", "tests", "tools", "benchmark", "scripts")

# Distribution name to the module it provides, where the two differ.
MODULE_NAME = {
    "pyyaml": "yaml",
    "pytest-cov": "pytest_cov",
}

# Dependencies nothing imports directly, with the reason each is required.
INDIRECT = {
    "ruff": "a linter invoked as a command, not a library",
    "respx": "a pytest plugin for mocking httpx, imported by tests rather than by the library",
    "pytest-asyncio": "a pytest plugin, enabled by asyncio_mode in pyproject rather than imported",
    "numpy": "used by the benchmark's stream and latency models, not by the library itself",
}


def declared() -> list[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    found: list[str] = []
    for block in re.findall(r"dependencies = \[(.*?)\]", text, re.DOTALL):
        found.extend(re.findall(r'"([a-zA-Z0-9_.-]+)\s*[><=~!\[]', block))
    return sorted(set(found))


def imported() -> set[str]:
    result = subprocess.run(
        ["grep", "-rhoE", r"^\s*(import|from) [a-zA-Z0-9_]+", *[str(ROOT / d) for d in SEARCH if (ROOT / d).is_dir()]],
        capture_output=True, text=True,
    )
    return {line.split()[1].split(".")[0] for line in result.stdout.splitlines() if len(line.split()) > 1}


def main() -> int:
    modules = imported()
    failures: list[str] = []
    checked = 0

    for name in declared():
        checked += 1
        if name in INDIRECT:
            print(f"  ok    {name:14s} indirect: {INDIRECT[name]}")
            continue
        module = MODULE_NAME.get(name, name.replace("-", "_"))
        if module in modules:
            print(f"  ok    {name:14s} imported as {module}")
        else:
            failures.append(
                f"{name} is declared in pyproject.toml but nothing imports it. "
                f"Remove it, or record it in INDIRECT with the reason it is required."
            )

    print()
    for failure in failures:
        print(f"  FAIL  {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"every one of the {checked} declared dependencies is used")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
