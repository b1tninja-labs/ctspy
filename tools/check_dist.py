#!/usr/bin/env python3
"""Assert the built distribution ships what the documentation promises.

Run after a wheel build. A docs claim about a packaged fixture is a promise to the reader,
and a promise nothing checks gets broken silently.
"""

from __future__ import annotations

import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = "ctspy"
REQUIRED = ("README.md", "ROADMAP.md", "LICENSE", "NOTICE", "SECURITY.md")


def main():
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if not wheels:
        print("no wheel in dist/: run python -m build first")
        return 1
    with zipfile.ZipFile(wheels[-1]) as wheel:
        names = set(wheel.namelist())
    problems = []
    if PKG + "/py.typed" not in names:
        problems.append(PKG + "/py.typed missing from the wheel")
    problems += [
        f + " missing from the repository root" for f in REQUIRED if not (ROOT / f).exists()
    ]
    for item in problems:
        print("problem:", item)
    print(f"{wheels[-1].name}: {len(names)} entries, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
