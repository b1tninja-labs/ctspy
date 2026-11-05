#!/usr/bin/env python3
"""Write the resolved environment to a requirements file for auditing.

A script rather than shell redirection so the CI step behaves the same on a self-hosted
runner, and so an empty freeze fails loudly instead of auditing nothing.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        print("usage: write_freeze.py PATH")
        return 2
    frozen = subprocess.run(
        [sys.executable, "-m", "pip", "freeze", "--all"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    lines = [line for line in frozen.splitlines() if line.strip()]
    pathlib.Path(sys.argv[1]).write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
    print(f"{len(lines)} distributions written to {sys.argv[1]}")
    return 0 if lines else 1


if __name__ == "__main__":
    sys.exit(main())
