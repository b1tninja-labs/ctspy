"""The obligation matrix and the code cannot drift apart silently.

Every row of ROADMAP.md names a callable. A row that names nothing is a wish, and wishes
belong in the milestone list rather than in the matrix, because a matrix is what someone
trusts when deciding whether a behaviour exists.
"""

from __future__ import annotations

import importlib
import pathlib

import ctspy as package

ROOT = pathlib.Path(__file__).resolve().parents[1]
BAR = chr(124)
TICK = chr(96)
CALL = chr(40) + chr(41)


def roadmap_rows():
    rows = []
    text = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    for line in text.splitlines():
        if not line.startswith(BAR + " " + TICK):
            continue
        cells = line.split(BAR)
        cell = cells[1].strip().strip(TICK)
        if not cell.endswith(CALL) or "." not in cell:
            continue
        module_name, fn = cell[: -len(CALL)].split(".", 1)
        rows.append((module_name, fn))
    return rows


def test_matrix_has_rows():
    assert roadmap_rows(), "ROADMAP.md lost its obligation rows"


def test_every_row_names_a_real_callable():
    missing = []
    for module_name, fn in roadmap_rows():
        module = importlib.import_module(package.__name__ + "." + module_name)
        if not hasattr(module, fn):
            missing.append(module_name + "." + fn)
    assert not missing, "matrix rows naming nothing: " + ", ".join(missing)
