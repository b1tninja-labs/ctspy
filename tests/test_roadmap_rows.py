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


DONE = {"[ok]", "[x]"}


def roadmap_entries():
    """(label, status, evidence) for every obligation row, as the matrix writes them."""
    entries = []
    text = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    for line in text.splitlines():
        if not line.startswith(BAR + " " + TICK):
            continue
        cells = [cell.strip() for cell in line.split(BAR)]
        if len(cells) < 5:
            continue
        label = cells[1].strip(TICK)
        if not label.endswith(CALL) or "." not in label:
            continue
        entries.append((label, cells[3].strip(TICK), cells[4].strip().strip(TICK)))
    return entries


def test_a_row_claimed_done_names_a_test_that_exists():
    """`AGENTS.md` invariant 1 promises this check, so the matrix cannot be the only record of a claim.

    A row flipped to done because the code exists is worth nothing on its own - the code was always
    there. What makes the row information is the named test, and what makes the *name* information is
    that resolving it finds a real function. Both halves are checked here, cheaply, without spawning
    pytest: the cell must be `path::test_name`, the file must exist, and the file must define it.

    This check did not exist until the day three rows were flipped to done, which is the usual
    sequence for a guard that documentation promised and code never delivered.
    """
    problems = []
    for label, status, evidence in roadmap_entries():
        if status not in DONE:
            continue
        if "::" not in evidence:
            problems.append(f"{label} claims {status} without naming a test: {evidence!r}")
            continue
        file, _, test_id = evidence.partition("::")
        path = ROOT / file
        if not path.is_file():
            problems.append(f"{label} claims {status} but {file.strip()} does not exist")
            continue
        name = test_id.split("[")[0].strip()  # a parametrised id still names its function
        if f"def {name}(" not in path.read_text(encoding="utf-8"):
            problems.append(f"{label} claims {status} but {file.strip()} defines no {name}()")
    assert not problems, "the matrix claims more than it can show: " + "; ".join(problems)
