"""The cross-generation duplication measurement, re-checked offline.

`tools/duplication_probe.py --list all --only Sphinx2026h1 --only Wyvern2026h1 --only Wyvern2026h2 --only
Argon2026h2 --at 2026-06-01T12:00:00 --window 60 --entries 1500` took these numbers from public logs on
2026-11-06 and wrote the JSON that is now the fixture. Capturing instead of re-fetching is the point: two of the
four logs measured are marked `rejected`, the partner generation of one operator is already `404`, and a claim
that rests on a log anyone may delete tomorrow should outlive it. `certledger/HARVEST-PLAN.md` sizes the DER tier
and orders the preservation pass on exactly what is asserted here, so the numbers are asserted rather than
paraphrased.

One detail worth reading off the fixture rather than from memory: its `verdict` strings were written by the tool
as it stood that afternoon, before a zero-overlap pair was allowed to report a bound. The counts are the evidence;
the prose beside them is not.
"""

from __future__ import annotations

import json
import pathlib

CAPTURE = pathlib.Path(__file__).parent / "fixtures" / "duplication-cross-generation.json"
RUN = json.loads(CAPTURE.read_text(encoding="utf-8"))
LOGS = {row["description"]: row for row in RUN["logs"]}
PAIRS = {(pair["left_log"], pair["right_log"]): pair for pair in RUN["pairs"]}


def pair_of(left: str, right: str) -> dict:
    """The captured comparison between two logs, whichever order the tool happened to put them in."""
    for (first, second), value in PAIRS.items():
        if {first, second} == {left, right}:
            return value
    raise AssertionError(f"no captured pair for {left} x {right}")


def test_captured_four_logs_across_two_generations():
    assert len(LOGS) == 4, "re-run tools/duplication_probe.py; the capture looks truncated"
    assert {row["state"] for row in RUN["logs"]} == {"rejected", "usable"}


def test_no_log_repeats_an_entry_inside_its_own_tree():
    """Distinct entries per leaf is 1.0 in all four, the rejected generation included."""
    for name, row in LOGS.items():
        assert row["distinct_entries"] == row["fetched"], name


def test_one_operators_two_rejected_logs_hold_the_same_certificates():
    """Nine in ten of `Wyvern2026h1`'s entries are also in `Sphinx2026h1`: one copy, kept twice."""
    pair = pair_of("DigiCert Wyvern2026h1", "DigiCert Sphinx2026h1")
    assert pair["shared"] / pair["left"] > 0.9
    assert LOGS["DigiCert Wyvern2026h1"]["state"] == "rejected"
    assert LOGS["DigiCert Sphinx2026h1"]["state"] == "rejected"


def test_the_rejected_generation_is_absent_from_the_logs_that_survive():
    """Nothing shared with a live DigiCert sibling or a live Google log, in the same window.

    Both sides of each comparison cover the whole common interval, so the zero is a census rather than a thin
    sample, and the rule of three on the sparser side bounds the overlap near 4%.
    """
    for other in ("DigiCert Wyvern2026h2", "Google Argon2026h2"):
        pair = pair_of("DigiCert Wyvern2026h1", other)
        assert pair["shared"] == 0, other
        sparsest = min(pair["left"], pair["right"])
        assert sparsest >= 60, "fewer entries than that would not bound anything"
        assert 3.0 / sparsest < 0.05


def test_two_live_logs_of_different_operators_do_share_in_the_same_window():
    """The control that makes the zero mean something: the detector fires at 34.06% live-to-live."""
    pair = pair_of("Google Argon2026h2", "DigiCert Wyvern2026h2")
    assert 0.2 < pair["shared"] / pair["left"] < 0.6, pair["shared"] / pair["left"]
