"""The cross-generation duplication measurement, re-checked offline.

`tools/duplication_probe.py --list all --only Sphinx2026h1 --only Wyvern2026h1 --only Wyvern2026h2 --only
Argon2026h2 --at 2026-06-01T12:00:00 --window 60 --entries 1500` took these numbers from public logs on
2026-11-06, and the same comparison at `--at 2026-04-15T09:00:00 --window 20 --entries 2000` took the second
capture. Capturing instead of re-fetching is the point: two of the four logs measured are marked `rejected`, the
partner generation of one operator is already `404`, and a claim that rests on a log anyone may delete tomorrow
should outlive it. `certledger/HARVEST-PLAN.md` sizes the DER tier and orders the preservation pass on exactly what
is asserted here, so the numbers are asserted rather than paraphrased.

One detail worth reading off the fixtures rather than from memory: the June capture's `verdict` strings were
written by the tool as it stood that afternoon, before a zero-overlap pair was allowed to report a bound. The
counts are the evidence; the prose beside them is not.
"""

from __future__ import annotations

import json
import pathlib

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
JUNE = json.loads((FIXTURES / "duplication-cross-generation.json").read_text(encoding="utf-8"))
APRIL = json.loads(
    (FIXTURES / "duplication-cross-generation-april.json").read_text(encoding="utf-8")
)
LOGS = {row["description"]: row for row in JUNE["logs"]}
REQUEST_CEILING = (
    120  # tools/duplication_probe.py's MAX_REQUESTS_PER_LOG, restated rather than imported
)


def pair_of(run: dict, left: str, right: str) -> dict:
    """The captured comparison between two logs, whichever order the tool happened to put them in."""
    for value in run["pairs"]:
        if {value["left_log"], value["right_log"]} == {left, right}:
            return value
    raise AssertionError(f"no captured pair for {left} x {right}")


def test_captured_four_logs_across_two_generations():
    assert len(LOGS) == 4, "re-run tools/duplication_probe.py; the capture looks truncated"
    assert {row["state"] for row in JUNE["logs"]} == {"rejected", "usable"}


def test_no_log_repeats_an_entry_inside_its_own_tree():
    """Distinct entries per leaf is 1.0 in all four, the rejected generation included."""
    for name, row in LOGS.items():
        assert row["distinct_entries"] == row["fetched"], name


def test_one_operators_two_rejected_logs_hold_the_same_certificates():
    """Nine in ten of `Wyvern2026h1`'s entries are also in `Sphinx2026h1`: one copy, kept twice."""
    pair = pair_of(JUNE, "DigiCert Wyvern2026h1", "DigiCert Sphinx2026h1")
    assert pair["shared"] / pair["left"] > 0.9
    assert LOGS["DigiCert Wyvern2026h1"]["state"] == "rejected"
    assert LOGS["DigiCert Sphinx2026h1"]["state"] == "rejected"


def test_the_rejected_generation_is_absent_from_the_logs_that_survive():
    """Nothing shared with a live DigiCert sibling or a live Google log, in the same window.

    Both sides of each comparison cover the whole common interval, so the zero is a census rather than a thin
    sample, and the rule of three on the sparser side bounds the overlap near 4%.
    """
    for other in ("DigiCert Wyvern2026h2", "Google Argon2026h2"):
        pair = pair_of(JUNE, "DigiCert Wyvern2026h1", other)
        assert pair["shared"] == 0, other
        sparsest = min(pair["left"], pair["right"])
        assert sparsest >= 60, "fewer entries than that would not bound anything"
        assert 3.0 / sparsest < 0.05


def test_two_live_logs_of_different_operators_do_share_in_the_same_window():
    """The control that makes the zero mean something: the detector fires at 34.06% live-to-live."""
    pair = pair_of(JUNE, "Google Argon2026h2", "DigiCert Wyvern2026h2")
    assert 0.2 < pair["shared"] / pair["left"] < 0.6, pair["shared"] / pair["left"]


def test_the_zero_between_generations_reproduces_at_a_second_instant():
    """2026-04-15, a different window: still nothing between the rejected log and its live sibling.

    The sparser side held 35 entries covering the whole common interval, which bounds the overlap at 8.6% rather
    than 4.3% — a weaker bound from a thinner sample, and the tool says so in the verdict instead of rounding it
    up to the earlier number.
    """
    pair = pair_of(APRIL, "DigiCert Wyvern2026h1", "DigiCert Wyvern2026h2")
    assert pair["shared"] == 0
    assert "95%" in pair["verdict"], pair["verdict"]


def test_a_starved_pair_refuses_to_turn_nothing_into_a_finding():
    """The same April run hit the request ceiling on Google, so its sample spanned 2.5s.

    That left 2 entries of the rejected log inside the common interval. The pair reports `sample too small`
    rather than a bound, which is the distinction the tool exists to keep: a zero from two entries proves
    nothing, and a reader who has just watched the tool bound a zero will otherwise read this row as one too.
    """
    pair = pair_of(APRIL, "Google Argon2026h2", "DigiCert Wyvern2026h1")
    assert pair["shared"] == 0
    assert pair["verdict"] == "sample too small"
    starved = next(row for row in APRIL["logs"] if row["description"] == "Google Argon2026h2")
    assert starved["requests"] > REQUEST_CEILING, starved["requests"]


def test_live_to_live_overlap_is_not_a_constant_across_windows():
    """13.33% in the April window against 34.06% in June: no single fleet factor exists.

    A third window in 2025 measured 50.9% on the same two operators. Anything that publishes one number for
    cross-operator duplication is describing its sample, not the fleet.
    """
    june = pair_of(JUNE, "Google Argon2026h2", "DigiCert Wyvern2026h2")
    april = pair_of(APRIL, "Google Argon2026h2", "DigiCert Wyvern2026h2")
    assert june["shared"] / june["left"] > 2 * (april["shared"] / april["left"])
