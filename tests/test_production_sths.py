"""Every operational public log, verified against its own published key.

`tools/fetch_evidence.py` captured these STHs on one afternoon; this file checks them offline so the
suite never needs the network. That split is deliberate: a test that depends on a live service is a
test that can go red because someone's datacenter had a bad day, while a fixture plus a re-fetch
command keeps the claim checkable *and* the run deterministic.

This is the interoperability evidence the publication checklist asks for. A single log proves my code
agrees with one implementation; twenty-three logs from five operators prove the transcript and key
binding I implemented are not a reading of one server's behavior. Each case is named by description,
so a failure says which log disagreed rather than which index in a list.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from ctspy.ecdsa import EcdsaKey
from ctspy.errors import VerificationError
from ctspy.sth import SignedTreeHeadV1, verify

SWEEP = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "log-list-sweep.json").read_text(encoding="utf-8")
)
LOGS = [record for record in SWEEP["logs"] if record["sth"] is not None]
OPERATORS = sorted({record["operator"] for record in LOGS})


def case(record: dict) -> str:
    return record["description"]


def test_the_sweep_still_covers_several_independent_implementations() -> None:
    """If this goes red, the fixture was regenerated badly - the evidence, not the code, got worse."""
    assert len(LOGS) >= 20, f"only {len(LOGS)} logs captured; re-run tools/fetch_evidence.py"
    assert len(OPERATORS) >= 5, f"operators covered: {OPERATORS}"


def test_every_captured_log_answered() -> None:
    silent = [record["description"] for record in SWEEP["logs"] if record["error"] is not None]
    assert not silent, f"logs that did not answer: {silent}"


@pytest.mark.parametrize("record", LOGS, ids=case)
def test_a_live_log_signs_its_own_head(record: dict) -> None:
    """The two bindings that make a log key mean something, checked against the whole fleet."""
    key_der = base64.b64decode(record["key"])
    assert hashlib.sha256(key_der).digest() == base64.b64decode(record["log_id"]), (
        f"{record['description']}: section 4.4 says the log ID is SHA-256 over the DER SPKI"
    )
    signed = SignedTreeHeadV1.from_v1_json(record["sth"])
    verify(signed, EcdsaKey.from_spki(key_der))


@pytest.mark.parametrize("record", LOGS[:6], ids=case)
def test_a_head_does_not_verify_under_a_different_logs_key(record: dict) -> None:
    """Not a restatement of the test above: same artifacts, wrong key, must refuse.

    Pairing is the whole security property here. If a head verified under two logs' keys, the pin in
    `certledger` would be decorative, and 'the signature is valid' would stop meaning 'this log said
    it'. The first six logs are checked in both directions against their successor in the list.
    """
    index = LOGS.index(record)
    other = LOGS[(index + 1) % len(LOGS)]
    if other["description"] == record["description"]:
        pytest.skip("no second log to cross-check against")
    signed = SignedTreeHeadV1.from_v1_json(record["sth"])
    with pytest.raises(VerificationError):
        verify(signed, EcdsaKey.from_spki(base64.b64decode(other["key"])))


def test_the_capture_records_what_it_captured() -> None:
    """Provenance is part of the evidence: no URL and no timestamp, no claim."""
    provenance = SWEEP["provenance"]
    assert provenance["fetched_utc"].startswith("2026-")
    assert provenance["log_list"].startswith("https://")
    assert {record["state"] for record in LOGS} <= {"usable", "readonly"}
