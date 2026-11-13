"""`sct.verify_embedded`: the embedded SCTs of a served chain, checked end to end.

The cases are the six live (leaf, issuer, log key) triples in `fixtures/live-sct-signatures.json`, each
captured from a public host on 2026-11-06. Nothing here supplies a transcript: the leaf's TBS, the issuer
key hash and the SCT list are all read from the certificates by `certscan`, so a pass means the whole
chain-to-signature path reproduces what a real log signed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from ctspy import certscan, sct
from ctspy.ecdsa import EcdsaKey

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "live-sct-signatures.json").read_text("utf-8")
)
CASES = FIXTURE["cases"]


def case_id(case: dict) -> str:
    return f"{case['host']}-{case['log'].split()[0]}"


def chain_of(case: dict) -> list[bytes]:
    return [base64.b64decode(case["certificate"]), base64.b64decode(case["issuer_certificate"])]


def key_of(case: dict) -> EcdsaKey:
    return EcdsaKey.from_spki(base64.b64decode(case["log_key"]))


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_production_embedded_scts_verify_from_a_served_chain(case: dict) -> None:
    key = key_of(case)
    results = sct.verify_embedded(chain_of(case), {key.log_id: key})
    mine = [item for item in results if item.sct.log_id == key.log_id]
    assert [item.verified for item in mine] == [True]
    # Every other SCT in the same certificate is for a log nobody pinned: undecided, never refuted.
    assert all(item.verified is None for item in results if item not in mine)
    assert not any(item.verified is False for item in results)


def test_an_unpinned_log_is_unknown_and_never_false() -> None:
    case = CASES[0]
    results = sct.verify_embedded(chain_of(case), {})
    assert results
    assert all(item.verified is None for item in results)
    assert all("not pinned" in item.reason for item in results)


@pytest.mark.parametrize("case", CASES[:3], ids=case_id)
def test_the_wrong_issuer_refutes_a_pinned_signature(case: dict) -> None:
    """The leaf offered as its own issuer changes `issuer_key_hash`, so the signature stops verifying."""
    key = key_of(case)
    leaf = chain_of(case)[0]
    wrong = sct.verify_embedded([leaf, leaf], {key.log_id: key})
    assert [item.verified for item in wrong if item.sct.log_id == key.log_id] == [False]


def test_a_chain_without_an_issuer_cannot_decide() -> None:
    case = CASES[0]
    key = key_of(case)
    results = sct.verify_embedded(chain_of(case)[:1], {key.log_id: key})
    assert all(item.verified is None for item in results)
    assert any("no issuer" in item.reason for item in results)


def test_a_certificate_with_no_sct_extension_returns_nothing() -> None:
    case = CASES[0]
    issuer = chain_of(case)[1]
    assert certscan.embedded_sct_list(issuer) is None
    assert sct.verify_embedded([issuer], {}) == ()


def test_an_empty_chain_is_refused() -> None:
    with pytest.raises(sct.VerificationError):
        sct.verify_embedded([], {})


def test_the_issuer_spki_helper_returns_the_exact_bytes_the_log_hashed() -> None:
    for case in CASES:
        issuer = chain_of(case)[1]
        spki = certscan.subject_public_key_info(issuer)
        assert hashlib.sha256(spki).hexdigest() == case["issuer_key_hash"]
        assert issuer.find(spki) > 0
