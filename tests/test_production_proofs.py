"""A consistency proof from a live log, verified offline.

This is the strongest evidence in the repository, and the reason is arithmetic rather than
arrangement. The fixture pairs a signed tree head at **3,024,266,407 entries** with a proof that the
one-entry tree inside it is a prefix of that tree - and the older root needs no trust in anybody,
because the root of a one-leaf tree *is* that leaf's hash, which this file recomputes from the entry
bytes. So `verify_consistency` is being checked against a real 3-billion-leaf structure built by an
implementation written in another language, by people who never saw this code, over data that was
never chosen to make my tests pass.

It found a specification-versus-deployment difference worth recording: RFC 6962 section 4.6 names the
response field `audit_consistency`, and Google's servers answer with `consistency`. The fixture stores
both the verbatim body and which name was used.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from ctspy import merkle
from ctspy.ecdsa import EcdsaKey
from ctspy.sth import SignedTreeHeadV1, verify

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "production-proofs.json").read_text(
        encoding="utf-8"
    )
)
HEAD = SignedTreeHeadV1.from_v1_json(FIXTURE["head"])
KEY = EcdsaKey.from_spki(base64.b64decode(FIXTURE["key"]))
LEAF_INPUT = base64.b64decode(FIXTURE["entry"]["leaf_input"])
LEAF_HASH = merkle.leaf_hash(LEAF_INPUT)
SIZE = HEAD.tree_size
AUDIT = tuple(
    base64.b64decode(node) for node in FIXTURE["consistency_proof"][FIXTURE["consistency_field"]]
)


def test_the_captured_head_is_genuine() -> None:
    """Nothing below means anything unless the root it is checked against was signed by that log."""
    verify(HEAD, KEY)
    assert SIZE > 3_000_000_000, "the fixture is meant to be a large production tree"


def test_the_older_root_needs_no_trust() -> None:
    """MTH of one entry is that entry's leaf hash - the property that makes this proof self-evident."""
    assert merkle.tree_hash([LEAF_INPUT]) == LEAF_HASH
    assert merkle.tree_hash_recursive([LEAF_INPUT]) == LEAF_HASH


def test_a_production_consistency_proof_verifies() -> None:
    """1 -> 3.02 billion, proved by the stack algorithm and the recursive one, independently."""
    assert merkle.verify_consistency(1, SIZE, AUDIT, LEAF_HASH, HEAD.root_hash)


def test_the_same_proof_refuses_a_different_history() -> None:
    """The point of the check: a proof must not be a form anyone can wave through.

    The older root, the truncated path, and the extended path are all refused. `second` alone is the
    exception, and it is refused only when it travels with the root that belongs to it - see the test
    below, which pins why.
    """
    assert not merkle.verify_consistency(1, SIZE, AUDIT, b"\x00" * 32, HEAD.root_hash)
    assert not merkle.verify_consistency(1, SIZE, AUDIT[:-1], LEAF_HASH, HEAD.root_hash)
    assert not merkle.verify_consistency(1, SIZE, AUDIT + AUDIT[:1], LEAF_HASH, HEAD.root_hash)
    wrong_history = merkle.tree_hash([LEAF_INPUT, b"a second entry never logged"])
    assert not merkle.verify_consistency(1, SIZE, AUDIT, LEAF_HASH, wrong_history)
    assert merkle.verify_consistency(1, SIZE, AUDIT, LEAF_HASH, HEAD.root_hash)


def test_second_is_weak_when_first_is_one_and_the_signature_is_what_pins_it() -> None:
    """A property of the specified algorithm, found in production data and pinned rather than hushed.

    With `first == 1`, step 3 sets `fn = 0`. LSB(fn) is never set, `fn == sn` never holds while `sn` is
    nonzero, so every path element takes the "Otherwise" branch: `fr` never moves, and the only
    remaining constraint on `second` is that shifting it once per path element reaches 0 (step 7). A
    proof for the live tree size therefore also "verifies" when `second` is claimed as a few less,
    while `second_hash` stays the root of the larger tree.

    This is not a forgery, and the reason matters: `second_hash` alone decides what the fold must end
    at, and a log's signature covers `tree_size` and `root_hash` together. No signed head exists whose
    size is a bit below the one it signed and whose root is the one it signed, so a caller that takes
    both fields from one verified head cannot be led anywhere. `certledger.HeadStore` does exactly that
    - it never accepts a size without the root the signature bound it to. What would be dangerous is a
    caller passing a size from one place and a root from another, which is what this test names.

    Checked against the specification text directly: an independent transcription of section 2.1.4.2
    in the probe that found this (`sdk-forge/probe_consistency_soundness.py`) behaves identically, and
    over every honest small-tree pair the two agree, so this is the algorithm, not my reading of it.
    """
    assert merkle.verify_consistency(1, SIZE - 1, AUDIT, LEAF_HASH, HEAD.root_hash)
    assert merkle.verify_consistency(1, SIZE - 1000, AUDIT, LEAF_HASH, HEAD.root_hash)

    # The weak constraint reaches only toward the tree this root belongs to. Pair the path with the
    # root of a genuinely different tree and the fold misses, and `first == second` is refused outright
    # rather than quietly treated as a trivial proof.
    assert not merkle.verify_consistency(2, SIZE, AUDIT, LEAF_HASH, HEAD.root_hash)
    with pytest.raises(merkle.ProofFormatError):
        merkle.verify_consistency(1, 1, AUDIT, LEAF_HASH, LEAF_HASH)


@pytest.mark.skipif(
    FIXTURE["inclusion"] is not None, reason="a log served an inclusion proof; see the fixture"
)
def test_no_deployed_log_would_give_an_inclusion_proof() -> None:
    """An honest gap, pinned so it cannot be forgotten rather than quietly left out of the suite.

    RFC 6962 section 4.5 defines `get-inclusion-proof-by-hash`, and every operational log in the list
    was asked. Twenty answered 404 and two answered 403; one answered 429, which is a throttle rather
    than an answer about the endpoint and is not counted as a refusal. Either the section 4.5 endpoint
    is simply not deployed, or these operators expose audit paths some other way - which is itself the
    finding. The inclusion verifier is pinned by the specification's worked example in
    `test_merkle.py`; what is missing is a production proof, and this test says so out loud rather than
    leaving the gap to be remembered by whoever found it.
    """
    failures = FIXTURE["inclusion_failures"]
    assert len(failures) >= 20, (
        f"only {len(failures)} logs were asked; re-run tools/fetch_evidence.py"
    )
    refusals = [reason for reason in failures.values() if "404" in reason or "403" in reason]
    assert len(refusals) >= 20, f"fewer than 20 explicit refusals: {failures}"
    assert all("Error" in reason or "error" in reason for reason in failures.values()), failures
    assert FIXTURE["provenance"]["fetched_utc"].startswith("2026-")
