"""My tree hash, vouched for by a production log.

The strongest Merkle evidence available without a proof endpoint that nobody deploys. Forty-one real
entries are taken from the log's own `get-entries`; the root of each prefix is computed here, from
scratch, by this library; and the log is asked to prove that each of those trees is a prefix of the
tree it signed. All five come back consistent. If `tree_hash` were wrong in any way that matters - the
0x00 leaf domain separator, the 0x01 node separator, a split point off by one, the odd-size case - the
fold would land somewhere else and the log's own proof would refuse to connect my root to its own
signature.

Nothing in the fixture was chosen to make a test pass: the entries are whatever the log stored first,
they are variable-length and independently produced, and the tree sizes include two exact powers of two
(2 and 8, which take step 2's prepend branch) and two ragged ones (13 and 41, where split-point
arithmetic is usually got wrong).
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from ctspy import merkle
from ctspy.ecdsa import EcdsaKey
from ctspy.sth import SignedTreeHeadV1, verify

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "production-tree.json").read_text(
        encoding="utf-8"
    )
)
LEAVES = [base64.b64decode(item) for item in FIXTURE["leaf_inputs"]]
HEAD = SignedTreeHeadV1.from_v1_json(FIXTURE["head"])
KEY = EcdsaKey.from_spki(base64.b64decode(FIXTURE["key"]))
SIZE = int(FIXTURE["tree_size"])
SIZES = sorted(int(key) for key in FIXTURE["proofs"])


def audit(count: int) -> tuple[bytes, ...]:
    record = FIXTURE["proofs"][str(count)]
    return tuple(base64.b64decode(node) for node in record["nodes"])


def root_of(count: int) -> bytes:
    return merkle.tree_hash(LEAVES[:count])


def test_the_fixture_is_internally_honest() -> None:
    """Before any verification: the head is signed, names this size, and the leaves are all present."""
    verify(HEAD, KEY)
    assert HEAD.tree_size == SIZE
    assert len(LEAVES) == max(SIZES), "the fixture has fewer entries than the largest tree claimed"
    assert max(SIZES) < SIZE, "a prefix must be shorter than the tree it is a prefix of"
    assert SIZES == [2, 3, 8, 13, 41], f"the fixture no longer covers both step-2 branches: {SIZES}"


@pytest.mark.parametrize("count", SIZES)
def test_a_tree_of_real_entries_is_a_prefix_of_the_signed_tree(count: int) -> None:
    assert merkle.verify_consistency(count, SIZE, audit(count), root_of(count), HEAD.root_hash)


@pytest.mark.parametrize("count", SIZES)
def test_one_changed_byte_in_the_entries_breaks_the_log_s_own_proof(count: int) -> None:
    """The same proof, the same head, one entry edited. This is what makes the accept above mean it."""
    tampered = list(LEAVES[:count])
    last = tampered[-1]
    tampered[-1] = last[:-1] + bytes([last[-1] ^ 0x01])
    assert root_of(count) != merkle.tree_hash(tampered)
    assert not merkle.verify_consistency(
        count, SIZE, audit(count), merkle.tree_hash(tampered), HEAD.root_hash
    )


def test_both_specifications_of_the_tree_hash_agree_on_production_bytes() -> None:
    """Sections 2.1.1 and 2.1.2, past the synthetic small trees and up to real, ragged input."""
    for count in SIZES:
        assert root_of(count) == merkle.tree_hash_recursive(LEAVES[:count])


def test_a_leaf_is_hashed_with_the_zero_prefix_and_a_node_with_one() -> None:
    """The domain separation second-order-preimage resistance depends on, on bytes that are real."""
    for entry in LEAVES[:3]:
        assert merkle.leaf_hash(entry) == hashlib.sha256(b"\x00" + entry).digest()
        assert merkle.leaf_hash(entry) != hashlib.sha256(entry).digest()
    left, right = merkle.leaf_hash(LEAVES[0]), merkle.leaf_hash(LEAVES[1])
    assert merkle.node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()
    assert merkle.node_hash(left, right) != merkle.node_hash(right, left)


def test_the_roots_recorded_in_the_fixture_are_the_ones_computed_here() -> None:
    """Catches a hand-edited or partially regenerated fixture rather than trusting the file."""
    for count in SIZES:
        recorded = FIXTURE["proofs"][str(count)]["root"]
        assert base64.b64encode(root_of(count)).decode() == recorded


def test_the_provenance_survives_being_read_by_a_stranger() -> None:
    provenance = FIXTURE["provenance"]
    assert provenance["fetched_utc"].startswith("2026-")
    assert provenance["origin"].startswith("https://")
    assert int(FIXTURE["head_after_sweep"]) >= SIZE, "time does not run backwards in a capture"
