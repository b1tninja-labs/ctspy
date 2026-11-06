"""The Merkle core, tested against the example the specification publishes.

RFC 9162 section 2.1.5 draws a 7-leaf tree and states, in prose, the inclusion proof for four of its
leaves and the consistency proof for three pairs of tree heads. Those are expected values written
down by the authors rather than by this implementation, which is the only kind of vector worth
trusting here. The test builds the same tree node by node with its own hashing, asserts that
`inclusion_path`/`consistency_path` reproduce exactly those node lists, and that the verifiers
accept them.

It also exploits the fact that sections 2.1.1 and 2.1.2 give two different algorithms for one tree
hash. Agreement between two normative statements is evidence; agreement between a function and
itself is not.
"""

from __future__ import annotations

import hashlib

import pytest

from ctspy import merkle

H = hashlib.sha256


def leaf(data: bytes) -> bytes:
    """Leaf hash written out here rather than imported, so the test cannot inherit a bug."""
    return H(b"\x00" + data).digest()


def branch(left: bytes, right: bytes) -> bytes:
    return H(b"\x01" + left + right).digest()


# The section 2.1.5 tree, node by node, following the diagram. a..f are leaf hashes; j has a single
# child in the picture, so it *is* d6's leaf hash rather than a branch.
D = [f"entry {i}".encode() for i in range(7)]
A, B, C, DD, E, F = (leaf(d) for d in D[:6])
J = leaf(D[6])
G = branch(A, B)
HH = branch(C, DD)
# The letters are the RFC's own node names, kept so each assertion reads against the diagram.
# E741 flags the single uppercase I as ambiguous; renaming it would cost more than it buys here.
I = branch(E, F)  # noqa: E741
K = branch(G, HH)
L = branch(I, J)
ROOT7 = branch(K, L)
ROOT3 = branch(G, C)  # MTH(D[0:3]): a complete pair plus a lone leaf
ROOT4 = K
ROOT6 = branch(K, I)


def test_the_published_inclusion_proofs_are_reproduced():
    """PATH(0,D7) = [b,h,l], PATH(3,D7) = [c,g,l], PATH(4,D7) = [f,j,k], PATH(6,D7) = [i,k]."""
    assert merkle.inclusion_path(0, D) == (B, HH, L)
    assert merkle.inclusion_path(3, D) == (C, G, L)
    assert merkle.inclusion_path(4, D) == (F, J, K)
    assert merkle.inclusion_path(6, D) == (I, K)


def test_the_published_inclusion_proofs_verify():
    for index, path, leaf_hash_value in (
        (0, (B, HH, L), A),
        (3, (C, G, L), DD),
        (4, (F, J, K), E),
        (6, (I, K), J),
    ):
        assert merkle.verify_inclusion(leaf_hash_value, index, 7, path, ROOT7)


def test_the_rightmost_leaf_consumes_exactly_two_path_nodes():
    """Index 6 in a 7-leaf tree: fn == sn == 6, even, so both must shift to (3, 3).

    This is the case erratum 8670 is about. The printed text allows the loop to end because
    "fn is 0"; the corrected text says it ends when the bit is set. Both produce this answer - but
    an implementation that treated `fn == 0` as a legitimate exit would stop for the wrong reason,
    and the way to see that is that the proof has exactly two nodes: a third must be refused, and
    dropping either must fail.
    """
    assert merkle.verify_inclusion(J, 6, 7, (I, K), ROOT7)
    assert not merkle.verify_inclusion(J, 6, 7, (I, K, G), ROOT7)
    assert not merkle.verify_inclusion(J, 6, 7, (I,), ROOT7)
    assert not merkle.verify_inclusion(J, 6, 7, (K,), ROOT7)


def test_the_published_consistency_proofs_are_reproduced():
    """PROOF(3,D7) = [c,d,g,l]; PROOF(4,D7) = [l]; PROOF(6,D7) = [i,j,k]."""
    assert merkle.consistency_path(3, D) == (C, DD, G, L)
    assert merkle.consistency_path(4, D) == (L,)
    assert merkle.consistency_path(6, D) == (I, J, K)


def test_the_published_consistency_proofs_verify():
    assert merkle.verify_consistency(3, 7, (C, DD, G, L), ROOT3, ROOT7)
    assert merkle.verify_consistency(4, 7, (L,), ROOT4, ROOT7)
    assert merkle.verify_consistency(6, 7, (I, J, K), ROOT6, ROOT7)


def test_the_two_specifications_of_the_tree_hash_agree():
    """Section 2.1.1 recursively, section 2.1.2 with a stack: the same function, two words."""
    for count in range(0, 18):
        entries = [f"e{i}".encode() for i in range(count)]
        assert merkle.tree_hash(entries) == merkle.tree_hash_recursive(entries)
    assert merkle.tree_hash([]) == H(b"").digest(), "MTH({}) = HASH()"
    assert merkle.tree_hash([D[0]]) == A


def test_every_proof_in_small_trees_verifies():
    """Exhaustive over small trees: every honestly built proof must be accepted."""
    for count in range(1, 13):
        entries = [f"leaf-{i}".encode() for i in range(count)]
        root = merkle.tree_hash(entries)
        for index in range(count):
            assert merkle.verify_inclusion(
                merkle.leaf_hash(entries[index]),
                index,
                count,
                merkle.inclusion_path(index, entries),
                root,
            )
        for first in range(1, count):
            assert merkle.verify_consistency(
                first,
                count,
                merkle.consistency_path(first, entries),
                merkle.tree_hash(entries[:first]),
                root,
            )


def test_a_forged_inclusion_is_refused():
    entries = [f"leaf-{i}".encode() for i in range(7)]
    root = merkle.tree_hash(entries)
    honest = merkle.inclusion_path(2, entries)
    assert merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 2, 7, honest, root)
    assert not merkle.verify_inclusion(merkle.leaf_hash(b"never logged"), 2, 7, honest, root)
    assert not merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 3, 7, honest, root)
    assert not merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 2, 7, honest[:-1], root)
    assert not merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 2, 7, honest[:1], root)
    assert not merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 7, 7, honest, root)
    assert not merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 8, 7, honest, root)
    grown = merkle.tree_hash([*entries, b"one more"])
    assert not merkle.verify_inclusion(merkle.leaf_hash(entries[2]), 2, 7, honest, grown)


def test_a_truncated_history_is_refused():
    """The append-only claim: the older root must not pass as the newer one."""
    entries = [f"leaf-{i}".encode() for i in range(9)]
    root9 = merkle.tree_hash(entries)
    root5 = merkle.tree_hash(entries[:5])
    honest = merkle.consistency_path(5, entries)
    assert merkle.verify_consistency(5, 9, honest, root5, root9)
    assert not merkle.verify_consistency(5, 9, honest, root5, root5)
    assert not merkle.verify_consistency(5, 9, honest[:-1], root5, root9)
    assert not merkle.verify_consistency(5, 9, (), root5, root9)
    assert not merkle.verify_consistency(5, 9, honest + honest[:1], root5, root9)
    tampered = [bytes(32) if i == 0 else node for i, node in enumerate(honest)]
    assert not merkle.verify_consistency(5, 9, tampered, root5, root9)


def test_impossible_shapes_are_refused_rather_than_guessed():
    entries = [b"x"]
    root = merkle.tree_hash(entries)
    assert merkle.verify_inclusion(merkle.leaf_hash(b"x"), 0, 1, (), root)
    with pytest.raises(merkle.ProofFormatError):
        merkle.inclusion_path(1, entries)
    with pytest.raises(merkle.ProofFormatError):
        merkle.consistency_path(1, entries)
    with pytest.raises(merkle.ProofFormatError):
        merkle.verify_consistency(0, 5, (bytes(32),), bytes(32), bytes(32))
    with pytest.raises(merkle.ProofFormatError):
        merkle.verify_consistency(5, 5, (bytes(32),), bytes(32), bytes(32))
    with pytest.raises(merkle.ProofFormatError):
        merkle.verify_inclusion(b"short", 0, 1, (), root)
