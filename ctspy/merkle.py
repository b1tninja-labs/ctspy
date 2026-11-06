"""Merkle tree hashes, inclusion proofs and consistency proofs (RFC 9162 section 2.1).

Two things make this module worth reading rather than skimming.

**The RFC states the tree hash twice, two different ways.** Section 2.1.1 defines it recursively on
a list of inputs; section 2.1.2 gives a stack algorithm that walks the list once. They are separate
normative statements of the same function, so making them agree on many trees is real evidence
rather than a tautology - and it is the cheap way to catch an off-by-one in the split point `k`,
which each formulation hides differently.

**Generating a proof and verifying one are not the same risk.** `verify_inclusion` and
`verify_consistency` are the security boundary: they decide whether a log has proved something, and
getting them wrong makes a lying log look honest. `inclusion_path` and `consistency_path` exist to
build fixtures and to let a monitor re-derive what a log should have sent; they follow sections
2.1.3.1 and 2.1.4.1 literally, which is what makes them usable as a cross-check on the verifiers.

Erratum 8670 touches the shift loops in section 2.1.3.2 step 4.b.ii and section 2.1.4.2 step
6.b.iii. The printed text ends the loop on "until either LSB(fn) is set or fn is 0"; the erratum
(held for document update, editorial) deletes the second condition, reasoning that `fn == 0` is
unreachable - step 4.a fails on `sn == 0`, and `fn <= sn` is invariant, so the only way in would be
`fn == sn == 0`. Both readings therefore compute the same result, *provided* the implementation does
not treat `fn == 0` as a legitimate exit. It does not: the loop runs until the bit is set, and
`test_rightmost_leaf_proof` exercises the `fn == sn` case that the printed text gestures at.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from .errors import CtspyError

__all__ = [
    "HASH_SIZE",
    "Path",
    "consistency_path",
    "inclusion_path",
    "leaf_hash",
    "node_hash",
    "tree_hash",
    "tree_hash_recursive",
    "verify_consistency",
    "verify_inclusion",
]

HASH_SIZE = 32
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

Hash = bytes
Path = tuple[Hash, ...]


class ProofFormatError(CtspyError, ValueError):
    """A proof is structurally impossible, as opposed to merely failing to verify."""


def _hash(data: bytes) -> Hash:
    return hashlib.sha256(data).digest()


def leaf_hash(entry: bytes) -> Hash:
    """Section 2.1.1: MTH({d[0]}) = HASH(0x00 || d[0]). The prefix is domain separation."""
    return _hash(LEAF_PREFIX + entry)


def node_hash(left: Hash, right: Hash) -> Hash:
    """Section 2.1.1: MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])) for n > 1."""
    return _hash(NODE_PREFIX + left + right)


def tree_hash(entries: Sequence[bytes]) -> Hash:
    """The Merkle Tree Hash over a list of entries, by the stack algorithm of section 2.1.2.

    Entries are the tree's inputs - in CT those are the serialized TransItem structures of section
    4.7, because section 4.7 defines a leaf as the leaf hash of a TransItem, and 2.1.1's 0x00 prefix
    is applied here.
    """
    stack: list[Hash] = []
    for index, entry in enumerate(entries):
        stack.append(leaf_hash(entry))
        # Step 2.b: merge_count is the number of consecutive set bits from the LSB of i - how many
        # complete subtrees end at this leaf. Miscount it and every later root is subtly wrong.
        merge_count = 0
        shifted = index
        while shifted & 1:
            merge_count += 1
            shifted >>= 1
        for _ in range(merge_count):
            right = stack.pop()
            left = stack.pop()
            stack.append(node_hash(left, right))
    while len(stack) > 1:
        right = stack.pop()
        left = stack.pop()
        stack.append(node_hash(left, right))
    if not stack:
        # Section 2.1.1: MTH({}) = HASH(). An empty log has a root; "no root" is a different answer,
        # and collapsing the two is how a fresh log reads as a fetch that returned nothing.
        return _hash(b"")
    return stack[0]


def _split_point(count: int) -> int:
    """The largest power of two strictly below `count`, which section 2.1.1 calls k."""
    return 1 << ((count - 1).bit_length() - 1)


def tree_hash_recursive(entries: Sequence[bytes]) -> Hash:
    """The same quantity by section 2.1.1's recursive definition, kept deliberately separate.

    Two independent readings of one specification agreeing is evidence. One algorithm testing itself
    is not, which is why this is not written as a helper of `tree_hash`.
    """
    count = len(entries)
    if count == 0:
        return _hash(b"")
    if count == 1:
        return leaf_hash(entries[0])
    split = _split_point(count)
    return node_hash(tree_hash_recursive(entries[:split]), tree_hash_recursive(entries[split:]))


def inclusion_path(index: int, entries: Sequence[bytes]) -> Path:
    """PATH(m, D_n) exactly as section 2.1.3.1 defines it, recursion and all.

    Only meaningful for `index < len(entries)`; the caller's index comes from a log, and a proof for
    a position the log does not have is not a thin edge case, it is the thing section 2.1.3.2 step 1
    exists to refuse.
    """
    count = len(entries)
    if not 0 <= index < count:
        raise ProofFormatError(f"index {index} is outside a tree of {count} entries")
    if count == 1:
        return ()
    split = _split_point(count)
    if index < split:
        return (*inclusion_path(index, entries[:split]), tree_hash_recursive(entries[split:]))
    return (*inclusion_path(index - split, entries[split:]), tree_hash_recursive(entries[:split]))


def _subproof(m: int, entries: Sequence[bytes], complete: bool) -> Path:
    count = len(entries)
    if m == count:
        # Section 2.1.4.1: empty when the subtree is already accounted for, otherwise a commitment
        # to it. Collapsing these two arms is the subtlest bug available in this function.
        return () if complete else (tree_hash_recursive(entries),)
    split = _split_point(count)
    if m <= split:
        return (*_subproof(m, entries[:split], complete), tree_hash_recursive(entries[split:]))
    return (*_subproof(m - split, entries[split:], False), tree_hash_recursive(entries[:split]))


def consistency_path(first: int, entries: Sequence[bytes]) -> Path:
    """PROOF(m, D_n) = SUBPROOF(m, D_n, true), section 2.1.4.1."""
    if not 0 < first < len(entries):
        raise ProofFormatError(
            f"consistency needs 0 < first < n, got first={first} n={len(entries)}"
        )
    return _subproof(first, entries, True)


def _shift_until_odd(pair: tuple[int, int]) -> tuple[int, int]:
    fn, sn = pair
    while not fn & 1:
        fn >>= 1
        sn >>= 1
    return fn, sn


def verify_inclusion(
    leaf: Hash, leaf_index: int, tree_size: int, proof: Sequence[Hash], root_hash: Hash
) -> bool:
    """Section 2.1.3.2 of RFC 9162, transcribed step by step. True only if the leaf is in the tree.

    The two refusals matter as much as the arithmetic: an index at or beyond `tree_size` (step 1)
    and a path that runs out while `sn` is still nonzero (step 4.a, and the `sn == 0` check in step
    5). A verifier that returns True on a short path will happily confirm a leaf that was never
    logged, which is the entire crime CT exists to detect.
    """
    if leaf_index >= tree_size:  # step 1
        return False
    if len(leaf) != HASH_SIZE or len(root_hash) != HASH_SIZE:
        raise ProofFormatError("leaf and root hashes must be HASH_SIZE bytes")
    fn, sn = leaf_index, tree_size - 1  # step 2
    accumulator = leaf  # step 3
    for node in proof:  # step 4
        if sn == 0:  # 4.a
            return False
        if fn & 1 or fn == sn:  # 4.b
            accumulator = node_hash(node, accumulator)
            if not fn & 1:  # 4.b.ii, per erratum 8670: shift until the bit is set
                fn, sn = _shift_until_odd((fn, sn))
        else:
            accumulator = node_hash(accumulator, node)  # 4.b otherwise
        fn, sn = fn >> 1, sn >> 1  # 4.c
    return sn == 0 and accumulator == root_hash  # step 5


def verify_consistency(
    first: int,
    second: int,
    proof: Sequence[Hash],
    first_hash: Hash,
    second_hash: Hash,
) -> bool:
    """Section 2.1.4.2 of RFC 9162, step by step: is the older tree a prefix of the newer one?

    This is the check that makes CT's append-only claim bite. A log that shrinks its tree or rewrites
    history has to break it, so the empty-proof refusal (step 1) and the three-way comparison in
    step 7 - both roots *and* `sn == 0` - are not fussy details. Dropping the `sn` check accepts a
    proof that accounts for only part of the newer tree.

    One asymmetry in the specified algorithm is worth knowing before calling it. When `first == 1`,
    step 3 leaves `fn` at 0: LSB(fn) is never set and `fn == sn` never holds, so every element takes
    the "Otherwise" branch, `fr` never moves, and `second` is constrained only by how far it shifts
    toward 0. A proof for one tree size therefore also folds for a few smaller claimed sizes, as long
    as `second_hash` is the root of the larger tree. That is not exploitable through a signed head -
    the STH signature covers `tree_size` and `root_hash` together, so the pair cannot be split - but it
    means this function must always be given the size and the root from the *same* verified artifact,
    never from two places. `ctspy`'s own callers do; see
    `tests/test_production_proofs.py::test_second_is_weak_when_first_is_one_and_the_signature_is_what_pins_it`,
    which pins the behavior against a real 3-billion-entry proof rather than a made-up one.
    """
    if not 0 < first < second:
        raise ProofFormatError(f"consistency needs 0 < first < second, got {first} and {second}")
    if not proof:  # step 1
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # step 2: an exact power of two, so the old root is a real subtree
        path.insert(0, first_hash)
    fn, sn = first - 1, second - 1  # step 3
    if fn & 1:  # step 4: line the two up by removing the shared trailing ones
        while fn & 1:
            fn >>= 1
            sn >>= 1
    accumulator_first = accumulator_second = path[0]  # step 5
    for node in path[1:]:  # step 6
        if sn == 0:  # 6.a
            return False
        if fn & 1 or fn == sn:  # 6.b
            accumulator_first = node_hash(node, accumulator_first)
            accumulator_second = node_hash(node, accumulator_second)
            if not fn & 1:  # 6.b.iii, per erratum 8670
                fn, sn = _shift_until_odd((fn, sn))
        else:
            accumulator_second = node_hash(accumulator_second, node)  # 6.b otherwise
        fn, sn = fn >> 1, sn >> 1  # 6.c
    # step 7
    return accumulator_first == first_hash and accumulator_second == second_hash and sn == 0
