"""static Merkle trees, leaf and node hash prefixes, proof validation (RFC 9162).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Hash = Any  # placeholder: give it a real type in the milestone that needs it
    SignedTreeHead = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "verify_consistency",
    "verify_inclusion",
]


def verify_inclusion(leaf: Hash, tree_size: int, proof: list, sth: SignedTreeHead) -> bool:
    """Pending behaviour defined by RFC 9162.

    Not implemented yet. See the ``merkle.verify_inclusion()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_inclusion() is not implemented: RFC 9162")


def verify_consistency(old: int, new: int, proof: list, old_root: Hash, new_root: Hash) -> bool:
    """Pending behaviour defined by RFC 9162.

    Not implemented yet. See the ``merkle.verify_consistency()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_consistency() is not implemented: RFC 9162")
