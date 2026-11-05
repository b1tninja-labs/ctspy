"""signed tree heads, timestamps and the STH consistency rule (RFC 9162).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    LogKey = Any  # placeholder: give it a real type in the milestone that needs it
    SignedTreeHead = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "verify",
]


def verify(sth: SignedTreeHead, log_key: LogKey) -> None:
    """Pending behaviour defined by RFC 9162.

    Not implemented yet. See the ``sth.verify()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify() is not implemented: RFC 9162")
