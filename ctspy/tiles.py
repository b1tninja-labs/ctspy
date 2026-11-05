"""log storage layout, fetching and caching (RFC 9162).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    LogUrl = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "fetch_tile",
]


async def fetch_tile(log: LogUrl, index: int, width: int) -> bytes:
    """Pending behaviour defined by RFC 9162.

    Not implemented yet. See the ``tiles.fetch_tile()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("fetch_tile() is not implemented: RFC 9162")
