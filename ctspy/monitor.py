"""stream reading, diffing and alerting on unexpected issuance.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    LogUrl = Any  # placeholder: give it a real type in the milestone that needs it
    Sink = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "watch",
]


async def watch(log: LogUrl, since: int, sink: Sink) -> None:
    """Pending behaviour defined by RFC 9162.

    Not implemented yet. See the ``monitor.watch()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("watch() is not implemented: RFC 9162")
