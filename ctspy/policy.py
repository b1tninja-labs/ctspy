"""which logs and which artifacts a deployment will accept.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from typing import Any

    Decision = Any  # placeholder: give it a real type in the milestone that needs it
    Policy = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "acceptable",
]


def acceptable(scts: list, at: datetime, policy: Policy) -> Decision:
    """Pending behaviour defined by design.

    Not implemented yet. See the ``policy.acceptable()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("acceptable() is not implemented: design")
