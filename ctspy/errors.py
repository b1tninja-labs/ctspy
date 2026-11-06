"""The two answers a verifier is allowed to give, kept apart.

`VerificationError` means the artifact was understood and is not genuine. A parse error -
`TranscriptError`, `ProofFormatError`, `SignatureDecodeError` - means the bytes were never an
artifact at all. Collapsing them is how "the log sent us something we could not read" becomes
recorded as "the log signed a lie", and those are different incidents with different responses: one
is a bug in this library or a fork in the wire format, the other is a page-at-3am event.

Trust model I8 in `certledger` names the same rule from the other side: unknown, unavailable, empty
and zero are four states, and a verifier that returns a bool has two.
"""

from __future__ import annotations

__all__ = ["CtspyError", "VerificationError"]


class CtspyError(Exception):
    """Base for everything this package raises."""


class VerificationError(CtspyError):
    """A log artifact failed to verify against the key it was pinned to."""
