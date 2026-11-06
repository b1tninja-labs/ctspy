"""The two answers a verifier is allowed to give, kept apart.

`VerificationError` means the artifact was understood and is not genuine. A parse error -
`TranscriptError`, `ProofFormatError`, `SignatureDecodeError` - means the bytes were never an
artifact at all. Collapsing them is how "the log sent us something we could not read" becomes
recorded as "the log signed a lie", and those are different incidents with different responses: one
is a bug in this library or a fork in the wire format, the other is a page-at-3am event.

Trust model I8 in `certledger` names the same rule from the other side: unknown, unavailable, empty
and zero are four states, and a verifier that returns a bool has two.

Every error in this package derives from `CtspyError`, so a caller who wants "anything ctspy rejected"
needs one `except` clause. The structural three - `TranscriptError`, `ProofFormatError`,
`SignatureDecodeError` - also derive from `ValueError`, because bad bytes are a value problem and callers
already catching that must keep working; `VerificationError` deliberately does not, so a failure to verify
cannot be swallowed by a malformed-input handler. This is stated because the earlier version of this file
claimed `CtspyError` was "base for everything this package raises" while three of its errors subclassed
`ValueError` instead, and a consumer writing `except CtspyError` around entry parsing was left holding an
uncaught exception.
"""

from __future__ import annotations

__all__ = ["CtspyError", "VerificationError"]


class CtspyError(Exception):
    """Base for everything this package raises."""


class VerificationError(CtspyError):
    """A log artifact failed to verify against the key it was pinned to."""
