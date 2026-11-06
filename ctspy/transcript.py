"""The TLS-style wire format of log artifacts (RFC 9162 sections 4.5-4.12, RFC 6962 section 3.2).

A log's signature is over a byte string, and there is exactly one byte string. One extra length
prefix, one wrong integer width, and a genuine artifact fails to verify while a forged one might
not - which is the kind of bug that never shows up until it is load-bearing. So the primitives are
here, narrow, and strict:

- integers are big-endian unsigned, 1/2/3 or 8 bytes, matching `uint8`/`uint16`/`uint24`/`uint64`;
- `opaque<T..U>` and vectors carry a length prefix whose width is fixed by the declared range, so
  `<32..2^8-1>` is one byte and `<1..2^24-1>` is three. Getting this width wrong from the range is
  the classic interop failure in this format, and it is checked on read, not assumed;
- nothing is skipped, defaulted, or padded. A reader that tolerates trailing bytes will happily
  "verify" a structure that a log never sent.

Section 4.4 is worth reading before parsing a LogID: it is the DER encoding of an OID **minus** the
tag and length, held in `opaque<2..127>`, which is why the vector's one length byte doubles as the
ASN.1 length.

Extensions carry two MUSTs from sections 4.8 and 4.9 - no duplicate `extension_type`, ascending
order - and both are enforced on parse, because an unordered extension list is a different byte
string, and therefore a different signature input.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "Extension",
    "HashAlgorithm",
    "Reader",
    "SignatureAlgorithm",
    "TranscriptError",
    "Writer",
    "parse_extensions",
    "serialize_extensions",
]

MAX_EXTENSIONS = 65535


class TranscriptError(ValueError):
    """The bytes are not the structure they claimed to be."""


class HashAlgorithm(IntEnum):
    """RFC 9162 section 10.2.1, Table 9. One value is assigned."""

    SHA256 = 0x00


class SignatureAlgorithm(IntEnum):
    """RFC 9162 section 10.2.2, Table 11.

    0x0403 appears twice in the registry - ECDSA over NIST P-256 with SHA-256, and deterministic
    ECDSA with HMAC-SHA256 - because the *verification* is identical and the choice belongs to the
    log. That is the note in section 10.2.2, and it is why one member carries both descriptions.
    """

    ECDSA_SECP256R1_SHA256 = 0x0403
    ED25519 = 0x0807


class Writer:
    """Accumulates a transcript, exactly as the struct declares it."""

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def uint8(self, value: int) -> Writer:
        return self._fixed(value, 1)

    def uint16(self, value: int) -> Writer:
        return self._fixed(value, 2)

    def uint24(self, value: int) -> Writer:
        return self._fixed(value, 3)

    def uint64(self, value: int) -> Writer:
        return self._fixed(value, 8)

    def _fixed(self, value: int, width: int) -> Writer:
        if not 0 <= value < 1 << (8 * width):
            raise TranscriptError(f"{value} does not fit in {width} bytes")
        self._parts.append(value.to_bytes(width, "big"))
        return self

    def opaque(self, data: bytes, *, length_bytes: int, minimum: int, maximum: int) -> Writer:
        """A length-prefixed opaque, with the declared range enforced before writing."""
        if not minimum <= len(data) <= maximum:
            raise TranscriptError(f"opaque of {len(data)} bytes is outside {minimum}..{maximum}")
        self._fixed(len(data), length_bytes)
        self._parts.append(data)
        return self

    def raw(self, data: bytes) -> Writer:
        self._parts.append(data)
        return self

    def build(self) -> bytes:
        return b"".join(self._parts)


class Reader:
    """A cursor over a transcript. Every read is bounds-checked; leftovers are an error."""

    def __init__(self, data: bytes, *, what: str = "transcript") -> None:
        self._data = data
        self._cursor = 0
        self.what = what

    def remaining(self) -> int:
        return len(self._data) - self._cursor

    def finish(self) -> None:
        if self.remaining():
            raise TranscriptError(f"{self.what}: {self.remaining()} unconsumed bytes at the end")

    def take(self, count: int) -> bytes:
        if self._cursor + count > len(self._data):
            raise TranscriptError(
                f"{self.what}: wanted {count} bytes at offset {self._cursor}, "
                f"{self.remaining()} remain"
            )
        chunk = self._data[self._cursor : self._cursor + count]
        self._cursor += count
        return chunk

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def uint8(self) -> int:
        return self.uint(1)

    def uint16(self) -> int:
        return self.uint(2)

    def uint24(self) -> int:
        return self.uint(3)

    def uint64(self) -> int:
        return self.uint(8)

    def opaque(self, *, length_bytes: int, minimum: int, maximum: int) -> bytes:
        length = self.uint(length_bytes)
        if not minimum <= length <= maximum:
            raise TranscriptError(
                f"{self.what}: opaque of {length} bytes is outside {minimum}..{maximum}"
            )
        return self.take(length)


@dataclass(frozen=True, slots=True)
class Extension:
    """Section 4.6: `ExtensionType extension_type; opaque extension_data<0..2^16-1>`."""

    extension_type: int
    extension_data: bytes

    def transcript(self) -> bytes:
        return (
            Writer()
            .uint16(self.extension_type)
            .opaque(self.extension_data, length_bytes=2, minimum=0, maximum=65535)
            .build()
        )


def serialize_extensions(items: tuple[Extension, ...]) -> bytes:
    """The `Extension <0..2^16-1>` vector: two length bytes, then each extension in order."""
    if len(items) > MAX_EXTENSIONS:
        raise TranscriptError(f"{len(items)} extensions exceed the vector limit")
    body = b"".join(item.transcript() for item in items)
    return len(body).to_bytes(2, "big") + body


def parse_extensions(reader: Reader) -> tuple[Extension, ...]:
    """Read an extension vector and enforce the two MUSTs of sections 4.8.5 and 4.9.7.

    Ordering and uniqueness are not cosmetic. The extension bytes are inside a signed transcript,
    so a list that reorders or repeats is a *different* byte string; accepting it leniently means two
    different artifacts can present as the same object, which is exactly the ambiguity a signature is
    supposed to remove.
    """
    length = reader.uint16()
    body = Reader(reader.take(length), what=f"{reader.what}.extensions")
    items: list[Extension] = []
    previous: int | None = None
    while body.remaining():
        extension_type = body.uint16()
        data = body.opaque(length_bytes=2, minimum=0, maximum=65535)
        if previous is not None and extension_type <= previous:
            raise TranscriptError(
                f"extension_type {extension_type} is not greater than the previous {previous}; "
                "section 4.8 requires ascending order and no duplicates"
            )
        previous = extension_type
        items.append(Extension(extension_type=extension_type, extension_data=data))
    body.finish()
    return tuple(items)
