"""Signed tree heads, and the one byte string a log signs over them (RFC 9162 sections 4.9-4.10).

An STH is what a monitor lives on: a timestamp, a tree size, a root hash, and a signature binding all
three to a log's key. Getting its verification wrong turns a lying log into an honest one, so the two
facts that are easy to get wrong are written down here instead of being left to a library.

**What is signed, in v1.** RFC 6962 section 3.5 declares a TLS `digitally-signed struct` beginning
with `Version version;` and `SignatureType signature_type = tree_hash;`, and RFC 5246 section 4.7
says the signature is "over the contents of the element" without saying whether a field given a
fixed value counts. The two readings differ by two bytes, and the 48-byte reading is a common
misreading. Production settles it: the transcript below is 50 bytes - version, signature type,
timestamp, tree size, root hash - and the STH published by Google's Xenon2026h2 log on 2026-11-05
verifies against that and fails against the 48-byte variant. `tests/fixtures/` pins that artifact so
the answer outlives the machine that measured it.

**What is signed, in v2.** Section 4.10.7 is explicit and different: the signature covers the
serialized `tree_head` field, not the enclosing TransItem. SCTs go the other way - section 4.8.6
signs the whole TransItem of the *entry*. That asymmetry is exactly what a generic "sign the object"
helper gets wrong, so each structure builds its own transcript.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .ecdsa import EcdsaKey, verify_sha256
from .errors import VerificationError
from .transcript import (
    Extension,
    Reader,
    TranscriptError,
    Writer,
    parse_extensions,
    serialize_extensions,
)

__all__ = [
    "SIGNED_TREE_HEAD_V2",
    "SignedTreeHeadV1",
    "SignedTreeHeadV2",
    "TreeHeadDataV2",
    "parse_sth_transitem",
    "verify",
]

# VersionedTransType.signed_tree_head_v2, RFC 9162 section 4.5.
SIGNED_TREE_HEAD_V2 = 0x0104

# RFC 6962 section 3.2: enum { v1(0) } Version, and SignatureType tree_hash = 1.
_V1 = 0x00
_V1_TREE_HASH = 0x01
# RFC 5246 section 7.4.1.4.1: HashAlgorithm.sha256 = 4, SignatureAlgorithm.ecdsa = 3.
_V1_HASH_SHA256 = 0x04
_V1_SIG_ECDSA = 0x03


def _parse_digitally_signed(raw: bytes) -> tuple[int, int, bytes]:
    """TLS 1.2 `DigitallySigned { SignatureAndHashAlgorithm; opaque<1..2^16-1> }`."""
    reader = Reader(raw, what="DigitallySigned")
    hash_byte = reader.uint8()
    signature_byte = reader.uint8()
    signature = reader.opaque(length_bytes=2, minimum=1, maximum=65535)
    reader.finish()
    return hash_byte, signature_byte, signature


@dataclass(frozen=True, slots=True)
class TreeHeadDataV2:
    """Section 4.9: `uint64 timestamp; uint64 tree_size; NodeHash root_hash; Extension <...>`."""

    timestamp: int
    tree_size: int
    root_hash: bytes
    extensions: tuple[Extension, ...] = ()

    def transcript(self) -> bytes:
        return (
            Writer()
            .uint64(self.timestamp)
            .uint64(self.tree_size)
            .opaque(self.root_hash, length_bytes=1, minimum=32, maximum=255)
            .raw(serialize_extensions(self.extensions))
            .build()
        )

    @classmethod
    def parse(cls, reader: Reader) -> TreeHeadDataV2:
        head = cls(
            timestamp=reader.uint64(),
            tree_size=reader.uint64(),
            root_hash=reader.opaque(length_bytes=1, minimum=32, maximum=255),
            extensions=parse_extensions(reader),
        )
        if len(head.root_hash) != 32:
            raise TranscriptError(
                f"section 4.9.3 requires NodeHash to match HASH_SIZE, got {len(head.root_hash)}"
            )
        return head


@dataclass(frozen=True, slots=True)
class SignedTreeHeadV1:
    """A v1 STH: the three fields, plus the ECDSA signature taken out of its DigitallySigned wrapper."""

    timestamp: int
    tree_size: int
    root_hash: bytes
    signature: bytes
    hash_algorithm: int = _V1_HASH_SHA256
    signature_algorithm: int = _V1_SIG_ECDSA

    def transcript(self) -> bytes:
        """The 50-byte input of section 3.5. The module docstring carries the evidence for its shape."""
        return (
            Writer()
            .uint8(_V1)
            .uint8(_V1_TREE_HASH)
            .uint64(self.timestamp)
            .uint64(self.tree_size)
            .raw(self.root_hash)
            .build()
        )

    @classmethod
    def from_v1_json(cls, body: dict[str, object]) -> SignedTreeHeadV1:
        """Read a `/ct/v1/get-sth` response, refusing anything that is not what it claims.

        JSON is where lenient parsing does silent damage: `tree_size` arriving as a string, a root
        hash with whitespace in its base64, a signature missing its DigitallySigned header. Each
        yields a plausible object whose signature will not verify, after which the failure looks like
        a compromised log rather than a malformed response.
        """
        fields = ("tree_size", "timestamp", "sha256_root_hash", "tree_head_signature")
        missing = [name for name in fields if name not in body]
        if missing:
            raise TranscriptError(f"STH response is missing {', '.join(missing)}")
        timestamp, tree_size = body["timestamp"], body["tree_size"]
        if not isinstance(timestamp, int) or not isinstance(tree_size, int):
            raise TranscriptError("timestamp and tree_size must be JSON integers")
        if timestamp < 0 or tree_size < 0:
            raise TranscriptError("timestamp and tree_size must not be negative")
        root = _decode_base64(body["sha256_root_hash"], field="sha256_root_hash")
        if len(root) != 32:
            raise TranscriptError(f"sha256_root_hash is {len(root)} bytes, not 32")
        wrapper = _decode_base64(body["tree_head_signature"], field="tree_head_signature")
        hash_byte, signature_byte, signature = _parse_digitally_signed(wrapper)
        return cls(
            timestamp=timestamp,
            tree_size=tree_size,
            root_hash=root,
            signature=signature,
            hash_algorithm=hash_byte,
            signature_algorithm=signature_byte,
        )


def _decode_base64(value: object, *, field: str) -> bytes:
    if not isinstance(value, str):
        raise TranscriptError(f"{field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error and friends, all of which mean "not base64"
        raise TranscriptError(f"{field} is not valid base64: {exc}") from exc


@dataclass(frozen=True, slots=True)
class SignedTreeHeadV2:
    """Section 4.10: `LogID log_id; TreeHeadDataV2 tree_head; opaque signature<1..2^16-1>`."""

    log_id: bytes
    tree_head: TreeHeadDataV2
    signature: bytes

    def transcript(self) -> bytes:
        """Section 4.10.7: over the `tree_head` field, not over the enclosing TransItem."""
        return self.tree_head.transcript()


def parse_sth_transitem(data: bytes) -> SignedTreeHeadV2:
    """Parse a complete `TransItem` of type signed_tree_head_v2 (section 4.5)."""
    reader = Reader(data, what="TransItem")
    kind = reader.uint16()
    if kind != SIGNED_TREE_HEAD_V2:
        raise TranscriptError(
            f"TransItem type is 0x{kind:04x}, not signed_tree_head_v2 (0x{SIGNED_TREE_HEAD_V2:04x})"
        )
    log_id = reader.opaque(length_bytes=1, minimum=2, maximum=127)
    tree_head = TreeHeadDataV2.parse(reader)
    signature = reader.opaque(length_bytes=2, minimum=1, maximum=65535)
    reader.finish()
    return SignedTreeHeadV2(log_id=log_id, tree_head=tree_head, signature=signature)


def verify(sth: SignedTreeHeadV1 | SignedTreeHeadV2, log_key: EcdsaKey) -> None:
    """Raise `VerificationError` unless `sth` is a genuine signature by `log_key` (RFC 9162).

    RFC 9162 governs both shapes. The algorithm is taken from the pinned key rather than from the
    artifact: section 4.1 makes the signature algorithm a log *parameter*, agreed out of band with
    the key, and `EcdsaKey.from_spki` already refuses a key that is not P-256 ECDSA. A log declaring
    `ed25519` therefore fails at pinning time, which is loud, instead of being silently verified
    under the wrong scheme.

    A v1 artifact that announces anything other than SHA-256/ECDSA is refused rather than attempted:
    there is no fallback path in this module, and "we tried the other algorithm and it worked" is not
    an answer anyone wants to read after the fact.
    """
    if isinstance(sth, SignedTreeHeadV1):
        if (sth.hash_algorithm, sth.signature_algorithm) != (_V1_HASH_SHA256, _V1_SIG_ECDSA):
            raise VerificationError(
                f"v1 STH declares hash {sth.hash_algorithm} and signature "
                f"{sth.signature_algorithm}; only sha256(4)/ecdsa(3) is supported"
            )
        message, label = sth.transcript(), "v1"
    elif isinstance(sth, SignedTreeHeadV2):
        message, label = sth.transcript(), "v2"
    else:
        raise TypeError(f"cannot verify {type(sth).__name__} as an STH")
    if not verify_sha256(log_key, message, sth.signature):
        raise VerificationError(
            f"{label} STH signature does not verify over the {len(message)}-byte transcript "
            "against the pinned key"
        )
