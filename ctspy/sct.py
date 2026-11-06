"""Signed Certificate Timestamps: the wire format, and what the signature is over.

RFC 9162 obsoletes RFC 6962 and redefines the SCT in section 4.8; **this module implements v1**, the
shape every deployed log issues today, and does not parse the v2 `SignedCertificateTimestampDataV2` or
its enclosing `TransItem`. That is a scope statement rather than a gap hidden in a docstring: v2 has no
deployed log to check against, and a v2 SCT reader written without one would be code nobody has seen
work.

What an SCT is: a log's promise about one submission - `key_id`, a timestamp, and a signature over the
entry. Two things make verification easy to get wrong.

**The signature input is the tree leaf.** RFC 6962 section 3.2's `digitally-signed struct` is
`version | signature_type(certificate_timestamp = 0) | timestamp | entry_type | signed_entry |
extensions`, and section 3.4's `MerkleTreeLeaf` is `version | leaf_type(timestamped_entry = 0) |` the
same fields. Both tags are zero, so the SCT signs exactly the bytes that go into the tree. That is not
a convenience - it is the property that makes an SCT and a tree head talk about the same object, and
`entry.MerkleTreeLeaf.sct_transcript()` derives it rather than assuming it.

**`key_id` is a claim, and it must be checked against the key.** Section 3.2: it is SHA-256 over the
log's DER `SubjectPublicKeyInfo`. An SCT that verifies under a pinned key while naming a different log
is either a caller mistake or a cross-log confusion, and `verify` refuses it instead of letting the
caller rediscover that later.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ecdsa import EcdsaKey, verify_sha256
from .entry import MerkleTreeLeaf
from .errors import VerificationError
from .transcript import Reader, TranscriptError

__all__ = ["SignedCertificateTimestamp", "parse", "parse_list", "verify"]

V1_SCT_VERSION = 0x00
# RFC 5246 section 7.4.1.4.1: HashAlgorithm.sha256 = 4, SignatureAlgorithm.ecdsa = 3.
_V1_HASH_SHA256 = 0x04
_V1_SIG_ECDSA = 0x03
LOG_ID_BYTES = 32


@dataclass(frozen=True, slots=True)
class SignedCertificateTimestamp:
    """`Version; LogID; uint64 timestamp; CtExtensions; digitally-signed struct` (RFC 6962 3.2)."""

    version: int
    log_id: bytes
    timestamp: int
    extensions: bytes
    signature: bytes
    hash_algorithm: int = _V1_HASH_SHA256
    signature_algorithm: int = _V1_SIG_ECDSA

    def transcript_for(self, leaf: MerkleTreeLeaf) -> bytes:
        """The bytes this SCT's signature must cover, given the entry the log stored."""
        return leaf.sct_transcript()


def parse(data: bytes) -> SignedCertificateTimestamp:
    """Read one v1 SCT in its TLS wire encoding (RFC 9162 obsoletes this format; logs use it still).

    The field order is the specification's, and two details are easy to get wrong: `LogID` is
    `opaque key_id[32]` - fixed width, **no length prefix** - while `CtExtensions` is a vector with two
    length bytes. Trailing bytes are refused, because an SCT arrives inside a length-delimited list and
    a reader that stops early would silently split one SCT's bytes across two.
    """
    reader = Reader(data, what="SignedCertificateTimestamp")
    version = reader.uint8()
    if version != V1_SCT_VERSION:
        raise TranscriptError(
            f"SCT version {version} is not v1(0); RFC 9162 section 4.8 defines a different v2 shape, "
            "which ctspy does not parse yet"
        )
    log_id = reader.take(LOG_ID_BYTES)
    timestamp = reader.uint64()
    extensions = reader.opaque(length_bytes=2, minimum=0, maximum=65535)
    hash_byte = reader.uint8()
    signature_byte = reader.uint8()
    signature = reader.opaque(length_bytes=2, minimum=1, maximum=65535)
    reader.finish()
    return SignedCertificateTimestamp(
        version=version,
        log_id=log_id,
        timestamp=timestamp,
        extensions=extensions,
        signature=signature,
        hash_algorithm=hash_byte,
        signature_algorithm=signature_byte,
    )


def parse_list(data: bytes) -> tuple[SignedCertificateTimestamp, ...]:
    """A `SignedCertificateTimestampList`, as carried by the TLS extension and the certificate extension.

    Section 3.3: `opaque SerializedSCT<1..2^16-1>` inside `SerializedSCT sct_list<1..2^16-1>` - so a
    two-byte total length, then per-SCT two-byte lengths. An empty list is legal in the encoding and
    useless as evidence; it is returned as an empty tuple and the caller decides, because "no SCTs" and
    "could not read the SCTs" are different answers and this function must not confuse them (the
    confusion being exactly the unknown-vs-zero failure the trust model warns about).

    Unwrapping the X.509 OCTET STRING that contains these bytes is the certificate reader's job; ctspy
    takes no X.509 dependency, so it is not done here. Note that the certificate form has **two** such
    layers, not one: the extension value is a `digitally-signed struct`, which RFC 5246 encodes as an
    OCTET STRING, and that sits inside the OCTET STRING that carries any X.509 extension value. The TLS
    extension has neither. Handing this function the certificate-extension bytes without stripping the
    inner layer reads a tag and length as a list length, and fails with a byte count that looks like
    corrupt data rather than a missing wrapper.
    """
    reader = Reader(data, what="SignedCertificateTimestampList")
    blob = reader.opaque(length_bytes=2, minimum=0, maximum=65535)
    reader.finish()
    body = Reader(blob, what="sct_list")
    items: list[SignedCertificateTimestamp] = []
    while body.remaining():
        items.append(parse(body.opaque(length_bytes=2, minimum=1, maximum=65535)))
    body.finish()
    return tuple(items)


def verify(sct: SignedCertificateTimestamp, leaf: MerkleTreeLeaf, log_key: EcdsaKey) -> None:
    """Raise `VerificationError` unless `sct` is a genuine signature by `log_key` over `leaf`.

    RFC 9162 obsoletes this SCT format but every deployed log still issues it, so this is the check
    that has to work today. Three tests, ordered so the message says the most useful thing first:

    1. **Algorithm.** SHA-256 with ECDSA over P-256, or nothing. A v1 SCT announces its algorithm in
       two bytes, and refusing an unexpected one is better than trying it and being pleased when
       something verifies (trust model I7: no fallback path).
    2. **Identity.** `sct.log_id` must equal SHA-256 over the pinned key's DER SPKI. Without this, a
       valid signature from log B would be credited to the log the caller pinned - the signature check
       would pass and the conclusion would still be wrong.
    3. **The signature**, over the leaf bytes (`entry.MerkleTreeLeaf.sct_transcript`).

    The `sct.timestamp == leaf.entry.timestamp` check is not needed for soundness - the timestamp is
    inside the signed bytes, so a mismatch cannot verify. It is here because the failure it detects is
    a caller pairing an SCT with the wrong leaf, and "this SCT is not for this entry" is a far more
    useful message than "signature does not verify".
    """
    if (sct.hash_algorithm, sct.signature_algorithm) != (_V1_HASH_SHA256, _V1_SIG_ECDSA):
        raise VerificationError(
            f"v1 SCT declares hash {sct.hash_algorithm} and signature {sct.signature_algorithm}; "
            "only sha256(4)/ecdsa(3) is supported"
        )
    if sct.log_id != log_key.log_id:
        raise VerificationError(
            f"SCT names log id {sct.log_id.hex()} but the key offered identifies "
            f"{log_key.log_id.hex()}; section 3.2 defines the id as SHA-256 over this key"
        )
    if sct.timestamp != leaf.entry.timestamp:
        raise VerificationError(
            f"SCT timestamp {sct.timestamp} does not match the leaf's {leaf.entry.timestamp}; "
            "these two do not belong to the same submission"
        )
    message = sct.transcript_for(leaf)
    if not verify_sha256(log_key, message, sct.signature):
        raise VerificationError(
            f"SCT signature does not verify over the {len(message)}-byte leaf transcript "
            "against the pinned key"
        )
