"""The tree leaf: what a log hashes, and what an SCT is a signature over.

RFC 9162 obsoletes RFC 6962, and every deployed log still speaks 6962's version 1. This module parses
that shape - the one whose bytes are on the wire today - and says plainly where v2 differs.

**The fact that makes SCT verification possible.** Compare the two structures:

    MerkleTreeLeaf      = version(0) | leaf_type(timestamped_entry = 0) | TimestampedEntry
    SCT signed struct   = version(0) | signature_type(certificate_timestamp = 0) | TimestampedEntry

`TimestampedEntry` is `timestamp | entry_type | signed_entry | extensions` in both, and the two
single-byte tags that differ - `timestamped_entry` and `certificate_timestamp` - are both zero. So the
bytes a log hashes into its tree are **the same bytes** the log signs for an SCT. Not similar, not
equivalent-by-convention: identical. That is why `sct_transcript()` below can be checked against
production data with no reconstruction of anything, and why the test asserts it equals the raw leaf
bytes rather than trusting the derivation.

**Byte fidelity.** `raw` is kept because the hash is over the bytes the log sent, not over a
re-encoding of what was parsed. A leaf whose parse-and-reserialise round-trips is evidence that the
parser understood it; a hash taken over a re-encoding would quietly verify a leaf the log never stored.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import merkle
from .transcript import Reader, TranscriptError, Writer

__all__ = [
    "V1_LEAF_TYPE",
    "V1_PRECERT_ENTRY",
    "V1_SIGNATURE_TYPE",
    "V1_VERSION",
    "V1_X509_ENTRY",
    "MerkleTreeLeaf",
    "PrecertEntry",
    "TimestampedEntry",
    "X509Entry",
]

V1_VERSION = 0x00
V1_LEAF_TYPE = 0x00  # MerkleLeafType.timestamped_entry, RFC 6962 section 3.4
V1_SIGNATURE_TYPE = 0x00  # SignatureType.certificate_timestamp, RFC 6962 section 3.2
V1_X509_ENTRY = 0x0000
V1_PRECERT_ENTRY = 0x0001

MAX_ENTRY = 0xFFFFFF  # opaque<1..2^24-1>: ASN.1Cert and TBSCertificate


@dataclass(frozen=True, slots=True)
class X509Entry:
    """entry_type x509_entry: the certificate itself, as submitted."""

    certificate: bytes

    entry_type = V1_X509_ENTRY

    def transcript(self) -> bytes:
        return (
            Writer()
            .uint16(self.entry_type)
            .opaque(self.certificate, length_bytes=3, minimum=1, maximum=MAX_ENTRY)
            .build()
        )

    @classmethod
    def parse(cls, reader: Reader) -> X509Entry:
        return cls(certificate=reader.opaque(length_bytes=3, minimum=1, maximum=MAX_ENTRY))


@dataclass(frozen=True, slots=True)
class PrecertEntry:
    """entry_type precert_entry: `opaque issuer_key_hash[32]; TBSCertificate`.

    The 32-byte hash is fixed-width with no length prefix - `PreCert` is a struct holding an
    `opaque[32]`, not an opaque vector. The TBS is the precertificate's TBSCertificate, which section
    3.2 notes can also be recovered from the final certificate by deleting the SCT extension.
    """

    issuer_key_hash: bytes
    tbs_certificate: bytes

    entry_type = V1_PRECERT_ENTRY

    def transcript(self) -> bytes:
        return (
            Writer()
            .uint16(self.entry_type)
            .raw(self.issuer_key_hash)
            .opaque(self.tbs_certificate, length_bytes=3, minimum=1, maximum=MAX_ENTRY)
            .build()
        )

    @classmethod
    def parse(cls, reader: Reader) -> PrecertEntry:
        return cls(
            issuer_key_hash=reader.take(32),
            tbs_certificate=reader.opaque(length_bytes=3, minimum=1, maximum=MAX_ENTRY),
        )


@dataclass(frozen=True, slots=True)
class TimestampedEntry:
    """`uint64 timestamp; LogEntryType entry_type; select(entry_type) {...} signed_entry; CtExtensions`.

    `parse` consumes the `entry_type` discriminator itself and hands the body to the selected variant;
    `transcript` asks the variant to write its own tag back. Asymmetric on purpose: the tag is what
    decides which variant is being read, so the reader has to have it in hand first.
    """

    timestamp: int
    entry: X509Entry | PrecertEntry
    extensions: bytes

    def transcript(self) -> bytes:
        return (
            Writer()
            .uint64(self.timestamp)
            .raw(self.entry.transcript())
            .opaque(self.extensions, length_bytes=2, minimum=0, maximum=65535)
            .build()
        )

    @classmethod
    def parse(cls, reader: Reader) -> TimestampedEntry:
        timestamp = reader.uint64()
        entry_type = reader.uint16()
        if entry_type == V1_X509_ENTRY:
            entry: X509Entry | PrecertEntry = X509Entry.parse(reader)
        elif entry_type == V1_PRECERT_ENTRY:
            entry = PrecertEntry.parse(reader)
        else:
            raise TranscriptError(
                f"LogEntryType 0x{entry_type:04x} is not defined; v1 has x509_entry(0) and "
                "precert_entry(1) only"
            )
        return cls(
            timestamp=timestamp,
            entry=entry,
            extensions=reader.opaque(length_bytes=2, minimum=0, maximum=65535),
        )


@dataclass(frozen=True, slots=True)
class MerkleTreeLeaf:
    """A v1 tree leaf: the bytes as the log sent them, plus what they mean.

    `raw` is authoritative. `leaf_hash()` hashes it and nothing else, so a leaf hash can only ever
    correspond to bytes a log actually stored - not to whatever this library would have written for the
    same fields. `transcript()` exists so the round trip can be asserted; on real leaves from
    production logs the two agree byte for byte, which is what tells you the parser understood them.
    """

    raw: bytes
    version: int
    leaf_type: int
    entry: TimestampedEntry

    def leaf_hash(self) -> bytes:
        return merkle.leaf_hash(self.raw)

    def transcript(self) -> bytes:
        return (
            Writer().uint8(self.version).uint8(self.leaf_type).raw(self.entry.transcript()).build()
        )

    def sct_transcript(self) -> bytes:
        """The `digitally-signed struct` of RFC 6962 section 3.2, as bytes.

        Identical to `transcript()` for v1, because `leaf_type` (timestamped_entry) and
        `signature_type` (certificate_timestamp) are both zero - see this module's docstring. Written
        out from the fields rather than returned as `self.raw` so that the identity is something the
        tests can discover rather than something this function quietly assumes.
        """
        return (
            Writer().uint8(V1_VERSION).uint8(V1_SIGNATURE_TYPE).raw(self.entry.transcript()).build()
        )

    @classmethod
    def parse(cls, data: bytes) -> MerkleTreeLeaf:
        reader = Reader(data, what="MerkleTreeLeaf")
        version = reader.uint8()
        if version != V1_VERSION:
            raise TranscriptError(
                f"MerkleTreeLeaf version {version} is not v1(0); RFC 9162 replaces the v1 leaf with a "
                "TransItem, which ctspy does not parse yet"
            )
        leaf_type = reader.uint8()
        if leaf_type != V1_LEAF_TYPE:
            raise TranscriptError(
                f"MerkleLeafType {leaf_type} is not timestamped_entry(0); a v1 log has no other leaf"
            )
        entry = TimestampedEntry.parse(reader)
        reader.finish()
        return cls(raw=data, version=version, leaf_type=leaf_type, entry=entry)
