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
    "StoredChain",
    "TimestampedEntry",
    "X509Entry",
    "parse_extra_data",
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


@dataclass(frozen=True, slots=True)
class StoredChain:
    """The certificate an entry is about, and the chain the submitter provided with it.

    `authenticated` says which of those two halves the tree commits to. It is a field rather than a comment
    because the two halves are not the same kind of evidence: RFC 6962 section 4.6 states plainly that the
    retrieved `extra_data` "is not signed", and for an x509 entry the certificate is carried in `leaf_input`
    - which the Merkle tree hashes - while the chain is not. A store that treats the chain as though a log
    had committed to it is claiming an integrity property the protocol does not provide.
    """

    certificate: bytes
    chain: tuple[bytes, ...]
    authenticated: bool

    def __post_init__(self) -> None:
        if not self.certificate:
            raise TranscriptError(
                "an entry needs the certificate it is about; extra_data gave none"
            )


def _der_span(data: bytes, at: int) -> int | None:
    """How many octets the DER element at `at` occupies, or None if none starts there.

    Only header structure is needed here and ctspy takes no ASN.1 dependency, so the tag and length octets
    are read directly. The check is not decoration: a 3-byte number from a mis-sliced blob is usually a
    plausible length, and the only thing that separates a real certificate from a coincidental number is
    whether a DER document actually begins where the length says it does.
    """
    if at + 1 >= len(data) or data[at] != 0x30:
        return None
    first = data[at + 1]
    if first < 0x80:
        span = 2 + first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or at + 2 + count > len(data):
            return None
        span = 2 + count + int.from_bytes(data[at + 2 : at + 2 + count], "big")
    return span if at + span <= len(data) else None


def _certificate_at(data: bytes, at: int, declared: int) -> bool:
    """Does a DER certificate start at `at` and occupy exactly the `declared` octets?"""
    return declared > 0 and _der_span(data, at) == declared


def _read_cert(data: bytes, at: int) -> tuple[bytes, int] | None:
    """One `ASN.1Cert` (an `opaque<1..2^24-1>`) at `at`, and where the next one would start."""
    if len(data) < at + 3:
        return None
    declared = int.from_bytes(data[at : at + 3], "big")
    if not _certificate_at(data, at + 3, declared):
        return None
    return data[at + 3 : at + 3 + declared], at + 3 + declared


def _read_vector(data: bytes, at: int) -> tuple[tuple[bytes, ...], int] | None:
    """An `ASN.1Cert<0..2^24-1>` at `at`: a 3-byte total, then that many octets of certificates."""
    if len(data) < at + 3:
        return None
    total = int.from_bytes(data[at : at + 3], "big")
    if at + 3 + total > len(data):
        return None
    certificates: list[bytes] = []
    cursor = at + 3
    while cursor < at + 3 + total:
        read = _read_cert(data, cursor)
        if read is None:
            return None
        certificates.append(read[0])
        cursor = read[1]
    return tuple(certificates), at + 3 + total


def parse_extra_data(leaf: MerkleTreeLeaf, data: bytes) -> StoredChain:
    """Read what a log stored alongside an entry, using the layout that entry type actually has.

    The two arms are **not** the same shape, and reading them as if they were is the most expensive mistake a
    monitor can make with this data. RFC 6962 section 3.1 defines both `X509ChainEntry` and
    `PrecertChainEntry` as a certificate followed by a chain, which invites one reader; section 4.6 then says
    what `get-entries` actually puts in `extra_data`: "In the case of an X509ChainEntry, this is the
    `certificate_chain`. In the case of a PrecertChainEntry, this is the whole `PrecertChainEntry`."

    The asymmetry is deliberate. An x509 entry's `signed_entry` in the leaf *is* the DER certificate (section
    3.4), so repeating it in `extra_data` would be redundant. A precert entry's `signed_entry` is a `PreCert`
    - an issuer key hash and a TBSCertificate with the poison extension removed - so the certificate the CA
    submitted exists nowhere but `extra_data`. The x509 arm is therefore a single `ASN.1Cert<0..2^24-1>`
    vector, which to a reader written from section 3.1 looks like a mysterious extra length layer, and the
    certificate it hands back comes from the leaf: the half the tree authenticates.

    A log that serves fewer chain certificates than the submission contained is invisible to MTH auditing,
    since `extra_data` is unsigned, so the chain is returned as a count the caller can act on rather than
    assumed complete.
    """
    signed = leaf.entry.entry
    if isinstance(signed, X509Entry):
        read = _read_vector(data, 0)
        if read is None or read[1] != len(data):
            raise TranscriptError(
                f"extra_data of {len(data)} bytes for an x509 entry is not an ASN.1Cert vector; refusing to "
                "guess, because the alternative is storing a chain no log committed to"
            )
        return StoredChain(certificate=signed.certificate, chain=read[0], authenticated=True)
    if isinstance(signed, PrecertEntry):
        submitted = _read_cert(data, 0)
        if submitted is None:
            raise TranscriptError(
                f"extra_data of {len(data)} bytes for a precert entry does not begin with the "
                "precertificate that was submitted"
            )
        if len(data) == submitted[1]:
            # `precertificate_chain` is <0..2^24-1>, so an absent chain is legal: the log stored only the
            # precertificate. Reported rather than repaired - a monitor that cannot reach a root through the
            # stored bytes has a finding about that log, not a parsing error.
            return StoredChain(certificate=submitted[0], chain=(), authenticated=False)
        read = _read_vector(data, submitted[1])
        if read is None or read[1] != len(data):
            raise TranscriptError(
                f"extra_data of {len(data)} bytes for a precert entry has bytes after its certificate vector"
            )
        return StoredChain(certificate=submitted[0], chain=read[0], authenticated=False)
    raise TranscriptError(f"unhandled LogEntryType 0x{signed.entry_type:04x} in parse_extra_data")
