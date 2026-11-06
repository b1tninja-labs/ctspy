"""Signing and verifying a v1 SCT.

Signatures come from OpenSSL through `cryptography`, so an accept here means the pure-Python verifier,
the DER reader, and the transcript all agree with an independent implementation over the same bytes.
The leaves are real: production entries from `production-tree.json`, signed with a throwaway key because
a log's own SCTs cannot be reproduced without submitting to it, which is not something a test suite
should do to somebody else's infrastructure.

The transcript question is settled the other way round from the STH: `entry.py` proves that the v1 SCT
signature input *is* the tree leaf bytes, so what is tested here is the wire format and the checks, not
the shape of the transcript.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ctspy import sct
from ctspy.ecdsa import EcdsaKey
from ctspy.entry import MerkleTreeLeaf
from ctspy.errors import VerificationError
from ctspy.transcript import TranscriptError, Writer

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "production-tree.json").read_text(
        encoding="utf-8"
    )
)
REAL_LEAF = MerkleTreeLeaf.parse(base64.b64decode(FIXTURE["leaf_inputs"][0]))


def key_pair() -> tuple[ec.EllipticCurvePrivateKey, EcdsaKey]:
    private = ec.generate_private_key(ec.SECP256R1())
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, EcdsaKey.from_spki(der)


def wire_bytes(
    log_id: bytes, timestamp: int, signature: bytes, *, extensions: bytes = b"", version: int = 0
) -> bytes:
    """The `SignedCertificateTimestamp` encoding, assembled from the declaration in section 3.2."""
    return (
        Writer()
        .uint8(version)
        .raw(log_id)
        .uint64(timestamp)
        .opaque(extensions, length_bytes=2, minimum=0, maximum=65535)
        .uint8(0x04)
        .uint8(0x03)
        .opaque(signature, length_bytes=2, minimum=1, maximum=65535)
        .build()
    )


def signed_sct(private: ec.EllipticCurvePrivateKey, leaf: MerkleTreeLeaf, log_id: bytes):
    signature = private.sign(leaf.sct_transcript(), ec.ECDSA(hashes.SHA256()))
    return sct.parse(wire_bytes(log_id, leaf.entry.timestamp, signature))


def test_a_real_leaf_and_a_signature_from_openssl_verify() -> None:
    private, key = key_pair()
    sct.verify(signed_sct(private, REAL_LEAF, key.log_id), REAL_LEAF, key)


def test_the_wire_format_offsets_are_what_section_32_declares() -> None:
    """LogID is `opaque key_id[32]`: fixed width, no length prefix. Easy to get wrong, so pinned."""
    log_id = bytes(range(32))
    data = wire_bytes(log_id, 1700000000000, b"\x30\x06\x02\x01\x01\x02\x01\x02")
    assert data[0] == 0x00
    assert data[1:33] == log_id
    assert int.from_bytes(data[33:41], "big") == 1700000000000
    assert data[41:43] == b"\x00\x00", "empty CtExtensions is two length bytes"
    assert data[43:45] == b"\x04\x03", "sha256 + ecdsa, RFC 5246 section 7.4.1.4.1"
    parsed = sct.parse(data)
    assert parsed.log_id == log_id
    assert parsed.timestamp == 1700000000000
    assert parsed.signature == b"\x30\x06\x02\x01\x01\x02\x01\x02"


def test_a_list_of_scts_parses_into_its_parts() -> None:
    one = wire_bytes(bytes(32), 1, b"\x30\x03\x02\x01\x01")
    two = wire_bytes(bytes([7] * 32), 2, b"\x30\x03\x02\x01\x02", extensions=b"\xab\xcd")
    listed = (
        (len(one) + len(two) + 4).to_bytes(2, "big")
        + len(one).to_bytes(2, "big")
        + one
        + len(two).to_bytes(2, "big")
        + two
    )
    parsed = sct.parse_list(listed)
    assert len(parsed) == 2
    assert parsed[1].extensions == b"\xab\xcd"
    assert sct.parse_list(b"\x00\x00") == ()


@pytest.mark.parametrize(
    ("mangle", "why"),
    [
        (lambda data: data + b"\x00", "unconsumed"),
        (lambda data: data[:-1], "wanted"),
        (lambda data: bytes([1]) + data[1:], "not v1"),
        (lambda data: data[:33], "wanted 8 bytes"),
    ],
)
def test_malformed_scts_are_refused(mangle, why: str) -> None:
    _, key = key_pair()
    data = wire_bytes(key.log_id, REAL_LEAF.entry.timestamp, b"\x30\x06\x02\x01\x01\x02\x01\x02")
    with pytest.raises(TranscriptError, match=why):
        sct.parse(mangle(data))


def test_a_changed_leaf_invalidates_the_sct() -> None:
    private, key = key_pair()
    good = signed_sct(private, REAL_LEAF, key.log_id)
    sct.verify(good, REAL_LEAF, key)
    tampered = (
        REAL_LEAF.raw[: len(REAL_LEAF.raw) // 2]
        + bytes([REAL_LEAF.raw[len(REAL_LEAF.raw) // 2] ^ 0x01])
        + REAL_LEAF.raw[len(REAL_LEAF.raw) // 2 + 1 :]
    )
    with pytest.raises(VerificationError, match="does not verify"):
        sct.verify(good, MerkleTreeLeaf.parse(tampered), key)


def test_a_signature_from_another_log_is_refused_on_identity_not_on_math() -> None:
    """The message matters: 'names log id X but the key identifies Y' beats 'signature invalid'."""
    issuing_private, issuing_key = key_pair()
    _, pinned_key = key_pair()
    forged = signed_sct(issuing_private, REAL_LEAF, issuing_key.log_id)
    with pytest.raises(VerificationError, match="names log id"):
        sct.verify(forged, REAL_LEAF, pinned_key)


def test_an_sct_paired_with_the_wrong_entry_is_refused_clearly() -> None:
    private, key = key_pair()
    other = MerkleTreeLeaf.parse(base64.b64decode(FIXTURE["leaf_inputs"][1]))
    assert other.entry.timestamp != REAL_LEAF.entry.timestamp, (
        "fixture would not exercise the check"
    )
    good = signed_sct(private, REAL_LEAF, key.log_id)
    with pytest.raises(VerificationError, match="do not belong to the same submission"):
        sct.verify(good, other, key)


def test_an_unsupported_algorithm_is_refused_before_any_crypto() -> None:
    """No fallback path: an SCT announcing something else fails rather than being attempted."""
    private, key = key_pair()
    good = signed_sct(private, REAL_LEAF, key.log_id)
    with pytest.raises(VerificationError, match="only sha256"):
        sct.verify(
            type(good)(
                version=good.version,
                log_id=good.log_id,
                timestamp=good.timestamp,
                extensions=good.extensions,
                signature=good.signature,
                hash_algorithm=0x03,
                signature_algorithm=0x02,
            ),
            REAL_LEAF,
            key,
        )
