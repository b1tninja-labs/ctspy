"""Signed tree heads, verified against artifacts published by production logs.

These fixtures are not synthetic. They are the verbatim bodies of `get-sth` responses from two
Google logs on 2026-11-05, together with the keys those logs publish in Chrome's log list, so a
failure here means either the log changed its wire format or this library got it wrong - both of
which are worth knowing about, and neither of which a self-generated test vector could tell me.

The first test also settles a specification ambiguity that no amount of reading resolves: RFC 6962
section 3.5 puts `Version version;` and `SignatureType signature_type = tree_hash;` inside a
`digitally-signed struct`, RFC 5246 section 4.7 says the signature covers "the contents of the
element", and nothing says whether a field with a declared value is one of those contents. 48 bytes
or 50. Production says 50, and `test_the_48_byte_misreading_is_refused` pins the wrong reading as a
failure rather than leaving it as a plausible alternative.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ctspy.ecdsa import EcdsaKey, verify_sha256
from ctspy.errors import VerificationError
from ctspy.sth import (
    SIGNED_TREE_HEAD_V2,
    SignedTreeHeadV1,
    SignedTreeHeadV2,
    TreeHeadDataV2,
    parse_sth_transitem,
    verify,
)
from ctspy.transcript import Extension, TranscriptError, Writer

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


XENON = load("xenon2026h2-sth.json")
ARGON = load("argon2026h2-sth.json")


def key_of(document: dict) -> EcdsaKey:
    return EcdsaKey.from_spki(base64.b64decode(document["key"]))


def sth_at(document: dict, index: int = 0) -> SignedTreeHeadV1:
    return SignedTreeHeadV1.from_v1_json(document["responses"][index])


def test_production_sths_verify_against_their_published_keys():
    for document in (XENON, ARGON):
        key = key_of(document)
        for position in range(len(document["responses"])):
            verify(sth_at(document, position), key)


def test_the_transcript_is_the_fifty_byte_reading():
    sth = sth_at(XENON)
    transcript = sth.transcript()
    assert len(transcript) == 50
    assert transcript[0] == 0x00, "Version v1"
    assert transcript[1] == 0x01, "SignatureType tree_hash"
    assert int.from_bytes(transcript[2:10], "big") == sth.timestamp
    assert int.from_bytes(transcript[10:18], "big") == sth.tree_size
    assert transcript[18:] == sth.root_hash


def test_the_48_byte_misreading_is_refused():
    """Drop the two declared fields, as a careless reader of RFC 5246 might, and it stops verifying."""
    sth = sth_at(XENON)
    shortened = sth.transcript()[2:]
    assert len(shortened) == 48
    assert verify_sha256(key_of(XENON), shortened, sth.signature) is False
    assert verify_sha256(key_of(XENON), sth.transcript(), sth.signature) is True


def test_one_logs_sth_does_not_verify_under_another_logs_key():
    verify(sth_at(XENON), key_of(XENON))
    with pytest.raises(VerificationError):
        verify(sth_at(XENON), key_of(ARGON))
    with pytest.raises(VerificationError):
        verify(sth_at(ARGON), key_of(XENON))


@pytest.mark.parametrize("field", ["timestamp", "tree_size", "root_hash", "signature"])
def test_a_single_change_invalidates_a_production_sth(field: str) -> None:
    sth = sth_at(XENON)
    current = getattr(sth, field)
    replacement = (
        current + 1 if isinstance(current, int) else bytes([current[0] ^ 0x01]) + current[1:]
    )
    with pytest.raises(VerificationError):
        verify(replace(sth, **{field: replacement}), key_of(XENON))


def test_the_log_id_is_the_sha256_of_the_published_key():
    """Section 4.4 and RFC 6962 section 3.2: SHA-256 over the DER SPKI, and nothing else."""
    for document in (XENON, ARGON):
        published = base64.b64decode(document["log_id"])
        assert key_of(document).log_id == published
        assert hashlib.sha256(base64.b64decode(document["key"])).digest() == published


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("tree_size", "3024195456", "JSON integers"),
        ("timestamp", None, "JSON integers"),
        ("sha256_root_hash", "not base64 at all!", "base64"),
        ("sha256_root_hash", base64.b64encode(b"short").decode(), "not 32"),
        ("tree_head_signature", base64.b64encode(b"\x04\x03").decode(), "DigitallySigned"),
    ],
)
def test_a_malformed_response_is_refused_rather_than_guessing(field, value, reason):
    body = dict(XENON["responses"][0])
    body[field] = value
    with pytest.raises(TranscriptError, match=reason):
        SignedTreeHeadV1.from_v1_json(body)


def test_a_missing_field_is_named():
    body = dict(XENON["responses"][0])
    del body["tree_head_signature"]
    with pytest.raises(TranscriptError, match="tree_head_signature"):
        SignedTreeHeadV1.from_v1_json(body)


def test_an_unsupported_v1_algorithm_is_refused_not_attempted():
    """No fallback path: a log that announces something else fails loudly (trust model I7)."""
    sth = sth_at(XENON)
    with pytest.raises(VerificationError, match="only sha256"):
        verify(replace(sth, signature_algorithm=0x01), key_of(XENON))


def test_v2_transcript_is_the_tree_head_field_alone():
    """Section 4.10.7 signs `tree_head`, unlike the SCT of section 4.8.6 which signs a TransItem."""
    root = bytes(range(32))
    head = TreeHeadDataV2(timestamp=1700000000000, tree_size=42, root_hash=root)
    assert head.transcript() == (
        (1700000000000).to_bytes(8, "big")
        + (42).to_bytes(8, "big")
        + b"\x20"
        + root
        + b"\x00\x00"  # empty extension vector: two length bytes, not zero bytes
    )
    sth = SignedTreeHeadV2(log_id=bytes.fromhex("550403"), tree_head=head, signature=b"\x30\x00")
    assert sth.transcript() == head.transcript()


def test_v2_transitem_round_trips_and_verifies():
    private = ec.generate_private_key(ec.SECP256R1())
    key = EcdsaKey.from_spki(
        private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    head = TreeHeadDataV2(
        timestamp=1700000001000,
        tree_size=7,
        root_hash=hashlib.sha256(b"tree").digest(),
        extensions=(Extension(extension_type=1, extension_data=b"\x01\x02"),),
    )
    signature = private.sign(head.transcript(), ec.ECDSA(hashes.SHA256()))
    data = (
        Writer()
        .uint16(SIGNED_TREE_HEAD_V2)
        .opaque(bytes.fromhex("550403"), length_bytes=1, minimum=2, maximum=127)
        .raw(head.transcript())
        .opaque(signature, length_bytes=2, minimum=1, maximum=65535)
        .build()
    )
    parsed = parse_sth_transitem(data)
    assert parsed.log_id == bytes.fromhex("550403")
    assert parsed.tree_head == head
    verify(parsed, key)


def test_v2_rejects_the_wrong_transitem_type_and_trailing_bytes():
    head = TreeHeadDataV2(timestamp=1, tree_size=1, root_hash=bytes(32))
    body = (
        Writer()
        .uint16(0x0106)  # inclusion_proof_v2, not an STH
        .opaque(bytes.fromhex("550403"), length_bytes=1, minimum=2, maximum=127)
        .raw(head.transcript())
        .opaque(b"\x30\x06\x02\x01\x01\x02\x01\x01"[1:], length_bytes=2, minimum=1, maximum=65535)
        .build()
    )
    with pytest.raises(TranscriptError, match="0x0106"):
        parse_sth_transitem(body)
    good = parse_sth_transitem(
        Writer()
        .uint16(SIGNED_TREE_HEAD_V2)
        .opaque(bytes.fromhex("550403"), length_bytes=1, minimum=2, maximum=127)
        .raw(head.transcript())
        .opaque(b"\x30\x03\x02\x01\x01", length_bytes=2, minimum=1, maximum=65535)
        .build()
    )
    with pytest.raises(TranscriptError):
        parse_sth_transitem(good_body(good) + b"\x00")


def good_body(sth: SignedTreeHeadV2) -> bytes:
    """Re-serialize a parsed STH so a trailing-byte case can be built without hardcoding it."""
    return (
        Writer()
        .uint16(SIGNED_TREE_HEAD_V2)
        .opaque(sth.log_id, length_bytes=1, minimum=2, maximum=127)
        .raw(sth.tree_head.transcript())
        .opaque(sth.signature, length_bytes=2, minimum=1, maximum=65535)
        .build()
    )


def test_extensions_must_be_ordered_and_unique():
    """Sections 4.8.5 and 4.9.7 put two MUSTs on the vector; both change the signed bytes."""
    from ctspy.transcript import Reader, parse_extensions, serialize_extensions

    def vector(items):
        body = b"".join(
            item.extension_type.to_bytes(2, "big")
            + len(item.extension_data).to_bytes(2, "big")
            + item.extension_data
            for item in items
        )
        return len(body).to_bytes(2, "big") + body

    good = (Extension(1, b"a"), Extension(2, b"b"))
    assert parse_extensions(Reader(vector(good), what="t")) == good
    for bad in ((Extension(2, b"b"), Extension(1, b"a")), (Extension(1, b"a"), Extension(1, b"b"))):
        with pytest.raises(TranscriptError, match="ascending order"):
            parse_extensions(Reader(vector(bad), what="t"))
    assert serialize_extensions(()) == b"\x00\x00"
