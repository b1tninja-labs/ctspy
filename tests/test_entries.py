"""The v1 tree leaf: parsed against bytes from a production log.

The 41 entries in `tests/fixtures/production-tree.json` were fetched from Google Xenon2026h2, and they
cover both arms of the `select (entry_type)` in RFC 6962 section 3.2 - 21 precert entries and 20 x509
entries - so this parser is exercised on shapes nobody wrote a fixture to flatter it. The load-bearing
assertion is the round trip: parse, re-serialise, and get back the exact bytes that came off the wire.
A parser that round-trips cannot have misread a length prefix, because the byte count would not come
out.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from ctspy.entry import (
    MerkleTreeLeaf,
    PrecertEntry,
    TimestampedEntry,
    X509Entry,
)
from ctspy.transcript import TranscriptError

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "production-tree.json").read_text(
        encoding="utf-8"
    )
)
LEAVES = [base64.b64decode(item) for item in FIXTURE["leaf_inputs"]]


def test_production_leaves_round_trip_exactly() -> None:
    for raw in LEAVES:
        leaf = MerkleTreeLeaf.parse(raw)
        assert leaf.transcript() == raw
        assert leaf.raw == raw


def test_both_entry_types_are_present_in_the_fixture() -> None:
    """If a refresh ever yields only one kind, this test says so instead of quietly narrowing."""
    kinds = {type(MerkleTreeLeaf.parse(raw).entry.entry).__name__ for raw in LEAVES}
    assert kinds == {"PrecertEntry", "X509Entry"}, kinds


def test_the_sct_transcript_is_the_leaf_bytes() -> None:
    """`leaf_type` and `signature_type` are both zero, so these are the same byte string.

    This is asserted against production leaves rather than derived from the code: if a future v2 path
    ever made `sct_transcript()` return something else for a v1 leaf, the mistake would be visible
    here rather than in an SCT that mysteriously fails to verify.
    """
    for raw in LEAVES[:8]:
        leaf = MerkleTreeLeaf.parse(raw)
        assert leaf.sct_transcript() == raw == leaf.transcript()


def test_the_leaf_hash_is_over_the_stored_bytes_with_the_zero_prefix() -> None:
    for raw in LEAVES[:5]:
        leaf = MerkleTreeLeaf.parse(raw)
        assert leaf.leaf_hash() == hashlib.sha256(b"\x00" + raw).digest()


def test_a_precert_is_a_fixed_hash_then_a_length_prefixed_tbs() -> None:
    """`opaque issuer_key_hash[32]` has no length byte; `TBSCertificate` has three."""
    entry = PrecertEntry(issuer_key_hash=bytes(range(32)), tbs_certificate=b"\x30\x03\x02\x01\x01")
    transcript = entry.transcript()
    assert transcript[:2] == b"\x00\x01"
    assert transcript[2:34] == bytes(range(32))
    assert transcript[34:37] == b"\x00\x00\x05", (
        "the tbs is five bytes, and the length is three bytes"
    )
    assert (
        MerkleTreeLeaf.parse(
            b"\x00\x00" + TimestampedEntry(timestamp=1, entry=entry, extensions=b"").transcript()
        ).entry.entry
        == entry
    )


def test_an_x509_entry_is_a_length_prefixed_certificate() -> None:
    entry = X509Entry(certificate=b"\x30\x82\x01\x00der")
    assert entry.transcript() == b"\x00\x00\x00\x00\x07\x30\x82\x01\x00der"
    leaf = MerkleTreeLeaf.parse(
        b"\x00\x00" + TimestampedEntry(timestamp=7, entry=entry, extensions=b"").transcript()
    )
    assert leaf.entry.timestamp == 7
    # No extensions means an empty vector. Passing b"\x00\x00" would mean two bytes of extension data
    # that happen to be zero - a distinction the encoder keeps and a reader must not lose.
    assert leaf.entry.extensions == b""


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (b"\x01\x00" + b"\x00" * 20, "version"),
        (b"\x00\x01" + b"\x00" * 20, "timestamped_entry"),
        (b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05" + b"\x00\x00", "not defined"),
        (b"\x00\x00", "wanted 8 bytes"),
        (b"\x00\x00" + b"\x00" * 8 + b"\x00\x00\x00\x00\x01\x30", "wanted 2 bytes"),
        (
            b"\x00\x00" + b"\x00" * 8 + b"\x00\x00\x00\x00\x01\x30" + b"\x00\x00" + b"\xff",
            "unconsumed",
        ),
    ],
)
def test_malformed_leaves_are_refused(data: bytes, why: str) -> None:
    with pytest.raises(TranscriptError, match=why):
        MerkleTreeLeaf.parse(data)


def test_an_empty_certificate_is_refused() -> None:
    """`ASN.1Cert` is opaque<1..2^24-1>: zero length is not a certificate."""
    with pytest.raises(TranscriptError, match=r"outside 1\.\."):
        MerkleTreeLeaf.parse(
            b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" + b"\x00\x00\x00" + b"\x00\x00"
        )
