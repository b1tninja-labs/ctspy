"""Fifteen SCTs from six live certificates, read by this library's parser.

`tools/fetch_evidence.py` took leaf certificates from public services over ordinary read-only TLS
handshakes - nothing is submitted to any log - and recorded the embedded `SignedCertificateTimestampList`
bytes. What this proves is that the v1 wire format here is the format the real world emits: twelve or
more SCTs across four or five operators, each parsing with no leftover bytes, each naming a log that
appears in the fleet sweep, and each `log_id` equal to SHA-256 over that log's published key.

What it deliberately does not prove: these signatures are not verified here. The embedded extension
carries **precert** SCTs, whose transcript is `issuer_key_hash | TBSCertificate-without-the-SCT-extension`,
and this fixture stores only the leaf certificate - no chain, and so no issuer key. The negative test
below is therefore the honest one for *this* fixture, and the positive case lives in
`tests/test_production_sct_signatures.py`, which carries the issuer certificate alongside each
signature. Splitting the two is not tidiness: the parsing evidence needs nothing but the certificate,
while the signature evidence needs the issuer, and a fixture that quietly grew that dependency would make
the first claim look as though it depended on the second.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from ctspy import sct
from ctspy.ecdsa import EcdsaKey
from ctspy.entry import MerkleTreeLeaf, TimestampedEntry, X509Entry
from ctspy.errors import VerificationError
from ctspy.transcript import TranscriptError, Writer

ROOT = pathlib.Path(__file__).parent
CAPTURED = json.loads((ROOT / "fixtures" / "live-scts.json").read_text(encoding="utf-8"))
SWEEP = json.loads((ROOT / "fixtures" / "log-list-sweep.json").read_text(encoding="utf-8"))
KEYS = {base64.b64decode(row["log_id"]): row for row in SWEEP["logs"]}

DOCUMENTS = [doc for doc in CAPTURED["documents"] if "sct_list" in doc]
CASES = [
    (doc, item) for doc in DOCUMENTS for item in sct.parse_list(base64.b64decode(doc["sct_list"]))
]


def wire(item: sct.SignedCertificateTimestamp) -> bytes:
    return (
        Writer()
        .uint8(item.version)
        .raw(item.log_id)
        .uint64(item.timestamp)
        .opaque(item.extensions, length_bytes=2, minimum=0, maximum=65535)
        .uint8(item.hash_algorithm)
        .uint8(item.signature_algorithm)
        .opaque(item.signature, length_bytes=2, minimum=1, maximum=65535)
        .build()
    )


def x509_transcript(cert_der: bytes, timestamp: int) -> MerkleTreeLeaf:
    entry = TimestampedEntry(
        timestamp=timestamp, entry=X509Entry(certificate=cert_der), extensions=b""
    )
    return MerkleTreeLeaf.parse(b"\x00\x00" + entry.transcript())


def test_the_capture_is_big_enough_to_mean_something() -> None:
    assert len(DOCUMENTS) >= 5, f"only {len(DOCUMENTS)} certificates captured"
    assert len(CASES) >= 12, f"only {len(CASES)} SCTs captured"
    known = {item.log_id for _, item in CASES if item.log_id in KEYS}
    operators = {KEYS[log_id]["operator"] for log_id in known}
    assert len(operators) >= 4, f"SCTs from only these operators: {operators}"


def test_every_sct_reparses_from_its_own_fields() -> None:
    """Round trip on production bytes: a wrong length prefix anywhere cannot survive this."""
    for _doc, item in CASES:
        again = sct.parse(wire(item))
        assert again == item
        assert wire(again) == wire(item)


def test_the_captured_counts_match_the_bytes_handed_to_the_parser() -> None:
    for doc in DOCUMENTS:
        assert len(sct.parse_list(base64.b64decode(doc["sct_list"]))) == doc["count"]
    with pytest.raises(TranscriptError):
        sct.parse_list(b"\x00\x05\x00\x01\x00")  # list length that the data cannot supply


def test_an_sct_that_names_a_pinned_log_names_it_correctly() -> None:
    """`log_id` is SHA-256 over the DER SPKI; on real SCTs, from real logs, that binding holds."""
    checked = 0
    for _, item in CASES:
        record = KEYS.get(item.log_id)
        if record is None:
            continue
        key_der = base64.b64decode(record["key"])
        assert hashlib.sha256(key_der).digest() == item.log_id, record["description"]
        assert EcdsaKey.from_spki(key_der).log_id == item.log_id
        assert item.version == 0
        assert 1_700_000_000_000 < item.timestamp < 1_800_000_000_000
        checked += 1
    assert checked >= 8, f"only {checked} SCTs matched a swept log key"


def test_embedded_precert_scts_do_not_verify_as_x509_entries() -> None:
    """The negative that keeps the positive honest.

    Every one of these is a signature over a precert transcript, so feeding the verifier the x509_entry
    transcript built from the certificate itself must fail. Had `sct.verify` been wrong about the
    transcript in the direction that makes things succeed - signing the wrong bytes, or ignoring a
    field - some SCT here would have "verified" against a tree the log never built.
    """
    attempts = 0
    for doc, item in CASES:
        record = KEYS.get(item.log_id)
        if record is None:
            continue
        key = EcdsaKey.from_spki(base64.b64decode(record["key"]))
        leaf = x509_transcript(base64.b64decode(doc["cert_der"]), item.timestamp)
        with pytest.raises(VerificationError, match="does not verify"):
            sct.verify(item, leaf, key)
        attempts += 1
    assert attempts >= 8, f"only {attempts} SCTs could be tested this way"
