"""Log signatures, verified. The test that says `sct.verify` works against a real log.

Each case is a certificate fetched from a public service, an SCT that a public log signed, that log's
published key, and the certificate that issued the precert. The transcript is rebuilt here from the
certificate - delete the SCT extension, hash the issuer's public key, re-encode the lengths - and the
log's own signature lands on it. Six cases, six logs, four operators.

The reconstruction lives in this file rather than being imported from the tool on purpose. A test that
trusted a precomputed transcript would prove only that ECDSA works; re-deriving it from the certificate
is what proves the *transcript rule*. The fixture also stores what the tool computed, so if the two
implementations ever drift apart, the reproducibility test says so rather than a signature mysteriously
failing later.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ctspy import sct
from ctspy.ecdsa import EcdsaKey
from ctspy.entry import MerkleTreeLeaf, PrecertEntry, TimestampedEntry
from ctspy.errors import VerificationError

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "live-sct-signatures.json").read_text(
        encoding="utf-8"
    )
)
CASES = FIXTURE["cases"]
SCT_OID = bytes.fromhex("060a2b06010401d679020402")  # 1.3.6.1.4.1.11129.2.4.2


def tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    tag = data[offset]
    cursor = offset + 1
    first = data[cursor]
    if first < 0x80:
        length, cursor = first, cursor + 1
    else:
        count = first & 0x7F
        length = int.from_bytes(data[cursor + 1 : cursor + 1 + count], "big")
        cursor = cursor + 1 + count
    return tag, cursor, cursor + length


def elements(content: bytes) -> list[tuple[int, int, int, int, int]]:
    out, cursor = [], 0
    while cursor < len(content):
        _, start, end = tlv(content, cursor)
        out.append((content[cursor], cursor, end, start, end))
        cursor = end
    return out


def encode_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tbs_of(cert_der: bytes) -> bytes:
    _, body_start, body_end = tlv(cert_der, 0)
    first = elements(cert_der[body_start:body_end])[0]
    return cert_der[body_start + first[1] : body_start + first[2]]


def strip_sct_extension(tbs: bytes) -> bytes:
    """RFC 6962 3.2's reconstruction: the TBS with the SCT extension deleted, lengths re-encoded."""
    _, body_start, body_end = tlv(tbs, 0)
    body = tbs[body_start:body_end]
    block = next((item for item in elements(body) if item[0] == 0xA3), None)
    assert block is not None, "a certificate carrying SCTs carries extensions"
    _, _, _, a3_cs, a3_ce = block
    wrapper = elements(body[a3_cs:a3_ce])[0]
    seq_cs, seq_ce = a3_cs + wrapper[3], a3_cs + wrapper[4]
    every = elements(body[seq_cs:seq_ce])
    kept = [
        body[seq_cs + item[1] : seq_cs + item[2]]
        for item in every
        if SCT_OID not in body[seq_cs + item[1] : seq_cs + item[2]]
    ]
    assert len(kept) == len(every) - 1, "exactly the SCT extension should have gone"
    inner = b"\x30" + encode_length(sum(len(item) for item in kept)) + b"".join(kept)
    outer = b"\xa3" + encode_length(len(inner)) + inner
    new_body = body[: block[1]] + outer + body[block[2] :]
    return b"\x30" + encode_length(len(new_body)) + new_body


def spki(cert_der: bytes) -> bytes:
    return (
        x509.load_der_x509_certificate(cert_der)
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def leaf_for(tbs: bytes, issuer_hash: bytes, timestamp: int) -> MerkleTreeLeaf:
    entry = TimestampedEntry(
        timestamp=timestamp, entry=PrecertEntry(issuer_hash, tbs), extensions=b""
    )
    return MerkleTreeLeaf.parse(b"\x00\x00" + entry.transcript())


def case_id(case: dict) -> str:
    return f"{case['host']}-{case['log'].split()[0]}"


def issuer_hash_of(case: dict) -> bytes:
    return hashlib.sha256(spki(base64.b64decode(case["issuer_certificate"]))).digest()


def test_the_capture_covers_several_logs_and_operators() -> None:
    assert len(CASES) >= 4, f"only {len(CASES)} verified signatures captured"
    assert len({case["log"] for case in CASES}) >= 4, "the cases should not all be one log"
    assert len({case["log"].split()[0] for case in CASES}) >= 3, "and not all one operator"


def test_more_attempts_than_successes_is_expected_not_a_defect() -> None:
    """Each host offers the leaf as a candidate issuer before the real one, and must reject it.

    Recording both numbers keeps the negatives visible: a capture that reported only its successes
    would hide the fact that a wrong issuer fails the same check, which is the property that makes the
    successes mean anything.
    """
    assert FIXTURE["attempts"] > FIXTURE["verified"] >= len(CASES)
    assert FIXTURE["provenance"]["fetched_utc"].startswith("2026-")


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_the_reconstruction_is_reproducible_from_the_certificate(case: dict) -> None:
    """The tool's transcript, re-derived here independently. Two implementations, one answer."""
    certificate = base64.b64decode(case["certificate"])
    assert strip_sct_extension(tbs_of(certificate)) == base64.b64decode(case["reconstructed_tbs"])
    assert issuer_hash_of(case) == bytes.fromhex(case["issuer_key_hash"])
    assert strip_sct_extension(tbs_of(certificate)) != tbs_of(certificate)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_a_real_log_signed_this_transcript(case: dict) -> None:
    """The claim in one line: this signature, from a published log key, covers these bytes."""
    signature = sct.parse(base64.b64decode(case["sct"]))
    key_der = base64.b64decode(case["log_key"])
    key = EcdsaKey.from_spki(key_der)
    assert signature.log_id == key.log_id == hashlib.sha256(key_der).digest()
    sct.verify(
        signature,
        leaf_for(
            base64.b64decode(case["reconstructed_tbs"]), issuer_hash_of(case), signature.timestamp
        ),
        key,
    )


@pytest.mark.parametrize("case", CASES[:3], ids=case_id)
def test_the_same_signature_refuses_a_different_precert(case: dict) -> None:
    """One byte of the TBS, or the leaf's key instead of the issuer's, and it stops verifying."""
    signature = sct.parse(base64.b64decode(case["sct"]))
    key = EcdsaKey.from_spki(base64.b64decode(case["log_key"]))
    tbs = base64.b64decode(case["reconstructed_tbs"])
    middle = len(tbs) // 2
    tampered = tbs[:middle] + bytes([tbs[middle] ^ 0x01]) + tbs[middle + 1 :]
    with pytest.raises(VerificationError, match="does not verify"):
        sct.verify(signature, leaf_for(tampered, issuer_hash_of(case), signature.timestamp), key)

    wrong_issuer = hashlib.sha256(spki(base64.b64decode(case["certificate"]))).digest()
    assert wrong_issuer != issuer_hash_of(case)
    with pytest.raises(VerificationError, match="does not verify"):
        sct.verify(signature, leaf_for(tbs, wrong_issuer, signature.timestamp), key)


@pytest.mark.parametrize("case", CASES[:3], ids=case_id)
def test_a_log_cannot_be_made_to_vouch_for_another_logs_signature(case: dict) -> None:
    """The binding that pinning depends on: a valid signature, offered to the wrong log."""
    other = next(item for item in CASES if item["log"] != case["log"])
    signature = sct.parse(base64.b64decode(case["sct"]))
    leaf = leaf_for(
        base64.b64decode(case["reconstructed_tbs"]), issuer_hash_of(case), signature.timestamp
    )
    with pytest.raises(VerificationError, match="names log id"):
        sct.verify(signature, leaf, EcdsaKey.from_spki(base64.b64decode(other["log_key"])))
