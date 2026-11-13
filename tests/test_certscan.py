"""Finding extensions by structure: the SCT list and the precertificate TBS, read from real certificates.

Ground truth is fixtures captured from live logs and services (`tests/fixtures`): six leaf certificates with
their embedded lists, and precert entries whose logged `tbs_certificate` is the answer `precert_tbs` must
reproduce byte for byte. The hostile cases build certificates by hand, because the defect they pin - a
lookup by substring - is only reachable by a certificate someone crafted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from ctspy import certscan, entry, sct
from ctspy.certscan import CertScanError

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
LIVE = json.loads((FIXTURES / "live-scts.json").read_text("utf-8"))["documents"]
LAYOUT = json.loads((FIXTURES / "extra-data-layout.json").read_text("utf-8"))["entries"]

SCT_OID_DER = bytes.fromhex("060A2B06010401D679020402")
POISON_OID_DER = bytes.fromhex("060A2B06010401D679020403")
KEY_USAGE_OID_DER = bytes.fromhex("0603551D0F")
SAN_OID_DER = bytes.fromhex("0603551D11")


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + certscan._der_length(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def extension(oid_der: bytes, value: bytes, critical: bool = False) -> bytes:
    flag = tlv(0x01, b"\xff") if critical else b""
    return seq(oid_der, flag, tlv(0x04, value))


def tbs_fields(extensions: list[bytes], subject_text: bytes = b"example") -> bytes:
    name = seq(tlv(0x31, seq(bytes.fromhex("0603550403"), tlv(0x0C, subject_text))))
    return b"".join(
        [
            tlv(0xA0, tlv(0x02, b"\x02")),
            tlv(0x02, b"\x01"),
            seq(bytes.fromhex("06082A8648CE3D040302")),
            name,
            seq(tlv(0x17, b"250101000000Z"), tlv(0x17, b"260101000000Z")),
            name,
            seq(seq(bytes.fromhex("06072A8648CE3D0201")), tlv(0x03, b"\x00\x04")),
            tlv(0xA3, seq(*extensions)) if extensions else b"",
        ]
    )


def wrap_certificate(tbs: bytes) -> bytes:
    return seq(tbs, seq(bytes.fromhex("06082A8648CE3D040302")), tlv(0x03, b"\x00\x00"))


def certificate(extensions: list[bytes], subject_text: bytes = b"example") -> bytes:
    return wrap_certificate(seq(tbs_fields(extensions, subject_text)))


def list_extension(payload: bytes) -> bytes:
    return extension(SCT_OID_DER, tlv(0x04, payload))


def with_tbs(der: bytes, new_tbs: bytes) -> bytes:
    """`der` with its TBSCertificate replaced, so a rebuilt TBS can be read back by the same scanner."""
    old, _ = certscan.split_certificate(der)
    return seq(new_tbs + der[der.index(old) + len(old) :])


def live_certificates() -> list[bytes]:
    return [base64.b64decode(doc["cert_der"]) for doc in LIVE if "sct_list" in doc]


def test_the_six_live_certificates_yield_the_fixture_lists() -> None:
    checked = 0
    for doc in LIVE:
        if "sct_list" not in doc:
            continue
        found = certscan.embedded_sct_list(base64.b64decode(doc["cert_der"]))
        assert found == base64.b64decode(doc["sct_list"]), doc["host"]
        assert len(sct.parse_list(found)) == doc["count"]
        checked += 1
    assert checked >= 6


def test_tbs_without_sct_drops_exactly_the_sct_extension() -> None:
    for der in live_certificates():
        tbs, before = certscan.split_certificate(der)
        rebuilt = certscan.tbs_without_sct(der)
        assert len(rebuilt) < len(tbs)
        again, after = certscan.split_certificate(with_tbs(der, rebuilt))
        assert [e.oid for e in after] == [e.oid for e in before if e.oid != certscan.SCT_OID]
        assert again == rebuilt


def spki_hash(der: bytes) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    key = x509.load_der_x509_certificate(der).public_key()
    return hashlib.sha256(
        key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).digest()


def test_precert_tbs_equals_the_logged_precert_tbs() -> None:
    """The reconstruction against ground truth the log produced itself: byte equality.

    Section 3.2 paragraph 9 rewrites issuer and Authority Key Identifier when a Precertificate Signing
    Certificate signed the precert, so equality is expected exactly when the logged `issuer_key_hash` is
    the hash of `chain[0]`'s key (`docs/interop.md`: perfectly diagonal over 494 production precerts). Both
    halves are asserted: the entries that should match do, and none that should not match does by accident.
    """
    equal = 0
    rewritten = 0
    for sample in LAYOUT:
        if sample["kind"] != "precert":
            continue
        leaf = entry.MerkleTreeLeaf.parse(base64.b64decode(sample["leaf_input"]))
        stored = entry.parse_extra_data(leaf, base64.b64decode(sample["extra_data"]))
        logged = leaf.entry.entry
        assert isinstance(logged, entry.PrecertEntry)
        assert certscan.is_precertificate(stored.certificate)
        rebuilt = certscan.precert_tbs(stored.certificate)
        if logged.issuer_key_hash == spki_hash(stored.chain[0]):
            assert rebuilt == logged.tbs_certificate
            equal += 1
        else:
            assert rebuilt != logged.tbs_certificate
            rewritten += 1
    assert equal >= 5
    assert rewritten >= 1


def test_an_oid_inside_another_value_is_not_the_extension() -> None:
    """A subject string that spells the OID's bytes must not be mistaken for the extension."""
    cert = certificate(
        [extension(KEY_USAGE_OID_DER, b"\x03\x02\x01\x86")],
        subject_text=SCT_OID_DER + b"\x04\x00",
    )
    assert SCT_OID_DER in cert
    assert certscan.embedded_sct_list(cert) is None
    assert certscan.tbs_without_sct(cert) == certscan.split_certificate(cert)[0]


def test_an_extension_that_merely_contains_the_oid_bytes_is_kept() -> None:
    decoy = extension(SAN_OID_DER, SCT_OID_DER + POISON_OID_DER)
    real = list_extension(b"\x00\x00")
    cert = certificate([decoy, real])
    kept = certscan.tbs_without_sct(cert)
    assert decoy in kept
    assert real not in kept
    assert certscan.embedded_sct_list(cert) == b"\x00\x00"


def test_two_sct_extensions_are_refused() -> None:
    cert = certificate([list_extension(b"\x00\x00"), list_extension(b"\x00\x00")])
    with pytest.raises(CertScanError):
        certscan.embedded_sct_list(cert)


def test_the_only_extension_cannot_be_removed() -> None:
    with pytest.raises(CertScanError):
        certscan.tbs_without_sct(certificate([list_extension(b"\x00\x00")]))


def test_a_malformed_inner_layer_is_refused() -> None:
    cert = certificate([extension(SCT_OID_DER, b"\x30\x00"), extension(KEY_USAGE_OID_DER, b"\x00")])
    with pytest.raises(CertScanError):
        certscan.embedded_sct_list(cert)


def test_a_certificate_without_the_extension_answers_none() -> None:
    cert = certificate([extension(KEY_USAGE_OID_DER, b"\x00")])
    assert certscan.embedded_sct_list(cert) is None
    assert not certscan.is_precertificate(cert)
    with pytest.raises(CertScanError):
        certscan.precert_tbs(cert)


def test_truncated_certificates_are_refused_never_index_errors() -> None:
    der = live_certificates()[0]
    for cut in range(len(der)):
        with pytest.raises(CertScanError):
            certscan.embedded_sct_list(der[:cut])


def test_non_minimal_length_is_refused() -> None:
    der = certificate([list_extension(b"\x00\x00")])
    header = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7F)
    padded = b"\x30\x83" + (len(der) - header).to_bytes(3, "big") + der[header:]
    with pytest.raises(CertScanError, match="non-minimal"):
        certscan.split_certificate(padded)


def test_trailing_garbage_after_the_certificate_is_refused() -> None:
    with pytest.raises(CertScanError):
        certscan.split_certificate(live_certificates()[0] + b"\x00")


def test_indefinite_length_is_refused() -> None:
    with pytest.raises(CertScanError):
        certscan.split_certificate(b"\x30\x80\x00\x00")


def test_a_second_extensions_field_is_refused() -> None:
    one = tlv(0xA3, seq(list_extension(b"\x00\x00")))
    with pytest.raises(CertScanError):
        certscan.split_certificate(wrap_certificate(seq(tbs_fields([]) + one + one)))


def test_a_chain_element_that_is_a_precertificate_is_refused() -> None:
    """RFC 6962 erratum 3686: only the first element of a precert chain may be a precertificate."""
    sample = next(item for item in LAYOUT if item["kind"] == "precert")
    leaf = entry.MerkleTreeLeaf.parse(base64.b64decode(sample["leaf_input"]))
    stored = entry.parse_extra_data(leaf, base64.b64decode(sample["extra_data"]))
    poisoned = certificate(
        [
            extension(POISON_OID_DER, b"\x05\x00", critical=True),
            extension(KEY_USAGE_OID_DER, b"\x00"),
        ]
    )

    def vector(items: list[bytes]) -> bytes:
        blob = b"".join(len(c).to_bytes(3, "big") + c for c in items)
        return len(blob).to_bytes(3, "big") + blob

    raw = len(stored.certificate).to_bytes(3, "big") + stored.certificate
    with pytest.raises(entry.TranscriptError, match="3686"):
        entry.parse_extra_data(leaf, raw + vector([*stored.chain, poisoned]))
