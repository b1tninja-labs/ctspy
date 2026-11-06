"""The pure-Python verifier, checked against OpenSSL and against the cases it must refuse.

`ctspy/ecdsa.py` implements ECDSA verification itself because the package keeps its runtime
dependency list empty (`AGENTS.md` invariant 4) and RFC 9162 section 10.2.2 registers only two
algorithms. That trade is only defensible if the implementation is checked against something
independent, so `cryptography` - a dev dependency here - is the oracle: signatures OpenSSL makes
must verify, and one-bit changes must not.

The structural refusals are the other half. A verifier that accepts a non-canonical encoding is
malleable, and a malleable log artifact is one two observers can honestly disagree about - which is
precisely the thing a transparency log exists to prevent.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ctspy.ecdsa import (
    P256,
    EcdsaKey,
    SignatureDecodeError,
    parse_der_signature,
    verify_sha256,
)

# A key published by a real log (see tests/fixtures), so the parser is exercised on the shape that
# actually arrives from the world and not only on ones this file made.
REAL_SPKI = base64.b64decode(
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5Xd4lXEos5XJpcx6TOgyA5Z7/C4duaTbQ6C9aXL5Rbqaw+mW1XDnDX7JlRUninIwZYZDU9wRRBhJmCVopzwFvw=="
)


def make_key_pair() -> tuple[ec.EllipticCurvePrivateKey, EcdsaKey]:
    private = ec.generate_private_key(ec.SECP256R1())
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, EcdsaKey.from_spki(der)


@pytest.mark.parametrize(
    "payload", [b"", b"a", b"32 bytes of payload, padded out ok!!", b"\xff" * 4096]
)
def test_signatures_openssl_makes_verify(payload: bytes) -> None:
    private, key = make_key_pair()
    assert verify_sha256(key, payload, private.sign(payload, ec.ECDSA(hashes.SHA256())))


def test_a_hundred_random_signatures_agree_with_openssl() -> None:
    private, key = make_key_pair()
    for index in range(100):
        message = f"ctspy {index}".encode()
        signature = private.sign(message, ec.ECDSA(hashes.SHA256()))
        assert verify_sha256(key, message, signature), index
        flipped = bytes([message[0] ^ 0x01]) + message[1:]
        assert not verify_sha256(key, flipped, signature), index
        broken = bytes([signature[0] ^ 0x20]) + signature[1:]
        assert not verify_sha256(key, message, broken), index


def test_a_signature_from_another_key_is_refused() -> None:
    private, _ = make_key_pair()
    _, other = make_key_pair()
    signature = private.sign(b"subject", ec.ECDSA(hashes.SHA256()))
    assert not verify_sha256(other, b"subject", signature)


def test_the_curve_constants_describe_the_curve_they_claim() -> None:
    """A transcribed constant off by one bit would still be self-consistent, so check it directly."""
    assert P256.contains(P256.gx, P256.gy)
    assert P256.n.bit_length() == 256
    assert P256.p.bit_length() == 256
    assert not P256.contains(P256.gx, (P256.gy + 1) % P256.p)
    assert EcdsaKey.from_spki(REAL_SPKI).log_id == hashlib.sha256(REAL_SPKI).digest()


def test_signature_parsing_is_canonical_or_refuses() -> None:
    assert parse_der_signature(bytes.fromhex("3006020101020102")) == (1, 2)
    cases = (
        (bytes.fromhex("3006020101020102") + b"\x00", "trailing"),
        (bytes.fromhex("308106020101020102"), "minimally"),
        (bytes.fromhex("3080"), "indefinite"),
        (bytes.fromhex("0206020101020102"), "expected tag"),
        (bytes.fromhex("3009020101020102020103"), "after s"),
        (bytes.fromhex("3009020101020400010203"), "minimally"),
        (bytes.fromhex("3006020181020102"), "negative"),
        (bytes.fromhex("3000"), "missing"),
    )
    for bad, why in cases:
        with pytest.raises(SignatureDecodeError, match=why):
            parse_der_signature(bad)


def test_out_of_range_components_are_refused_without_doing_the_math() -> None:
    """s == 0 is the classic 'make the verifier skip its work' signature; r == 0 likewise."""
    private, key = make_key_pair()
    assert verify_sha256(key, b"subject", private.sign(b"subject", ec.ECDSA(hashes.SHA256())))
    assert not verify_sha256(key, b"subject", bytes.fromhex("3006020101020100"))
    assert not verify_sha256(key, b"subject", bytes.fromhex("3006020100020101"))


def test_key_parsing_refuses_everything_that_is_not_a_p256_public_key() -> None:
    rsa_public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    rsa_spki = rsa_public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(SignatureDecodeError, match="id-ecPublicKey"):
        EcdsaKey.from_spki(rsa_spki)

    other_curve = (
        ec.generate_private_key(ec.SECP384R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(SignatureDecodeError, match="prime256v1"):
        EcdsaKey.from_spki(other_curve)

    with pytest.raises(SignatureDecodeError):
        EcdsaKey.from_spki(REAL_SPKI[:-1])
    with pytest.raises(SignatureDecodeError):
        EcdsaKey.from_spki(b"")


def test_a_valid_looking_key_off_the_curve_is_rejected() -> None:
    """The invalid-curve attack: a point off P-256 still supports group arithmetic."""
    private, key = make_key_pair()
    der = key.spki
    # One bit of the affine x coordinate. The chance the result is still on the curve is ~2^-256.
    tampered = der[:-33] + bytes([der[-33] ^ 0x01]) + der[-32:]
    with pytest.raises(SignatureDecodeError, match="not a point on the curve"):
        EcdsaKey.from_spki(tampered)
    assert verify_sha256(key, b"x", private.sign(b"x", ec.ECDSA(hashes.SHA256())))
