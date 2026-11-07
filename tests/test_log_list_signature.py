"""Chrome's log-list signature, checked offline against the captured document and against OpenSSL.

`ctspy/loglist.py` verifies RSASSA-PKCS1-v1_5 with SHA-256 in pure Python, because the package keeps
`dependencies = []` and a journal that cannot check its own history is a journal that trusts its transport. Both
sides are exercised here. The three files under `tests/fixtures/loglist/` are `log_list.json`, its signature and
the published key exactly as gstatic served them on 2026-11-06, and `cryptography` - a dev dependency - is the
oracle for signatures this file makes itself.

The negative cases carry as much weight as the positive one. Chrome signs the octets it serves, trailing newline
included, so a snapshot written through a text-mode handle on Windows - which re-translates newlines on the way
out - cannot be verified afterwards. That failure is silent, permanent and specific to how this journal will run,
so it is pinned here rather than left for someone to discover at 3 a.m. against a year of unusable snapshots.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ctspy.loglist import (
    LogListFormatError,
    fingerprint,
    public_key_from_pem,
    rsa_public_from_spki,
    verify_pkcs1_sha256,
)

FIXTURES = Path(__file__).parent / "fixtures" / "loglist"
MESSAGE = (FIXTURES / "log_list.json").read_bytes()
SIGNATURE = (FIXTURES / "log_list.sig").read_bytes()
PUBKEY_PEM = (FIXTURES / "log_list_pubkey.pem").read_text(encoding="ascii")

# Pinned so that editing the fixture is a decision rather than an accident. The document's digest is what a
# coverage claim cites; the key's is what needs an out-of-band pin (see BROWSER-POLICY.md §3).
MESSAGE_SHA256 = "e7930ddd50db8f2f99ad43a331fef94cd76234b1dde6a589b77a446d9783fa17"
KEY_FINGERPRINT = "f1d8b68e50210d8e73d9a3e97f571773c52d7f28c0b1a71beee81d8562e6fd85"


def test_the_captured_document_verifies_offline() -> None:
    """The whole point: this repository can check Chrome's list with no network and no crypto dependency."""
    modulus, exponent = public_key_from_pem(PUBKEY_PEM)
    assert verify_pkcs1_sha256(MESSAGE, SIGNATURE, modulus, exponent)


def test_the_fixture_is_the_document_that_was_signed() -> None:
    assert hashlib.sha256(MESSAGE).hexdigest() == MESSAGE_SHA256
    assert len(MESSAGE) == 65_356
    assert len(SIGNATURE) == 512  # RSA-4096: the signature length is the modulus length


def test_key_fingerprint_is_stable_across_armour_and_der() -> None:
    """`fingerprint` is what an operator pins, so it must not depend on which form they happened to save."""
    import base64

    body = PUBKEY_PEM.split("-----BEGIN PUBLIC KEY-----", 1)[1].split(
        "-----END PUBLIC KEY-----", 1
    )[0]
    assert fingerprint(PUBKEY_PEM) == KEY_FINGERPRINT
    assert fingerprint(base64.b64decode("".join(body.split()))) == KEY_FINGERPRINT


BYTE_MUTATIONS = [
    pytest.param(lambda data: data[:-1], id="dropped-final-byte"),
    pytest.param(lambda data: data.replace(b"\n", b"\r\n"), id="crlf-translation"),
    pytest.param(lambda data: data + b"\n", id="extra-final-byte"),
    pytest.param(
        lambda data: data[:100] + bytes([data[100] ^ 0x01]) + data[101:], id="one-bit-change"
    ),
]


@pytest.mark.parametrize("mutate", BYTE_MUTATIONS)
def test_any_change_to_the_bytes_breaks_the_signature(mutate) -> None:
    """Including the newline case every Windows journal must avoid: text mode is not cosmetic."""
    modulus, exponent = public_key_from_pem(PUBKEY_PEM)
    assert not verify_pkcs1_sha256(mutate(MESSAGE), SIGNATURE, modulus, exponent)


def test_a_foreign_key_answers_false_rather_than_raising() -> None:
    """Asking whether a signature is authentic under the *wrong* key answers False; only bad bytes raise."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = private.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256())
    other_modulus, other_exponent = public_key_from_pem(PUBKEY_PEM)
    assert not verify_pkcs1_sha256(MESSAGE, signature, other_modulus, other_exponent)


def test_signatures_openssl_makes_verify_here() -> None:
    """The oracle relationship `ctspy/ecdsa.py` keeps with OpenSSL, now for the RSA path."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    modulus, exponent = rsa_public_from_spki(der)
    for index in range(20):
        message = f"log list {index}".encode()
        signature = private.sign(message, padding.PKCS1v15(), hashes.SHA256())
        assert verify_pkcs1_sha256(message, signature, modulus, exponent), index
        flipped = bytes([message[0] ^ 0x01]) + message[1:]
        assert not verify_pkcs1_sha256(flipped, signature, modulus, exponent), index


KEY_REFUSALS = [
    pytest.param(b"\x30\x03\x02\x01\x01", id="not-an-spki"),
    pytest.param(b"\x30\x00", id="empty-sequence"),
    pytest.param(b"\x30\x05\x30\x03\x02", id="truncated-inside"),
]


@pytest.mark.parametrize("corrupt", KEY_REFUSALS)
def test_malformed_keys_raise_instead_of_answering_false(corrupt: bytes) -> None:
    """A format problem reported as "not authentic" would turn a broken parser into a security decision."""
    with pytest.raises(LogListFormatError):
        rsa_public_from_spki(corrupt)


def test_an_ecc_key_is_refused_rather_than_misread() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(LogListFormatError, match="rsaEncryption"):
        rsa_public_from_spki(der)


def test_signature_length_mismatch_is_a_refusal_not_a_crash() -> None:
    modulus, exponent = public_key_from_pem(PUBKEY_PEM)
    assert not verify_pkcs1_sha256(MESSAGE, SIGNATURE[:-1], modulus, exponent)
    assert not verify_pkcs1_sha256(MESSAGE, b"\x00" * 512, modulus, exponent)
