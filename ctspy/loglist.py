"""Chrome's signed CT log list, verified with nothing but the standard library.

This is **not** part of RFC 9162. It is the mechanism described by Chrome's own log-list page: *"Chrome also
signs these lists (log_list/all_logs_list) to facilitate offline verification of the contents using a published
public key."* A monitor that journals those lists cannot say much about its own history unless it can check the
bytes it stored years later, so the verification primitive lives here rather than in a script.

Two properties are worth being precise about, because both have bitten this project already:

**The signature covers the exact octets served.** Chrome signs `log_list.json` as it is published, trailing
newline included: folding `\n` to `\r\n` or stripping the final byte makes a valid snapshot fail to verify, which
was confirmed against the live documents on 2026-11-06. On Windows that is a trap, because a snapshot written
through a text-mode file handle re-translates every newline. Every writer here opens binary, and a test pins the
consequence.

**A key fetched next to the data proves consistency, not authenticity.** `log_list_pubkey.pem` is served by the
same origin as the lists it signs, so verifying with a freshly fetched key shows that a document and a signature
belong together - which is worth a great deal across a journal's own history - while detection of a substituted
key needs the key's fingerprint pinned out of band. That is a decision for whoever operates the journal, so it is
a parameter here rather than a constant, and `certledger/BROWSER-POLICY.md` §3 records the open item.

Padding is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 section 8.2.2), the scheme the published 512-octet signatures
use. `cryptography`, declared only as a dev extra, is used in the tests as an oracle: signatures it makes must
verify here and single-bit changes must not - the same relationship `ctspy/ecdsa.py` keeps with OpenSSL.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

__all__ = [
    "LogListFormatError",
    "fingerprint",
    "public_key_from_pem",
    "rsa_public_from_spki",
    "verify_pkcs1_sha256",
]

# DigestInfo for SHA-256, DER-encoded: SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING digest }.
# Inlined rather than assembled, because comparing a fixed prefix is harder to get wrong than building it.
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_PEM_LABEL = "PUBLIC KEY"
_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")


class LogListFormatError(ValueError):
    """The bytes are not a shape this module can read. Never a signature failure."""


def _tlv(buffer: bytes, offset: int, *, name: str) -> tuple[int, int, int]:
    """Tag, content offset and content length of one DER object, with framing checked before slicing.

    Python slicing truncates silently, so a decoder that trusts a declared length returns a short value and an
    offset past the end - the failure mode `asn1core` exists to prevent. Everything here validates against the
    buffer it was given before cutting it.
    """
    if offset >= len(buffer):
        raise LogListFormatError(f"{name} missing at offset {offset}")
    tag = buffer[offset]
    cursor = offset + 1
    if cursor >= len(buffer):
        raise LogListFormatError(f"{name} has no length octet")
    first = buffer[cursor]
    cursor += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise LogListFormatError(f"{name} uses an unsupported length form at offset {offset}")
        if cursor + count > len(buffer):
            raise LogListFormatError(f"{name} length octets run past the end")
        length = int.from_bytes(buffer[cursor : cursor + count], "big")
        cursor += count
    else:
        length = first
    if cursor + length > len(buffer):
        raise LogListFormatError(
            f"{name} declares {length} content octets at offset {offset}, {len(buffer) - cursor} present"
        )
    return tag, cursor, length


def rsa_public_from_spki(der: bytes) -> tuple[int, int]:
    """Extract (modulus, public exponent) from a DER SubjectPublicKeyInfo holding an RSA key.

    Deliberately narrow: one SPKI, one RSA key, no algorithm negotiation and no BER tolerance. The general ASN.1
    work belongs to `asn1core`; this reads the single shape a log-list key has ever had, and refuses anything
    else rather than guessing at it.
    """
    tag, cursor, length = _tlv(der, 0, name="SubjectPublicKeyInfo")
    if tag != 0x30:
        raise LogListFormatError(f"want a SEQUENCE, got tag 0x{tag:02x}")
    outer_end = cursor + length
    tag, alg_off, alg_len = _tlv(der, cursor, name="AlgorithmIdentifier")
    if tag != 0x30:
        raise LogListFormatError(f"want an AlgorithmIdentifier SEQUENCE, got tag 0x{tag:02x}")
    _, oid_off, oid_len = _tlv(der, alg_off, name="algorithm OID")
    oid = der[oid_off : oid_off + oid_len]
    if oid != _RSA_ENCRYPTION_OID:
        raise LogListFormatError(f"algorithm OID is not rsaEncryption: {oid.hex()}")
    tag, bits_off, bits_len = _tlv(der, alg_off + alg_len, name="subjectPublicKey")
    if tag != 0x03:
        raise LogListFormatError(f"want a BIT STRING, got tag 0x{tag:02x}")
    if bits_len < 1 or der[bits_off] != 0x00:
        raise LogListFormatError("subjectPublicKey BIT STRING declares unused bits")
    key_start, key_end = bits_off + 1, bits_off + bits_len
    if key_end > outer_end:
        raise LogListFormatError("subjectPublicKey overruns its SubjectPublicKeyInfo")
    tag, seq_off, seq_len = _tlv(der, key_start, name="RSAPublicKey")
    if tag != 0x30 or seq_off + seq_len != key_end:
        raise LogListFormatError("RSAPublicKey does not tile the BIT STRING")
    tag, n_off, n_len = _tlv(der, seq_off, name="modulus")
    if tag != 0x02 or n_len == 0:
        raise LogListFormatError("modulus is not a non-empty INTEGER")
    modulus = int.from_bytes(der[n_off : n_off + n_len], "big", signed=True)
    tag, e_off, e_len = _tlv(der, n_off + n_len, name="publicExponent")
    if tag != 0x02 or e_len == 0:
        raise LogListFormatError("publicExponent is not a non-empty INTEGER")
    exponent = int.from_bytes(der[e_off : e_off + e_len], "big", signed=True)
    if modulus <= 0 or exponent <= 1:
        raise LogListFormatError("RSAPublicKey holds a nonsensical key")
    return modulus, exponent


def public_key_from_pem(text: str) -> tuple[int, int]:
    """The RSA key inside an armoured `PUBLIC KEY`, accepting the plain Figure-1 shape.

    `asn1core.pem` is where the RFC 7468 grammars live; this only has to read one well-formed label, because the
    document it reads is published by Chrome rather than collected from the wild.
    """
    begin, end = f"-----BEGIN {_PEM_LABEL}-----", f"-----END {_PEM_LABEL}-----"
    if begin not in text or end not in text:
        raise LogListFormatError(f"no armoured {_PEM_LABEL} block found")
    interior = text.split(begin, 1)[1].split(end, 1)[0]
    try:
        der = base64.b64decode("".join(interior.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LogListFormatError(f"armour payload is not base64: {exc}") from exc
    return rsa_public_from_spki(der)


def verify_pkcs1_sha256(message: bytes, signature: bytes, modulus: int, exponent: int) -> bool:
    """True when `signature` is a valid RSASSA-PKCS1-v1_5 SHA-256 signature by that key.

    Verification is one modular exponentiation and a comparison, so it happens here rather than being inherited:
    `ctspy` ships `dependencies = []`. Returning False is normal (a foreign key, a changed byte); a malformed key
    or encoding raises, so a format problem can never be reported as "not authentic".
    """
    k = (modulus.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    integer = int.from_bytes(signature, "big")
    if integer >= modulus:
        return False
    digest = hashlib.sha256(message).digest()
    tail = SHA256_DIGEST_INFO_PREFIX + digest
    padding_len = k - len(tail) - 3
    if padding_len < 8:  # PKCS #1 v1.5 requires at least eight 0xFF octets
        return False
    expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + tail
    return pow(integer, exponent, modulus).to_bytes(k, "big") == expected


def fingerprint(der_or_pem: bytes | str) -> str:
    """Hex SHA-256 of a key's DER - what to pin out of band so a substituted key becomes visible."""
    if isinstance(der_or_pem, str):
        begin, end = f"-----BEGIN {_PEM_LABEL}-----", f"-----END {_PEM_LABEL}-----"
        if begin not in der_or_pem or end not in der_or_pem:
            raise LogListFormatError(f"no armoured {_PEM_LABEL} block found")
        body = "".join(der_or_pem.split(begin, 1)[1].split(end, 1)[0].split())
        try:
            raw = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise LogListFormatError(f"armour payload is not base64: {exc}") from exc
    else:
        raw = der_or_pem
    return hashlib.sha256(raw).hexdigest()
