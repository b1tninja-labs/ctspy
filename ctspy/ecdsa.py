"""ECDSA over NIST P-256 with SHA-256: the CT-shaped edge around `sigwire.verify`.

**What this file is now.** It used to hold a pure-Python P-256 verifier. The portfolio rule (PORTFOLIO.md
section 9 item 15) is that signature verification goes through `sigwire[verify]`, a strict seam over the
`cryptography` package, so the curve arithmetic moved there and the copy here was deleted. What remains is
what is specific to Certificate Transparency and to the bytes a log serves:

- `EcdsaKey.from_spki`, which reads the base64 SPKI of Chrome's log list and refuses anything but an
  uncompressed P-256 point on the curve, and whose `log_id` is RFC 9162 section 4.4's SHA-256 over that SPKI;
- `parse_der_signature`, which reads the DER `ECDSA-Sig-Value` strictly (minimal integers, exact length,
  nothing trailing), because a lenient parser makes a log artifact that can be rewritten while still
  verifying;
- `verify_sha256`, which keeps its contract (False for a signature that is undecodable or does not
  verify, an exception for a bad key) and delegates the check itself to `sigwire.verify.ecdsa.verify`.

Verification only: nothing here can sign. The OpenSSL oracle tests in `tests/test_signatures.py` stay,
because they pin this module's own parts (DER strictness, SPKI parsing, the False-not-raise contract) and
now also the seam's agreement with OpenSSL over real log signatures. `P256` and `Curve` are re-exported from
`sigwire.verify.ecdsa` so existing imports keep working.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sigwire.verify import ecdsa as _sigwire_ecdsa
from sigwire.verify.ecdsa import P256, Curve

from .errors import CtspyError

__all__ = ["P256", "Curve", "EcdsaKey", "SignatureDecodeError", "verify_sha256"]


class SignatureDecodeError(CtspyError, ValueError):
    """A signature or public key could not be decoded. Never a verification failure."""


def _read_tlv(data: bytes, offset: int, *, expect: int, what: str) -> tuple[bytes, int]:
    """One strict DER element: exact tag, definite minimal length, no trailing slop."""
    if offset >= len(data):
        raise SignatureDecodeError(f"{what} is missing at offset {offset}")
    tag = data[offset]
    if tag != expect:
        raise SignatureDecodeError(f"{what}: expected tag 0x{expect:02x}, found 0x{tag:02x}")
    if offset + 1 >= len(data):
        raise SignatureDecodeError(f"{what}: length byte is missing")
    first = data[offset + 1]
    cursor = offset + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise SignatureDecodeError(f"{what}: indefinite length is not valid DER")
    else:
        count = first & 0x7F
        if count > 4:
            raise SignatureDecodeError(f"{what}: absurd length prefix of {count} bytes")
        if cursor + count > len(data):
            raise SignatureDecodeError(f"{what}: length bytes run past the end")
        raw = data[cursor : cursor + count]
        # Minimality, both ways: a leading zero inflates the encoding, and a single byte below 0x81
        # should have been written in short form. Trusting a padded length is how parsers get
        # convinced two documents are the same object.
        if raw[0] == 0 or (count == 1 and raw[0] < 0x81):
            raise SignatureDecodeError(f"{what}: length is not minimally encoded")
        length = int.from_bytes(raw, "big")
        cursor += count
    if cursor + length > len(data):
        raise SignatureDecodeError(f"{what}: content of {length} bytes runs past the end")
    return data[cursor : cursor + length], cursor + length


def _read_integer(content: bytes, *, what: str) -> int:
    if not content:
        raise SignatureDecodeError(f"{what}: empty INTEGER")
    if content[0] & 0x80:
        raise SignatureDecodeError(f"{what}: INTEGER is negative")
    if len(content) > 1 and content[0] == 0 and content[1] < 0x80:
        raise SignatureDecodeError(f"{what}: INTEGER is not minimally encoded")
    return int.from_bytes(content, "big")


def parse_der_signature(raw: bytes) -> tuple[int, int]:
    """DER `SEQUENCE { INTEGER r, INTEGER s }`, strictly: no padding, no trailing bytes."""
    body, end = _read_tlv(raw, 0, expect=0x30, what="ECDSA-Sig-Value")
    if end != len(raw):
        raise SignatureDecodeError(f"ECDSA-Sig-Value has {len(raw) - end} trailing bytes")
    r_bytes, cursor = _read_tlv(body, 0, expect=0x02, what="r")
    s_bytes, end_of_s = _read_tlv(body, cursor, expect=0x02, what="s")
    if end_of_s != len(body):
        raise SignatureDecodeError("ECDSA-Sig-Value has unexpected elements after s")
    return _read_integer(r_bytes, what="r"), _read_integer(s_bytes, what="s")


_EC_PUBLIC_KEY_OID = bytes.fromhex("2A8648CE3D0201")  # 1.2.840.10045.2.1
_PRIME256V1_OID = bytes.fromhex("2A8648CE3D030107")  # 1.2.840.10045.3.1.7


@dataclass(frozen=True, slots=True)
class EcdsaKey:
    """A P-256 public key validated to lie on the curve, plus its SPKI for log-id hashing."""

    x: int
    y: int
    spki: bytes
    curve: Curve = P256

    @classmethod
    def from_spki(cls, der: bytes, curve: Curve = P256) -> EcdsaKey:
        """Parse a `SubjectPublicKeyInfo` for an EC key on `curve`, rejecting anything else.

        Logs publish their key as base64 SPKI - it is the `key` field of Chrome's log list - so this
        is the shape that arrives from the world. A parser that hunted for a 65-byte tail would
        accept an RSA key with a plausible suffix; this matches both OIDs, requires an uncompressed
        point, and then checks the point satisfies the curve equation.
        """
        outer, end = _read_tlv(der, 0, expect=0x30, what="SubjectPublicKeyInfo")
        if end != len(der):
            raise SignatureDecodeError(f"SubjectPublicKeyInfo has {len(der) - end} trailing bytes")
        algorithm, cursor = _read_tlv(outer, 0, expect=0x30, what="AlgorithmIdentifier")
        key_bits, end_of_spki = _read_tlv(outer, cursor, expect=0x03, what="subjectPublicKey")
        if end_of_spki != len(outer):
            raise SignatureDecodeError("SubjectPublicKeyInfo has elements after the key")
        algorithm_oid, after_oid = _read_tlv(algorithm, 0, expect=0x06, what="algorithm OID")
        if algorithm_oid != _EC_PUBLIC_KEY_OID:
            raise SignatureDecodeError(f"algorithm is {algorithm_oid.hex()}, not id-ecPublicKey")
        curve_oid, _ = _read_tlv(algorithm[after_oid:], 0, expect=0x06, what="curve OID")
        if curve is P256 and curve_oid != _PRIME256V1_OID:
            raise SignatureDecodeError(
                f"curve is {curve_oid.hex()}, not prime256v1; refusing to guess a curve"
            )
        if not key_bits or key_bits[0] != 0:
            raise SignatureDecodeError("subjectPublicKey BIT STRING must have zero unused bits")
        point = key_bits[1:]
        if len(point) != 65 or point[0] != 0x04:
            raise SignatureDecodeError(
                f"expected an uncompressed 65-byte point, got {len(point)} bytes"
            )
        x = int.from_bytes(point[1:33], "big")
        y = int.from_bytes(point[33:65], "big")
        if not curve.contains(x, y):
            raise SignatureDecodeError("public key is not a point on the curve")
        return cls(x=x, y=y, spki=der, curve=curve)

    @property
    def log_id(self) -> bytes:
        """RFC 9162 section 4.4: the log's ID is SHA-256 over the DER-encoded SPKI, nothing else."""
        return hashlib.sha256(self.spki).digest()


def verify_sha256(key: EcdsaKey, message: bytes, signature_der: bytes) -> bool:
    """True when `signature_der` verifies as ECDSA-P256 over SHA-256(message).

    Returns False rather than raising for a malformed signature: callers treat "this artifact is not
    genuine" as a normal answer, and an undecodable signature is that answer. Structural problems in
    the *key* do raise, because those are a configuration mistake and not an adversary.
    """
    try:
        r, s = parse_der_signature(signature_der)
    except SignatureDecodeError:
        return False
    digest = hashlib.sha256(message).digest()
    # sigwire answers False for r or s outside [1, n-1] (FIPS 186-5 section 6.4.2 step 1), so the
    # s == 0 forgery never reaches the backend. The key was validated on the curve when it was built.
    return _sigwire_ecdsa.verify(key.curve, key.x, key.y, digest, r, s, hash_name="sha256")
