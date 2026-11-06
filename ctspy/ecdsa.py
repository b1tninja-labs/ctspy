"""ECDSA over NIST P-256 with SHA-256, in pure Python.

**Why this file exists instead of a dependency.** `ctspy/AGENTS.md` invariant 4 keeps the runtime
dependency list empty, and RFC 9162 section 10.2.2 registers exactly two signature algorithms for
CT logs - `ecdsa_secp256r1_sha256` (0x0403) and `ed25519` (0x0807) - so the surface needed is one
curve and one hash, not a general-purpose crypto layer. Verification only: nothing here can produce
a signature, which removes the whole class of constant-time and nonce-reuse problems that make
writing ECDSA yourself genuinely dangerous. Signing stays with an HSM or a library that has been
through that fire.

What that trade buys has to be paid for in evidence, so the tests do three things rather than one:
check against vectors derived from FIPS 186-4's algorithm, cross-check several thousand random
signatures against OpenSSL through `cryptography` as a *dev* dependency, and verify a signed tree
head published by a production log. A pure-Python implementation that only agrees with itself is
worth nothing.

The checks that are load-bearing, in the order an attacker would meet them:

1. the public key is a valid point on the curve, not the point at infinity (invalid-curve attack);
2. `r` and `s` are both in `[1, n-1]` (`s == 0` is the classic forgery that skips the math);
3. the DER encoding is canonical - minimal integers, exact length, nothing trailing - because a
   lenient parser gives signature malleability, and a log artifact that can be rewritten while
   still verifying is an artifact that can be disagreed about.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = ["P256", "Curve", "EcdsaKey", "SignatureDecodeError", "verify_sha256"]


class SignatureDecodeError(ValueError):
    """A signature or public key could not be decoded. Never a verification failure."""


@dataclass(frozen=True, slots=True)
class Curve:
    """Short Weierstrass parameters, `y^2 = x^3 + a*x + b (mod p)`, with generator G of order n."""

    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    def contains(self, x: int, y: int) -> bool:
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


P256 = Curve(
    name="secp256r1",
    # FIPS 186-4 D.2.3 / SEC 2: field, a = -3, b, generator and order. Written as literals rather
    # than derived, so a transcription error shows up as a cross-check failure against OpenSSL
    # rather than as a self-consistent but wrong curve.
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

Infinity = None
Point = tuple[int, int] | None


def _add(curve: Curve, first: Point, second: Point) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    modulus = curve.p
    if x1 == x2:
        if (y1 + y2) % modulus == 0:
            return Infinity  # P + (-P) = O
        slope = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, modulus) % modulus
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, modulus) % modulus
    x3 = (slope * slope - x1 - x2) % modulus
    y3 = (slope * (x1 - x3) - y1) % modulus
    return (x3, y3)


def _multiply(curve: Curve, scalar: int, point: Point) -> Point:
    """Double-and-add. Only public values go in, so the lack of constant time is not a secret leak."""
    result: Point = Infinity
    addend = point
    k = scalar % curve.n
    while k:
        if k & 1:
            result = _add(curve, result, addend)
        addend = _add(curve, addend, addend)
        k >>= 1
    return result


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
    order = key.curve.n
    if not 1 <= r < order or not 1 <= s < order:
        return False
    digest = hashlib.sha256(message).digest()
    # FIPS 186-4 4.1.3: leftmost min(Nbits, outlen) bits of the digest, big-endian. Equal here
    # because P-256's order and SHA-256 are both 256 bits, but written out so a future curve with a
    # shorter order (P-224, or a hash longer than the curve) cannot silently inherit the shortcut.
    e = int.from_bytes(digest, "big") >> max(0, 8 * len(digest) - order.bit_length())
    w = pow(s, -1, order)
    u1, u2 = (e * w) % order, (r * w) % order
    base = _multiply(key.curve, u1, (key.curve.gx, key.curve.gy))
    ours = _multiply(key.curve, u2, (key.x, key.y))
    point = _add(key.curve, base, ours)
    if point is None:
        return False
    return point[0] % order == r
