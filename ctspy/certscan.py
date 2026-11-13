"""Find certificate extensions by walking the DER, never by searching the bytes.

An X.509 certificate is a tree, and an extension is a node at one position in it. A byte string that
looks like the SCT extension's OID can occur anywhere else - in a subject name, in another extension's
value - so a lookup that scans for those bytes is deceived by a certificate its author controls. This
module walks the structure of RFC 5280's `Certificate` and `TBSCertificate` instead, and an extension
exists only where the walk finds it: the `[3]` field of the TBSCertificate, one `Extension` SEQUENCE at
a time.

ASN.1 and X.509 are our own code (`AGENTS.md` invariant 4), so the walk is in-tree: about a hundred
lines of strict DER, which is the grain this question needs. It reads only the shape of the certificate
and interprets nothing inside names, validity or keys. Anything it cannot place exactly is refused with
`CertScanError`; it never guesses and never returns an empty value for malformed input, because "no SCT
extension" and "could not read the certificate" are different answers.

Strictness, all of it deliberate: lengths are minimal (a DER rule, and a non-minimal length is a second
encoding of the same bytes), indefinite lengths are refused, multi-byte tags are refused (none occurs in
the fields walked), the certificate must end where its outer SEQUENCE ends, the extensions field may
appear once, and an extension's `critical` flag is encoded only when TRUE, as DER requires.

RFC 6962 section 3.3 paragraph 4 gives the extension (OID 1.3.6.1.4.1.11129.2.4.2) and section 3.2
paragraph 9 gives the reconstruction rule: the logged TBSCertificate is the final certificate's with
that extension deleted. The precertificate's poison extension is 1.3.6.1.4.1.11129.2.4.3.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import CtspyError

__all__ = [
    "POISON_OID",
    "SCT_OID",
    "CertExtension",
    "CertScanError",
    "embedded_sct_list",
    "is_precertificate",
    "precert_tbs",
    "split_certificate",
    "subject_public_key_info",
    "tbs_without_extension",
    "tbs_without_sct",
]

SCT_OID = "1.3.6.1.4.1.11129.2.4.2"
POISON_OID = "1.3.6.1.4.1.11129.2.4.3"

_SEQUENCE = 0x30
_INTEGER = 0x02
_BOOLEAN = 0x01
_OCTET_STRING = 0x04
_OID = 0x06
_VERSION = 0xA0
_ISSUER_UID = 0x81
_SUBJECT_UID = 0x82
_EXTENSIONS = 0xA3


class CertScanError(CtspyError, ValueError):
    """The bytes are not a certificate this scanner can place field by field."""


@dataclass(frozen=True, slots=True)
class CertExtension:
    """One X.509 extension, with where its whole encoding sits in the certificate."""

    oid: str
    critical: bool
    value: bytes
    span: tuple[int, int]


def _tlv(data: bytes, offset: int, end: int) -> tuple[int, int, int]:
    """(tag, content_start, content_end) of the element at `offset`, which must lie within `end`."""
    if offset + 2 > end:
        raise CertScanError(f"truncated element header at offset {offset}")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise CertScanError(f"multi-byte tag at offset {offset}")
    first = data[offset + 1]
    cursor = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise CertScanError(f"indefinite length at offset {offset}")
        if count > 4 or cursor + count > end:
            raise CertScanError(f"unusable length-of-length at offset {offset}")
        raw = data[cursor : cursor + count]
        length = int.from_bytes(raw, "big")
        if raw[0] == 0 or length < 0x80:
            raise CertScanError(f"non-minimal length at offset {offset}")
        cursor += count
    if cursor + length > end:
        raise CertScanError(f"element at offset {offset} runs past its container")
    return tag, cursor, cursor + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """(tag, element_start, content_start, content_end) for each element filling [start, end)."""
    out = []
    cursor = start
    while cursor < end:
        tag, content_start, content_end = _tlv(data, cursor, end)
        out.append((tag, cursor, content_start, content_end))
        cursor = content_end
    return out


def _oid(content: bytes) -> str:
    if not content or content[-1] & 0x80:
        raise CertScanError("malformed OBJECT IDENTIFIER")
    arcs: list[int] = []
    value = 0
    fresh = True
    for octet in content:
        if fresh and octet == 0x80:
            raise CertScanError("non-minimal OBJECT IDENTIFIER arc")
        fresh = False
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(value)
            value = 0
            fresh = True
    head, rest = divmod(arcs[0], 40)
    first = [head, rest] if head < 2 else [2, arcs[0] - 80]
    return ".".join(str(arc) for arc in first + arcs[1:])


def _der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _parse_extension(data: bytes, start: int, end: int) -> CertExtension:
    tag, content_start, content_end = _tlv(data, start, end)
    if tag != _SEQUENCE:
        raise CertScanError("an extension is not a SEQUENCE")
    parts = _children(data, content_start, content_end)
    if not 2 <= len(parts) <= 3 or parts[0][0] != _OID or parts[-1][0] != _OCTET_STRING:
        raise CertScanError("an extension is not OID, optional BOOLEAN, OCTET STRING")
    critical = False
    if len(parts) == 3:
        flag = parts[1]
        if flag[0] != _BOOLEAN or data[flag[2] : flag[3]] != b"\xff":
            raise CertScanError("the critical flag is not a DER TRUE (and FALSE is never encoded)")
        critical = True
    oid = _oid(data[parts[0][2] : parts[0][3]])
    return CertExtension(oid, critical, data[parts[-1][2] : parts[-1][3]], (start, content_end))


def _walk(der: bytes) -> tuple[int, int, int, int, list[CertExtension], tuple[int, int]]:
    """(tbs_start, tbs_end, ext_field_start, ext_field_end, extensions, spki_span); the `[3]` field is empty if absent."""
    tag, body_start, body_end = _tlv(der, 0, len(der))
    if tag != _SEQUENCE:
        raise CertScanError("a certificate is a SEQUENCE")
    if body_end != len(der):
        raise CertScanError(f"{len(der) - body_end} octets after the certificate")
    tbs_tag, tbs_body, tbs_end = _tlv(der, body_start, body_end)
    if tbs_tag != _SEQUENCE:
        raise CertScanError("the TBSCertificate is a SEQUENCE")
    fields = _children(der, tbs_body, tbs_end)
    index = 0
    if fields and fields[0][0] == _VERSION:
        index = 1
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    shape = [_INTEGER, _SEQUENCE, _SEQUENCE, _SEQUENCE, _SEQUENCE, _SEQUENCE]
    spki_span = (0, 0)
    for want in shape:
        if index >= len(fields) or fields[index][0] != want:
            raise CertScanError("the TBSCertificate fields are not in the RFC 5280 order")
        # The last field of the shape is the SubjectPublicKeyInfo: element start to content end.
        spki_span = (fields[index][1], fields[index][3])
        index += 1
    for optional in (_ISSUER_UID, _SUBJECT_UID):
        if index < len(fields) and fields[index][0] == optional:
            index += 1
    extensions: list[CertExtension] = []
    field = (tbs_end, tbs_end)
    if index < len(fields) and fields[index][0] == _EXTENSIONS:
        _, element, content_start, content_end = fields[index]
        field = (element, content_end)
        index += 1
        wrapper = _children(der, content_start, content_end)
        if len(wrapper) != 1 or wrapper[0][0] != _SEQUENCE:
            raise CertScanError("the extensions field is not one SEQUENCE")
        for _, element_start, _, element_end in _children(der, wrapper[0][2], wrapper[0][3]):
            extensions.append(_parse_extension(der, element_start, element_end))
        if not extensions:
            raise CertScanError("an extensions field with no extensions")
    if index != len(fields):
        raise CertScanError("fields after the extensions, or a second extensions field")
    return body_start, tbs_end, field[0], field[1], extensions, spki_span


def split_certificate(der: bytes) -> tuple[bytes, tuple[CertExtension, ...]]:
    """The exact TBSCertificate octets and its extensions, in the order the certificate lists them."""
    tbs_start, tbs_end, _, _, extensions, _ = _walk(der)
    return der[tbs_start:tbs_end], tuple(extensions)


def subject_public_key_info(der: bytes) -> bytes:
    """The exact DER `SubjectPublicKeyInfo` of a certificate: the bytes a log's `issuer_key_hash` covers.

    RFC 6962 section 3.2 defines `issuer_key_hash` as the SHA-256 of the issuer's `SubjectPublicKeyInfo`, so
    the octets must be the certificate's own and not a re-encoding. Raises `CertScanError` for a certificate
    the walk cannot place.
    """
    spki_span = _walk(der)[5]
    return der[spki_span[0] : spki_span[1]]


def _only(extensions: tuple[CertExtension, ...], oid: str) -> CertExtension | None:
    found = [item for item in extensions if item.oid == oid]
    if len(found) > 1:
        raise CertScanError(f"extension {oid} appears {len(found)} times")
    return found[0] if found else None


def is_precertificate(der: bytes) -> bool:
    """True when the certificate carries the CT poison extension (RFC 6962 section 3.1)."""
    return _only(split_certificate(der)[1], POISON_OID) is not None


def embedded_sct_list(der: bytes) -> bytes | None:
    """The `SignedCertificateTimestampList` bytes inside a certificate, or None if it has no SCT extension.

    The extension value is an OCTET STRING (X.509's wrapper for every extension), and inside it the list is
    wrapped in a second OCTET STRING (RFC 6962 section 3.3 paragraph 4). Both layers are removed and both
    must fill their container exactly. The TLS extension has neither wrapper. Raises `CertScanError` for a
    malformed certificate, a duplicated extension, or a malformed inner layer.
    """
    found = _only(split_certificate(der)[1], SCT_OID)
    if found is None:
        return None
    tag, start, end = _tlv(found.value, 0, len(found.value))
    if tag != _OCTET_STRING or end != len(found.value):
        raise CertScanError("the SCT extension value is not one inner OCTET STRING")
    return found.value[start:end]


def tbs_without_extension(der: bytes, oid: str) -> bytes:
    """The TBSCertificate with exactly the extension `oid` deleted, every enclosing length re-encoded.

    The log hashed the re-encoded DER, not the original with a hole in it, so the extension SEQUENCE, its
    `[3]` wrapper and the TBSCertificate all get fresh lengths. A certificate without the extension comes
    back unchanged. Removing the only extension is refused: RFC 5280 does not allow an empty extensions
    field, and which encoding a log would have hashed then is not something to guess.
    """
    tbs_start, tbs_end, field_start, field_end, extensions, _ = _walk(der)
    target = _only(tuple(extensions), oid)
    if target is None:
        return der[tbs_start:tbs_end]
    if len(extensions) == 1:
        raise CertScanError(f"extension {oid} is the only extension; the result would be ambiguous")
    kept = b"".join(der[item.span[0] : item.span[1]] for item in extensions if item.oid != oid)
    sequence = bytes([_SEQUENCE]) + _der_length(len(kept)) + kept
    wrapper = bytes([_EXTENSIONS]) + _der_length(len(sequence)) + sequence
    _, tbs_body, _ = _tlv(der, tbs_start, tbs_end)
    body = der[tbs_body:field_start] + wrapper + der[field_end:tbs_end]
    return bytes([_SEQUENCE]) + _der_length(len(body)) + body


def tbs_without_sct(der: bytes) -> bytes:
    """The TBSCertificate a log signed for a precertificate whose final certificate is `der` (3.2 para 9)."""
    return tbs_without_extension(der, SCT_OID)


def precert_tbs(der: bytes) -> bytes:
    """The logged `tbs_certificate` of a precertificate: its TBS without the poison extension (3.2 para 9).

    Raises `CertScanError` when `der` is not a precertificate, because a certificate without the poison
    extension has nothing to strip and returning it unchanged would hide a caller's mistake.
    """
    if not is_precertificate(der):
        raise CertScanError("not a precertificate: no CT poison extension")
    return tbs_without_extension(der, POISON_OID)
