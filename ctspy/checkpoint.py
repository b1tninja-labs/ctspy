"""C2SP signed notes and transparency-log checkpoints.

Specifications, outside the RFC series, read at commit `09f3e519fe79bcbdccadcf821182e3b488a14d71` (also in the
primarysource `c2sp` collection): `signed-note` (the container), `tlog-checkpoint` (the note text of a signed
tree head) and `static-ct-api` section "Checkpoints" (how a static CT log signs one, type 0x05). They are the
missing half of `tools/tile_probe.py`'s `checkpoint_verified: false`: a static log serves a checkpoint where a
dynamic one serves `get-sth`.

A note is text, a blank line, and signature lines `<em dash> <name> <base64(key id || signature)>`. Three rules
decide what a verifier may believe, and all three are enforced here:

- a signature whose (key name, key ID) pair is not a known key is **ignored**, even when the name or the ID
  alone matches one;
- a signature from a known key that does not verify **rejects the whole note** (the specification says
  "SHOULD"; refusing is the strict reading and the only one that cannot be talked past);
- a note with **no** verifying signature from a known key is rejected.

Supported signature types: `0x01` Ed25519 over the note text (verified through `sigwire.verify`), `0x04` the
timestamped Ed25519 checkpoint cosignature of c2sp.org/tlog-cosignature (the signed message is
`cosignature/v1`, `time <decimal>`, then the note text; read in the same commit), and `0x05` the RFC 6962
`TreeHeadSignature` wrapped as static-ct-api defines it (verified through `sth.verify`). Two assigned types are
refused when a verifier is constructed, never skipped: `0x02` (ECDSA "as implemented by
transparency-dev/witness", defined by code and not by a document) and `0x06` (timestamped ML-DSA-44; its
specification is read, but the `cryptography` floor `sigwire[verify]` declares offers no ML-DSA, and ML-DSA is a
primitive, so it is not written here). A verifier that quietly accepted a key it cannot use would turn a
configuration mistake into "no signature verified" later.

`from_sth` and `to_sth` are the conversion static-ct-api section "Checkpoints" says a `get-sth` response allows
"with knowledge of the origin line": no private key is involved, so neither makes a signature genuine. Verify
the result (`verify_checkpoint`, or `sth.verify` on what `to_sth` returns).

Structural problems raise `NoteError` (the bytes were never a note); a note that parses but is not genuine raises
`VerificationError`. The two are different incidents, as `errors.py` explains.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass

from sigwire.verify import eddsa as _eddsa

from . import sth as _sth
from .ecdsa import EcdsaKey
from .errors import CtspyError, VerificationError
from .transcript import Reader, TranscriptError

__all__ = [
    "SIG_ED25519",
    "SIG_ED25519_COSIGNATURE",
    "SIG_RFC6962_TREE_HEAD",
    "Checkpoint",
    "NoteError",
    "NoteSignature",
    "SignedNote",
    "VerifiedSignature",
    "Verifier",
    "ed25519_cosigner_verifier",
    "ed25519_verifier",
    "from_sth",
    "key_id",
    "parse_checkpoint",
    "parse_note",
    "parse_vkey",
    "rfc6962_verifier",
    "static_log_origin",
    "static_log_verifier",
    "to_sth",
    "verify_checkpoint",
    "verify_note",
    "verify_static_log_checkpoint",
]

SIG_ED25519 = 0x01
SIG_ED25519_COSIGNATURE = 0x04
SIG_RFC6962_TREE_HEAD = 0x05
_DEFERRED = {
    0x02: "ECDSA note signatures are defined by transparency-dev/witness, not by signed-note",
    0x06: (
        "ML-DSA-44 cosignatures need an ML-DSA verifier, which the cryptography floor of "
        "sigwire[verify] does not offer"
    ),
}

_EM_DASH_PREFIX = "— "
# signed-note, "Format": verifiers MUST accept at least 16 signatures and SHOULD apply a limit.
DEFAULT_MAX_SIGNATURES = 64
_DECIMAL = re.compile(r"(0|[1-9][0-9]*)")
_UINT64_MAX = 2**64 - 1


class NoteError(CtspyError, ValueError):
    """The bytes are not a signed note, a checkpoint or a verifier key. Never a verification failure."""


def _b64(text: str, *, what: str) -> bytes:
    """Standard base64 with padding, canonical only (RFC 4648 section 3.5), as both specifications demand."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise NoteError(f"{what} is not base64: {exc}") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise NoteError(f"{what} is base64 but not the canonical encoding")
    return raw


def _check_name(name: str) -> None:
    if not name:
        raise NoteError("a key name must not be empty")
    if "+" in name:
        raise NoteError("a key name must not contain '+' (U+002B)")
    if any(ch.isspace() or unicodedata.category(ch) == "Zs" for ch in name):
        raise NoteError("a key name must not contain Unicode spaces")


def key_id(name: str, signature_type: int, public_key: bytes) -> int:
    """The recommended key ID: the first four bytes of SHA-256(name || 0x0A || type || public key), big-endian."""
    _check_name(name)
    digest = hashlib.sha256(
        name.encode("utf-8") + b"\n" + bytes([signature_type]) + public_key
    ).digest()
    return int.from_bytes(digest[:4], "big")


@dataclass(frozen=True, slots=True)
class NoteSignature:
    """One signature line: who claims it (name, key ID) and the signature bytes after the key ID."""

    name: str
    key_id: int
    signature: bytes


@dataclass(frozen=True, slots=True)
class SignedNote:
    """The note text, with its final newline and without the blank line, and every signature line."""

    text: bytes
    signatures: tuple[NoteSignature, ...]


def parse_note(data: bytes, *, max_signatures: int = DEFAULT_MAX_SIGNATURES) -> SignedNote:
    """Read a signed note strictly, without judging any signature (`verify_note` does that).

    The text must be UTF-8 with no control character below U+0020 other than newline and must end in one; it
    is separated from the signatures by the *last* empty line. Signature lines are an em dash, a space, a key
    name, a space and canonical base64 of at least four bytes. Zero signatures, more than `max_signatures`,
    and any deviation are `NoteError`.
    """
    if max_signatures < 16:
        raise ValueError("signed-note requires a verifier to accept at least 16 signatures")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NoteError(f"a note must be valid UTF-8: {exc}") from exc
    if any(ord(ch) < 0x20 and ch != "\n" for ch in text):
        raise NoteError("a note must not contain ASCII control characters other than newline")
    split = text.rfind("\n\n")
    if split == -1:
        raise NoteError("a note needs an empty line between its text and its signatures")
    body, tail = text[: split + 1], text[split + 2 :]
    if not tail:
        raise NoteError("a note needs at least one signature line")
    if not tail.endswith("\n"):
        raise NoteError("the last signature line must end in a newline")
    lines = tail[:-1].split("\n")
    if len(lines) > max_signatures:
        raise NoteError(f"{len(lines)} signatures is more than the limit of {max_signatures}")
    signatures: list[NoteSignature] = []
    for line in lines:
        if not line.startswith(_EM_DASH_PREFIX):
            raise NoteError("a signature line starts with an em dash (U+2014) and a space")
        parts = line[len(_EM_DASH_PREFIX) :].split(" ")
        if len(parts) != 2:
            raise NoteError(
                "a signature line is '<key name> <base64 signature>', one space between"
            )
        name, encoded = parts
        _check_name(name)
        blob = _b64(encoded, what=f"the signature of {name}")
        if len(blob) < 4:
            raise NoteError(
                f"the signature of {name} is {len(blob)} bytes; it needs a 4-byte key ID"
            )
        signatures.append(NoteSignature(name, int.from_bytes(blob[:4], "big"), blob[4:]))
    return SignedNote(body.encode("utf-8"), tuple(signatures))


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """tlog-checkpoint note text: origin, tree size, root hash, and any opaque extension lines."""

    origin: str
    size: int
    root_hash: bytes
    extensions: tuple[str, ...] = ()


def parse_checkpoint(text: bytes) -> Checkpoint:
    """Read the text of a checkpoint (the note text, newline included). `NoteError` for anything else.

    At least three non-empty lines; the size is an ASCII decimal with no leading zeros; the root is canonical
    base64 of a SHA-256 hash (RFC 6962 hash tree, so 32 bytes); extension lines are kept, opaque.
    """
    try:
        decoded = text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NoteError(f"a checkpoint must be valid UTF-8: {exc}") from exc
    if not decoded.endswith("\n"):
        raise NoteError("checkpoint text ends with a newline")
    lines = decoded[:-1].split("\n")
    if len(lines) < 3:
        raise NoteError(f"a checkpoint has at least three lines, this one has {len(lines)}")
    if any(not line for line in lines):
        raise NoteError("every checkpoint line must be non-empty")
    origin, size_text, root_text, *extensions = lines
    if not _DECIMAL.fullmatch(size_text):
        raise NoteError("the tree size is an ASCII decimal with no leading zeros")
    size = int(size_text)
    if size > _UINT64_MAX:
        raise NoteError("the tree size does not fit RFC 6962's uint64")
    root = _b64(root_text, what="the root hash")
    if len(root) != 32:
        raise NoteError(f"the root hash is {len(root)} bytes, not a 32-byte SHA-256 value")
    return Checkpoint(origin, size, root, tuple(extensions))


@dataclass(frozen=True, slots=True)
class Verifier:
    """A known key: its name, ID and signature type, plus what verifying with it takes."""

    name: str
    key_id: int
    signature_type: int
    public_key: bytes
    ecdsa_key: EcdsaKey | None = None

    def vkey(self) -> str:
        """The verifier-key text, `name+hex(key id)+base64(type || public key)`."""
        material = base64.b64encode(bytes([self.signature_type]) + self.public_key).decode("ascii")
        return f"{self.name}+{self.key_id:08x}+{material}"


def ed25519_verifier(name: str, public_key: bytes) -> Verifier:
    """A type-0x01 verifier: Ed25519 (RFC 8032) over the note text, key ID by the recommended formula."""
    if len(public_key) != 32:
        raise NoteError(f"an Ed25519 public key is 32 bytes, this one is {len(public_key)}")
    return Verifier(name, key_id(name, SIG_ED25519, public_key), SIG_ED25519, public_key)


def ed25519_cosigner_verifier(name: str, public_key: bytes) -> Verifier:
    """A type-0x04 verifier: a timestamped Ed25519 checkpoint cosignature (c2sp.org/tlog-cosignature)."""
    if len(public_key) != 32:
        raise NoteError(f"an Ed25519 public key is 32 bytes, this one is {len(public_key)}")
    return Verifier(
        name,
        key_id(name, SIG_ED25519_COSIGNATURE, public_key),
        SIG_ED25519_COSIGNATURE,
        public_key,
    )


def rfc6962_verifier(name: str, log_key: EcdsaKey) -> Verifier:
    """A type-0x05 verifier for a static CT log (static-ct-api): the key ID commits to the 32-byte `LogID`."""
    log_id = log_key.log_id
    return Verifier(
        name, key_id(name, SIG_RFC6962_TREE_HEAD, log_id), SIG_RFC6962_TREE_HEAD, log_id, log_key
    )


def parse_vkey(text: str) -> Verifier:
    """Read a verifier key: Ed25519 (0x01) or an Ed25519 cosigner (0x04); see the module docstring.

    The stated key ID must equal the one the formula gives, because the spec says the name and ID "MUST match
    those used in the signatures" and an ID that does not follow from the key is a transcription error.
    """
    parts = text.split(
        "+", 2
    )  # base64 has '+' in it; a key name may not, so only the first two split
    if len(parts) != 3:
        raise NoteError("a verifier key is '<name>+<hex key id>+<base64 type||key>'")
    name, hex_id, material = parts
    _check_name(name)
    if not re.fullmatch(r"[0-9a-f]{8}", hex_id):
        raise NoteError("the key ID in a verifier key is eight lowercase hex digits")
    raw = _b64(material, what="the verifier key material")
    if not raw:
        raise NoteError("the verifier key material is empty")
    signature_type, public_key = raw[0], raw[1:]
    if signature_type in _DEFERRED:
        raise NoteError(
            f"signature type 0x{signature_type:02x} is not supported: {_DEFERRED[signature_type]}"
        )
    if signature_type == SIG_ED25519_COSIGNATURE:
        verifier = ed25519_cosigner_verifier(name, public_key)
    elif signature_type == SIG_ED25519:
        verifier = ed25519_verifier(name, public_key)
    else:
        raise NoteError(
            f"signature type 0x{signature_type:02x} cannot be a self-contained vkey here"
        )
    if verifier.key_id != int(hex_id, 16):
        raise NoteError(
            f"the stated key ID {hex_id} is not the {verifier.key_id:08x} that its name and key give"
        )
    return verifier


@dataclass(frozen=True, slots=True)
class VerifiedSignature:
    """A signature that verified, and the timestamp it carried (type 0x05 only; Ed25519 has none)."""

    verifier: Verifier
    timestamp: int | None = None


def _verify_one(
    verifier: Verifier, note: SignedNote, signature: NoteSignature
) -> VerifiedSignature | None:
    if verifier.signature_type == SIG_ED25519:
        ok = _eddsa.verify_ed25519(verifier.public_key, note.text, signature.signature)
        return VerifiedSignature(verifier) if ok else None
    if verifier.signature_type == SIG_ED25519_COSIGNATURE:
        return _verify_cosignature(verifier, note, signature)
    if verifier.signature_type == SIG_RFC6962_TREE_HEAD:
        return _verify_tree_head(verifier, note, signature)
    raise VerificationError(  # unreachable for the constructors above; a hand-built Verifier lands here
        f"signature type 0x{verifier.signature_type:02x} has no verifier in ctspy"
    )


def _verify_cosignature(
    verifier: Verifier, note: SignedNote, signature: NoteSignature
) -> VerifiedSignature | None:
    """tlog-cosignature, Ed25519: `uint64 timestamp` then a 64-byte signature over the cosigned lines.

    The signed message is `cosignature/v1`, `time <ASCII decimal>`, then the checkpoint's lines (origin, size,
    root, and every extension line - this algorithm, unlike 0x06, covers them), which is exactly the note text
    once `parse_checkpoint` has confirmed that text is canonical. Verifiers MAY reject a future timestamp;
    this one returns it and leaves that policy to the caller, who has the clock.
    """
    if len(signature.signature) != 8 + 64:
        raise NoteError(
            f"a type-0x04 signature body is a uint64 timestamp and 64 bytes, "
            f"this one is {len(signature.signature)}"
        )
    parse_checkpoint(note.text)
    timestamp = int.from_bytes(signature.signature[:8], "big")
    message = b"cosignature/v1\ntime " + str(timestamp).encode("ascii") + b"\n" + note.text
    if not _eddsa.verify_ed25519(verifier.public_key, message, signature.signature[8:]):
        return None
    return VerifiedSignature(verifier, timestamp)


def _split_rfc6962_body(body: bytes) -> tuple[int, int, int, bytes]:
    """`RFC6962NoteSignature`: the timestamp, then a `DigitallySigned` as (timestamp, hash, signature, DER)."""
    try:
        reader = Reader(body, what="RFC6962NoteSignature")
        timestamp = reader.uint64()
        wrapper = reader.take(reader.remaining())
        hash_byte, signature_byte, der = _sth._parse_digitally_signed(wrapper)
    except TranscriptError as exc:
        raise NoteError(f"the type-0x05 signature body is malformed: {exc}") from exc
    return timestamp, hash_byte, signature_byte, der


def _verify_tree_head(
    verifier: Verifier, note: SignedNote, signature: NoteSignature
) -> VerifiedSignature | None:
    """static-ct-api: `uint64 timestamp; TreeHeadSignature` signed per RFC 6962 over the checkpoint's head."""
    assert verifier.ecdsa_key is not None  # noqa: S101 - rfc6962_verifier always sets it
    timestamp, hash_byte, signature_byte, der = _split_rfc6962_body(signature.signature)
    checkpoint = parse_checkpoint(note.text)
    if checkpoint.extensions:
        raise NoteError("a type-0x05 checkpoint must not include extension lines")
    head = _sth.SignedTreeHeadV1(
        timestamp=timestamp,
        tree_size=checkpoint.size,
        root_hash=checkpoint.root_hash,
        signature=der,
        hash_algorithm=hash_byte,
        signature_algorithm=signature_byte,
    )
    try:
        _sth.verify(head, verifier.ecdsa_key)
    except VerificationError:
        return None
    return VerifiedSignature(verifier, timestamp)


def verify_note(
    data: bytes,
    verifiers: list[Verifier] | tuple[Verifier, ...],
    *,
    max_signatures: int = DEFAULT_MAX_SIGNATURES,
) -> tuple[SignedNote, tuple[VerifiedSignature, ...]]:
    """Parse `data` and return the note with the signatures that verified, or raise.

    Unknown (name, ID) pairs are skipped. A known pair that fails to verify raises `VerificationError`, and so
    does a note in which no known key signed. Several lines from one known key are each verified.
    """
    note = parse_note(data, max_signatures=max_signatures)
    known = {(item.name, item.key_id): item for item in verifiers}
    verified: list[VerifiedSignature] = []
    for signature in note.signatures:
        verifier = known.get((signature.name, signature.key_id))
        if verifier is None:
            continue
        result = _verify_one(verifier, note, signature)
        if result is None:
            raise VerificationError(
                f"the signature of {signature.name} (key ID {signature.key_id:08x}) does not verify "
                "over the note"
            )
        verified.append(result)
    if not verified:
        raise VerificationError("no signature on the note is from a key this verifier knows")
    return note, tuple(verified)


def verify_checkpoint(
    data: bytes,
    verifiers: list[Verifier] | tuple[Verifier, ...],
    *,
    max_signatures: int = DEFAULT_MAX_SIGNATURES,
) -> tuple[Checkpoint, tuple[VerifiedSignature, ...]]:
    """`verify_note`, then read the note text as a checkpoint.

    tlog-checkpoint: there must not be two lines with both the same key name and the same key ID. Checking
    the text structure after the signatures keeps the order a verifier must have: nothing about the text is
    believed until a known key has vouched for it.
    """
    note, verified = verify_note(data, verifiers, max_signatures=max_signatures)
    seen = [(item.name, item.key_id) for item in note.signatures]
    if len(set(seen)) != len(seen):
        raise NoteError("a checkpoint must not repeat a (key name, key ID) pair")
    return parse_checkpoint(note.text), verified


def static_log_origin(submission_prefix: str) -> str:
    """static-ct-api "Checkpoints": the origin line is the submission prefix, scheme removed, no trailing slash.

    `https://rome.ct.example.com/2024h1/` gives `rome.ct.example.com/2024h1`, the specification's own example.
    The log list calls the prefix `submission_url`.
    """
    scheme, separator, rest = submission_prefix.partition("://")
    origin = rest.rstrip("/")
    if not separator or not scheme or not origin:
        raise NoteError("a submission prefix is a URL with a scheme, such as https://host/path/")
    _check_name(origin)
    return origin


def static_log_verifier(submission_prefix: str, spki: bytes) -> Verifier:
    """The type-0x05 verifier for a static log from what the log list publishes: its submission URL and key."""
    return rfc6962_verifier(static_log_origin(submission_prefix), EcdsaKey.from_spki(spki))


def verify_static_log_checkpoint(
    data: bytes, submission_prefix: str, spki: bytes
) -> tuple[Checkpoint, VerifiedSignature]:
    """Verify what `<monitoring prefix>/checkpoint` served, against the log's published key and prefix.

    On top of `verify_checkpoint`: the origin line must be the one the submission prefix gives. The type-0x05
    signature does not cover the origin ("the origin line is unauthenticated", static-ct-api), so a valid
    signature under a pinned key proves nothing about *which log* the text names until this is checked; a
    mismatch is a `VerificationError`, because that is how a head from one log is replayed as another's.
    """
    verifier = static_log_verifier(submission_prefix, spki)
    parsed, verified = verify_checkpoint(data, [verifier])
    if parsed.origin != verifier.name:
        raise VerificationError(
            f"the checkpoint names the origin {parsed.origin!r}, not {verifier.name!r}, "
            "which is what the submission prefix gives"
        )
    return parsed, verified[0]


def from_sth(sth: _sth.SignedTreeHeadV1, origin: str, log_id: bytes) -> bytes:
    """A v1 STH as the signed note a static CT log serves: static-ct-api's `get-sth` to checkpoint direction.

    Needs the origin line and the 32-byte `LogID` (it is hashed into the key ID) and nothing secret. The
    signature body is `uint64 timestamp` then the `DigitallySigned` the STH already carried, rebuilt from the
    algorithm bytes and DER the STH holds; for an STH read with `from_v1_json` the result is byte-identical to
    the log's own wrapper. Nothing is verified here.
    """
    _check_name(origin)
    if len(log_id) != 32:
        raise NoteError(f"a LogID is 32 bytes, this one is {len(log_id)}")
    if len(sth.root_hash) != 32:
        raise NoteError(f"a SHA-256 root hash is 32 bytes, this one is {len(sth.root_hash)}")
    if not 0 <= sth.tree_size <= _UINT64_MAX or not 0 <= sth.timestamp <= _UINT64_MAX:
        raise NoteError("the tree size and the timestamp are RFC 6962 uint64 values")
    if not 1 <= len(sth.signature) <= 65535:
        raise NoteError("a DigitallySigned signature is 1 to 65535 bytes")
    text = f"{origin}\n{sth.tree_size}\n{base64.b64encode(sth.root_hash).decode('ascii')}\n"
    body = (
        sth.timestamp.to_bytes(8, "big")
        + bytes([sth.hash_algorithm, sth.signature_algorithm])
        + len(sth.signature).to_bytes(2, "big")
        + sth.signature
    )
    blob = key_id(origin, SIG_RFC6962_TREE_HEAD, log_id).to_bytes(4, "big") + body
    line = f"{_EM_DASH_PREFIX}{origin} {base64.b64encode(blob).decode('ascii')}\n"
    return (text + "\n" + line).encode("utf-8")


def to_sth(data: bytes, origin: str, log_id: bytes) -> _sth.SignedTreeHeadV1:
    """A static log's checkpoint as the v1 STH `sth.verify` takes: static-ct-api's other direction.

    The signature line to use is the one with the key name `origin` and the key ID the 0x05 formula gives for
    `log_id`; any other line is somebody else's and is ignored. Nothing is verified: pass the result to
    `sth.verify` with the log's key. Refused (`NoteError`): no such line, two such lines, an origin line that
    is not `origin`, extension lines (a 0x05 checkpoint must not carry any), or a malformed body.
    """
    if len(log_id) != 32:
        raise NoteError(f"a LogID is 32 bytes, this one is {len(log_id)}")
    note = parse_note(data)
    wanted = key_id(origin, SIG_RFC6962_TREE_HEAD, log_id)
    lines = [item for item in note.signatures if (item.name, item.key_id) == (origin, wanted)]
    if len(lines) != 1:
        raise NoteError(
            f"the note has {len(lines)} signature lines for {origin!r} with key ID {wanted:08x}, not one"
        )
    parsed = parse_checkpoint(note.text)
    if parsed.origin != origin:
        raise NoteError(f"the checkpoint names the origin {parsed.origin!r}, not {origin!r}")
    if parsed.extensions:
        raise NoteError("a type-0x05 checkpoint must not include extension lines")
    timestamp, hash_byte, signature_byte, der = _split_rfc6962_body(lines[0].signature)
    return _sth.SignedTreeHeadV1(
        timestamp=timestamp,
        tree_size=parsed.size,
        root_hash=parsed.root_hash,
        signature=der,
        hash_algorithm=hash_byte,
        signature_algorithm=signature_byte,
    )
