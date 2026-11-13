"""C2SP signed notes and checkpoints (`ctspy.checkpoint`).

Evidence, with where each piece came from:

- the signed-note specification's own example (vkey `example.com/foo+530d903a+...` and its note), read at C2SP
  commit 09f3e519fe79bcbdccadcf821182e3b488a14d71 (section "Verifier keys", "Example"): a real Ed25519 vector;
- the tlog-checkpoint specification's example note text (origin `example.com/behind-the-sofa`), parsed only,
  because the specification publishes no key for it;
- a production STH, `fixtures/argon2026h2-sth.json` (captured 2026-11-05 from Google's Argon2026h2 log), re-wrapped
  as the type-0x05 checkpoint static-ct-api describes, which is the conversion that section says a `get-sth`
  response allows without the private key. This proves the 0x05 plumbing against a real log signature, though
  not against a static log's own checkpoint: no such log's key is pinned in this repository;
- notes signed here with `cryptography` as an Ed25519 oracle, for the rules the specification states in prose.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ctspy import checkpoint
from ctspy.checkpoint import NoteError
from ctspy.ecdsa import EcdsaKey
from ctspy.errors import VerificationError

DASH = "—"
SPEC_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
SPEC_NOTE = (
    "This is an example message.\n\n"
    f"{DASH} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
).encode()
SPEC_CHECKPOINT_TEXT = (
    b"example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
)
ZERO_ROOT = base64.b64encode(b"\x00" * 32)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
ARGON = json.loads((FIXTURES / "argon2026h2-sth.json").read_text("utf-8"))


def sign_ed25519(private: Ed25519PrivateKey, name: str, text: bytes) -> bytes:
    public = private.public_key().public_bytes_raw()
    blob = checkpoint.key_id(name, 1, public).to_bytes(4, "big") + private.sign(text)
    return f"{DASH} {name} {base64.b64encode(blob).decode()}\n".encode()


def make_note(private: Ed25519PrivateKey, name: str, text: bytes, *extra: bytes) -> bytes:
    return text + b"\n" + sign_ed25519(private, name, text) + b"".join(extra)


def verifier_for(private: Ed25519PrivateKey, name: str) -> checkpoint.Verifier:
    return checkpoint.ed25519_verifier(name, private.public_key().public_bytes_raw())


# -- the specification's own vector ----------------------------------------------------------------


def test_the_signed_note_spec_example_verifies_under_its_vkey() -> None:
    verifier = checkpoint.parse_vkey(SPEC_VKEY)
    assert verifier.key_id == 0x530D903A
    assert verifier.vkey() == SPEC_VKEY
    note, verified = checkpoint.verify_note(SPEC_NOTE, [verifier])
    assert note.text == b"This is an example message.\n"
    assert [item.verifier for item in verified] == [verifier]


def test_one_changed_byte_of_the_spec_note_text_fails_verification() -> None:
    verifier = checkpoint.parse_vkey(SPEC_VKEY)
    tampered = SPEC_NOTE.replace(b"This is", b"This Is")
    with pytest.raises(VerificationError, match="does not verify"):
        checkpoint.verify_note(tampered, [verifier])


def test_a_vkey_whose_key_id_is_not_the_formulas_is_refused() -> None:
    with pytest.raises(NoteError, match="key ID"):
        checkpoint.parse_vkey(SPEC_VKEY.replace("530d903a", "530d903b"))


@pytest.mark.parametrize("kind", [0x02, 0x04, 0x06])
def test_signature_types_whose_documents_were_not_read_are_refused_not_skipped(kind: int) -> None:
    material = base64.b64encode(bytes([kind]) + b"\x00" * 32).decode()
    with pytest.raises(NoteError, match="not supported"):
        checkpoint.parse_vkey(f"example.com/x+00000000+{material}")


# -- the verification rules ------------------------------------------------------------------------


def test_signatures_from_unknown_keys_are_ignored_and_a_known_one_carries_the_note() -> None:
    mine, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    text = b"hello\n"
    data = make_note(other, "other.example/k", text, sign_ed25519(mine, "mine.example/k", text))
    _, verified = checkpoint.verify_note(data, [verifier_for(mine, "mine.example/k")])
    assert [item.verifier.name for item in verified] == ["mine.example/k"]


def test_a_note_with_no_known_signer_is_rejected() -> None:
    mine, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    data = make_note(other, "other.example/k", b"hello\n")
    with pytest.raises(VerificationError, match="no signature"):
        checkpoint.verify_note(data, [verifier_for(mine, "mine.example/k")])


def test_a_shared_name_or_a_shared_id_alone_does_not_make_a_key_known() -> None:
    """The pair identifies the key: the right name with another key's ID is not it, nor the reverse."""
    mine, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    text = b"hello\n"
    same_name = make_note(other, "mine.example/k", text)  # a different key's ID under my name
    with pytest.raises(VerificationError, match="no signature"):
        checkpoint.verify_note(same_name, [verifier_for(mine, "mine.example/k")])
    public = mine.public_key().public_bytes_raw()
    same_id = checkpoint.Verifier(
        "renamed.example/k", checkpoint.key_id("mine.example/k", 1, public), 1, public
    )
    with pytest.raises(VerificationError, match="no signature"):
        checkpoint.verify_note(make_note(mine, "mine.example/k", text), [same_id])


def test_a_known_key_that_fails_rejects_the_whole_note_even_beside_a_good_one() -> None:
    good, bad = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    text = b"hello\n"
    forged = sign_ed25519(bad, "bad.example/k", b"another text\n")
    data = make_note(good, "good.example/k", text, forged)
    with pytest.raises(VerificationError, match="does not verify"):
        checkpoint.verify_note(
            data, [verifier_for(good, "good.example/k"), verifier_for(bad, "bad.example/k")]
        )


# -- note format -----------------------------------------------------------------------------------


def good_line(name: str = "a.example/k", blob: bytes = b"\x00\x00\x00\x01sig") -> bytes:
    return f"{DASH} {name} {base64.b64encode(blob).decode()}\n".encode()


@pytest.mark.parametrize(
    ("data", "why"),
    [
        (b"text\n" + good_line(), "empty line"),
        (b"text\n\n", "at least one signature"),
        (b"text\n\n" + good_line().rstrip(b"\n"), "newline"),
        (b"te\x01xt\n\n" + good_line(), "control"),
        (b"\xff\n\n" + good_line(), "UTF-8"),
        (b"text\n\n" + good_line("a b"), "one space"),
        (b"text\n\n" + good_line("a+b"), "'[+]'"),
        (b"text\n\n" + good_line("a" + chr(0x2003) + "b"), "Unicode spaces"),
        (b"text\n\n- a.example/k AAAA\n", "em dash"),
        (b"text\n\n" + good_line(blob=b"abc"), "4-byte key ID"),
        (f"text\n\n{DASH} a.example/k AAAAAQ\n".encode(), "base64"),
        (f"text\n\n{DASH} a.example/k AAAAAXN=\n".encode(), "canonical"),
    ],
)
def test_malformed_notes_are_refused(data: bytes, why: str) -> None:
    with pytest.raises(NoteError, match=why):
        checkpoint.parse_note(data)


def test_a_note_may_contain_empty_lines_and_the_last_one_separates_the_signatures() -> None:
    note = checkpoint.parse_note(b"one\n\ntwo\n\n" + good_line())
    assert note.text == b"one\n\ntwo\n"
    assert len(note.signatures) == 1


def test_sixteen_signatures_are_accepted_and_the_limit_is_enforced() -> None:
    lines = b"".join(good_line(f"k{i}.example/k") for i in range(16))
    assert len(checkpoint.parse_note(b"t\n\n" + lines).signatures) == 16
    with pytest.raises(NoteError, match="limit"):
        checkpoint.parse_note(b"t\n\n" + lines + good_line("extra.example/k"), max_signatures=16)
    with pytest.raises(ValueError, match="at least 16"):
        checkpoint.parse_note(b"t\n\n" + lines, max_signatures=8)


# -- checkpoint text -------------------------------------------------------------------------------


def test_the_checkpoint_spec_example_text_parses() -> None:
    parsed = checkpoint.parse_checkpoint(SPEC_CHECKPOINT_TEXT)
    assert parsed.origin == "example.com/behind-the-sofa"
    assert parsed.size == 20852163
    assert parsed.root_hash == base64.b64decode("CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=")
    assert parsed.extensions == ()


def test_extension_lines_are_kept_as_written() -> None:
    parsed = checkpoint.parse_checkpoint(SPEC_CHECKPOINT_TEXT + b"extra one\nextra two\n")
    assert parsed.extensions == ("extra one", "extra two")


@pytest.mark.parametrize(
    ("text", "why"),
    [
        (b"origin\n5\n", "at least three"),
        (b"origin\n5\n" + ZERO_ROOT, "newline"),
        (b"origin\n05\n" + ZERO_ROOT + b"\n", "leading zeros"),
        (b"origin\n+5\n" + ZERO_ROOT + b"\n", "leading zeros"),
        (b"origin\n\xd9\xa5\n" + ZERO_ROOT + b"\n", "ASCII decimal"),
        (f"origin\n{2**64}\n".encode() + ZERO_ROOT + b"\n", "uint64"),
        (b"origin\n5\n" + base64.b64encode(b"\x00" * 31) + b"\n", "32-byte"),
        (b"origin\n5\n" + ZERO_ROOT + b"\n\nextra\n", "non-empty"),
        (b"\n5\n" + ZERO_ROOT + b"\n", "non-empty"),
    ],
)
def test_malformed_checkpoint_text_is_refused(text: bytes, why: str) -> None:
    with pytest.raises(NoteError, match=why):
        checkpoint.parse_checkpoint(text)


def test_a_signed_checkpoint_round_trips_through_verify_checkpoint() -> None:
    private = Ed25519PrivateKey.generate()
    data = make_note(private, "log.example/t", SPEC_CHECKPOINT_TEXT)
    parsed, verified = checkpoint.verify_checkpoint(data, [verifier_for(private, "log.example/t")])
    assert parsed.size == 20852163
    assert verified[0].timestamp is None  # an Ed25519 log signature carries no timestamp


def test_two_lines_with_the_same_name_and_key_id_are_refused_in_a_checkpoint() -> None:
    private = Ed25519PrivateKey.generate()
    line = sign_ed25519(private, "log.example/t", SPEC_CHECKPOINT_TEXT)
    data = SPEC_CHECKPOINT_TEXT + b"\n" + line + line
    with pytest.raises(NoteError, match="repeat"):
        checkpoint.verify_checkpoint(data, [verifier_for(private, "log.example/t")])


# -- type 0x05: an RFC 6962 tree head signature as a note signature ------------------------------


def argon_checkpoint(extra: bytes = b"") -> tuple[bytes, EcdsaKey, str]:
    """A real Argon2026h2 STH rewritten as the static-ct-api checkpoint form, and the key to verify it."""
    key = EcdsaKey.from_spki(base64.b64decode(ARGON["key"]))
    assert key.log_id == base64.b64decode(ARGON["log_id"])
    sth = ARGON["responses"][0]
    origin = "ct.googleapis.com/logs/us1/argon2026h2"
    text = f"{origin}\n{sth['tree_size']}\n{sth['sha256_root_hash']}\n".encode() + extra
    body = base64.b64decode(sth["tree_head_signature"])
    blob = (
        checkpoint.key_id(origin, 5, key.log_id).to_bytes(4, "big")
        + int(sth["timestamp"]).to_bytes(8, "big")
        + body
    )
    line = f"{DASH} {origin} {base64.b64encode(blob).decode()}\n".encode()
    return text + b"\n" + line, key, origin


def test_a_production_sth_rewrapped_as_a_type_5_checkpoint_verifies() -> None:
    data, key, origin = argon_checkpoint()
    parsed, verified = checkpoint.verify_checkpoint(
        data, [checkpoint.rfc6962_verifier(origin, key)]
    )
    assert parsed.origin == origin
    assert parsed.size == ARGON["responses"][0]["tree_size"]
    assert verified[0].timestamp == ARGON["responses"][0]["timestamp"]


def test_the_type_5_key_id_is_over_the_log_id_as_static_ct_api_says() -> None:
    _, key, origin = argon_checkpoint()
    expected = hashlib.sha256(origin.encode() + b"\n" + b"\x05" + key.log_id).digest()[:4]
    assert checkpoint.rfc6962_verifier(origin, key).key_id == int.from_bytes(expected, "big")


def test_a_type_5_checkpoint_with_extension_lines_is_refused() -> None:
    data, key, origin = argon_checkpoint(extra=b"unsigned extension\n")
    with pytest.raises(NoteError, match="extension"):
        checkpoint.verify_checkpoint(data, [checkpoint.rfc6962_verifier(origin, key)])


def test_a_type_5_signature_over_another_size_does_not_verify() -> None:
    data, key, origin = argon_checkpoint()
    size = str(ARGON["responses"][0]["tree_size"]).encode()
    tampered = data.replace(b"\n" + size + b"\n", b"\n" + str(int(size) + 1).encode() + b"\n", 1)
    assert tampered != data
    with pytest.raises(VerificationError, match="does not verify"):
        checkpoint.verify_checkpoint(tampered, [checkpoint.rfc6962_verifier(origin, key)])
