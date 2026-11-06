"""`extra_data` is not one structure. It is two, and the difference is where the certificate lives.

RFC 6962 section 3.1 defines `X509ChainEntry` and `PrecertChainEntry` side by side, each a certificate
followed by a chain, and section 4.6 then says that what `get-entries` puts in `extra_data` is the whole
`PrecertChainEntry` but only the `certificate_chain` of an `X509ChainEntry`. That is not sloppy prose, it is
the protocol: an x509 entry's `signed_entry` in `leaf_input` *is* the DER certificate, so the log already
commits to it in the Merkle tree, while a precert entry's `signed_entry` is a `PreCert` - issuer key hash
plus a TBSCertificate with the poison extension removed - so the submitted certificate exists nowhere else.

A reader written from section 3.1 alone does not fail loudly on the x509 arm. The first 3-byte number is a
plausible length, the bytes it selects are not a certificate, and everything after them is discarded: the
chain, which is the only place the issuer intermediates appear. That is how a monitor comes to report a CA
layer of the right size containing nothing, so both layouts are tested against bytes that logs actually
served, including a chain long enough to expose a truncated read.
"""

import base64
import json
import pathlib

import pytest

from ctspy import entry
from ctspy.transcript import TranscriptError

DOCUMENT = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "extra-data-layout.json").read_text("utf-8")
)
SAMPLES = DOCUMENT["entries"]


def vector(certificates: list[bytes]) -> bytes:
    """`ASN.1Cert<0..2^24-1>`: a 3-byte total, then a length-prefixed certificate each."""
    blob = b"".join(len(cert).to_bytes(3, "big") + cert for cert in certificates)
    return len(blob).to_bytes(3, "big") + blob


def precert_arm(certificate: bytes, chain: list[bytes]) -> bytes:
    """`PrecertChainEntry`: the submitted precertificate, then its chain as a vector."""
    return len(certificate).to_bytes(3, "big") + certificate + vector(chain)


def samples(kind: str) -> list[dict]:
    return [sample for sample in SAMPLES if sample["kind"] == kind]


def leaf_of(sample: dict) -> entry.MerkleTreeLeaf:
    return entry.MerkleTreeLeaf.parse(base64.b64decode(sample["leaf_input"]))


def test_every_entry_in_the_survey_reads_with_the_layout_its_type_has() -> None:
    """Nothing in the fleet was refused once the two arms are read as the two structures they are.

    A refusal here means an implementation started to package `extra_data` some third way, which would need
    measuring rather than accommodating: a reader that grows to accept anything has stopped checking.
    """
    parsed = DOCUMENT["parsed"]
    assert DOCUMENT["logs"] >= 20, DOCUMENT["logs"]
    assert not [key for key in parsed if key.endswith(":refused")], parsed
    assert parsed.get("precert:read", 0) > 100, parsed
    assert parsed.get("x509:read", 0) > 100, parsed


def test_both_entry_types_are_kept_as_bytes_so_the_claims_are_reproducible() -> None:
    assert len(samples("precert")) >= 3
    assert len(samples("x509")) >= 3


@pytest.mark.parametrize("kind", ["precert", "x509"])
def test_rereading_an_entry_rebuilds_the_exact_octets_the_log_sent(kind: str) -> None:
    """Parse, then write the layout back, and compare byte for byte.

    This is the check that a chain arrives whole. A length that "looks plausible" can still drop the last
    certificate, and a chain missing its last element is a chain that no longer reaches a trust anchor -
    which would be reported as a suspicious issuance rather than as a read error, in a system whose entire
    purpose is to tell those two apart.
    """
    for sample in samples(kind):
        raw = base64.b64decode(sample["extra_data"])
        stored = entry.parse_extra_data(leaf_of(sample), raw)
        assert len(stored.chain) == sample["chain_count"]
        rebuilt = (
            precert_arm(stored.certificate, list(stored.chain))
            if kind == "precert"
            else vector(list(stored.chain))
        )
        assert rebuilt == raw, f"entry {sample['index']} of {sample['log']}"
        assert stored.certificate[:1] == b"\x30", (
            "the certificate is a DER SEQUENCE, not a coincident slice"
        )


def test_the_x509_certificate_is_the_one_the_tree_commits_to() -> None:
    """For an x509 entry the certificate comes out of `leaf_input`, which is the signed half.

    The chain beside it is not in the tree at all, which is why `authenticated` distinguishes the two. A
    store that hashes the `extra_data` copy of an x509 certificate is verifying a claim the log never made:
    two logs can serve different chains for the same entry and both produce the same Merkle Tree Hash.
    """
    for sample in samples("x509"):
        leaf = leaf_of(sample)
        signed = leaf.entry.entry
        assert isinstance(signed, entry.X509Entry)
        stored = entry.parse_extra_data(leaf, base64.b64decode(sample["extra_data"]))
        assert stored.authenticated
        assert stored.certificate == signed.certificate
        assert stored.certificate in leaf.raw, (
            "the certificate is inside the hashed leaf, not beside it"
        )


def test_the_precert_certificate_can_only_come_from_extra_data() -> None:
    """The mirror-image case: here the leaf holds no certificate, so `extra_data` is the only source.

    The leaf's `signed_entry` for a precert entry is the `PreCert` - issuer key hash and the TBSCertificate
    with the poison extension removed - so the DER the CA submitted is unauthenticated, and that is a
    property of the protocol rather than an oversight to engineer away.
    """
    for sample in samples("precert"):
        leaf = leaf_of(sample)
        signed = leaf.entry.entry
        assert isinstance(signed, entry.PrecertEntry)
        stored = entry.parse_extra_data(leaf, base64.b64decode(sample["extra_data"]))
        assert not stored.authenticated
        assert signed.tbs_certificate not in stored.certificate, (
            "the logged TBS has the poison extension removed, so it is not a substring of the precert"
        )


def test_the_layout_written_from_section_3_1_alone_loses_the_chain() -> None:
    """The trap, run over real x509 bytes rather than described.

    Reading `ASN.1Cert` then `ASN.1Cert<0..2^24-1>` - which is what section 3.1's `X509ChainEntry` says -
    takes the vector's total length as a certificate length. The slice it returns does not begin with a DER
    SEQUENCE, so it is not a certificate, and the arithmetic lands exactly on the end of the blob, so the
    chain comes back empty. No exception, no shortfall reported, and the intermediates are gone.
    """
    for sample in samples("x509"):
        raw = base64.b64decode(sample["extra_data"])
        claimed = int.from_bytes(raw[:3], "big")
        naive_certificate = raw[3 : 3 + claimed]
        assert naive_certificate[:1] != b"\x30", (
            "an x509 blob that section 3.1 would read correctly; remeasure"
        )
        rest = raw[3 + claimed :]
        assert rest == b"", "the naive read should have consumed everything, which is the point"
        stored = entry.parse_extra_data(leaf_of(sample), raw)
        if sample["chain_count"]:
            assert stored.chain, "the real reader must find the chain the naive one discarded"


def test_a_chain_of_several_certificates_arrives_whole() -> None:
    """The case the survey cannot guarantee: a long chain, built from two certificates logs served.

    A vector reader that stops after the first element passes every test written against a single-certificate
    chain, which is most of what a log serves. Two real certificates are used rather than invented bytes so
    the lengths are of the kind that occur in practice.
    """
    first, second = samples("x509")[0], samples("x509")[-1]
    left = entry.parse_extra_data(leaf_of(first), base64.b64decode(first["extra_data"]))
    right = entry.parse_extra_data(leaf_of(second), base64.b64decode(second["extra_data"]))
    issued = [left.certificate, right.certificate]
    read = entry.parse_extra_data(leaf_of(first), vector(issued))
    assert list(read.chain) == issued
    assert read.certificate == left.certificate, "the entry's certificate still comes from the leaf"


def test_handing_a_blob_to_the_wrong_entry_type_is_refused() -> None:
    """A precert blob read as an x509 chain, and the other way round, must fail rather than mislead.

    The two structures start with different things - a certificate length versus a vector total - and both
    checks require a DER SEQUENCE exactly where the declared length says one is. Silently succeeding is the
    outcome to avoid: it would store a "chain" made of sliced certificate bytes.
    """
    certificate = samples("x509")[0]
    precert = samples("precert")[0]
    with pytest.raises(TranscriptError, match=r"not an ASN\.1Cert vector"):
        entry.parse_extra_data(leaf_of(certificate), base64.b64decode(precert["extra_data"]))
    with pytest.raises(TranscriptError, match="does not begin with the precertificate"):
        entry.parse_extra_data(leaf_of(precert), base64.b64decode(certificate["extra_data"]))


def test_truncated_and_empty_blobs_are_refused() -> None:
    raw = base64.b64decode(samples("precert")[0]["extra_data"])
    leaf = leaf_of(samples("precert")[0])
    for bad in (b"", b"\x00\x00\x05hello", raw[: len(raw) // 2], raw + b"\x00"):
        with pytest.raises(TranscriptError):
            entry.parse_extra_data(leaf, bad)


def test_a_precert_entry_with_no_chain_is_read_and_reported_as_having_none() -> None:
    """`precertificate_chain` is <0..2^24-1>, so an absent chain is legal and must not be invented.

    A monitor that fills in a chain it did not receive would build a path to a root the log never saw, and
    that path would then be published as evidence about the log.
    """
    sample = samples("precert")[0]
    stored = entry.parse_extra_data(leaf_of(sample), base64.b64decode(sample["extra_data"]))
    alone = precert_arm(stored.certificate, [])
    read = entry.parse_extra_data(leaf_of(sample), alone)
    assert read.chain == ()
    assert read.certificate == stored.certificate


def test_an_empty_certificate_is_not_a_stored_chain() -> None:
    with pytest.raises(TranscriptError, match="extra_data gave none"):
        entry.StoredChain(certificate=b"", chain=(), authenticated=True)
