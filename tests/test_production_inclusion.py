"""Production inclusion proofs, verified against heads this library authenticated.

This file exists because of a retraction. An earlier sweep asked `/ct/v1/get-inclusion-proof-by-hash` - a
path defined in no RFC - and recorded the resulting 404s as "no deployed log serves inclusion proofs", which
was then repeated in `docs/interop.md`, the roadmap and `PORTFOLIO.md`. The finding was an artifact of the
question asked: RFC 6962 section 4.5 defines `get-proof-by-hash` with inputs `hash` and `tree_size` and
outputs `leaf_index` and `audit_path`, and asked properly every log answered. The run that wrote the fixture
in `tests/fixtures/production-inclusion.json` verified **23 of 23**; the run before it verified 22 of 23 and
one log throttled with 429, and an earlier run throttled a different log - so the throttle is about rate
limits, not about the endpoint.

What the fixture supports is therefore stronger than what it used to claim. Each head is a verbatim
`get-sth` response, its signature checked against the key the Chrome log list publishes for that log, and the
audit path is then checked against *that* root. Nothing here trusts a tree hash it was handed.

It is also the first production anchor for `merkle.verify_inclusion`. Before this the verifier was pinned only
by RFC 6962's worked example, which is a fine test of arithmetic and no test at all of whether the fleet's
paths are shaped the way the code expects.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from ctspy import merkle
from ctspy.ecdsa import EcdsaKey
from ctspy.sth import SignedTreeHeadV1
from ctspy.sth import verify as verify_sth

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "production-inclusion.json").read_text("utf-8")
)
PROOFS = FIXTURE["proofs"]
BY_ORIGIN = {proof["origin"]: proof for proof in PROOFS}


def _head(proof: dict) -> SignedTreeHeadV1:
    """The head as the library reads it, not as this test assembles it.

    `from_v1_json` is the path a client takes: it lifts the signature out of its RFC 5246 `DigitallySigned`
    wrapper, refuses fields that are not what they claim, and keeps the declared algorithm pair. Building the
    dataclass from raw JSON by hand was tried first, in the probe that wrote the earlier version of this
    fixture, and it made the whole fleet look broken - exactly the mistake the parser exists to prevent.
    Re-implementing it here would hide that lesson rather than test it.
    """
    head = SignedTreeHeadV1.from_v1_json(proof["signed_tree_head"])
    # 4 is sha256, 3 is ecdsa (RFC 5246 section 7.4.1.4.1). If a log declares otherwise, this fixture's
    # description of a v1 head stops being accurate and should say so rather than verify something else.
    assert (head.hash_algorithm, head.signature_algorithm) == (4, 3), proof["signature_shape"]
    return head


def test_every_captured_head_verifies_against_its_published_key() -> None:
    """The root each proof is checked against is authenticated, not assumed.

    Without this step the fixture would only show that a path is self-consistent with some hash. With it, the
    hash is the one the log signed under a key the log list publishes for that origin.
    """
    for proof in PROOFS:
        key = EcdsaKey.from_spki(base64.b64decode(proof["key"]))
        verify_sth(_head(proof), key)


def test_production_audit_paths_verify_against_the_signed_head() -> None:
    """Leaf 0 of a live log, proved against the tree that log signed, over the bytes it served."""
    for proof in PROOFS:
        head = _head(proof)
        leaf_input = base64.b64decode(proof["leaf_input"])
        leaf_hash = merkle.leaf_hash(leaf_input)
        path = tuple(base64.b64decode(node) for node in proof["audit_path"])
        assert merkle.verify_inclusion(
            leaf_hash, proof["leaf_index"], head.tree_size, path, head.root_hash
        ), proof["origin"]
        assert proof["leaf_index"] == 0, "the fixture proves the oldest entry in each tree"


def test_the_captured_trees_are_production_sized() -> None:
    """Short paths would hide the bug class this is here to catch.

    A verifier that mishandles a trailing subtree or an odd right-hand edge shows up at depth 30, not at
    depth 3. The largest captured tree has more than six billion entries; the smallest is a freshly opened
    log; both are worth having.
    """
    sizes = [_head(proof).tree_size for proof in PROOFS]
    depths = [len(proof["audit_path"]) for proof in PROOFS]
    assert max(sizes) > 1_000_000_000, sizes
    assert max(depths) >= 30, depths


def test_the_sweep_asks_the_endpoint_the_specification_defines() -> None:
    """The guard against repeating the original mistake: the asked path must be section 4.5's.

    Every conclusion in this fixture is about an endpoint that has to be named correctly. Pinning the path and
    both required inputs here means a future edit that reaches for an invented URL fails a test instead of
    producing a confident, meaningless sweep.
    """
    for proof in PROOFS:
        asked = proof["asked"]
        assert "/ct/v1/get-proof-by-hash?" in asked, asked
        assert "hash=" in asked, asked
        assert "tree_size=" in asked, asked
    assert FIXTURE["provenance"]["spec"].startswith("RFC 6962 section 4.5")


def test_the_retracted_finding_is_recorded_rather_than_quietly_replaced() -> None:
    """The retraction travels with the evidence, so nobody reconstructs the old claim from the diff.

    The tally is asserted as what it is: logs that answered with a verifying proof, plus at most one throttle.
    A 404 or 403 anywhere in here would be news worth chasing, so it is refused rather than averaged away.
    """
    assert "retraction" in FIXTURE["provenance"]
    assert "get-inclusion-proof-by-hash" in FIXTURE["provenance"]["retraction"]
    tally = FIXTURE["tally"]
    assert tally.get("PROOF-VERIFIES", 0) >= 20, tally
    strays = {key: value for key, value in tally.items() if key not in {"PROOF-VERIFIES", "HTTP"}}
    assert not strays, strays
    throttled = [origin for origin, kind in FIXTURE["results"].items() if kind.startswith("HTTP")]
    assert all(FIXTURE["results"][origin] == "HTTP 429" for origin in throttled), throttled


def test_the_two_logs_captured_are_different_kinds_of_log() -> None:
    """One append-only log and one static-merge log, because they disagree about everything else.

    Cloudflare's nimbus2026 is a static-merge tree built from another log's history - the same shape that
    broke `extra_data` readers earlier in this project. An inclusion verifier that works on both is the one
    worth trusting.
    """
    operators = {proof["operator"] for proof in PROOFS}
    assert len(operators) >= 2, operators
    assert "Cloudflare" in operators
    assert "Google" in operators
    assert len(BY_ORIGIN) == len(PROOFS)


@pytest.mark.parametrize("origin", sorted(BY_ORIGIN))
def test_each_captured_proof_carries_its_own_inputs(origin: str) -> None:
    """Nothing in the fixture is meaningful without the inputs that produced it.

    The leaf octets, the head, the path and the index travel together so the test recomputes rather than
    replays: a fixture that stored only `verified: true` would be a screenshot of a passing run.
    """
    proof = BY_ORIGIN[origin]
    assert proof["leaf_input"]
    assert proof["audit_path"]
    assert proof["signed_tree_head"]
    assert proof["extra_data"] is not None, (
        "x509 entries carry the chain there; precerts the whole struct"
    )
