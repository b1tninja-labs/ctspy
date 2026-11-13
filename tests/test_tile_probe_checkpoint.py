"""`tools/tile_probe.py` feeds the checkpoint it fetched to `ctspy.checkpoint` (offline).

The probe is networked and not a gate; what it does with the bytes is a pure function, `verify_log_checkpoint`,
and it is loaded by path here so the part that decides `checkpoint_verified` is exercised without a request.
The log entries come from the committed log-list snapshot (`tests/fixtures/loglist/log_list.json`, the
`tiled_logs` array), so the key and submission prefix are the ones Chrome's list declares. No tiled log's own
private key is available, so a *genuine* static-log checkpoint cannot be made here: the positive case re-wraps a
production STH of a dynamic log under a tiled log's declared prefix with that dynamic log's key standing in,
which exercises the same plumbing; the negative cases are the point of the test.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import sys
from typing import Any

import pytest

from ctspy import checkpoint
from ctspy import sth as sth_module
from ctspy.ecdsa import EcdsaKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
ARGON = json.loads((FIXTURES / "argon2026h2-sth.json").read_text("utf-8"))


def load_probe() -> Any:
    spec = importlib.util.spec_from_file_location("tile_probe", ROOT / "tools" / "tile_probe.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["tile_probe"] = module
    spec.loader.exec_module(module)
    return module


probe = load_probe()


def a_tiled_log() -> dict[str, Any]:
    logs = probe.tiled_logs(FIXTURES / "loglist" / "log_list.json")
    log = next(item for item in logs if item["usable"] and item["submission_url"] and item["key"])
    return dict(log)


def test_the_probe_reads_the_key_and_submission_prefix_from_the_log_list() -> None:
    log = a_tiled_log()
    assert log["submission_url"].startswith("https://")
    key = EcdsaKey.from_spki(base64.b64decode(log["key"]))
    assert (
        key.log_id
    )  # a P-256 SPKI the library accepts: the list's key is what the verifier is built from


def test_a_checkpoint_signed_by_the_declared_key_under_the_declared_origin_is_verified() -> None:
    argon_key = base64.b64decode(ARGON["key"])
    log = {"submission_url": "https://ct.googleapis.com/logs/us1/argon2026h2/", "key": ARGON["key"]}
    head = sth_module.SignedTreeHeadV1.from_v1_json(ARGON["responses"][0])
    raw = checkpoint.from_sth(
        head,
        checkpoint.static_log_origin(log["submission_url"]),
        EcdsaKey.from_spki(argon_key).log_id,
    )
    result = probe.verify_log_checkpoint(raw, log)
    assert result["verified"] is True
    assert result["tree_size"] == ARGON["responses"][0]["tree_size"]
    assert result["origin"] == "ct.googleapis.com/logs/us1/argon2026h2"


def test_a_checkpoint_from_a_log_the_list_does_not_declare_is_not_verified() -> None:
    log = a_tiled_log()  # a different log's key and prefix than the one that signed the head
    argon_key = EcdsaKey.from_spki(base64.b64decode(ARGON["key"]))
    head = sth_module.SignedTreeHeadV1.from_v1_json(ARGON["responses"][0])
    raw = checkpoint.from_sth(
        head, checkpoint.static_log_origin(log["submission_url"]), argon_key.log_id
    )
    result = probe.verify_log_checkpoint(raw, log)
    assert result["verified"] is False
    assert result["reason"]


@pytest.mark.parametrize("raw", [b"", b"not a note", b"origin\n1\nAAAA\n\n"])
def test_garbage_is_reported_as_unverified_and_never_raises(raw: bytes) -> None:
    result = probe.verify_log_checkpoint(raw, a_tiled_log())
    assert result["verified"] is False
    assert result["reason"]


def test_a_log_entry_without_a_key_is_unverifiable_not_failing() -> None:
    result = probe.verify_log_checkpoint(b"x", {"submission_url": "", "key": ""})
    assert result == {
        "verified": False,
        "reason": "the log list gives no submission_url or key",
    }
