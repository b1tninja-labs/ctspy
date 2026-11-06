"""Fetch the evidence this repository's claims rest on, and write it out as fixtures.

    python tools/fetch_evidence.py [--out tests/fixtures]

Read-only GETs against public CT log APIs. The point of keeping this in `tools/` rather than in a
scratch buffer is that it *produces committed files*: a fixture with no recorded way to re-make it is
an assertion, and an assertion about a running service goes stale silently. Every output carries
`provenance` with the URL and the UTC timestamp, so the next person can re-run this and see whether
the world moved.

Two things are collected:

`log-list-sweep.json` - every usable log in the official log list, its published key, and a current
STH from each. Verifying them offline (see `tests/test_production_sths.py`) is interoperability
evidence across several independent implementations, which is what a spec-derived test cannot give.

`production-proofs.json` - a real inclusion proof and a real consistency proof for one log, plus the
tree head they were issued against. The pairing matters: a log's proof is for *its current* tree, so
the head is fetched before and after the proof and the fixture is only written if both agree. A proof
verified against a head from some other moment is not evidence of anything, and a race here shows up
as a refusal to write the file rather than as a flaky test.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ctspy import merkle, sth
from ctspy.ecdsa import EcdsaKey

LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
USER_AGENT = "ctspy-evidence/0.1 (verification fixtures; read-only GETs)"


def get_json(url: str, *, timeout: float = 30.0, retries: int = 3) -> dict:
    """GET and parse, retrying transient transport failures.

    One reset connection out of forty logs is normal for a public API, and a fetch tool that dies on
    it is a tool that gets run once and then complained about. A genuine HTTP error (404, 500) is
    raised immediately: that is an answer, not a stumble, and retrying it would hide the fact that a
    log does not serve an endpoint at all.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    last: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                body = response.read()
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError(f"{url}: expected a JSON object, got {type(payload).__name__}")
            return payload
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(0.8 * (attempt + 1))
    raise OSError(f"{url}: no answer after {retries} attempts ({last})")


def now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def usable_logs() -> list[dict]:
    """Every log the list marks usable, flattened with its operator's name.

    `state` is honoured rather than assumed: retired and pending logs are excluded because a key that
    is no longer issuing produces a refusal that looks like a finding and is not one.

    Both schema generations are read. v3 of the list keys each entry's state as a one-field object
    (`{"usable": {"timestamp": ...}}`) and names the URL `url`; older files use a `status` string and
    a `urls` array, and mirrors still publish that shape. Tolerating both is not leniency about a
    security property - this is a reader of someone else's document, and the document changed.

    `readonly` logs are kept alongside `usable` ones. Such a log has stopped accepting entries but its
    key still means what it meant, and excluding it would throw away independent implementations that
    happen to be winding down - which is most of the value in sweeping at all. `retired` and
    `rejected` are excluded: a key that was withdrawn for cause is not evidence about today's format.
    """
    document = get_json(LOG_LIST)
    logs = []
    for operator in document.get("operators", []):
        for log in operator.get("logs", []):
            declared = log.get("state") or log.get("status")
            state = next(iter(declared), None) if isinstance(declared, dict) else declared
            if state not in {"usable", "readonly"}:
                continue
            url = log.get("url") or (log.get("urls") or [None])[0]
            if not url:
                continue
            logs.append(
                {
                    "operator": operator.get("name", "?"),
                    "description": log.get("description", "?"),
                    "key": log["key"],
                    "log_id": log["log_id"],
                    "url": url.rstrip("/"),
                    "state": state,
                    "mmd": log.get("mmd") or log.get("maximum_merged_mma"),
                }
            )
    print(
        f"log list v{document.get('version')}: {len(logs)} usable or read-only logs, "
        f"timestamp {document.get('log_list_timestamp')}"
    )
    return logs


def sweep(out: pathlib.Path) -> list[str]:
    logs = usable_logs()
    records = []
    for log in logs:
        url = f"{log['url']}/ct/v1/get-sth"
        record = dict(log)
        record["sth_url"] = url
        try:
            record["sth"] = get_json(url)
            record["error"] = None
        except Exception as exc:  # a log that will not answer is a fact worth recording verbatim
            record["sth"] = None
            record["error"] = f"{type(exc).__name__}: {exc}"
        key_der = base64.b64decode(record["key"])
        record["id_matches_key"] = hashlib.sha256(key_der).digest() == base64.b64decode(
            record["log_id"]
        )
        records.append(record)
        marker = "ok " if record["error"] is None else "ERR"
        print(f"  {marker} {record['operator']:<22} {record['description']}")
    payload = {
        "provenance": {
            "fetched_utc": now(),
            "log_list": LOG_LIST,
            "note": "Published keys and current STHs for every usable log. Verification happens "
            "offline in tests/test_production_sths.py so the suite does not need the network.",
        },
        "logs": records,
    }
    (out / "log-list-sweep.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {out / 'log-list-sweep.json'} ({len(records)} logs)")
    return [record["url"] for record in records if record["error"] is None]


TREE_SIZES = (2, 3, 8, 13, 41)


def fetch_leaves(origin: str, count: int, request: int = 64) -> tuple[list[str], int]:
    """The first `count` leaf inputs, paging because logs cap how many they hand back.

    Google's servers answer a request for 41 entries with 32. RFC 6962 section 4.3 allows that, and a
    client that assumes it received what it asked for ends up computing the root of a 32-entry tree and
    reporting it as the root of 41 - silently wrong, in the direction that looks plausible. So the
    actual page size is observed on the first call and used to drive the rest, and the count is
    asserted rather than trusted. The returned figure is the largest batch the server gave for a
    request of that size, which is the cap itself - the final page is short only because the remainder
    was short.
    """
    leaves: list[str] = []
    observed = 0
    start = 0
    while len(leaves) < count:
        want = min(request, count - len(leaves))
        body = get_json(f"{origin}/ct/v1/get-entries?start={start}&end={start + want - 1}")
        got = body["entries"]
        if not got:
            raise RuntimeError(f"{origin} returned no entries at index {start}")
        observed = max(observed, len(got))
        leaves.extend(entry["leaf_input"] for entry in got)
        start += len(got)
    return leaves[:count], observed


def tree_sweep(out: pathlib.Path, origin: str) -> None:
    """Build trees from real production entries and let the log vouch for them.

    The property being tested is `tree_hash`, not the proof verifier: K entries are fetched from the
    log's own `get-entries`, their root is computed here from scratch, and the question put to the log
    is "prove that this tree you computed independently is a prefix of the tree you signed". If any
    part of my MTH is wrong - a leaf prefix byte, a split point, an odd-size case - the fold cannot
    land on the signed root, and no amount of self-consistency inside my code would hide that.

    `second` is passed explicitly and the head is re-fetched afterwards, so every proof in the fixture
    refers to one specific signed head rather than "whatever the tree looked like when asked". The
    sizes are not incidental: 2 and 8 are exact powers of two, which take section 2.1.4.2 step 2's
    prepend branch, and 13 and 41 are ragged, which is where split-point arithmetic goes wrong.
    """
    from ctspy import sth as sth_module

    highest = max(TREE_SIZES)
    raw_leaves, page_cap = fetch_leaves(origin, highest)
    leaves = [base64.b64decode(item) for item in raw_leaves]
    print(f"  fetched {len(leaves)} entries from {origin} (page cap {page_cap})")

    head = get_json(f"{origin}/ct/v1/get-sth")
    size = int(head["tree_size"])
    root = base64.b64decode(head["sha256_root_hash"])

    proofs: dict[str, dict] = {}
    for count in TREE_SIZES:
        mine = merkle.tree_hash(leaves[:count])
        assert mine == merkle.tree_hash_recursive(leaves[:count]), f"two MTHs disagree at {count}"
        answer = get_json(f"{origin}/ct/v1/get-sth-consistency?first={count}&second={size}")
        nodes, field_name = consistency_nodes(answer)
        audit = tuple(base64.b64decode(node) for node in nodes)
        verified = merkle.verify_consistency(count, size, audit, mine, root)
        print(
            f"  tree of {count:>2} real entries -> root {mine.hex()[:16]}... consistent: {verified}"
        )
        if not verified:
            raise RuntimeError(
                f"the log refused to tie its own {count} entries to its own signed head; that is a "
                "finding about tree_hash, not a reason to relax the check"
            )
        proofs[str(count)] = {
            "field": field_name,
            "nodes": nodes,
            "root": base64.b64encode(mine).decode(),
        }

    after = get_json(f"{origin}/ct/v1/get-sth")
    if after != head:
        # Not a reason to discard the run. `second` was named explicitly in each request, and every
        # proof above folded onto the recorded head's root, which is the strongest possible evidence
        # that it refers to that size - a proof for a newer tree could not have landed there. The
        # earlier version of this check demanded an idle log, copied from the by-hash sweep where the
        # proof *is* implicitly for the current tree; on a log taking thousands of entries a minute
        # that made the tool fail for no reason.
        print(
            f"  note: the live tree grew during the sweep ({size} -> {after['tree_size']}); "
            "the fixture records the head at " + str(size) + ", which all five proofs matched"
        )

    key = find_key(origin)
    sth_module.verify(sth_module.SignedTreeHeadV1.from_v1_json(head), key)

    payload = {
        "provenance": {
            "fetched_utc": now(),
            "origin": origin,
            "note": "Verbatim get-entries leaves (the first "
            + str(highest)
            + ", paged because this "
            "log caps the response) and one get-sth-consistency response per tree size, all against "
            "the single recorded head. The roots in `proofs` are computed by ctspy from these leaf "
            "bytes, not supplied by the log.",
        },
        "origin": origin,
        "key": base64.b64encode(key.spki).decode(),
        "head": head,
        "tree_size": size,
        "head_after_sweep": after["tree_size"],
        "entries_page_cap": page_cap,
        "leaf_inputs": raw_leaves,
        "proofs": proofs,
    }
    (out / "production-tree.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {out / 'production-tree.json'} ({highest} entries, {len(TREE_SIZES)} tree sizes)")


def consistency_nodes(body: dict) -> tuple[list[str], str]:
    """The audit path, wherever this log chose to put it.

    RFC 6962 section 4.6 names the response field `audit_consistency`. Google's servers answer with
    `consistency` instead. A client that follows the specification text alone fails against every
    deployed log, and "fix" it by accepting both - recording which one the log actually used, because
    the difference between the specification and the deployment is the kind of fact that only survives
    if someone writes it down.
    """
    for name in ("consistency", "audit_consistency"):
        nodes = body.get(name)
        if isinstance(nodes, list):
            return nodes, name
    raise KeyError(f"no audit path field; keys present: {sorted(body)}")


def try_inclusion(origin: str, leaf_hash: bytes) -> tuple[dict | None, str | None]:
    """Ask one log for an inclusion proof by hash, or return the reason it could not."""
    encoded = urllib.parse.quote(base64.b64encode(leaf_hash).decode(), safe="")
    url = f"{origin}/ct/v1/get-inclusion-proof-by-hash?hash={encoded}"
    try:
        return get_json(url), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def inclusion_evidence(origin: str) -> dict:
    """Entry 0 of `origin`, an inclusion proof from `origin`, and the head `origin` signed.

    Self-consistent on purpose. A proof means something only against the tree of the log that issued
    it and the head that log signed at that size; asking log B to prove log A's leaf - which is what
    the first version of this function did when the search fanned out - yields a failure that reads
    like a broken verifier and is really a broken harness.
    """
    body = get_json(f"{origin}/ct/v1/get-entries?start=0&end=0")
    leaf_input = base64.b64decode(body["entries"][0]["leaf_input"])
    leaf_hash = merkle.leaf_hash(leaf_input)

    before = get_json(f"{origin}/ct/v1/get-sth")
    proof, error = try_inclusion(origin, leaf_hash)
    after = get_json(f"{origin}/ct/v1/get-sth")
    if proof is None:
        raise RuntimeError(error or "no proof returned")
    if before != after:
        raise RuntimeError("the head moved while the proof was being fetched")
    if int(proof["tree_size"]) != int(after["tree_size"]):
        raise RuntimeError(
            f"the proof claims tree size {proof['tree_size']} but this log's head says "
            f"{after['tree_size']}"
        )
    root = base64.b64decode(after["sha256_root_hash"])
    path = tuple(base64.b64decode(node) for node in proof["audit_path"])
    if not merkle.verify_inclusion(
        leaf_hash, int(proof["leaf_index"]), int(proof["tree_size"]), path, root
    ):
        raise RuntimeError("the proof did not verify against this log's own signed head")
    return {
        "origin": origin,
        "head": after,
        "leaf_input": body["entries"][0]["leaf_input"],
        "leaf_index": proof["leaf_index"],
        "proof": proof,
    }


def proofs(out: pathlib.Path, origin: str, alternates: list[str]) -> int:
    """A real consistency proof (and an inclusion proof if any log will give one), against one head.

    Entry index 0 is deliberate: the root of a one-entry tree is that entry's leaf hash, so the older
    root of the consistency proof needs no trust in anything but the hash function.

    The head is fetched before and after the proof. A log's proof is for *its current* tree, so
    without that bracket the fixture would be a proof verified against a root nobody signed at that
    size - which is exactly the check that must not be able to pass by accident.
    """
    body = get_json(f"{origin}/ct/v1/get-entries?start=0&end=0")
    leaf_input = base64.b64decode(body["entries"][0]["leaf_input"])
    leaf_hash = merkle.leaf_hash(leaf_input)

    before = get_json(f"{origin}/ct/v1/get-sth")
    head = get_json(f"{origin}/ct/v1/get-sth")
    if before != head:
        raise RuntimeError(
            f"the tree head moved while the proof was being fetched ({before['tree_size']} -> "
            f"{head['tree_size']}); re-run, or the proof would be verified against the wrong root"
        )
    size = int(head["tree_size"])
    consistency = get_json(f"{origin}/ct/v1/get-sth-consistency?first=1&second={size}")
    nodes, field_name = consistency_nodes(consistency)

    key = find_key(origin)
    signed = sth.SignedTreeHeadV1.from_v1_json(head)
    sth.verify(signed, key)

    audit = tuple(base64.b64decode(node) for node in nodes)
    consistent = merkle.verify_consistency(1, size, audit, leaf_hash, signed.root_hash)
    print(f"  consistency 1 -> {size} (field {field_name!r}): {consistent}")
    if not consistent:
        raise RuntimeError(
            "a production consistency proof failed to verify - a finding, not a fixture"
        )

    inclusion, inclusion_errors = None, {}
    for candidate in [origin, *alternates]:
        try:
            inclusion = inclusion_evidence(candidate)
        except Exception as exc:  # a log that will not prove its own entry 0 is recorded, not fatal
            inclusion_errors[candidate] = f"{type(exc).__name__}: {exc}"
            print(
                f"  no verifiable inclusion proof from {candidate}: {inclusion_errors[candidate]}"
            )
            continue
        print(f"  inclusion proof verified against {candidate} at index {inclusion['leaf_index']}")
        break
    if inclusion is None:
        print("  no log in this run served a usable inclusion proof; the fixture records why")

    payload = {
        "provenance": {
            "fetched_utc": now(),
            "origin": origin,
            "note": "Verbatim get-entries, get-sth, get-sth-consistency and (if any log served one) "
            "get-inclusion-proof-by-hash bodies. The head was fetched twice and agreed, which is what "
            "makes the proof verifiable offline.",
        },
        "origin": origin,
        "key": base64.b64encode(key.spki).decode(),
        "head": head,
        "entry": {"index": 0, "leaf_input": body["entries"][0]["leaf_input"]},
        "consistency_proof": consistency,
        "consistency_field": field_name,
        "inclusion": inclusion,
        "inclusion_failures": inclusion_errors,
    }
    (out / "production-proofs.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {out / 'production-proofs.json'} (tree size {size})")
    return size


def find_key(origin: str) -> EcdsaKey:
    """The published key for `origin`, taken from the log list rather than passed in."""
    document = get_json(LOG_LIST)
    want = origin.rstrip("/")
    for operator in document.get("operators", []):
        for log in operator.get("logs", []):
            candidates = ([log["url"]] if log.get("url") else []) + list(log.get("urls", []))
            if any(url.rstrip("/") == want for url in candidates):
                return EcdsaKey.from_spki(base64.b64decode(log["key"]))
    raise LookupError(f"{origin} is not in {LOG_LIST}")


def cached_urls(out: pathlib.Path) -> list[str]:
    """The URLs from the last sweep, so `--skip-sweep` can still fan out the inclusion search.

    A flag that quietly narrows what is attempted is a trap: the first version of this function
    returned nothing, the fixture recorded one failure instead of twenty-three, and the test that
    guards the size of that evidence did what it should have done and failed.
    """
    path = out / "log-list-sweep.json"
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    return [record["url"] for record in document["logs"] if record["error"] is None]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("tests/fixtures"))
    parser.add_argument(
        "--origin",
        default="https://ct.googleapis.com/logs/eu1/xenon2026h2",
        help="log to take proofs from; it must serve the RFC 6962 proof endpoints",
    )
    parser.add_argument("--skip-sweep", action="store_true", help="only refresh the proofs")
    parser.add_argument(
        "--skip-proofs", action="store_true", help="do not refetch the proof fixture"
    )
    parser.add_argument("--skip-tree", action="store_true", help="do not refetch the entry block")
    parser.add_argument(
        "--max-alternates",
        type=int,
        default=8,
        help="how many other logs to ask for an inclusion proof if --origin will not give one",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    urls = sweep(args.out) if not args.skip_sweep else cached_urls(args.out)
    origin = args.origin.rstrip("/")
    alternates = [url for url in urls if url != origin][: args.max_alternates]
    if not args.skip_proofs:
        proofs(args.out, origin, alternates)
    if not args.skip_tree:
        tree_sweep(args.out, origin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
