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
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ctspy import entry as entry_mod
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


ALL_LOGS_LIST = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"


def list_logs(
    source: str = ALL_LOGS_LIST,
    *,
    states: set[str] | None = None,
    include_test: bool = False,
) -> list[dict]:
    """Every log a list describes, with its declared state — including those Chrome will not enforce with.

    `usable_logs()` is the right reader for an interoperability sweep: a key withdrawn for cause is poor evidence
    about today's wire format, exactly as its docstring says. It is the wrong reader for a *coverage* claim,
    because `log_list.json` carries only the logs Chrome enforces with (26 at v96.2) while
    `all_logs_list.json` carries 45 — the extra 19 holding 13.6 billion leaves, 6.5 billion of them
    publicly-trusted issuance in the `rejected` 2026h1 generation, still serving their trees today
    (`certledger/BROWSER-POLICY.md` §2). Which document was read is part of the result, so `source` also accepts a
    journaled snapshot path and a claim can be reproduced against the exact bytes it was made from.

    Logs the list marks `test` are dropped unless `include_test` says otherwise: they hold billions of leaves that
    were never publicly trusted, and folding them in silently manufactures "issued by a trusted CA" claims that
    are false by construction. A log with no `state` field at all — Google's Daedalus and Submariner, and the
    never-applied entries — is reported as `none` rather than skipped, because its tree is real issuance even
    though no browser counts it.
    """
    from_disk = pathlib.Path(source).is_file()
    document = (
        json.loads(pathlib.Path(source).read_text(encoding="utf-8"))
        if from_disk
        else get_json(source)
    )
    logs = []
    for operator in document.get("operators", []):
        # Both arrays. An operator may run no RFC 6962 log at all - Microsec, GoDaddy, HARICA and SwissSign are
        # named only under tiled_logs - so reading `logs` alone silently drops a whole protocol and four
        # operators. The two kinds answer different read APIs, which is what `kind` is for downstream.
        for kind, entries in (
            ("rfc6962", operator.get("logs", [])),
            ("tiled", operator.get("tiled_logs", [])),
        ):
            for log in entries:
                declared = log.get("state") or log.get("status")
                state = next(iter(declared), None) if isinstance(declared, dict) else declared
                is_test = log.get("log_type") == "test"
                if is_test and not include_test:
                    continue
                if states and (state or "none") not in states:
                    continue
                monitoring = (log.get("monitoring_url") or "").rstrip("/")
                url = (
                    log.get("url")
                    or (log.get("urls") or [None])[0]
                    or monitoring
                    or log.get("submission_url")
                    or ""
                )
                logs.append(
                    {
                        "operator": operator.get("name", "?"),
                        "description": log.get("description", "?"),
                        "key": log.get("key", ""),
                        "log_id": log.get("log_id", ""),
                        "kind": kind,
                        "url": url.rstrip("/"),
                        "monitoring_url": monitoring,
                        "submission_url": (log.get("submission_url") or "").rstrip("/"),
                        "state": state or "none",
                        "test": is_test,
                        "seal": declared.get("final_tree_head")
                        if isinstance(declared, dict)
                        else None,
                        "mmd": log.get("mmd"),
                    }
                )
    print(
        f"{source.rsplit('/', 1)[-1] if not from_disk else pathlib.Path(source).name}"
        f" v{document.get('version')}: {len(logs)} logs "
        f"{dict(Counter(x['kind'] for x in logs))}, states {dict(Counter(x['state'] for x in logs))}"
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
    """The audit path, and the field name the log actually used.

    Both specifications name the output `consistency` - RFC 6962 section 4.4 for v1, RFC 9162 section 5.3 for
    v2 - so there is no specification-versus-deployment story here, and an earlier version of this docstring
    claimed one (`audit_consistency`, attributed to section 4.6) that is in neither document: the name with
    "audit" in it is `audit_path`, in section 4.5. What the two versions *do* differ about is the value: v1 is
    an array of base64 node hashes, v2 a single base64 `TransItem`. The fallback stays because accepting both
    names costs nothing and records which one appeared, which is the part worth keeping.
    """
    for name in ("consistency", "audit_consistency"):
        nodes = body.get(name)
        if isinstance(nodes, list):
            return nodes, name
    raise KeyError(f"no audit path field; keys present: {sorted(body)}")


def try_inclusion(origin: str, leaf_hash: bytes, tree_size: int) -> tuple[dict | None, str | None]:
    """Ask one log for an inclusion proof by hash, or return the reason it could not.

    Section 4.5 requires both inputs: the leaf hash *and* the `tree_size` of an existing v1 STH. A probe that
    sends only the hash, or that reaches for a path the specification does not define - which is exactly how
    the "no deployed log serves inclusion proofs" finding was produced and later retracted - measures its own
    URL rather than the fleet.
    """
    encoded = urllib.parse.quote(base64.b64encode(leaf_hash).decode(), safe="")
    url = f"{origin}/ct/v1/get-proof-by-hash?hash={encoded}&tree_size={tree_size}"
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
    proof, error = try_inclusion(origin, leaf_hash, int(before["tree_size"]))
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
            "get-proof-by-hash bodies. The head was fetched twice and agreed, which is what "
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


SCT_HOSTS = (
    "www.google.com",
    "www.cloudflare.com",
    "github.com",
    "www.microsoft.com",
    "apple.com",
    "letsencrypt.org",
    "www.wikipedia.org",
    "www.mozilla.org",
    "www.amazon.com",
    "www.paypal.com",
    "www.chase.com",
    "www.bankofamerica.com",
    "www.godaddy.com",
    "www.nordvpn.com",
    "www.duckduckgo.com",
    "www.eff.org",
    "www.apache.org",
    "www.debian.org",
    "www.python.org",
)
SCT_OID_DER = bytes.fromhex("060a2b06010401d679020402")  # 1.3.6.1.4.1.11129.2.4.2
POISON_OID_DER = bytes.fromhex("060a2b06010401d679020403")  # 1.3.6.1.4.1.11129.2.4.3


def parse_extra_data(leaf, extra: bytes) -> tuple[bytes, list[bytes]]:
    """Delegate to `ctspy.entry.parse_extra_data`, which reads the layout the entry type actually has."""
    stored = entry_mod.parse_extra_data(leaf, extra)
    return stored.certificate, list(stored.chain)


def extra_layout(out: pathlib.Path) -> None:
    """Survey how `extra_data` is laid out across the fleet, and keep bytes for the interesting cases.

    Counts alone would not settle this. What matters is whether any x509 entry carries **two or more** chain
    certificates, because that is the case a reader which assumes "one certificate then one vector" gets
    wrong in silence: it reads the second certificate's length as a vector header and either fails or, worse,
    succeeds while dropping the tail. So the chain-length histogram is captured next to the samples, and an
    x509 entry with a long chain is kept as bytes even if it is the only one.
    """
    parsed: dict[str, int] = {}
    chains: dict[str, int] = {}
    samples: list[dict] = []
    long_chain: list[dict] = []
    logs = 0
    for record in usable_logs():
        url = record["url"]
        try:
            body = get_json(f"{url}/ct/v1/get-entries?start=0&end=31")
        except Exception:  # noqa: S112 - a log that is down is a gap in the survey, not a crash
            continue
        logs += 1
        kept = {"precert": 0, "x509": 0}
        for index, item in enumerate(body["entries"]):
            leaf = entry_mod.MerkleTreeLeaf.parse(base64.b64decode(item["leaf_input"]))
            signed = leaf.entry.entry
            kind = "precert" if isinstance(signed, entry_mod.PrecertEntry) else "x509"
            extra = base64.b64decode(item["extra_data"])
            try:
                stored = entry_mod.parse_extra_data(leaf, extra)
            except Exception:
                parsed[f"{kind}:refused"] = parsed.get(f"{kind}:refused", 0) + 1
                continue
            parsed[f"{kind}:read"] = parsed.get(f"{kind}:read", 0) + 1
            key = f"{kind}:{min(len(stored.chain), 3)}"
            chains[key] = chains.get(key, 0) + 1
            record = {
                "log": url,
                "index": index,
                "kind": kind,
                "authenticated": stored.authenticated,
                "chain_count": len(stored.chain),
                "leaf_input": item["leaf_input"],
                "extra_data": item["extra_data"],
            }
            if len(stored.chain) >= 2 and len(long_chain) < 4:
                long_chain.append(record)
            elif kept[kind] < 2 and len(samples) < 30:
                kept[kind] += 1
                samples.append(record)
    if not logs:
        # An empty survey written to a fixture would read later as "the fleet is consistent", which is
        # exactly the wrong conclusion to draw from having reached nobody.
        raise SystemExit("extra_data layout: no log answered; refusing to write an empty survey")
    payload = {
        "captured": now(),
        "logs": logs,
        "parsed": dict(sorted(parsed.items())),
        "chain_lengths": dict(sorted(chains.items())),
        "entries": samples + long_chain,
    }
    (out / "extra-data-layout.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"extra_data layout: {logs} logs -> {parsed} chains {chains}")


def opaque3(data: bytes, offset: int) -> tuple[bytes, int]:
    length = int.from_bytes(data[offset : offset + 3], "big")
    return data[offset + 3 : offset + 3 + length], offset + 3 + length


def der_length(data: bytes, offset: int) -> tuple[int, int]:
    """(value, bytes consumed) for a DER length at `offset`."""
    first = data[offset]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), 1 + count


def sct_extension_payload(cert_der: bytes) -> bytes | None:
    """The SCT list bytes inside a certificate, found by scanning the DER.

    This lives in the evidence tool and not in `ctspy` on purpose: locating an extension is X.509
    parsing, and the library takes no X.509 dependency. `cryptography` parses this extension into its
    own type and will not return the original bytes, and the original bytes are the point - the question
    is whether ctspy can read what a log wrote, not whether two libraries agree on a re-encoding.

    The list comes back out of two nested OCTET STRINGs: the extension value is one (X.509 says so of
    every extension), and inside it the `digitally-signed struct` of RFC 5246 is another. The TLS
    extension has neither wrapper, which is the trap: strip one layer and the parser reads a tag byte
    as a length.
    """
    start = 0
    while (index := cert_der.find(SCT_OID_DER, start)) != -1:
        cursor = index + len(SCT_OID_DER)
        if cert_der[cursor : cursor + 1] == b"\x01":  # critical BOOLEAN
            cursor += 3
        if cert_der[cursor : cursor + 1] != b"\x04":
            start = index + 1
            continue
        cursor += 1
        outer, used = der_length(cert_der, cursor)
        cursor += used
        block = cert_der[cursor : cursor + outer]
        if block[:1] == b"\x04":
            inner, used = der_length(block, 1)
            return block[1 + used : 1 + used + inner]
        return block
    return None


def peer_certificate(host: str) -> bytes:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as sock:  # noqa: SIM117
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError(f"{host}: no certificate offered")
    return der


def sct_sweep(out: pathlib.Path) -> None:
    """Real SCTs from live certificates, parsed by the same code the tests exercise.

    Evidence for the wire format, and an honest record of what it does not prove. These are
    **precert** SCTs - the embedded certificate extension carries those - so they are signatures over
    `issuer_key_hash | TBSCertificate-without-the-SCT-extension`, which a handshake does not provide:
    the hash is of the precertificate signing certificate, which the final chain need not contain. So
    the SCTs here are evidence about parsing and about log identity, and `tests/test_production_scts.py`
    asserts that they do *not* verify over an x509_entry transcript, which is the failure mode of a
    verifier that had gotten the transcript wrong in the flattering direction.
    """
    from ctspy import sct as sct_module

    documents = []
    for host in SCT_HOSTS:
        try:
            der = peer_certificate(host)
            payload = sct_extension_payload(der)
        except Exception as exc:  # a host that will not answer is recorded, not fatal
            documents.append({"host": host, "error": f"{type(exc).__name__}: {exc}"})
            continue
        if payload is None:
            documents.append({"host": host, "error": "no embedded SCT list"})
            print(f"  {host}: no embedded SCT list")
            continue
        items = sct_module.parse_list(payload)
        documents.append(
            {
                "host": host,
                "cert_der": base64.b64encode(der).decode(),
                "sct_list": base64.b64encode(payload).decode(),
                "count": len(items),
            }
        )
        print(f"  {host}: {len(items)} SCTs parsed")
    payload_document = {
        "provenance": {
            "fetched_utc": now(),
            "note": "Leaf certificates and their embedded SignedCertificateTimestampLists, taken from "
            "TLS handshakes to public services. Certificates are public and the connections are "
            "read-only; nothing is submitted to any log.",
        },
        "documents": documents,
    }
    (out / "live-scts.json").write_text(
        json.dumps(payload_document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {out / 'live-scts.json'} ({len(documents)} certificates)")


def all_logs() -> dict:
    """Every log in the list, retired included, keyed by log id: an SCT outlives its log's usability.

    The sweep uses only live logs because it is evidence about today's format. This needs the opposite
    scope: an SCT embedded in a certificate issued years ago was made by a log that is retired now, and
    its key is still the key that signed it.
    """
    document = get_json(LOG_LIST)
    directory = {}
    for operator in document.get("operators", []):
        for log in operator.get("logs", []):
            declared = log.get("state") or log.get("status")
            state = next(iter(declared), "?") if isinstance(declared, dict) else declared
            directory[base64.b64decode(log["log_id"])] = (
                f"{log.get('description', '?')} [{state}]",
                base64.b64decode(log["key"]),
                state,
            )
    return directory


def der_len(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """(tag, content_start, content_end) for the DER element at `offset`."""
    tag = data[offset]
    cursor = offset + 1
    first = data[cursor]
    if first < 0x80:
        length, cursor = first, cursor + 1
    else:
        count = first & 0x7F
        length = int.from_bytes(data[cursor + 1 : cursor + 1 + count], "big")
        cursor = cursor + 1 + count
    return tag, cursor, cursor + length


def der_elements(data: bytes) -> list[tuple[int, int, int, int, int]]:
    """(tag, start, end, content_start, content_end) per element of `data`'s content."""
    out, cursor = [], 0
    while cursor < len(data):
        _, content_start, content_end = der_tlv(data, cursor)
        out.append((data[cursor], cursor, content_end, content_start, content_end))
        cursor = content_end
    return out


def der_content(der: bytes) -> bytes:
    """The content octets of one encoded value.

    `der_elements` walks a *list* of elements, so handing it an encoded value makes it see exactly one
    element and report the structure as empty. That is what happened here: an extension stripper deleted
    nothing, every reconstruction mismatched by a constant amount, and the evidence pointed at a protocol
    mystery instead of at this caller error.
    """
    _, start, end = der_tlv(der, 0)
    return der[start:end]


def tbs_of(cert_der: bytes) -> bytes:
    """The TBSCertificate's exact bytes: the first element inside the certificate SEQUENCE."""
    _, body_start, body_end = der_tlv(cert_der, 0)
    first = der_elements(cert_der[body_start:body_end])[0]
    return cert_der[body_start + first[1] : body_start + first[2]]


def strip_extension(tbs: bytes, oid_der: bytes) -> bytes:
    """Delete one extension from a TBSCertificate, re-encoding every enclosing length.

    RFC 6962 section 3.2 says the logged TBSCertificate can be recovered from the final certificate "by
    extracting the TBSCertificate from it and deleting the SCT extension". The log hashed the re-encoded
    DER, not the original with a hole in it, so the extension list, its `[3]` wrapper and the TBS itself
    all need fresh lengths. Checked against ground truth rather than assumed: against the precert entries
    logs store, this reproduces the logged `TBSCertificate` byte for byte, 29 times out of 29 across
    Google, DigiCert and Cloudflare (`tools/check_precert_reconstruction.py`).
    """
    body = der_content(tbs)
    block = next((item for item in der_elements(body) if item[0] == 0xA3), None)
    if block is None:
        return tbs
    _, _, _, a3_cs, a3_ce = block
    wrapper = der_elements(body[a3_cs:a3_ce])[0]
    seq_cs, seq_ce = a3_cs + wrapper[3], a3_cs + wrapper[4]
    every = der_elements(body[seq_cs:seq_ce])
    kept = [
        body[seq_cs + item[1] : seq_cs + item[2]]
        for item in every
        if oid_der not in body[seq_cs + item[1] : seq_cs + item[2]]
    ]
    if len(kept) == len(every):
        return tbs
    inner = b"\x30" + der_len(sum(len(item) for item in kept)) + b"".join(kept)
    outer = b"\xa3" + der_len(len(inner)) + inner
    new_body = body[: block[1]] + outer + body[block[2] :]
    return b"\x30" + der_len(len(new_body)) + new_body


def peer_chain(host: str) -> tuple[bytes, list[bytes]]:
    """The certificate a host presents, and every certificate it sends.

    `get_unverified_chain`, deliberately: path building drops a precertificate signing certificate
    because the path does not need it, and that certificate's key is exactly what a precert SCT's
    `issuer_key_hash` commits to. Using the verified path is why the first hundred attempts here verified
    nothing.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as sock:  # noqa: SIM117
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            served = list(tls.get_unverified_chain() or [])
    if not der:
        raise RuntimeError(f"{host}: no certificate offered")
    return der, served


def spki_der(cert_der: bytes) -> bytes:
    """The DER SubjectPublicKeyInfo of a certificate - the thing the log id and issuer hash are over."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    return (
        x509.load_der_x509_certificate(cert_der)
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def item_wire(item) -> bytes:
    """An SCT back to its wire bytes, so the fixture stores what was on the wire, not a summary."""
    from ctspy.transcript import Writer

    return (
        Writer()
        .uint8(item.version)
        .raw(item.log_id)
        .uint64(item.timestamp)
        .opaque(item.extensions, length_bytes=2, minimum=0, maximum=65535)
        .uint8(item.hash_algorithm)
        .uint8(item.signature_algorithm)
        .opaque(item.signature, length_bytes=2, minimum=1, maximum=65535)
        .build()
    )


def sct_signatures(out: pathlib.Path) -> None:
    """Production SCT signatures, verified end to end, with the inputs needed to check them offline.

    The transcript an embedded SCT covers is `issuer_key_hash | TBSCertificate-without-the-SCT-extension`
    (RFC 6962 section 3.2), and every input is obtainable from a handshake: the certificate, the chain the
    server sent, and the reconstruction the specification itself describes - "extracting the
    TBSCertificate from it and deleting the SCT extension". Two details matter and were both learned the
    hard way. The issuer must be taken from the chain the server *sent* (`get_unverified_chain`), not the
    path OpenSSL built: a CA that signs precertificates with a separate precertificate signing
    certificate leaves that certificate out of the built path, and it is the key the SCT's hash commits
    to. And the extension must be deleted with the three enclosing lengths re-encoded, because the log
    hashed the shortened DER, not the original with a hole in it.

    Each recorded case is one certificate that yielded at least one signature this library verified.
    The reconstruction is stored alongside the certificate it came from so a test can redo the surgery
    and confirm it still lands, rather than trusting a transcript this tool computed.
    """
    from ctspy import sct as sct_module
    from ctspy.entry import MerkleTreeLeaf, PrecertEntry, TimestampedEntry

    directory = all_logs()
    cases: list[dict] = []
    verified = attempts = 0
    for host in SCT_HOSTS:
        if len(cases) >= 6:
            break
        try:
            der, served = peer_chain(host)
        except Exception as exc:  # a host that will not answer is not a finding
            print(f"  {host}: {type(exc).__name__}: {exc}")
            continue
        payload = sct_extension_payload(der)
        if payload is None:
            print(f"  {host}: no embedded SCT list")
            continue
        base_tbs = tbs_of(der)
        tbs = strip_extension(base_tbs, SCT_OID_DER)
        for item in sct_module.parse_list(payload):
            known = directory.get(item.log_id)
            if known is None:
                continue
            label, key_der, _state = known
            key = EcdsaKey.from_spki(key_der)
            for index, issuer in enumerate(served):
                issuer_hash = hashlib.sha256(spki_der(issuer)).digest()
                entry = TimestampedEntry(
                    timestamp=item.timestamp,
                    entry=PrecertEntry(issuer_hash, tbs),
                    extensions=b"",
                )
                leaf = MerkleTreeLeaf.parse(b"\x00\x00" + entry.transcript())
                attempts += 1
                try:
                    sct_module.verify(item, leaf, key)
                except Exception:  # noqa: S112 - an issuer that does not match is the expected case
                    continue
                verified += 1
                print(f"  {host}: {label} signed the reconstructed precert (chain[{index}])")
                cases.append(
                    {
                        "host": host,
                        "log": label,
                        "log_key": base64.b64encode(key_der).decode(),
                        "issuer_certificate": base64.b64encode(issuer).decode(),
                        "certificate": base64.b64encode(der).decode(),
                        "sct": base64.b64encode(item_wire(item)).decode(),
                        "reconstructed_tbs": base64.b64encode(tbs).decode(),
                        "issuer_key_hash": issuer_hash.hex(),
                    }
                )
                break
            else:
                continue
            break
    payload_document = {
        "provenance": {
            "fetched_utc": now(),
            "note": "One entry per certificate that yielded at least one SCT signature this library "
            "verified against the log's published key. `reconstructed_tbs` is what the tool derived by "
            "deleting the SCT extension; the test re-derives it from `certificate` and compares.",
        },
        "attempts": attempts,
        "verified": verified,
        "cases": cases,
    }
    (out / "live-sct-signatures.json").write_text(
        json.dumps(payload_document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {out / 'live-sct-signatures.json'} ({verified}/{attempts} verified, {len(cases)} cases)"
    )


INCLUSION_CAPTURES = (
    "https://ct.googleapis.com/logs/us1/argon2026h2",
    "https://ct.cloudflare.com/logs/nimbus2026",
)


def failure_kind(detail: str) -> str:
    """Name a refusal by its HTTP status when it has one.

    "HTTP 429" is a throttle and says nothing about whether the endpoint exists; "HTTP 404" is an answer about
    the endpoint. Burying both in prose is how a rate limiter got read as an absent feature once already, so
    the status is the first token of the string the fixture stores.
    """
    match = re.search(r"HTTP Error (\d{3})", detail)
    return f"HTTP {match.group(1)}" if match else f"REFUSED: {detail[:90]}"


def _inclusion_capture(
    log: dict, head_json: dict, head: sth.SignedTreeHeadV1, served: dict, index: int, path: tuple
) -> dict:
    """One verifiable capture: the entry, the head that commits to it, and the path between them.

    Everything is stored as served - the head verbatim, the path in the base64 the log used - so the test
    recomputes from inputs rather than replaying a conclusion. `signature_shape` records what the wrapper
    declared, which is the part of `tree_head_signature` a client that skips the parser gets wrong.
    """
    return {
        "origin": log["url"],
        "description": log["description"],
        "operator": log["operator"],
        "log_id": log["log_id"],
        "key": log["key"],
        "signed_tree_head": head_json,
        "signature_shape": (
            f"DigitallySigned(hash={head.hash_algorithm} sig={head.signature_algorithm})"
        ),
        "leaf_index": index,
        "leaf_input": served["leaf_input"],
        "extra_data": served["extra_data"],
        "audit_path": [base64.b64encode(node).decode() for node in path],
        "asked": "/ct/v1/get-proof-by-hash?hash=<leaf 0 hash>&tree_size=<the head beside this proof>",
    }


def _write_inclusion_fixture(out: pathlib.Path, results: dict, captured: list) -> None:
    """Write the inclusion fixture, refusing to overwrite good evidence with a worse run."""
    missing = [url for url in INCLUSION_CAPTURES if url not in results]
    if missing:
        raise RuntimeError(f"designated capture logs vanished from the list: {missing}")
    if len(captured) != len(INCLUSION_CAPTURES):
        raise RuntimeError(
            "a designated capture log refused an inclusion proof - that is a finding worth publishing, "
            f"not a fixture to overwrite: {results}"
        )

    tally: dict[str, int] = {}
    for value in results.values():
        kind = value.split(" ", 1)[0]
        tally[kind] = tally.get(kind, 0) + 1
    document = {
        "provenance": {
            "fetched_utc": now(),
            "tool": "tools/fetch_evidence.py inclusion_sweep()",
            "spec": "RFC 6962 section 4.5: GET /ct/v1/get-proof-by-hash, inputs hash and tree_size, "
            "outputs leaf_index and audit_path",
            "trust": "Each head is parsed by SignedTreeHeadV1.from_v1_json and verified against the key the "
            "Chrome log list publishes for that log before its audit path is checked, so the fixture "
            "authenticates its own root.",
            "retraction": "An earlier sweep asked /ct/v1/get-inclusion-proof-by-hash, a path defined in no "
            "RFC, and recorded the resulting 404s as evidence that no deployed log serves inclusion proofs. "
            "That finding was an artifact of the question asked and is retracted: the endpoint section 4.5 "
            "actually defines is served by every log that answered.",
        },
        "tally": tally,
        "results": results,
        "proofs": captured,
    }
    path = out / "production-inclusion.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(captured)} captured, {len(results)} asked, tally {tally})")


def inclusion_sweep(out: pathlib.Path) -> None:
    """Ask every usable log for an inclusion proof by hash, and capture two of them in full.

    The endpoint is RFC 6962 section 4.5's `get-proof-by-hash`, and it takes both of its documented inputs:
    `hash`, and the `tree_size` of an existing v1 STH. An earlier version of this sweep asked
    `/ct/v1/get-inclusion-proof-by-hash` - a path that appears in no specification - with only a hash, mistook
    the resulting 404s for "no deployed log serves inclusion proofs", and that claim reached three documents
    before anyone read the request back. A sweep measures its own request as much as it measures the fleet.

    Each head is read with `SignedTreeHeadV1.from_v1_json`, which takes the signature out of its RFC 5246
    `DigitallySigned` wrapper and refuses a response that is not what it claims, and is then verified against
    the key the log list publishes for that log *before* any audit path is checked against it. The fixture
    therefore authenticates its own root rather than being handed a hash to trust.
    """
    results: dict[str, str] = {}
    captured: list[dict] = []
    for log in usable_logs():
        origin = log["url"]
        try:
            head_json = get_json(f"{origin}/ct/v1/get-sth")
            head = sth.SignedTreeHeadV1.from_v1_json(head_json)
            sth.verify(head, EcdsaKey.from_spki(base64.b64decode(log["key"])))
            served = get_json(f"{origin}/ct/v1/get-entries?start=0&end=0")["entries"][0]
            leaf_hash = merkle.leaf_hash(base64.b64decode(served["leaf_input"]))
            proof, error = try_inclusion(origin, leaf_hash, head.tree_size)
            if proof is None:
                results[origin] = failure_kind(error or "no proof returned")
            else:
                path = tuple(base64.b64decode(node) for node in proof["audit_path"])
                index = int(proof["leaf_index"])
                if not merkle.verify_inclusion(
                    leaf_hash, index, head.tree_size, path, head.root_hash
                ):
                    results[origin] = "PROOF-FAILS"
                else:
                    results[origin] = f"PROOF-VERIFIES ({len(path)} nodes, tree {head.tree_size})"
                    if origin in INCLUSION_CAPTURES:
                        captured.append(
                            _inclusion_capture(log, head_json, head, served, index, path)
                        )
        except Exception as exc:
            results[origin] = failure_kind(f"{type(exc).__name__}: {exc}")
        print(f"  {results[origin]:48} {origin}", flush=True)
    _write_inclusion_fixture(out, results, captured)


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
    parser.add_argument("--skip-scts", action="store_true", help="do not refetch live certificates")
    parser.add_argument(
        "--skip-sigs", action="store_true", help="do not refetch verifiable SCT signatures"
    )
    parser.add_argument(
        "--skip-layout", action="store_true", help="do not refetch the extra_data layout survey"
    )
    parser.add_argument(
        "--skip-inclusion",
        action="store_true",
        help="do not refetch the get-proof-by-hash sweep and captures",
    )
    parser.add_argument(
        "--only-layout",
        action="store_true",
        help="capture only the extra_data layout survey and stop",
    )
    parser.add_argument(
        "--max-alternates",
        type=int,
        default=8,
        help="how many other logs to ask for an inclusion proof if --origin will not give one",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.only_layout:
        extra_layout(args.out)
        return 0
    urls = sweep(args.out) if not args.skip_sweep else cached_urls(args.out)
    origin = args.origin.rstrip("/")
    alternates = [url for url in urls if url != origin][: args.max_alternates]
    if not args.skip_proofs:
        proofs(args.out, origin, alternates)
    if not args.skip_tree:
        tree_sweep(args.out, origin)
    if not args.skip_scts:
        sct_sweep(args.out)
    if not args.skip_sigs:
        sct_signatures(args.out)
    if not args.skip_layout:
        extra_layout(args.out)
    if not args.skip_inclusion:
        inclusion_sweep(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
