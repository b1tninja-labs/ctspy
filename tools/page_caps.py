#!/usr/bin/env python3
"""Every usable log's real `get-entries` page size, measured instead of remembered.

`certledger/HARVEST-PLAN.md` sizes the whole walk on 537M requests, and 462M of those belong to two operators
answerin 32 entries at a time. That figure came from five observations, one per operator, and the plan says so:
"the page-size survey done properly - several observations per log rather than one per operator". This is that
survey. It matters because the request count is the part of the cost that is not negotiable - bandwidth is
cheap, and a rate limit a log is willing to hand out is not.

Method, and why it is a measurement rather than a guess: each log is asked, in ascending steps, for 16, 64, 256,
1024 and 4096 entries from the same offset near the head of its tree. The **served** count per step is recorded,
not the requested count - the difference is the whole point, since a log is free to answer less than it was
asked (RFC 6962 section 4.3). The plateau is that log's effective cap, and a log whose served count keeps rising
with the request has no cap in this range, which is a different answer and is recorded as one.

Costs: two requests per log at most are used for the walk estimate, and the sweep is under a hundred requests in
total. Run: ``python tools/page_caps.py``. Networked, read-only, not a test gate.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fetch_evidence import USER_AGENT, get_json, usable_logs

STEPS = (16, 64, 256, 1024)  # never ask a public log for more: 1024 entries is ~1.5 MB per response


def get_raw(url: str, *, timeout: float) -> bytes:
    """GET and hand back the response bytes, because size is the quantity being measured here."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def probe(log: dict, *, timeout: float = 60.0) -> dict:
    """Ask one log for rising page sizes from a fixed offset and record what actually came back.

    Both the entry count and the response size are recorded, because the first run of this tool showed why: a
    log asked for 64 entries returned 8, and another returned 1. The limit being enforced is on **bytes**, and
    `extra_data` carries the chain, so entries-per-response depends on how long those chains are. Dividing
    tree_size by an entries-per-response figure taken at some other entry size is how a request estimate ends
    up wrong by an order of magnitude.
    """
    origin = log["url"]
    record = {**log, "served": {}, "bytes": {}, "head": None, "errors": 0, "note": ""}
    try:
        head = int(get_json(f"{origin}/ct/v1/get-sth", timeout=timeout)["tree_size"])
    except Exception as exc:
        record["note"] = f"get-sth failed: {type(exc).__name__}"
        return record
    record["head"] = head
    anchor = max(0, head - 1024)
    for want in STEPS:
        if anchor + want > head:
            break  # a tree too small to serve this step is not evidence about the cap
        url = f"{origin}/ct/v1/get-entries?start={anchor}&end={anchor + want - 1}"
        try:
            raw = get_raw(url, timeout=timeout)
        except urllib.error.HTTPError as exc:
            record["errors"] += 1
            record["served"][str(want)] = f"HTTP {exc.code}"
            continue
        except Exception as exc:
            record["errors"] += 1
            record["served"][str(want)] = type(exc).__name__
            continue
        entries = json.loads(raw).get("entries") or []
        record["served"][str(want)] = len(entries)
        record["bytes"][str(want)] = len(raw)
    # What a walk experiences is the served count at the largest step it would ask for, not the best answer seen
    # across steps - the best one came from asking for less than the server's byte budget allowed.
    steps = {int(k): v for k, v in record["served"].items() if isinstance(v, int)}
    top = max(steps) if steps else 0
    record["sustained"] = steps.get(top)
    sizes = [v for v in record["bytes"].values() if isinstance(v, int)]
    record["byte_cap"] = max(sizes) if sizes else None
    served_at_top = steps.get(1024, steps.get(top))
    record["bytes_per_entry"] = (
        round(record["bytes"][str(1024)] / served_at_top)
        if record["bytes"].get("1024") and served_at_top
        else None
    )
    record["ceiling_found"] = bool(top and steps[top] < top)
    time.sleep(0.1)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure every CT log's get-entries page size")
    parser.add_argument("--json", type=pathlib.Path, default=None)
    parser.add_argument(
        "--workers", type=int, default=4, help="concurrent logs (per-log steps stay serial)"
    )
    args = parser.parse_args()

    logs = usable_logs()
    print(f"{len(logs)} usable or read-only logs; steps {STEPS}")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        records = list(pool.map(probe, logs))

    print(
        f"{'operator':<22} {'description':<30} {'tree':>12}  served per request  B/entry  walk (M req)"
    )
    ordered = sorted(records, key=lambda r: (r.get("sustained") or 0, r["description"]))
    total = 0.0
    for record in ordered:
        served = " ".join(
            str(record["served"][str(step)]) for step in sorted(record["served"], key=int)
        )
        sustained = record.get("sustained") or 0
        cost = (record["head"] / sustained / 1e6) if sustained and record["head"] else 0.0
        total += cost
        print(
            f"{record['operator'][:21]:<22} {record['description'][:29]:<30} "
            f"{record['head'] or 0:>12}  {served:<19} {record.get('bytes_per_entry') or '-':>7}  "
            f"{cost:>8.1f} {record['note']}"
        )

    answering = [r for r in records if r.get("sustained") and r["head"]]
    print(f"\nlogs answering: {len(answering)} of {len(records)}")
    print(
        f"walk cost at each log's own sustained page: {total / 1e3:.2f}B requests "
        f"(sustained = entries served when asked for 1024)"
    )
    bytes_total = sum(
        r["head"] * (r.get("bytes_per_entry") or 0) for r in answering if r.get("bytes_per_entry")
    )
    print(f"that walk would move {bytes_total / 1e12:.1f} TB of JSON responses")
    if args.json:
        args.json.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
