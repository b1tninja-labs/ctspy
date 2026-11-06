#!/usr/bin/env python3
"""How much of the fleet is the same certificate twice? The measurement that sizes the DER tier.

`certledger/HARVEST-PLAN.md` computes a 35.5 TB DER tier "before deduplication" and names this number as the one
input that decides what it really costs. Two duplication questions hide in that phrase, and they need different
comparisons:

* **Inside one log.** A static-merge log adds a leaf per *submission*, so one certificate can appear several times
  in one tree. Measurable within a single log's window, and it is the ratio that turns "leaves" into
  "certificates".
* **Across logs.** A submitter sends one certificate to several logs. The join key cannot be the leaf hash:
  RFC 6962 section 3.4 puts the log's own submission timestamp in the leaf, so the same certificate has a
  **different leaf hash in every log** - the very property `INCIDENT-CT-FORENSICS.md` rests on. The key has to be
  the entry's own bytes: the certificate for an `x509_entry`, the TBSCertificate for a `precert_entry`.

Precert and final certificate are deliberately not collapsed onto one key. They are different bytes, a log holding
both holds two things, and folding them would understate the DER tier while misreporting what was issued.

Comparing across logs needs the logs to describe the same minutes, and `get-entries` is indexed, not timed. So each
log contributes the tail of its tree, each comparison is restricted to that *pair's* common timestamp interval, and
a pair whose shared interval holds too few entries says so instead of printing a percentage.

Run: ``python tools/duplication_probe.py``. Networked, read-only, not a test gate - the standing of
`tools/fetch_evidence.py`. Requests are serialised and a refusal is counted and reported, because throttling that
becomes an unrecorded hole is how a crawler ends up reporting its gaps as absence.

Known limitation, stated because it produced a misleading line on the first run: logs are sampled **sequentially**,
so a busy log's tail is fetched up to a minute after a quiet one's, and the pair's common interval can come out
empty. Those pairs report `no common interval`, which is an artifact of this tool's own pacing and says nothing
about the logs. A proper cross-log survey fetches concurrently or seeks each log to one agreed timestamp.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
from collections import Counter, defaultdict
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from fetch_evidence import get_json, usable_logs

from ctspy import MerkleTreeLeaf
from ctspy.entry import PrecertEntry, X509Entry

DEFAULT_LOGS = 7
MIN_PAIR_SAMPLE = (
    150  # entries each side needs in the common interval before a ratio means anything
)
DELAY = 0.15
MAX_PROBE = 512  # largest page to ask for; operators are under no obligation to grant it


@dataclass(frozen=True, slots=True)
class Leaf:
    """One entry, reduced to what the two comparisons need."""

    index: int
    timestamp: int
    key: bytes
    kind: str
    issuer_key_hash: bytes | None

    @property
    def second(self) -> float:
        return self.timestamp / 1000.0


def entry_key(leaf: MerkleTreeLeaf) -> tuple[bytes, str, bytes | None]:
    """The deduplication identity of an entry, and why it is that rather than the leaf hash."""
    entry = leaf.entry.entry
    if isinstance(entry, X509Entry):
        return hashlib.sha256(entry.certificate).digest(), "x509", None
    if isinstance(entry, PrecertEntry):
        return hashlib.sha256(entry.tbs_certificate).digest(), "precert", entry.issuer_key_hash
    raise AssertionError("entry.py refuses any other LogEntryType")  # pragma: no cover


def tail(origin: str, count: int, stats: Counter) -> tuple[list[Leaf], int, int]:
    """The last `count` entries of a log's tree, oldest first, with the page cap observed not assumed.

    Returns the largest batch the log actually served and how many requests it took. The distinction is the
    whole lesson of `page_caps.py`: what this client *asked* for is not evidence about the operator, and the
    walk cost in `HARVEST-PLAN.md` is computed from the served figure.
    """
    head = int(get_json(f"{origin}/ct/v1/get-sth")["tree_size"])
    start = max(0, head - count)
    cap = 64
    leaves: list[Leaf] = []
    served_max = 0
    requests = 1
    while start + len(leaves) < head:
        want = min(cap, head - start - len(leaves))
        first = start + len(leaves)
        url = f"{origin}/ct/v1/get-entries?start={first}&end={first + want - 1}"
        try:
            body = get_json(url)
        except urllib.error.HTTPError as exc:
            stats["http_errors"] += 1
            if exc.code == 429:
                stats["throttled_429"] += 1
                pause = float(exc.headers.get("Retry-After") or 5.0)
                print(f"  429 from {origin}; sleeping {pause:.0f}s (recorded, not skipped)")
                time.sleep(min(pause, 30.0))
                requests += 1
                continue
            print(f"  {exc.code} from {origin}: giving up on this tail")
            break
        requests += 1
        got = body.get("entries") or []
        if not got:
            break
        served_max = max(served_max, len(got))
        if len(got) < want:
            cap = len(got)  # the operator's own page size, observed rather than assumed
        elif cap < MAX_PROBE:
            cap = MAX_PROBE  # it answered in full, so ask for more next time
        for offset, item in enumerate(got):
            leaf = MerkleTreeLeaf.parse(base64.b64decode(item["leaf_input"]))
            key, kind, issuer = entry_key(leaf)
            leaves.append(Leaf(first + offset, leaf.entry.timestamp, key, kind, issuer))
        time.sleep(DELAY)
    return leaves, served_max, requests


def select(how_many: int) -> list[dict]:
    """Which logs to compare. Operators with several logs come first.

    They are where one operator's fan-out is visible at all, and a sample drawn one-per-operator would be the
    least informative set available. Within an operator the log list's own order is used, so nothing here
    cherry-picks a log that looks friendly.
    """
    by_operator: dict[str, list[dict]] = defaultdict(list)
    for log in usable_logs():
        by_operator[log["operator"]].append(log)
    ordered = sorted(by_operator.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    picked: list[dict] = []
    for _operator, logs in ordered:
        picked.extend(logs[: 2 if len(logs) > 1 else 1])
        if len(picked) >= how_many:
            break
    return picked[:how_many]


def summarise(log: dict, leaves: list[Leaf], served: int, requests: int, stats: Counter) -> dict:
    """What one log's tail says about itself."""
    span = leaves[-1].second - leaves[0].second
    distinct = len({leaf.key for leaf in leaves})
    return {
        "operator": log["operator"],
        "description": log["description"],
        "origin": log["url"],
        "fetched": len(leaves),
        "page_served_max": served,
        "requests": requests,
        "interval_seconds": round(span, 3),
        "entries_per_second": round(len(leaves) / span, 2) if span > 0.5 else None,
        "distinct_entries": distinct,
        "duplicate_leaves": len(leaves) - distinct,
        "kinds": dict(Counter(leaf.kind for leaf in leaves)),
        "distinct_issuer_keys": len(
            {leaf.issuer_key_hash for leaf in leaves if leaf.issuer_key_hash}
        ),
        "throttled_429": stats["throttled_429"],
        "http_errors": stats["http_errors"],
    }


@dataclass
class Pairing:
    """Overlap of two logs, restricted to the interval both of them actually cover."""

    left_log: str
    right_log: str
    interval: tuple[float, float]
    left: int = 0
    right: int = 0
    shared: int = 0
    kinds: dict[str, int] = field(default_factory=dict)
    verdict: str = ""


def pair(left_name: str, left: list[Leaf], right_name: str, right: list[Leaf]) -> Pairing:
    """Compare two tails over their common interval, and refuse to quantify a thin sample."""
    low = max(left[0].second, right[0].second)
    high = min(left[-1].second, right[-1].second)
    result = Pairing(left_name, right_name, (round(low, 3), round(high, 3)))
    if high <= low:
        result.verdict = "no common interval"
        return result
    left_slice = [x for x in left if low <= x.second <= high]
    right_slice = [x for x in right if low <= x.second <= high]
    right_keys = {x.key for x in right_slice}
    hits = [x for x in left_slice if x.key in right_keys]
    result.left, result.right = len(left_slice), len(right_slice)
    result.shared = len({x.key for x in hits})
    result.kinds = dict(Counter(x.kind for x in hits))
    if min(result.left, result.right) < MIN_PAIR_SAMPLE:
        result.verdict = "sample too small"
    elif result.shared == 0:
        result.verdict = "zero overlap in this window"
    else:
        result.verdict = "overlap"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure CT fleet duplication")
    parser.add_argument("--entries", type=int, default=1200, help="tail size per log")
    parser.add_argument("--logs", type=int, default=DEFAULT_LOGS, help="how many logs to compare")
    parser.add_argument("--json", type=pathlib.Path, default=None, help="also write this JSON")
    args = parser.parse_args()

    logs = select(args.logs)
    print("sampling: " + ", ".join(f"{x['operator']}/{x['description']}" for x in logs))
    samples: dict[str, list[Leaf]] = {}
    rows: list[dict] = []
    for log in logs:
        stats: Counter = Counter()
        leaves, served, requests = tail(log["url"], args.entries, stats)
        if not leaves:
            print(f"  NO DATA  {log['operator']}: {log['description']}")
            continue
        samples[log["description"]] = leaves
        row = summarise(log, leaves, served, requests, stats)
        rows.append(row)
        print(
            f"  {row['operator']:<18} {row['description'][:30]:<32} "
            f"leaves={row['fetched']:<5} served={row['page_served_max']:<4} req={row['requests']:<4} "
            f"span={row['interval_seconds']:<9}s distinct={row['distinct_entries']:<5} "
            f"dup={row['duplicate_leaves']:<4} rate={row['entries_per_second']}"
        )

    if len(rows) < 2:
        print("need at least two logs with data")
        return 1

    print("\nintra-log: unique entries per leaf (1.0 means the tree holds no repeats)")
    for row in rows:
        print(
            f"  {row['description'][:42]:<44} {row['distinct_entries'] / row['fetched']:.4f}"
            f"  kinds={row['kinds']} issuer_keys={row['distinct_issuer_keys']}"
        )

    print("\npairwise: overlap over each pair's own common interval")
    names = list(samples)
    pairs = []
    for index, left_name in enumerate(names):
        for right_name in names[index + 1 :]:
            result = pair(left_name, samples[left_name], right_name, samples[right_name])
            pairs.append(result.__dict__)
            share = (
                f"{result.shared / max(1, result.left):6.2%} of left ({result.shared})"
                if result.verdict == "overlap"
                else f"{result.shared:>3} shared"
            )
            print(
                f"  {left_name[:24]:<26} x {right_name[:24]:<26} "
                f"{result.left:>5}/{result.right:>5} {share:<26} [{result.verdict}]"
            )

    payload = {"logs": rows, "pairs": pairs, "min_pair_sample": MIN_PAIR_SAMPLE}
    if args.json:
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
