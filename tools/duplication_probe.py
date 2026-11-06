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

Two limits worth stating before reading a number off this tool. Logs are sampled **concurrently** (four at a
time), because sequential sampling made each busy log's tail land up to a minute after a quiet one's, emptied the
common interval for most pairs, and turned the matrix into blanks - an artifact of the tool's own pacing, not a
fact about the fleet. Concurrency is also what earns a `429`, and TrustAsia is the usual author, so refusals are
counted per log and printed rather than quietly retried into nothing. And the windows that do survive are seconds
wide: a shared entry between two logs is strong evidence of fan-out, an absent one is weak evidence of its
opposite, which is why every pair prints its sample sizes next to its ratio.
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
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
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
MAX_THROTTLE = (
    3  # refusals tolerated before the log is left alone; a hole we record, not one we hide
)


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
    head_body = fetch(f"{origin}/ct/v1/get-sth", stats, origin)
    if head_body is None:
        return [], 0, 1
    head = int(head_body["tree_size"])
    start = max(0, head - count)
    cap = 64
    leaves: list[Leaf] = []
    served_max = 0
    requests = 1
    while start + len(leaves) < head:
        want = min(cap, head - start - len(leaves))
        first = start + len(leaves)
        requests += 1
        body = fetch(
            f"{origin}/ct/v1/get-entries?start={first}&end={first + want - 1}", stats, origin
        )
        if body is None:
            break
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


def fetch(url: str, stats: Counter, origin: str) -> dict | None:
    """GET with the refusal policy in one place: a bounded number of retries, then leave the log alone.

    A log that keeps answering 429 has told us "not at this rate". Grinding against it is how a crawler gets an
    endpoint withdrawn for everyone, so the shortfall comes back as None and is counted - a hole that gets
    recorded, never a reported absence.
    """
    for _attempt in range(MAX_THROTTLE + 1):
        try:
            return get_json(url)
        except urllib.error.HTTPError as exc:
            stats["http_errors"] += 1
            if exc.code != 429:
                print(f"  {exc.code} from {origin}: giving up (recorded as a hole)")
                return None
            stats["throttled_429"] += 1
            if stats["throttled_429"] > MAX_THROTTLE:
                print(f"  {origin}: {stats['throttled_429']} refusals, leaving this log alone")
                return None
            pause = float(exc.headers.get("Retry-After") or 5.0)
            print(f"  429 from {origin}; sleeping {pause:.0f}s (recorded, not skipped)")
            time.sleep(min(pause, 30.0))
        except (
            Exception
        ) as exc:  # get_json already retried transport trouble; this is its exhaustion
            stats["transport_errors"] += 1
            print(f"  {type(exc).__name__} from {origin}: giving up (recorded as a hole)")
            return None
    return None


def _time_at(origin: str, index: int, stats: Counter) -> int | None:
    """The log's own submission timestamp at one tree index - a probe for the seek."""
    body = fetch(f"{origin}/ct/v1/get-entries?start={index}&end={index}", stats, origin)
    if body is None:
        return None
    entries = body.get("entries") or []
    if not entries:
        return None
    return MerkleTreeLeaf.parse(base64.b64decode(entries[0]["leaf_input"])).entry.timestamp


def head_stamp(origin: str, stats: Counter) -> tuple[int, int | None]:
    """This log's tree size and the timestamp of its newest leaf - the fleet's present, from the log.

    Never `time.time()`. The window has to be an instant the logs actually issued into, so the present is defined
    by their own signed timestamps and not by the clock of whichever machine happens to be asking; a host clock a
    few hours ahead aims every seek into the future and every window comes back empty for a reason that looks
    like an absence.
    """
    body = fetch(f"{origin}/ct/v1/get-sth", stats, origin)
    if body is None:
        return 0, None
    head = int(body["tree_size"])
    if head < 1:
        return head, None
    return head, _time_at(origin, head - 1, stats)


def window(
    origin: str, target_ms: int, width_ms: int, cap: int, stats: Counter
) -> tuple[list[Leaf], int, int]:
    """Entries this log added inside [target_ms, target_ms + width_ms], located by seeking, not by tailing.

    `get-entries` is indexed and never timed, so comparing two logs on the clock means finding the index of an
    instant by binary search over a monotone sequence - a log's timestamps are its own insertion times and do not
    go backwards. Tailing cannot do this at all: 512 entries span 2.7 s in one log and 1,055 s in another, which
    is why two earlier runs of this tool reported cross-operator pairs as blank and nearly called that a finding.
    """
    head_body = fetch(f"{origin}/ct/v1/get-sth", stats, origin)
    if head_body is None:
        return [], 0, 1
    head = int(head_body["tree_size"])
    requests = 1
    lo, hi = 0, max(0, head - 1)
    while lo < hi:
        mid = (lo + hi) // 2
        stamp = _time_at(origin, mid, stats)
        requests += 1
        if stamp is None:
            return [], 0, requests
        if stamp < target_ms:
            lo = mid + 1
        else:
            hi = mid
    leaves: list[Leaf] = []
    served_max = 0
    page = 64
    index = lo
    while index < head and len(leaves) < cap:
        want = min(page, cap - len(leaves), head - index)
        body = fetch(
            f"{origin}/ct/v1/get-entries?start={index}&end={index + want - 1}", stats, origin
        )
        requests += 1
        if body is None:
            break
        got = body.get("entries") or []
        if not got:
            break
        served_max = max(served_max, len(got))
        if len(got) < want:
            page = len(got) or 1
        for offset, item in enumerate(got):
            leaf = MerkleTreeLeaf.parse(base64.b64decode(item["leaf_input"]))
            stamp = leaf.entry.timestamp
            if stamp > target_ms + width_ms:
                return leaves, served_max, requests
            if stamp >= target_ms:
                key, kind, issuer = entry_key(leaf)
                leaves.append(Leaf(index + offset, stamp, key, kind, issuer))
        index += len(got)
        time.sleep(DELAY)
    return leaves, served_max, requests


def fleet_factor(samples: dict[str, list[Leaf]]) -> dict | None:
    """Leaves per distinct entry across the interval every sampled log covers - the DER tier's number.

    No single log can answer this, and it is what `HARVEST-PLAN.md` needs: how much of the fleet is the same
    certificate witnessed again. Computed only over the interval all of them cover, and printed with its n,
    because a factor from two seconds of issuance is a hint rather than a constant.
    """
    if len(samples) < 2:
        return None
    # A log with a handful of entries in the window would collapse the common interval to a single instant, so
    # the aggregate runs over the logs that actually have a sample and says which ones sat out.
    usable = {name: leaves for name, leaves in samples.items() if len(leaves) >= MIN_PAIR_SAMPLE}
    if len(usable) < 2:
        return None
    low = max(min(x.second for x in leaves) for leaves in usable.values())
    high = min(max(x.second for x in leaves) for leaves in usable.values())
    if high <= low:
        return None
    total = 0
    union: set[bytes] = set()
    per_log: dict[str, int] = {}
    for name, leaves in usable.items():
        inside = [x for x in leaves if low <= x.second <= high]
        per_log[name] = len(inside)
        total += len(inside)
        union |= {x.key for x in inside}
    return {
        "interval_seconds": round(high - low, 3),
        "logs": per_log,
        "excluded": sorted(set(samples) - set(usable)),
        "leaves": total,
        "distinct_entries": len(union),
        "factor": round(total / len(union), 4) if union else None,
    }


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
    parser.add_argument(
        "--entries", type=int, default=1200, help="tail size, or the cap in --window mode"
    )
    parser.add_argument("--logs", type=int, default=DEFAULT_LOGS, help="how many logs to compare")
    parser.add_argument(
        "--window",
        type=float,
        default=0.0,
        help="seconds of issuance to compare, seeked by timestamp; 0 tails each log instead",
    )
    parser.add_argument(
        "--lag",
        type=float,
        default=120.0,
        help="seconds before now to start the window (window mode)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="concurrent logs (four is one too many for TrustAsia)",
    )
    parser.add_argument("--json", type=pathlib.Path, default=None, help="also write this JSON")
    args = parser.parse_args()

    logs = select(args.logs)
    width = int(args.window * 1000)
    target = 0
    if args.window:
        # Where is "now" for the fleet? Ask the logs. Their signed timestamps are the only present that
        # matters here, and a host clock ahead of them aims every seek into the future - which returns empty
        # windows for every log and looks exactly like an absence.
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            heads = list(pool.map(lambda item: head_stamp(item["url"], Counter()), logs))
        probes = {
            log["description"]: stamp
            for log, (_head, stamp) in zip(logs, heads, strict=True)
            if stamp
        }
        if len(probes) < 2:
            print("cannot place a window: fewer than two logs answered with a head timestamp")
            return 1
        # Anchor on the median head, not the oldest. The first run of this mode anchored on the oldest head and
        # landed the window in September 2025 - over a year in the past - because one usable log's newest leaf is
        # 414 days old, and three of the eight sampled logs reported NO DATA for the simpler reason that they had
        # not been opened yet. The median keeps the window in the present for the logs that matter; a log whose
        # head precedes it reports NO DATA, which is the truth about that log rather than a hole in the window.
        ordered_stamps = sorted(probes.values())
        anchor = ordered_stamps[len(ordered_stamps) // 2]
        oldest, newest = ordered_stamps[0], ordered_stamps[-1]
        target = anchor - int(args.lag * 1000)
        moment = datetime.datetime.fromtimestamp(target / 1000, datetime.UTC)
        print(
            f"log heads span {(newest - oldest) / 1000:.0f}s oldest-to-newest "
            f"({(newest - anchor) / 1000:.0f}s to the median); this host clock is "
            f"{(int(time.time() * 1000) - newest) / 1000:+.0f}s from the newest"
        )
        print(
            f"window: {args.window:g}s from {moment.isoformat(timespec='seconds')} "
            f"(median head minus {args.lag:g}s)"
        )
    else:
        print("tailing each log: pairs overlap only by luck, which is what --window is for")
    print("sampling: " + ", ".join(f"{x['operator']}/{x['description']}" for x in logs))

    def sample_one(log: dict) -> tuple[dict, list[Leaf], int, int, Counter]:
        stats: Counter = Counter()
        if args.window:
            leaves, served, requests = window(log["url"], target, width, args.entries, stats)
        else:
            leaves, served, requests = tail(log["url"], args.entries, stats)
        return log, leaves, served, requests, stats

    # Concurrent on purpose. Sequential sampling made each busy log's tail land up to a minute after a quiet
    # one's, which emptied the common interval for most pairs and turned the matrix into blanks - an artifact of
    # this tool's own pacing, not a fact about the fleet.
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        fetched = list(pool.map(sample_one, logs))

    samples: dict[str, list[Leaf]] = {}
    rows: list[dict] = []
    for log, leaves, served, requests, stats in fetched:
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

    aggregate = fleet_factor(samples)
    if aggregate:
        print(
            f"\nfleet across the {aggregate['interval_seconds']}s every participating log covers:"
            f"\n  leaves={aggregate['leaves']} distinct entries={aggregate['distinct_entries']}"
            f" -> deduplication factor {aggregate['factor']}x"
        )
        print(f"  participating: {', '.join(f'{k} ({v})' for k, v in aggregate['logs'].items())}")
        if aggregate["excluded"]:
            print(f"  sat out (too few entries in the window): {', '.join(aggregate['excluded'])}")
    else:
        print("\nfleet factor: no interval is covered by two or more logs with a usable sample")

    payload = {
        "logs": rows,
        "pairs": pairs,
        "fleet": aggregate,
        "min_pair_sample": MIN_PAIR_SAMPLE,
    }
    if args.json:
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
