"""Measure the static-CT (tiled) tier: checkpoint, data tiles, bytes per entry.

Why. `certledger/HARVEST-PLAN.md` §4 sizes the harvest from RFC 6962 `get-entries` alone, because
that was the only read path ever measured here. Chrome's list now carries a second array of
static-API logs (`c2sp.org/static-ct-api`) whose read path is a tree of files: a `checkpoint`, then
`tile/data/<N>` holding the entries. Those logs hold leaves no `get-entries` call can reach, and
they may hold them more compactly, so both the size of the harvest and the size of the DER tier
depend on a number nobody had taken. This takes it.

What the numbers are, and are not:

- `bytes_per_entry` is exact for the tile fetched. The request says `Accept-Encoding: identity`,
  so what arrives is what the log stores, with no transformation we then divide by.
- the compression ratio is ours. It is labelled `our_gzip9_ratio` because it is what our compressor
  does to those exact bytes, not what a CDN will do to them; it is evidence that a ratio is
  achievable, never the ratio a mirror will get.
- the checkpoint is parsed, **not verified**. A checkpoint's provenance signature covers a
  structured serialization `ctspy` does not implement yet, and no static-API log key is pinned
  anywhere in this repository. Every artifact says `checkpoint_verified: false`. Entries measured
  from a tile nobody checked are a sizing input, not an attestation.
- entries per tile is measured from tile 0 rather than assumed. The constant lives in an
  implementation, not in the text of the spec, and a wrong guess indexes the wrong tile and
  mis-dates the whole sample.

What it deliberately does not do: join a tile against an RFC 6962 log at the same instant. That
needs the window-seek machinery, which is not in the tree (see the note in CHANGELOG), so the
cross-protocol duplication factor remains unmeasured. The tile's timestamp span is reported so a
later join can be anchored to it.

Usage:
    python tools/tile_probe.py --index 71
    python tools/tile_probe.py --slug 'Tiled: Let's Encrypt Willow2026h2' --out tile.json
"""

from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import json
import pathlib
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ctspy.entry import PrecertEntry, TimestampedEntry, X509Entry
from ctspy.transcript import Reader

DEFAULT_LIST = (
    pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "loglist" / "log_list.json"
)
USER_AGENT = "ctspy-tile-probe/0.1 (static-CT measurement; read-only GET)"
MAX_TILE = (
    64 * 1024 * 1024
)  # a full tile is ~8k entries; refusing to hold one would hide the number
TILE_LEAF_KIND = 0x08  # TranscriptItem kind for a TileLeaf, confirmed from the first byte pair


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def _iso(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.UTC).isoformat(timespec="seconds")


HOST_SUBSTITUTIONS: set[str] = set()  # URLs only reachable through the other Google host form


def _expand(url: str) -> list[str]:
    """Every host form a Google-hosted monitoring prefix can be reached by, most-likely first.

    Observed against production: `tile/data/1000` is 404 through the `monitoring_url` Chrome
    publishes for ParcelYard2026h2 (`https://storage.googleapis.com/<bucket>`) and 200 through the
    bucket's own load-balancer hostname (`https://<bucket>`). Without the retry, a whole log reads
    as though it refuses to serve its tiles, which is false; with it, the substitution is recorded
    so a plan can see that the published prefix is not the only way in.
    """
    prefix = "https://storage.googleapis.com/"
    if url.startswith(prefix):
        rest = url[len(prefix) :]
        return [url, f"https://{rest}"]
    return [url]


def get(url: str) -> tuple[bytes, str | None]:
    """GET with `Accept-Encoding: identity`, so the bytes we divide by are the bytes stored."""
    last = "no candidate"
    for candidate in _expand(url):
        request = urllib.request.Request(  # noqa: S310
            candidate, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=60.0, context=ssl.create_default_context()
            ) as response:
                raw = response.read(MAX_TILE + 1)
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            continue
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {str(exc)[:120]}"
            continue
        if candidate != url:
            HOST_SUBSTITUTIONS.add(candidate)
        if len(raw) > MAX_TILE:
            return raw, f"more than {MAX_TILE} octets"
        return raw, None
    return b"", last


def parse_checkpoint(raw: bytes) -> dict[str, Any]:
    """Read a checkpoint: origin, decimal tree size, base64 root hash, then provenance lines.

    The bytes are reported hashed, never re-serialised: the bytes are what a signature covers, and
    rebuilding them from parsed fields would destroy exactly what a later verifier needs.
    """
    lines = raw.decode("utf-8", "replace").split("\n")
    out: dict[str, Any] = {"bytes": len(raw), "verified": False}
    if len(lines) < 3:
        return {**out, "error": f"checkpoint has {len(lines)} lines"}
    out["origin"] = lines[0].strip()
    try:
        out["tree_size"] = int(lines[1].strip())
        out["tree_head_hash"] = base64.b64decode(lines[2].strip()).hex()
    except (ValueError, Exception) as exc:
        return {**out, "error": f"unparsable checkpoint ({type(exc).__name__}: {str(exc)[:80]})"}
    out["sha256"] = hashlib.sha256(raw).hexdigest()
    out["signatures"] = sum(1 for line in lines[3:] if line.startswith("—"))
    return out


def tile_entry_key(ts_entry: TimestampedEntry) -> tuple[bytes, str]:
    """The deduplication identity of a tile entry, mirroring `duplication_probe.entry_key`.

    Not an import: that function takes a `MerkleTreeLeaf`, and a tile carries a bare
    `TimestampedEntry`. The *rule* is what has to agree — leaf-certificate hash for an x509 entry,
    TBSCertificate hash for a precert — because two tools that key differently cannot be joined,
    and the mismatch would show up as a duplication rate of zero.
    """
    entry = ts_entry.entry
    if isinstance(entry, X509Entry):
        return hashlib.sha256(entry.certificate).digest(), "x509"
    return hashlib.sha256(entry.tbs_certificate).digest(), "precert"


def iter_tile_leaves(data: bytes, notes: list[str]) -> list[dict[str, Any]]:
    """Parse a data tile as a bare sequence of TileLeaf structures, stopping at the first doubt.

    TileLeaf is a `TimestampedEntry`, then the submitted Precertificate *only* when the entry is a
    precert, then a vector of 32-byte issuer fingerprints. There is no TranscriptItem framing and no
    per-entry length: the first byte of a real tile is 0x00, the high byte of a uint64 timestamp,
    where `0x06 0x08` would have been. Entries follow one another and the entry type inside
    `TimestampedEntry` is what decides which shape comes next. Parsing stops rather than
    resynchronises, because a tile whose third entry will not parse is a finding about our reading
    of the format, and guessing past it would silently truncate the sample.
    """
    entries: list[dict[str, Any]] = []
    total = len(data)
    pos = 0
    while pos < total:
        reader = Reader(data[pos:], what="data tile")
        try:
            ts_entry = TimestampedEntry.parse(reader)
            pre_certificate = (
                reader.opaque(length_bytes=3, minimum=1, maximum=16777215)
                if isinstance(ts_entry.entry, PrecertEntry)
                else b""
            )
            chain = reader.opaque(length_bytes=2, minimum=0, maximum=65535)
            consumed = total - pos - reader.remaining()
        except Exception as exc:
            notes.append(
                f"entry {len(entries)} at offset {pos} failed to parse "
                f"({type(exc).__name__}: {str(exc)[:120]}); stopped"
            )
            break
        if len(chain) % 32:
            notes.append(
                f"entry {len(entries)} has a {len(chain)}-byte chain, not a whole number of "
                "32-byte fingerprints; stopped"
            )
            break
        pos += consumed
        key, entry_kind = tile_entry_key(ts_entry)
        entries.append(
            {
                "index": len(entries),
                "timestamp": ts_entry.timestamp,
                "timestamp_iso": _iso(ts_entry.timestamp),
                "kind": entry_kind,
                "entry_key": key.hex(),
                "pre_certificate_bytes": len(pre_certificate),
                "issuer_fingerprints": [chain[i : i + 32].hex() for i in range(0, len(chain), 32)],
                "encoded_bytes": consumed,
            }
        )
    return entries


def tiled_logs(list_path: pathlib.Path) -> list[dict[str, Any]]:
    """Tiled logs in the local snapshot, with state and reachability, in list order.

    Read here rather than through `fetch_evidence.list_logs`, which walks only the `logs` array
    and so knows nothing about this tier.
    """
    document = json.loads(list_path.read_text(encoding="utf-8"))
    out: list[dict[str, Any]] = []
    operators = document.get("operators")
    sources = (
        [entry.get("tiled_logs", []) for entry in operators if isinstance(entry, dict)]
        if isinstance(operators, list)
        else [document.get("tiled_logs", [])]
    )
    for group in sources:
        for entry in group or []:
            if not isinstance(entry, dict):
                continue
            monitoring = str(entry.get("monitoring_url") or "")
            # In the schema `state` is a one-key object (`{"usable": {...}}`): the key is the
            # state, the value its evidence. Reading it as a string prints a dict as a state.
            declared = entry.get("state")
            if entry.get("final_sth"):
                name = "pending"
            elif isinstance(declared, dict):
                name = next(iter(declared), "usable")
            else:
                name = str(declared or "usable")
            out.append(
                {
                    "index": len(out),
                    "slug": f"Tiled: {entry.get('description', '?')}",
                    "id": str(entry.get("id", "")),
                    "state": name,
                    "monitoring_url": monitoring.rstrip("/"),
                    "usable": bool(monitoring)
                    and not any(entry.get(k) for k in ("rejected", "final_sth")),
                }
            )
    return out


def measure(client_url: str, index: int, notes: list[str]) -> dict[str, Any] | None:
    """Fetch one data tile and reduce it to the numbers the harvest plan needs."""
    raw, err = get(f"{client_url}/tile/data/{index}")
    if err:
        notes.append(f"tile/data/{index}: {err}")
        return None
    entries = iter_tile_leaves(raw, notes)
    if not entries:
        return None
    compressed = len(gzip.compress(raw, 9))
    kinds: dict[str, int] = {}
    for entry in entries:
        kinds[entry["kind"]] = kinds.get(entry["kind"], 0) + 1
    return {
        "index": index,
        "octets": len(raw),
        "entries": len(entries),
        "bytes_per_entry": round(len(raw) / len(entries), 3),
        "our_gzip9_octets": compressed,
        "our_gzip9_ratio": round(len(raw) / compressed, 3),
        "kinds": kinds,
        "distinct_keys": len({e["entry_key"] for e in entries}),
        "first_timestamp_iso": entries[0]["timestamp_iso"],
        "last_timestamp_iso": entries[-1]["timestamp_iso"],
        "window_ms": [entries[0]["timestamp"], entries[-1]["timestamp"]],
        "issuer_fingerprints": sum(len(e["issuer_fingerprints"]) for e in entries),
        "sample_entry": entries[0],
    }


def tile_status(client_url: str, index: int) -> str:
    """Does this data tile exist? Asked with a one-byte Range so the answer costs nothing.

    Existence is probed rather than assumed because the answer is itself a finding: a log that
    returns 404 for its own oldest tile cannot be replayed from the beginning by anyone.
    """
    last = "no candidate"
    for candidate in _expand(f"{client_url}/tile/data/{index}"):
        request = urllib.request.Request(  # noqa: S310
            candidate,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity", "Range": "bytes=0-0"},
        )
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=30.0, context=ssl.create_default_context()
            ) as response:
                if response.status in (200, 206):
                    if candidate != f"{client_url}/tile/data/{index}":
                        HOST_SUBSTITUTIONS.add(candidate)
                    return "present"
                return f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                last = "absent"
                continue
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {str(exc)[:80]}"
    return last


def derive_entries_per_tile(
    client_url: str, tree_size: int, notes: list[str]
) -> dict[str, Any] | None:
    """Solve for the entries-per-tile constant from the tail of the tree, with no assumed number.

    The spec leaves the tile width to the implementation, and tile 0 is not always served, so the
    constant comes from arithmetic instead. Let `T` be the highest tile index the log serves and
    `C` the entries in it. That tile is the last one, so `T * E + C == tree_size`, hence
    `E = (tree_size - C) / T` exactly. Requiring the division to be exact and `E >= C` is what
    makes this a derivation and not a guess: a wrong `T` (an interior tile, which is full) leaves a
    remainder, and the function then refuses instead of reporting a plausible constant.
    """
    top = max(1, tree_size // 256)
    status = tile_status(client_url, top)
    while status == "present" and top < tree_size:
        top *= 4
        status = tile_status(client_url, top)
    if status not in ("absent", "present"):
        notes.append(f"tile probe at {top} returned {status}; cannot bound the search")
        return None
    high = top if status == "absent" else top - 1
    if tile_status(client_url, 0) == "absent":
        notes.append(
            "tile/data/0 is absent: presence is not prefix-monotone, so the highest tile found is "
            "the tree's end only if the gap is confined to the low end. The previous-tile check "
            "below is what this derivation is actually resting on."
        )
    best = -1
    lo, hi = 0, high
    while lo <= hi:
        mid = (lo + hi) // 2
        if tile_status(client_url, mid) == "present":
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if best < 1:
        notes.append(f"highest served tile is {best}; nothing to derive from")
        return None
    tail = measure(client_url, best, notes)
    if tail is None:
        return None
    count = tail["entries"]
    remainder = (tree_size - count) % best
    derived = (tree_size - count) // best
    out: dict[str, Any] = {
        "highest_tile": best,
        "tail_entries": count,
        "tail_full": remainder == 0 and derived == count,
        "derived_entries_per_tile": None,
        "arithmetic": f"({tree_size} - {count}) / {best} = {derived} remainder {remainder}",
        "tail": tail,
    }
    if remainder != 0 or derived < count or (tree_size - 1) // derived != best:
        notes.append(
            f"tile {best} holds {count} entries, and ({tree_size} - {count}) / {best} = {derived} "
            f"remainder {remainder} does not put tile {best} at the end of the tree: the "
            "derivation is inconsistent, so no constant is claimed"
        )
        return out
    previous = measure(client_url, best - 1, notes)
    out["previous_tile"] = previous
    if previous is None or previous["entries"] != derived:
        notes.append(
            f"tile {best - 1} holds {None if previous is None else previous['entries']} entries, "
            f"not the {derived} a full tile must hold: the constant is falsified by the tile "
            f"before the last one, and only the tail measurement is claimed"
        )
        return out
    out["derived_entries_per_tile"] = derived
    out["confirmed_by_previous_tile"] = True
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--list", type=pathlib.Path, default=DEFAULT_LIST, help="local log list snapshot"
    )
    parser.add_argument("--index", type=int, default=None, help="index into the tiled_logs array")
    parser.add_argument("--slug", default=None, help="match a substring of the description instead")
    parser.add_argument(
        "--tile", type=int, default=None, help="fetch this tile index and nothing else"
    )
    parser.add_argument("--out", type=pathlib.Path, default=None, help="write the report here")
    args = parser.parse_args()

    logs = tiled_logs(args.list)
    if args.index is None and args.slug is None:
        print(f"{sum(1 for log in logs if log['usable'])} of {len(logs)} tiled logs are reachable")
        for log in logs:
            if log["usable"]:
                print(f"  {log['index']:>3}  {log['state']:<9}  {log['slug']}")
        print("pick one with --index or --slug")
        return 2
    if args.index is not None:
        chosen = next((log for log in logs if log["index"] == args.index), None)
        if chosen is None:
            print(f"--index must be 0..{len(logs) - 1}")
            return 2
    else:
        hits = [log for log in logs if args.slug and args.slug.lower() in log["slug"].lower()]
        if not hits:
            print(f"no tiled log matches {args.slug!r}")
            return 2
        if len(hits) > 1:
            print(f"{args.slug!r} matches {len(hits)} logs; be more specific")
            return 2
        chosen = hits[0]
    if not chosen["usable"]:
        print(f"refusing: {chosen['slug']} is {chosen['state']}")
        return 2

    notes: list[str] = []
    monitoring = chosen["monitoring_url"]
    raw, err = get(f"{monitoring}/checkpoint")
    if err:
        print(f"checkpoint fetch failed: {err}")
        return 1
    checkpoint = parse_checkpoint(raw)
    print(f"{chosen['slug']}  {monitoring}\n  {checkpoint}")
    if "tree_size" not in checkpoint:
        return 1

    tile0 = tile_status(monitoring, 0)
    print(f"  tile/data/0: {tile0}")
    derived: dict[str, Any] | None = None
    if args.tile is not None:
        recent = measure(monitoring, args.tile, notes)
    else:
        derived = derive_entries_per_tile(monitoring, checkpoint["tree_size"], notes)
        recent = None if derived is None else (derived.get("tail") or derived.get("previous_tile"))
    if recent is None:
        print("no data tile parsed; nothing downstream is claimed")
        for note in notes:
            print(f"  note: {note}")
        return 1
    full = None if derived is None else derived.get("previous_tile")
    if full is not None:
        print(
            f"  tile {full['index']}, a full tile of {derived['derived_entries_per_tile']} entries: "
            f"{full['octets']} octets = {full['bytes_per_entry']} bytes per entry; our gzip-9 "
            f"{full['our_gzip9_ratio']}x"
        )
    print(
        f"  tile {recent['index']}: {recent['octets']} octets / {recent['entries']} entries = "
        f"{recent['bytes_per_entry']} bytes per entry; our gzip-9 {recent['our_gzip9_ratio']}x"
    )
    print(
        f"  window {recent['first_timestamp_iso']} .. {recent['last_timestamp_iso']}; kinds "
        f"{recent['kinds']}; {recent['distinct_keys']} distinct keys of {recent['entries']}; "
        f"{recent['issuer_fingerprints']} issuer fingerprints"
    )
    if full is None:
        notes.append(
            "no full tile was confirmed, so the bytes-per-entry figure above describes one tile of "
            f"{recent['entries']} entries and is not yet a per-entry cost for the log"
        )
    for note in notes:
        print(f"  note: {note}")

    report = {
        "tool": "tile_probe",
        "retrieved_at": _now(),
        "log": chosen,
        "checkpoint": checkpoint,
        "tile_0_status": tile0,
        "derivation": derived,
        "tile_measured": recent,
        "checkpoint_verified": False,
        "notes": notes,
    }
    if args.out:
        args.out.write_bytes(json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
