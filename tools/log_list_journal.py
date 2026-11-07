#!/usr/bin/env python3
"""Journal Chrome's signed CT log lists, so that coverage claims stay checkable after the fact.

`certledger/HARVEST-PLAN.md` sequencing step 1 says today's log-list membership is tomorrow's history: v96.2
carries 26 logs in `log_list.json` and 45 in `all_logs_list.json`, including 19 that the enforcement list omits
while their trees still serve 13.6 billion leaves (`BROWSER-POLICY.md` §2). Lists change daily, are offered
"without SLA or availability guarantee", and may change *"unannounced"*; a claim of the form "there are N logs" is
worthless unless the document behind it was kept. Four documents and a key are a few hundred kilobytes a day.

The signature is what makes a kept copy more than a cached page. `ctspy/loglist.py` verifies Chrome's
RSASSA-PKCS1-v1_5/SHA-256 signature over the exact bytes, so a snapshot can be re-checked years later without
trusting the transport, the operator, or this tool. Three properties the code has to keep, each true as measured
on 2026-11-06 and each easy to break by accident:

* **Bytes are signed verbatim.** The trailing newline is inside the signature, so every write here is binary. A
  text-mode write on Windows re-translates newlines and silently makes a snapshot unverifiable forever.
* **A snapshot is never rewritten.** Each run writes a fresh date-stamped directory and refuses to clobber one,
  because a journal whose oldest entry is also its most editable is a cache.
* **A key fetched beside the data proves consistency, not authenticity.** `--expect-key-sha256` pins the
  fingerprint out of band; without it the manifest records `pinned: false` rather than implying more than it has.

Run: ``python tools/log_list_journal.py --dir ~/journal`` to snapshot, ``--dir ... --verify`` to re-check
everything already stored, with no network. Read-only against gstatic; the standing of `fetch_evidence.py`.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from ctspy.loglist import fingerprint, public_key_from_pem, verify_pkcs1_sha256

BASE = "https://www.gstatic.com/ct/log_list/v3"
USER_AGENT = "ctspy-journal/0.1 (log-list monitoring; read-only GET)"
DOCUMENTS = ("log_list.json", "log_list.sig", "all_logs_list.json", "all_logs_list.sig")
KEY = "log_list_pubkey.pem"
RETRIES = 3


def get_bytes(url: str) -> bytes:
    """GET raw bytes, retrying transport trouble but never rewriting what came back."""
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            request = urllib.request.Request(  # noqa: S310
                url, headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                return response.read()
        except urllib.error.HTTPError:
            raise  # a 404 on a published list is news, not a blip
        except Exception as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{url} unreachable after {RETRIES} attempts: {last}")


def summary_of(body: bytes) -> dict:
    """What the document claims, recorded beside the bytes so the claim can be re-read without parsing again."""
    document = json.loads(body)
    counts: dict[str, int] = {}
    operators = 0
    for operator in document.get("operators", []):
        operators += 1
        for log in operator.get("logs", []):
            declared = log.get("state") or {}
            state = (
                next(iter(declared), "none") if isinstance(declared, dict) else (declared or "none")
            )
            if log.get("log_type") == "test":
                state = f"{state}/test"
            counts[state] = counts.get(state, 0) + 1
    return {
        "version": document.get("version"),
        "log_list_timestamp": document.get("log_list_timestamp"),
        "operators": operators,
        "logs": sum(counts.values()),
        "states": dict(sorted(counts.items())),
    }


def snapshot(directory: pathlib.Path, expected_key: str | None, force: bool) -> int:
    """Fetch today's four documents plus the key, verify them, and write one immutable journal entry."""
    moment = datetime.datetime.now(datetime.UTC)
    target = directory / moment.strftime("%Y%m%d")
    if target.exists() and not force:
        print(
            f"{target} already holds a snapshot. A journal entry is not rewritten; "
            f"use --force only if you mean to keep a second copy of the same day."
        )
        return 1
    target.mkdir(parents=True, exist_ok=True)

    pem = get_bytes(f"{BASE}/{KEY}")
    key_sha = fingerprint(pem.decode("ascii"))
    modulus, exponent = public_key_from_pem(pem.decode("ascii"))
    (target / KEY).write_bytes(pem)
    matches = key_sha == expected_key if expected_key else None
    print(
        f"key {key_sha[:16]}...  pinned={'yes' if expected_key else 'no'}"
        f"{'' if matches is None else f'  matches_pin={matches}'}"
    )
    if expected_key and not matches:
        print(
            "  the key served today is not the pinned key, so nothing below is verifiable until that is"
        )
        print(
            "  resolved - either Chrome rotated it or something between here and gstatic is editing responses."
        )

    manifest: dict = {
        "fetched_at": moment.isoformat(timespec="seconds"),
        "base": BASE,
        "key": {
            "file": KEY,
            "octets": len(pem),
            "fingerprint_der": key_sha,
            "pinned": bool(expected_key),
            "matches_pin": matches,
        },
        "documents": {},
    }
    failed = 0
    # Fetched before anything is checked: a document and its signature are only meaningful as the pair that was
    # served together, and verifying as-you-go would compare today's list against a signature that failed to
    # arrive if the second fetch happened to fail.
    fetched: dict[str, bytes] = {}
    for name in DOCUMENTS:
        body = get_bytes(f"{BASE}/{name}")
        (target / name).write_bytes(
            body
        )  # binary on purpose: the signature covers these exact octets
        fetched[name] = body

    for name in DOCUMENTS:
        body = fetched[name]
        entry: dict = {"octets": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        if name.endswith(".json"):
            signature = fetched[name.replace(".json", ".sig")]
            entry["verified"] = verify_pkcs1_sha256(body, signature, modulus, exponent)
            entry.update(summary_of(body))
            if entry["verified"]:
                print(
                    f"  verified {name}: {entry['octets']} octets, v{entry['version']}, "
                    f"{entry['logs']} logs, {entry['states']}"
                )
            else:
                failed += 1
                print(
                    f"  SIGNATURE FAILED {name}: the document and the signature served with it do not agree"
                )
        manifest["documents"][name] = entry
    (target / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    total = len(pem) + sum(entry["octets"] for entry in manifest["documents"].values())
    print(f"wrote {target}  ({total} octets, {len(manifest['documents'])} documents)")
    return 1 if failed else 0


def verify_tree(directory: pathlib.Path, expected_key: str | None) -> int:
    """Re-check every stored snapshot with no network at all - the reason the signatures were kept.

    Each entry is checked twice: the bytes against the digest recorded when they were fetched, and the document
    against the signature using the key stored inside that same entry. The first catches a corrupted or edited
    snapshot; the second catches a document that never matched its signature. Neither catches a substituted key,
    which is what `--expect-key-sha256` exists for.
    """
    entries = sorted(path for path in directory.iterdir() if (path / "manifest.json").is_file())
    if not entries:
        print(f"no snapshots under {directory}")
        return 1
    problems = 0
    for entry in entries:
        manifest = json.loads((entry / "manifest.json").read_text(encoding="utf-8"))
        pem = (entry / KEY).read_bytes()
        key_sha = fingerprint(pem.decode("ascii"))
        modulus, exponent = public_key_from_pem(pem.decode("ascii"))
        bad: list[str] = []
        if expected_key and key_sha != expected_key:
            bad.append("key-substituted")
        for name, recorded in manifest["documents"].items():
            body = (entry / name).read_bytes()
            if (
                len(body) != recorded["octets"]
                or hashlib.sha256(body).hexdigest() != recorded["sha256"]
            ):
                bad.append(f"{name}:digest")
                continue
            if name.endswith(".json"):
                signature = (entry / name.replace(".json", ".sig")).read_bytes()
                if not verify_pkcs1_sha256(body, signature, modulus, exponent):
                    bad.append(f"{name}:signature")
        listed = manifest["documents"].get("log_list.json", {})
        print(
            f"  {entry.name}  v{listed.get('version', '?')}  {listed.get('logs', '?')} logs in log_list.json"
            f"  key {key_sha[:12]}...  [{'ok' if not bad else 'PROBLEM: ' + ', '.join(bad)}]"
        )
        problems += bool(bad)
    print(f"{len(entries)} snapshots checked, {problems} with problems")
    return 1 if problems else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Journal and re-verify Chrome's signed CT log lists"
    )
    parser.add_argument("--dir", type=pathlib.Path, default=pathlib.Path("log-list-journal"))
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-check what is already stored and exit; needs no network",
    )
    parser.add_argument(
        "--expect-key-sha256",
        default=None,
        help="hex SHA-256 of the key's DER, pinned out of band; without it a substituted key cannot be spotted",
    )
    parser.add_argument(
        "--force", action="store_true", help="write a second snapshot for the same day"
    )
    args = parser.parse_args()

    if args.verify:
        return verify_tree(args.dir, args.expect_key_sha256)
    args.dir.mkdir(parents=True, exist_ok=True)
    return snapshot(args.dir, args.expect_key_sha256, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
