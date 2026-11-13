"""Does the precert reconstruction match what logs actually logged? A check, not a demonstration.

    python tools/check_precert_reconstruction.py [--entries 12] [--origin URL]

A log's precert entry stores the answer to this question twice over. `leaf_input` contains the `PreCert`
the log hashed - `issuer_key_hash` and the exact `TBSCertificate`. `extra_data` contains the precert as it
was submitted, plus the issuer chain. RFC 6962 section 3.2 says the logged TBS is that precert's TBS with
the poison extension removed, so the two must agree byte for byte, and the logged issuer hash must be
SHA-256 over the SPKI of a certificate in that chain.

No signature is needed to interpret this, which is what makes it worth having as its own check: it
validates the reconstruction rule and the helper it depends on (`certscan.precert_tbs`) against ground truth the
log produced itself, before anyone builds a claim on top of it. It found the bug it was written to guard
against - a walker handed an encoded value instead of its content silently stripped nothing, and the
result looked like a protocol puzzle rather than a caller error.

Exits non-zero on any mismatch, so it can be re-run after touching the DER helpers.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
# Both directories, and the order below is load-bearing: `fetch_evidence` puts the repository root on
# `sys.path` when it is imported, which is what makes the `ctspy` import after it resolvable. Swapping
# the two lines turns this into a ModuleNotFoundError that ruff's sort will happily reintroduce.
sys.path[:0] = [str(HERE), str(HERE.parent)]

from fetch_evidence import get_json, parse_extra_data  # noqa: E402

from ctspy import certscan  # noqa: E402
from ctspy.entry import MerkleTreeLeaf  # noqa: E402

V1_PRECERT_ENTRY = 0x0001


def precert_entries(origin: str, start: int, count: int) -> list[dict]:
    body = get_json(f"{origin}/ct/v1/get-entries?start={start}&end={start + count - 1}")
    return body["entries"]


def check(origin: str, start: int, count: int) -> tuple[int, int, list[str]]:
    """Compare the reconstruction with the `PreCert` the log itself stored. (checked, ok, problems)."""
    problems: list[str] = []
    checked = ok = 0
    for raw in precert_entries(origin, start, count):
        leaf_bytes = base64.b64decode(raw["leaf_input"])
        if int.from_bytes(leaf_bytes[10:12], "big") != V1_PRECERT_ENTRY:
            continue
        logged = MerkleTreeLeaf.parse(leaf_bytes).entry.entry
        subject, chain = parse_extra_data(base64.b64decode(raw["extra_data"]))
        rebuilt = certscan.precert_tbs(subject)
        checked += 1
        if rebuilt == logged.tbs_certificate:
            ok += 1
        else:
            problems.append(
                f"tbs mismatch: rebuilt {len(rebuilt)} bytes, logged {len(logged.tbs_certificate)}"
            )
        issuers = {
            hashlib.sha256(certscan.subject_public_key_info(cert)).digest() for cert in chain
        }
        if logged.issuer_key_hash not in issuers:
            problems.append(
                f"issuer hash {logged.issuer_key_hash.hex()[:16]}... is not any of "
                f"{len(chain)} chain certificates"
            )
    return checked, ok, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--origin",
        default="https://ct.googleapis.com/logs/us1/argon2026h2",
        help="log to ask; recent entries, because merged entries do not reconstruct (see docs)",
    )
    parser.add_argument("--entries", type=int, default=12)
    args = parser.parse_args()
    origin = args.origin.rstrip("/")
    size = int(get_json(f"{origin}/ct/v1/get-sth")["tree_size"])
    checked, ok, problems = check(origin, size - args.entries, args.entries)
    print(f"{origin} at {size}: {ok}/{checked} precert entries reconstructed exactly")
    for problem in problems:
        print(f"  {problem}")
    if checked < 5:
        print("  too few precert entries sampled to conclude anything")
        return 1
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
