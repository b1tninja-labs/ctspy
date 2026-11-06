# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation ctspy could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `sct.parse()` | RFC 6962 section 3.2 (v1, deployed; obsoleted by RFC 9162, whose section 4.8 v2 shape this is not) | `[ok]` | `tests/test_scts.py::test_the_wire_format_offsets_are_what_section_32_declares` |
| `sct.verify()` | RFC 6962 section 3.2 (v1); RFC 9162 obsoletes the format and v2 is unimplemented | `[ok]` | `tests/test_scts.py::test_a_real_leaf_and_a_signature_from_openssl_verify` |
| `sth.verify()` | RFC 9162 | `[ok]` | `tests/test_sth.py::test_production_sths_verify_against_their_published_keys` |
| `merkle.verify_inclusion()` | RFC 9162 | `[ok]` | `tests/test_merkle.py::test_the_published_inclusion_proofs_verify` |
| `merkle.verify_consistency()` | RFC 9162 | `[ok]` | `tests/test_merkle.py::test_the_published_consistency_proofs_verify` |
| `tiles.fetch_tile()` | RFC 9162 | `[ ]` | milestone M3 |
| `client.add_chain()` | RFC 9162 | `[ ]` | milestone M4 |
| `monitor.watch()` | RFC 9162 | `[ ]` | milestone M5 |
| `policy.acceptable()` | design | `[ ]` | design undecided |

The `Where` column used to name `tests/test_obligations.py`, a file this repository never had. That
was the row lying about being checkable, which is worse than an honest gap.


## 2. Milestones

- M1 static Merkle trees and both proof types against published vectors
- M2 SCT and STH parsing plus signature verification
- M3 tile fetching with caching and a mirror fallback
- M4 the submission client for chains and pre-certificates
- M5 a monitor with a durable cursor and diff output
- M6 publication: 0.1.0 with cross checks against a production log

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9162 is Experimental with 1 erratum on file and none verified: expect variation between implementations and pin tests to real logs.
- **Measured against the deployed fleet, 2026-11-05** (`tools/fetch_evidence.py`, 23 operational logs
  across 5 operators): every log signs its own head as section 4.4 predicts, and a production
  consistency proof from a 3-billion-entry tree verifies, as do proofs for five prefixes of a 41-entry
  block whose roots `ctspy` computed itself - which checks the tree hash, not only the proof verifier.
  Three differences from the specification text matter for a client. `get-sth-consistency` answers with
  the field `consistency`, not section 4.6's `audit_consistency`; **no** operational log serves section
  4.5's `get-inclusion-proof-by-hash` (20 answered 404, two 403, one 429); and `get-entries` hands back
  at most 32 entries whatever was asked. All three are recorded in `docs/interop.md` with the fixture
  that shows it, because "the RFC says X" stops being sufficient evidence the moment the fleet says Y.

- **Erratum 8670** (editorial, held for document update) touches the shift loops of sections 2.1.3.2
  step 4.b.ii and 2.1.4.2 step 6.b.iii: the printed text ends the loop on "until either LSB(fn) is
  set or fn is 0", and the corrector deletes the second clause because `fn == 0` is unreachable
  (step 4.a fails on `sn == 0`, and `fn <= sn` is invariant). Both readings compute the same thing
  provided the implementation does not *accept* `fn == 0` as an exit; `ctspy/merkle.py` shifts until
  the bit is set and `test_the_rightmost_leaf_consumes_exactly_two_path_nodes` pins the case.
- RFC 9162 obsoletes RFC 6962; log artifacts from 2013 deployments still follow 6962 shapes, so the reader must accept both.


## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| running a log: the audit trail needs independent operators, not another client library | `[no]` | a named document requires it |
| browser policy decisions about which logs are accepted, which belong to the platform | `[no]` | a named document requires it |
| certificate issuance, which is enrollkit and pkix | `[no]` | a named document requires it |

## 5. Open questions

- **No production SCT signature has been verified end to end.** The fleet evidence covers STHs, tree
  heads, consistency proofs and SCT *parsing*; the signatures in `live-scts.json` are precert SCTs whose
  transcript needs the precertificate signing certificate. The recipe that would obtain one is in
  `docs/interop.md` (a merged log's `extra_data`, minus the SCT extension). Until that is done,
  `sct.verify` is pinned by OpenSSL over production leaf bytes, not by a log's own signature.
- **No log serves an inclusion proof**, so inclusion rests on the specification's worked example plus the
  entry-block proofs in `production-tree.json`. Is that a deployment gap or a reading of section 4.5?
  Nobody who asked got a different answer than 404.
- **v2 has no one to interoperate with.** `TransItem`, v2 SCTs and tile fetching are specified in
  RFC 9162 and unimplemented or untested against a server here, because no v2 log is in the log list.
  Writing them first means writing code nobody has confirmed reads the same bytes.
- **Ed25519** is registered by section 10.2.2 (0x0807) and deliberately unimplemented; a log declaring it
  currently fails at pin-load, loudly. Is loud refusal enough until a log actually uses it?

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [x] interoperability evidence recorded in `docs/` against a non-Python implementation
      (`docs/interop.md`: 23 operational logs across 5 operators, production consistency proofs against
      roots this library computed itself, 15 SCTs from live certificates)
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
