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

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `sct.parse()` | RFC 6962 section 3.2 (v1, deployed; obsoleted by RFC 9162, whose section 4.8 v2 shape this is not) | `[ok]` | `tests/test_scts.py::test_the_wire_format_offsets_are_what_section_32_declares` | M2 |
| `sct.verify()` | RFC 6962 section 3.2 (v1); RFC 9162 obsoletes the format and v2 is unimplemented | `[ok]` | `tests/test_production_sct_signatures.py::test_a_real_log_signed_this_transcript` | M2 |
| `sth.verify()` | RFC 9162 section 4.10 | `[ok]` | `tests/test_sth.py::test_production_sths_verify_against_their_published_keys` | M2 |
| `merkle.verify_inclusion()` | RFC 9162 section 2.1.3.2 | `[ok]` | `tests/test_merkle.py::test_the_published_inclusion_proofs_verify` | M1 |
| `merkle.verify_consistency()` | RFC 9162 section 2.1.4.2 | `[ok]` | `tests/test_merkle.py::test_the_published_consistency_proofs_verify` | M1 |
| `entry.parse_extra_data()` | RFC 6962 sections 3.1, 3.2, 4.6 (v1, deployed) | `[ok]` | `tests/test_production_extra_data.py::test_rereading_an_entry_rebuilds_the_exact_octets_the_log_sent` | M6 |
| `tiles.fetch_tile()` | RFC 9162 | `[ ]` | `tests/test_tiles.py::test_fetch_tile` (to be written) | M3 |
| `client.add_chain()` | RFC 9162 section 5.1 | `[ ]` | `tests/test_client.py::test_add_chain` (to be written) | M4 |
| `monitor.watch()` | RFC 9162 section 8.2 | `[ ]` | `tests/test_monitor.py::test_watch` (to be written) | M5 |
| `policy.acceptable()` | design | `[ ]` | `tests/test_policy.py::test_acceptable` (to be written) | - (open question, section 5) |

The `Where` column used to name `tests/test_obligations.py`, a file this repository never had. That
was the row lying about being checkable, which is worse than an honest gap.

An open row's `Where` names the test that will pin it, marked `(to be written)`: none of those files
exists yet. The `Milestone` column places each row on the section 2 ladder; `entry.parse_extra_data()`
at M6 is a judgement (production-entry reconstruction is cross-checked against live logs), the others
quote the ladder. Section numbers in the `Spec` column were read from RFC 9162's outline through rfclib
on 2026-11-07.


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
  Two facts matter for a client, and one retired finding had to be corrected. `get-entries` hands back at
  most 32 entries whatever was asked - which RFC 9162 section 5.6 paragraph 8 *permits*, and which silently
  produces a wrong tree root in a client that assumes it received what it requested - and `get-sth`'s
  `tree_head_signature` is RFC 5246's `DigitallySigned`, so the transcript was signed over the inner bytes
  and a verifier handed the served value fails against the whole fleet. The third item in this list used to
  read "no operational log serves inclusion proofs" (20 answered 404, two 403, one 429); the sweep had asked
  a path no RFC defines and omitted a required input, and asked correctly every log in the list served a proof
  that verified - see `tests/test_production_inclusion.py`. The `consistency` field name, also once listed as a
  discrepancy, matches both specifications. All of it is recorded in `docs/interop.md` with the fixtures that
  show it, because "the RFC says X" stops being sufficient evidence the moment the fleet says Y - and, as this
  correction shows, so does "the fleet says Y" stop being evidence once someone has misread the question.

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

- **Static-merge logs appeared to store something the specification does not describe.** Resolved, and the
  question was wrong in both of its halves. Three of the ten entries at Argon2026h2 indices 0-9 are x509
  entries, whose
  `extra_data` contains no precertificate at all (section 4.6), so part of the "11-byte divergence" was a
  real `TBSCertificate` compared against an issuer's. The precerts that fail to reconstruct are not a merge
  artefact either: they fail in live logs at the same rate, because they were signed by a Precertificate
  Signing Certificate, and RFC 6962 section 3.2 paragraph 9 rewrites the issuer and the Authority Key
  Identifier of the logged `TBSCertificate` in exactly that case. Cross-tabulated over 494 precerts in five
  logs, poison-only reconstruction and `issuer_key_hash == SHA256(chain[0].SPKI)` are perfectly diagonal -
  321 entries both - and the other 173 match `chain[1]`. `docs/interop.md` carries the measurement and the
  consequence: an issuer graph must key on `issuer_key_hash`, because a third of `chain[0]` values are
  CT-only signing certificates that are not CAs.
- **v2 has no one to interoperate with.** `TransItem`, v2 SCTs and tile fetching are specified in
  RFC 9162 and unimplemented or untested against a server here, because no v2 log is in the log list.
  Writing them first means writing code nobody has confirmed reads the same bytes.
- **Ed25519** is registered by section 10.2.2 (0x0807) and deliberately unimplemented; a log declaring it
  currently fails at pin-load, loudly. Is loud refusal enough until a log actually uses it?
- **The precert transcript rule was verified, the poison-vs-SCT question was not generalised.** Six
  signatures from six logs all reconstruct with "delete the SCT extension from the final certificate", and
  thirteen logged precert entries all reconstruct with "delete the poison extension from the stored
  precert". Those are the two shapes deployed logs emit today; whether a log exists that logs a precert
  whose TBS keeps an SCT list is unknown, and `certledger` should refuse rather than guess if it meets one.
- **Where does `policy.acceptable()` sit?** The row is `design` with no ladder rung. Two readings: M6, as
  part of publication, or `[no]` under the section 4 non-goal that browser log-acceptance policy belongs
  to the platform. The row keeps its meaning until that is decided (portfolio decision D24).
- **Which document does `tiles.fetch_tile()` cite?** The row says RFC 9162, but RFC 9162's outline has no
  tile section (read through rfclib, 2026-11-07); the tile layout deployed logs serve is specified outside
  the RFC series. The cell is unchanged until the citation is settled.

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [x] interoperability evidence recorded in `docs/` against a non-Python implementation
      (`docs/interop.md`: 23 operational logs across 5 operators, production consistency proofs against
      roots this library computed itself, 15 SCTs from live certificates)
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

## Board projection

`py sdk-forge/sync_roadmap.py --project ctspy --check` projects section 1 onto GitHub issues, collected on
Project V2 **#4 "Protocol SDK portfolio"**, the only board. Read with `gh project item-list 4` on 2026-11-07:
**7 items** from this repository, all in Backlog: 4 row issues (`tiles.fetch_tile`, `client.add_chain`,
`monitor.watch`, `policy.acceptable`, each `status:unimplemented`) and 3 milestone issues (M3, M4, M5).
The matrix holds 13 rows: 6 `[ok]` and 3 `[no]` are deliberately not filed, which is why four rows out of
thirteen appear on the board.

A dated snapshot, not a live count. The board is the live view; this file is the source of truth.
