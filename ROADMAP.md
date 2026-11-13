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
| `tiles.fetch_tile()` | static-ct-api and tlog-tiles (C2SP, outside the RFC series; `docs/rfc-map.md`), read at commit `09f3e519fe79bcbdccadcf821182e3b488a14d71`; sans-IO, the caller supplies `get(url)`, and no checkpoint verification (the caller's, with `tiles.verify_data_tile` and `tiles.subtree_hash`) | `[ok]` | `tests/test_tiles.py::test_fetch_tile` | M3 |
| `client.add_chain()` | RFC 6962 sections 4.1, 4.2 with erratum 3686 (every deployed log speaks v1; RFC 9162 section 5.1 is v2) | `[ ]` | `tests/test_client.py::test_add_chain` (to be written) | M4 |
| `monitor.watch()` | RFC 6962 section 5.3 (the deployed monitor; RFC 9162 section 8.2 is v2) | `[ ]` | `tests/test_monitor.py::test_watch` (to be written) | M5 |
| `policy.acceptable()` | design | `[ ]` | `tests/test_policy.py::test_acceptable` (to be written) | - (open question, section 5) |
| `certscan.embedded_sct_list()` | RFC 6962 section 3.3 paragraph 4 (extension 1.3.6.1.4.1.11129.2.4.2, two OCTET STRING layers) | `[ok]` | `tests/test_certscan.py::test_the_six_live_certificates_yield_the_fixture_lists` | M2 |
| `certscan.tbs_without_sct()` | RFC 6962 section 3.2 paragraph 9 (delete the SCT extension, re-encode lengths) | `[ok]` | `tests/test_certscan.py::test_an_extension_that_merely_contains_the_oid_bytes_is_kept` | M2 |
| `certscan.precert_tbs()` | RFC 6962 section 3.2 paragraph 9 (delete the poison extension); equals the logged TBS when the issuer did not change | `[ok]` | `tests/test_certscan.py::test_precert_tbs_equals_the_logged_precert_tbs` | M2 |
| `certscan.subject_public_key_info()` | RFC 6962 section 3.2 paragraph 8 (`issuer_key_hash` is SHA-256 over the issuer's DER `SubjectPublicKeyInfo`, so the certificate's own octets) | `[ok]` | `tests/test_embedded_verify.py::test_the_issuer_spki_helper_returns_the_exact_bytes_the_log_hashed` | M2 |
| `sct.verify_embedded()` | RFC 6962 section 3.2 paragraph 9 and section 3.3: the embedded SCTs of a served chain, rebuilt from the chain alone; an unpinned log is `verified=None`, never false | `[ok]` | `tests/test_embedded_verify.py::test_production_embedded_scts_verify_from_a_served_chain` | M2 |
| `checkpoint.parse_note()` | C2SP signed-note, "Format" (commit `09f3e51`) | `[ok]` | `tests/test_checkpoint.py::test_malformed_notes_are_refused` | M3 |
| `checkpoint.verify_note()` | C2SP signed-note, "Signatures": unknown (name, ID) ignored, a known key that fails rejects the note, no known signer rejects it; Ed25519 (0x01) and RFC 6962 tree head (0x05) | `[ok]` | `tests/test_checkpoint.py::test_the_signed_note_spec_example_verifies_under_its_vkey` | M3 |
| `checkpoint.parse_checkpoint()` | C2SP tlog-checkpoint, "Note text" | `[ok]` | `tests/test_checkpoint.py::test_the_checkpoint_spec_example_text_parses` | M3 |
| `checkpoint.verify_checkpoint()` | C2SP tlog-checkpoint "Signatures" and static-ct-api "Checkpoints" (type 0x05, against a production STH re-wrapped; a static log's own checkpoint is not in the fixtures) | `[ok]` | `tests/test_checkpoint.py::test_a_production_sth_rewrapped_as_a_type_5_checkpoint_verifies` | M3 |
| `certscan.split_certificate()` | RFC 5280 `Certificate`/`TBSCertificate` field order, strict DER; a substring lookup is the defect it replaces | `[ok]` | `tests/test_certscan.py::test_an_oid_inside_another_value_is_not_the_extension` | M2 |

Rows that name no callable are decisions, migrations and prerequisites rather than functions; the matrix tests
skip them, and the same honesty rule binds them.

| Item | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `sct.verify_embedded` over a served chain: compose `certscan.tbs_without_sct`, the issuer SPKI hash of the chain element the server sent, and `sct.verify`; an unpinned log is `verified=None`, never false | RFC 6962 sections 3.2, 3.3 | `[ok]` | `tests/test_embedded_verify.py::test_production_embedded_scts_verify_from_a_served_chain` (the six live captures; every other SCT in those certificates is for an unpinned log and comes back `None`) | M2 |
| Move the private P-256 verifier (`ctspy/ecdsa.py`) into the sibling seam `sigwire[verify]` and delete the copy here | FIPS 186-5; the portfolio rule on cryptographic primitives | `[ok]` | `tests/test_signatures.py::test_a_hundred_random_signatures_agree_with_openssl`, and the 23-log fleet in `tests/test_production_sths.py`, stay green through the move; the suite went from 3.2 s to 0.7 s. `ctspy/ecdsa.py` keeps `EcdsaKey`, the strict SPKI and DER readers and `verify_sha256`'s False-not-raise contract; `P256` and `Curve` are re-exported. `sigwire[verify]` is now ctspy's one runtime dependency (`docs/strategy.md`) | - |
| Signed-note and checkpoint parsing and verification (the missing half of `tools/tile_probe.py`'s `checkpoint_verified: false`) | C2SP signed-note, tlog-checkpoint, static-ct-api "Checkpoints" at commit `09f3e519fe79bcbdccadcf821182e3b488a14d71`, read in full 2026-11-13 | `[ok]` | `tests/test_checkpoint.py`: the signed-note example vector verifies, 12 malformed notes and 9 malformed checkpoints are refused, and the unknown-key, known-failing-key and name-or-ID-alone rules are each pinned. Code in `ctspy/checkpoint.py` | M3 |
| `tools/tile_probe.py` records `checkpoint_verified` from `checkpoint.verify_static_log_checkpoint`, fed the key and submission prefix the log list declares (`verify_log_checkpoint`, a pure function the networked tool calls; the origin line is checked against the prefix because the type-0x05 signature does not cover it). **Not run live** (no request to a third-party host was made in writing this); the tile data is still not tied to the root by an inclusion proof | C2SP static-ct-api "Checkpoints" | `[ok]` | `tests/test_tile_probe_checkpoint.py::test_a_checkpoint_signed_by_the_declared_key_under_the_declared_origin_is_verified`, `::test_a_checkpoint_from_a_log_the_list_does_not_declare_is_not_verified`, and `tests/test_checkpoint.py::test_a_valid_signature_under_a_different_origin_line_is_a_forgery`. A genuine static log's own checkpoint is still absent from the fixtures: the positive case re-wraps a dynamic log's STH | M3 |
| Signature type 0x04 (timestamped Ed25519 cosignature): signed message `cosignature/v1`, `time <decimal>`, then the checkpoint lines including extension lines; body is `uint64 timestamp` and 64 bytes; key ID over type byte 0x04. Read in tlog-cosignature and tlog-checkpoint at commit `09f3e51`. The spec prints the signature *input* for an example but no signature, so the test signs that input with a generated key; no third-party vector. A future timestamp is returned, not rejected (the spec's MAY; the caller owns the clock) | C2SP tlog-cosignature "Ed25519", tlog-checkpoint "Ed25519 Checkpoint Cosignatures" | `[ok]` | `tests/test_checkpoint.py::test_the_cosignature_message_is_the_specifications_example_input`, `::test_a_cosignature_covers_the_extension_lines_and_the_timestamp`, `::test_the_cosignature_key_id_uses_type_byte_four_and_its_vkey_round_trips` | M3 |
| Signature type 0x06 (timestamped ML-DSA-44) and subtree cosignatures (`CosignedSubtree`, start/end): the specification is read, but `cryptography` 46.0.7 (the version measured here) has no `mldsa` module and the floor `sigwire[verify]` declares is lower, so there is no primitive to verify with. `parse_vkey` still refuses 0x06 by name. Close when `sigwire[verify]` offers ML-DSA-44 at its floor | C2SP tlog-cosignature "ML-DSA-44" | `[ ]` | `tests/test_checkpoint.py::test_signature_types_whose_documents_were_not_read_are_refused_not_skipped` pins today's refusal | M3 |
| Signature type 0x02 (ECDSA note signatures "as implemented by github.com/transparency-dev/witness"): defined by code, not by a C2SP document; decide whether to implement from that source | signed-note "Signature types" | `[ ]` | owner decision | - |
| A `get-sth` response to a checkpoint and back: static-ct-api says it is possible "with knowledge of the origin line" and no private key. `checkpoint.from_sth(sth, origin, log_id)` and `checkpoint.to_sth(data, origin, log_id)` do it (the log ID is needed because it is hashed into the key ID); neither verifies. `to_sth` refuses a missing or duplicated signature line, extension lines and a different origin line | C2SP static-ct-api "Checkpoints" | `[ok]` | `tests/test_checkpoint.py::test_a_checkpoint_made_from_a_production_sth_verifies_and_converts_back_to_the_same_sth` (a real Argon2026h2 STH, byte-equal to the hand-built form and back to an equal STH that `sth.verify` accepts), `::test_from_sth_produces_exactly_the_checkpoint_built_by_hand`, `::test_to_sth_ignores_other_signature_lines_and_refuses_ambiguity` | M3 |
| Data-tile parse and leaf layout of a static-CT log | C2SP static-ct-api, tlog-tiles at commit `09f3e519fe79bcbdccadcf821182e3b488a14d71`, read raw 2026-11-13 (sha256 `951b7c96...` and `e7173ca6...`, matching primarysource's catalogue); INVENTED tiles, since neither specification has a sample and no real production tile is checked in | `[ok]` | `tests/test_tiles.py::test_a_data_tile_is_parsed_and_each_entry_hashes_to_the_level_0_tile` | M3 |
| Tile hashes to a checkpoint: rebuild the root of a tree from the tiles of each level (full tiles hashed with `tiles.subtree_hash`, the partial tile at the edge folded in) and compare it to a verified checkpoint's root; fetch only the partial tiles the checkpoint's size requires | C2SP tlog-tiles, "Merkle Tree" and "Partial Tiles" | `[ ]` | `tests/test_tiles.py::test_tiles_rebuild_the_checkpoint_root` (to be written) | M3 |
| `tools/tile_probe.py` parses with `tiles.parse_data_tile` instead of its own `iter_tile_leaves`, and reports `leaf_index` | static-ct-api, "Log entries" | `[ ]` | `tests/test_tile_probe_checkpoint.py::test_the_probe_uses_the_library_parser` (to be written) | M3 |
| A real data tile and its level-0 hash tile of a production log in `tests/fixtures`, so the layout is pinned to a log's output and not only to the text; needs one GET per tile from a third-party log, not done (this round may not observe third-party hosts) | static-ct-api | `[ ]` | `tests/test_tiles.py::test_a_production_data_tile_hashes_to_its_hash_tile` (to be written) | M3 |
| The tile-level range differs between the two documents (static-ct-api 0 to 5, tlog-tiles 0 to 63) and the directory name differs (`data`, `entries`); `TiledLog.max_level` and `kind` carry both, default static-ct-api | tlog-tiles, static-ct-api | `[part]` | `tests/test_tiles.py::test_tile_paths_for_hash_data_and_entry_tiles` | M3 |
| C2SP specifications cited by URL and commit; the primarysource `c2sp` collection now holds them (`c2sp:static-ct-api@09f3e51§Checkpoints`) | `docs/rfc-map.md`, "Documents outside the RFC series" | `[part]` | signed-note, tlog-checkpoint, tlog-cosignature (read 2026-11-13, raw from the same commit, sha256 `9cf3f0ef2690319697fcbb4d1e823b593d90a1769912fdcb859ab89a3f924fbe`) and static-ct-api "Checkpoints" are read and cited (sha256 checked against the collection catalogue for the first three). Still unread: tlog-tiles and the rest of static-ct-api (tiles, log entries, issuers, SCT extension): read them before `tiles.fetch_tile` or the data-tile row, and switch the URLs to collection refs once the collection is imported locally (it is not on this machine) | - |
| RFC 5246's 10 verified errata read against `DigitallySigned` and the registry bytes in `sct.py` | RFC 5246 (obsolete; frozen into CT v1) | `[ok]` | read 2026-11-13, table in `docs/rfc-map.md`: none touches section 4.7 or 7.4.1.4.1 and none changes a byte ctspy reads; 4109 (`ASN.1Cert<1..2^24-1>`) is already what `entry.py` does. A documentation row, so it has no test | - |
| Where the ECDSA signature body inside `DigitallySigned` is defined: RFC 5246 section 4.7 specifies RSA and DSA only. Find the document (the ECC-in-TLS RFC and its successor), read its errata, and cite it from `ecdsa.parse_der_signature` | RFC 5246 section 4.7; the ECC-in-TLS document (not read) | `[ ]` | a note in `docs/rfc-map.md` (to be written) | - |
| Ed25519 (0x0807): `[no]` until a log in Chrome's list declares it; add a test that fails when any pinned log key is not P-256 | RFC 8032 (6 verified errata) | `[ ]` | `tests/test_signatures.py` (to be written) | - |
| `tools/fetch_evidence.py` carried its own DER helpers (`sct_extension_payload` found the OID by substring, `strip_extension` deleted any extension whose bytes merely contain it). They are deleted and `fetch_evidence.py` and `check_precert_reconstruction.py` call `certscan`; this is its own step, separate from the library work, so the evidence stays byte-comparable. Before the edit the old helpers and `certscan` were compared on the six live fixtures: payload, reconstructed TBS and issuer SPKI were identical in all six. **Not run live**: both tools are networked, so the owner runs `python tools/check_precert_reconstruction.py` once to see 29 of 29 again | RFC 6962 section 3.2 | `[part]` | `tools/check_precert_reconstruction.py` (networked; not a gate) | - |
| `policy.acceptable()`: resolve to `[no]` and delete the stub (it contradicts the README non-goal) | owner decision | `[ ]` | `tests/test_public_api.py::test_stubs_are_loud` | - |

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

- **RFC 6962 errata, read through rfclib on 2026-11-13.** Erratum 3686 (**verified**, section 4.2): in a
  precertificate chain only the first element may be a precertificate. It is applied: `entry.parse_extra_data`
  refuses a stored chain with a second one, pinned by
  `tests/test_certscan.py::test_a_chain_element_that_is_a_precertificate_is_refused`, and it binds
  `client.add_chain`. Erratum 4204 (reported, section 3.1): the first `precertificate_chain` certificate must
  certify the Precertificate, not "the first certificate". Erratum 4286 (reported, editorial, section 3). Only a
  verified erratum is applied; the details are in `docs/rfc-map.md`.
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
- **Which document does `tiles.fetch_tile()` cite?** Settled for now: the C2SP specifications, by URL and commit, in `docs/rfc-map.md`; the owner may still prefer a snapshot. The row used to say RFC 9162, whose outline has no
  tile section (read through rfclib, 2026-11-07); the tile layout deployed logs serve is specified outside
  the RFC series, and the row now cites it.

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
