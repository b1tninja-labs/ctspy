# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9162 | Experimental | 2021-12 | 2026-11-05 |
| RFC 6962 | Obsolete | 2013-07 | 2026-11-05 |
| RFC 5246 | Obsolete (RFC 8446, RFC 9846) | 2008-08 | 2026-11-13 |
| RFC 8017 | Informational, current | 2016-11 | 2026-11-13 |
| RFC 8032 | Informational, current | 2017-01 | 2026-11-13 |
| RFC 9942 | Proposed Standard, current | 2026-06 | 2026-11-13 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

## Why each document is here

- **RFC 9162** (obsoletes RFC 6962): CT 2.0, the Merkle tree and proof algorithms `merkle` and `sth` implement.
- **RFC 6962** (obsoleted by RFC 9162, still what every deployed log speaks): the v1 SCT, `MerkleTreeLeaf`,
  `extra_data` layouts, the X.509 SCT extension and the precertificate rules in `sct`, `entry` and `certscan`.
- **RFC 5246** (obsolete): still cited because CT v1 freezes the TLS 1.2 `digitally-signed` encoding and the
  hash and signature registry bytes (`sct`, `sth`). 10 verified errata on file, none read against the code
  yet; see the roadmap row.
- **RFC 8017** (PKCS #1 v2.2): RSASSA-PKCS1-v1_5 for `loglist`'s check of Chrome's log-list signature. Errata
  read 2026-11-13 (5 verified, 1 held): A.2.3, A.2.4 (a SHA-224 label), 8.1.1, B.1 and 11.2/7.2 are naming and
  typography. None touches RSASSA-PKCS1-v1_5 verification with SHA-256.
- **RFC 8032** (EdDSA): not implemented. Ed25519 (0x0807) is refused at pin-load; its 6 verified errata must
  be read before it is ever built.
- **RFC 9942** (COSE Receipts, new 2026-06) and RFC 9943 (SCITT): tracked, not built. A second published
  encoding of Merkle inclusion and consistency proofs; no CT log serves it.
- ECDSA P-256 (FIPS 186-5, and RFC 6979 for deterministic signing) is what the private verifier in
  `ctspy/ecdsa.py` implements; the NIST source has no entry here yet (roadmap row).

## Errata, as the RFC Editor recorded them (read through rfclib, 2026-11-13)

| Document | Erratum | Status | Section | Effect on ctspy |
|---|---|---|---|---|
| RFC 6962 | 3686 | **Verified**, technical | 4.2 | In an `add-pre-chain` chain only the first element may be a precertificate; the rest are proper certificates. **Applied**: `entry.parse_extra_data` refuses a precert entry whose chain holds a second precertificate (`tests/test_certscan.py::test_a_chain_element_that_is_a_precertificate_is_refused`). Binds `client.add_chain` when it is written. |
| RFC 6962 | 4204 | Reported, technical | 3.1 | `precertificate_chain`'s first certificate MUST certify the Precertificate, not "the first certificate" (a cut-and-paste error). Not applied: unverified, and checking it needs a signature check along the chain. Read it this way when writing `client.add_chain`. |
| RFC 6962 | 4286 | Reported, editorial | 3 | The SCT promise covers a Precertificate as well as a certificate. No code effect. |
| RFC 9162 | 8670 | Held for Document Update, editorial | 2.1.3.2 | The shift loop's `or fn is 0` is unreachable; `merkle.py` exits only on the bit (ROADMAP section 3). |

## Documents outside the RFC series

Neither rfclib nor itulib holds these, so each is cited by URL **and a commit of the repository that
publishes it**, until a primarysource collection exists. Commit `09f3e519fe79bcbdccadcf821182e3b488a14d71` is the tip of `main` of
<https://github.com/C2SP/C2SP> as read on 2026-11-13 (`git ls-remote`). The four files below were confirmed to
exist at that commit (HTTP 200); **none has been read in full yet, so no section of any of them is cited**.
Rule 2 above applies as it does to an RFC.

| Specification | URL at the commit | Needed for |
|---|---|---|
| static-ct-api | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/static-ct-api.md> | tiled log layout, data tiles, the leaf encoding of a static log (`tiles.fetch_tile`) |
| tlog-tiles | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/tlog-tiles.md> | the tile paths and hash-tile encoding static-ct-api builds on |
| tlog-checkpoint | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/tlog-checkpoint.md> | the checkpoint a static log signs in place of an STH |
| signed-note | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/signed-note.md> | the signature container a checkpoint is wrapped in |

Chrome's CT log list (`loglist`) is the other non-RFC source; its signature scheme is RFC 8017 above, and the
list's own format is Chrome's published schema, recorded in `docs/interop.md`.
