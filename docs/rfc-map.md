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
  hash and signature registry bytes (`sct`, `sth`). 10 verified errata on file, all read against the code on
  2026-11-13 (table below): none changes a byte ctspy reads or writes.
- **RFC 8017** (PKCS #1 v2.2): RSASSA-PKCS1-v1_5 for `loglist`'s check of Chrome's log-list signature. Errata
  read 2026-11-13 (5 verified, 1 held): A.2.3, A.2.4 (a SHA-224 label), 8.1.1, B.1 and 11.2/7.2 are naming and
  typography. None touches RSASSA-PKCS1-v1_5 verification with SHA-256.
- **RFC 8032** (EdDSA): not implemented. Ed25519 (0x0807) is refused at pin-load; its 6 verified errata must
  be read before it is ever built.
- **RFC 9942** (COSE Receipts, new 2026-06) and RFC 9943 (SCITT): tracked, not built. A second published
  encoding of Merkle inclusion and consistency proofs; no CT log serves it.
- ECDSA P-256 (FIPS 186-5) is verified by `sigwire.verify` since 2026-11-13; `ctspy/ecdsa.py` keeps only the
  CT-specific reading of the SPKI and the DER signature. The NIST source has no entry here yet (roadmap row).

## Errata, as the RFC Editor recorded them (read through rfclib, 2026-11-13)

| Document | Erratum | Status | Section | Effect on ctspy |
|---|---|---|---|---|
| RFC 6962 | 3686 | **Verified**, technical | 4.2 | In an `add-pre-chain` chain only the first element may be a precertificate; the rest are proper certificates. **Applied**: `entry.parse_extra_data` refuses a precert entry whose chain holds a second precertificate (`tests/test_certscan.py::test_a_chain_element_that_is_a_precertificate_is_refused`). Binds `client.add_chain` when it is written. |
| RFC 6962 | 4204 | Reported, technical | 3.1 | `precertificate_chain`'s first certificate MUST certify the Precertificate, not "the first certificate" (a cut-and-paste error). Not applied: unverified, and checking it needs a signature check along the chain. Read it this way when writing `client.add_chain`. |
| RFC 6962 | 4286 | Reported, editorial | 3 | The SCT promise covers a Precertificate as well as a certificate. No code effect. |
| RFC 9162 | 8670 | Held for Document Update, editorial | 2.1.3.2 | The shift loop's `or fn is 0` is unreachable; `merkle.py` exits only on the bit (ROADMAP section 3). |

### RFC 5246, ten verified errata read against `sct.py`, `sth.py` and `entry.py` (rfclib, 2026-11-13)

RFC 5246 is Obsolete (RFC 8446, RFC 9846) and is updated by RFC 5746, 5878, 6176, 7465, 7507, 7568, 7627, 7685,
7905, 7919, 8447, 9155 and 10015, none of which touches `digitally-signed`. ctspy uses three things from it: the
`DigitallySigned` structure (section 4.7), the `SignatureAndHashAlgorithm` code points (section 7.4.1.4.1:
sha256 = 4, ecdsa = 3, which `sct.py` and `sth.py` pin) and the vector rules (section 4.3). Neither section 4.7
nor section 7.4.1.4.1 has an erratum. Of the ten verified:

| Erratum | Section | Effect on ctspy |
|---|---|---|
| 4109 | A.4.2 | `ASN.1Cert` is `<1..2^24-1>`, not `<2^24-1>`. `entry.py` already reads it with `minimum=1` (`MAX_ENTRY`), as RFC 6962 section 3.1 also writes it. No change. |
| 4750 | 4.3 | A vector's length is a *whole* multiple of its element size, not an "even" one. ctspy reads vectors of length-prefixed opaque elements and checks every length against its container (`Reader.opaque`, `parse_list`). No change. |
| 1585, 2864, 2865, 4912 | A.4.2, 7.4.4, A.4.1 | `CertificateRequest.supported_signature_algorithms` bounds `<2..2^16-2>`. ctspy sends no handshake. Not applicable. |
| 3122, 3123 | A.4, A.4.2 | A missing comma and a missing `};` in the grammar appendix. Not applicable. |
| 2643 | E.3 | An inverted SSL 2.0 rollback check. Not applicable. |
| 4507 | 7.4.1.2 | A ServerHello after a ClientHello is not an error. Not applicable. |

One difference from the text, not an erratum: section 4.7 gives `DigitallySigned.signature` as
`opaque<0..2^16-1>`, and `sct.py` and `sth.py` read it as `<1..2^16-1>`. A zero-length signature cannot verify,
so refusing it early is deliberate strictness. Section 4.7 specifies RSA and DSA signature bodies only; where the
ECDSA body (`Ecdsa-Sig-Value`) is defined was not read here and is a roadmap row, so no section is cited for it.

## Documents outside the RFC series

Neither rfclib nor itulib holds these. The primarysource `c2sp` collection now does (refs such as
`c2sp:signed-note@09f3e51§Format`), and until that collection is imported locally each is cited by URL **and a
commit of the repository that publishes it**. Commit `09f3e519fe79bcbdccadcf821182e3b488a14d71` is the tip of `main` of
<https://github.com/C2SP/C2SP> as read on 2026-11-13 (`git ls-remote`). The four files below were confirmed to
exist at that commit (HTTP 200). On 2026-11-13 `signed-note`, `tlog-checkpoint` and the "Checkpoints" section of
`static-ct-api` were fetched from `raw.githubusercontent.com` at that commit, their sha256 matched the primarysource
catalogue, and they were read in full: they are what `ctspy/checkpoint.py` implements. `tlog-tiles` and the rest
of `static-ct-api` (tiles, log entries, issuers) are **not read yet, so no section of them is cited**. Rule 2
above applies as it does to an RFC.

| Specification | URL at the commit | Needed for |
|---|---|---|
| static-ct-api | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/static-ct-api.md> | tiled log layout, data tiles, the leaf encoding of a static log (`tiles.fetch_tile`) |
| tlog-tiles | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/tlog-tiles.md> | the tile paths and hash-tile encoding static-ct-api builds on |
| tlog-checkpoint | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/tlog-checkpoint.md> | the checkpoint a static log signs in place of an STH (`checkpoint.parse_checkpoint`; read) |
| tlog-cosignature | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/tlog-cosignature.md> | the definition of "origin", and the Ed25519 checkpoint cosignature (type 0x04: `checkpoint.ed25519_cosigner_verifier`; read; the ML-DSA-44 half is read but not implemented) |
| signed-note | <https://github.com/C2SP/C2SP/blob/09f3e519fe79bcbdccadcf821182e3b488a14d71/signed-note.md> | the signature container a checkpoint is wrapped in (`checkpoint.parse_note`, `verify_note`; read) |

Read and implemented from these on 2026-11-13: signed-note "Format" (UTF-8, no control characters, text ends with a
newline, the last empty line separates the signatures, at least 16 signatures accepted), "Signatures" (unknown
(name, ID) pairs ignored; a known key that fails rejects the note; no verifying known key rejects it), "Signature
types" (0x01 Ed25519, 0x05 RFC 6962 `TreeHeadSignature`; 0x02, 0x04, 0x06 assigned but defined elsewhere) and
"Verifier keys"; tlog-checkpoint "Note text" (origin, decimal size without leading zeros, base64 root, opaque
extension lines) and "Signatures" (no repeated name and key ID); static-ct-api "Checkpoints" (type 0x05: key ID over
the log ID, body `uint64 timestamp` then the `TreeHeadSignature`, no extension lines). The signed-note example is a
test vector. tlog-cosignature was read the same day: the "origin" is the checkpoint's first line (for a static CT log
the submission prefix, `checkpoint.static_log_origin`); the Ed25519 cosignature (0x04) signs `cosignature/v1`,
`time <decimal>` and then the checkpoint lines, extension lines included, and is implemented; the ML-DSA-44
cosignature (0x06) signs a `CosignedSubtree` and is not, because `cryptography` 46.0.7 has no ML-DSA. The
specification prints the 0x04 signature input for an example and no signature, so no third-party vector exists.

Chrome's CT log list (`loglist`) is the other non-RFC source; its signature scheme is RFC 8017 above, and the
list's own format is Chrome's published schema, recorded in `docs/interop.md`.
