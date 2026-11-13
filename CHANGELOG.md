# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `ctspy.tiles` (round 8): tile paths and widths, the strict data-tile (`TileLeaf`) parse, the data-tile to level-0-hash-tile check,
  the subtree hash a tile contributes upward, and a sans-IO `fetch_tile` over a caller-supplied `get`, from C2SP
  tlog-tiles and static-ct-api at commit `09f3e51`. Invented tile vectors; no production tile yet.
- `ctspy.checkpoint`: C2SP signed notes and transparency-log checkpoints (signed-note, tlog-checkpoint and
  static-ct-api "Checkpoints", read at commit `09f3e51`): strict note and checkpoint parsing, vkeys, and
  verification with Ed25519 (type 0x01) and RFC 6962 tree head (type 0x05) signatures, applying the specification's
  rules for unknown, failing and absent signers. Types 0x02, 0x04 and 0x06 are refused by name, not skipped.
- `sct.verify_embedded`: checks every embedded SCT of a served chain, rebuilding the signed entry from the chain
  alone; an unpinned log is `verified=None`, never false. `certscan.subject_public_key_info` supplies the issuer key
  hash input.
- `docs/rfc-map.md`: RFC 5246's ten verified errata read against the code (none changes a byte ctspy handles).

### Changed

- ECDSA verification moved to `sigwire.verify` (`sigwire[verify]`, now the one runtime dependency; a sibling
  checkout found through `pyproject.toml`). `ctspy/ecdsa.py` keeps the CT-specific SPKI and DER readers; the
  pure-Python curve arithmetic is deleted. `tools/fetch_evidence.py` and `tools/check_precert_reconstruction.py`
  call `certscan` instead of their own DER helpers.

- `ctspy.certscan`: finds the embedded SCT list and the precertificate `TBSCertificate` by walking the certificate's
  DER (strict: minimal lengths, no trailing bytes, one extensions field) instead of searching its bytes for the OID,
  which a crafted certificate could fool. `entry.parse_extra_data` now refuses a precert chain with a second
  precertificate (RFC 6962 erratum 3686). `docs/rfc-map.md` records the RFC 6962 errata and the C2SP specs.

- `ctspy.loglist`: verifies Chrome's signed CT log list (RSASSA-PKCS1-v1_5 with SHA-256) using only the standard
  library, parses the RSA key out of its armoured SPKI, and exposes the key's DER fingerprint for pinning. The
  signature is over the exact octets served - newline included - so snapshots must be written in binary; tests
  cover the captured document from `tests/fixtures/loglist/`, the byte-level and newline-level tamper cases,
  refusal of non-RSA and malformed keys, and agreement with OpenSSL on signatures it generates.
- `tools/log_list_journal.py`: snapshots both lists, both signatures and the key into a date-stamped directory,
  verifies on write, re-verifies offline, refuses to rewrite an existing day, and takes `--expect-key-sha256` for
  an out-of-band key pin.

Otherwise unchanged: parts of the public surface remain typed stubs that raise
`NotImplementedError`, and [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for ctspy.
- `ctspy.apps` namespace reserved for composition that is not protocol behaviour.
