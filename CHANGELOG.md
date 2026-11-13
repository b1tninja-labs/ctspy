# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

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
