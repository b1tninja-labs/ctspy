# Interoperability evidence

The publication checklist asks for evidence "against a non-Python implementation". This file is
where that evidence lives, with the URL, the date and the artifact, because a claim that cannot be
re-fetched is a claim that cannot be checked.

## Verified against production logs (2026-11-05)

Two Google logs, fetched through their public v1 APIs and recorded verbatim under
`tests/fixtures/`:

| Log | Key source | tree_size at capture | Result |
|---|---|---|---|
| Google Xenon2026h2 (`ct.googleapis.com/logs/eu1/xenon2026h2`) | Chrome log list v96.2, `log_list_timestamp` 2026-11-05T13:36:08Z | 3024195456, 3024221414 | both STHs verify |
| Google Argon2026h2 (`ct.googleapis.com/logs/us1/argon2026h2`) | same | 3489348669 | verifies |

Each log's published `log_id` also equals SHA-256 over its published `key` (a DER
`SubjectPublicKeyInfo`), which is what section 4.4 says it must be, and a signature made by one log
does not verify under the other's key.

## What production settled: the v1 STH transcript is 50 bytes, not 48

RFC 6962 section 3.5 declares the signed struct as `Version version; SignatureType signature_type =
tree_hash; uint64 timestamp; uint64 tree_size; opaque sha256_root_hash[32];`, and RFC 5246 section
4.7 says a signature covers "the contents of the element" - without saying whether a field carrying a
declared value is among those contents. The two readings differ by two bytes, and the shorter one is
widely repeated in tutorials and in at least one well-known client library's comments.

The Xenon2026h2 artifact verifies over `version || tree_hash || timestamp || tree_size || root_hash`
and fails over the same without the first two bytes. `test_the_48_byte_misreading_is_refused` pins
both outcomes, so the question cannot be re-opened by a future reader of RFC 5246.

## Not yet cross-checked, and what stopped it

- **Inclusion and consistency proofs.** These are pinned to the worked example in RFC 9162 section
  2.1.5 - the authors' own stated proofs for a 7-leaf tree - which is an expectation written by the
  specification rather than by this code. A production proof would be stronger: Google's
  `get-inclusion-proof-by-hash` returned 404 through the sandbox's fetch path on 2026-11-05, so it is
  recorded here as pending rather than approximated.
- **A second log implementation.** Both fixtures come from the same codebase family, so the evidence
  shows the transcript shape is what Google's servers emit, not that every v1 log agrees. Nimbus2026
  (C++) was fetched but its key could not be obtained from a citable source through this path; a
  mismatch there would be a real finding, not a test bug, and should be investigated as one.
- **Ed25519.** Registered by section 10.2.2 (0x0807) and deliberately unimplemented: the pinned key
  must parse as P-256 ECDSA or pinning fails loudly, so there is no path where an Ed25519 log is
  silently verified under the wrong scheme.
