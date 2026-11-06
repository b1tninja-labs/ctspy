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

## Verified against the whole fleet (2026-11-05, second sweep)

`tools/fetch_evidence.py` walks the official log list and captures a current head from every log that
is usable or read-only. The result is interoperability evidence across independent implementations,
which is the thing a spec-derived test cannot supply:

| Operator | Logs captured | All heads verified under their published keys |
|---|---|---|
| Google | 4 (Argon/Xenon 2026h2, 2027h1) | yes |
| Cloudflare | 2 (Nimbus2026, Nimbus2027) | yes |
| DigiCert | 6 (Wyvern, Sphinx) | yes |
| Sectigo | 8 (Mammoth, Sabre, Elephant, Tiger) | yes |
| TrustAsia | 3 (log2026a/b, HETU2027) | yes |
| **Total** | **23** (21 usable, 2 read-only) | **23 of 23** |

Each `log_id` was also confirmed to equal SHA-256 over the published DER SPKI, and each head was
confirmed *not* to verify under the next log's key. `tests/test_production_sths.py` runs offline from
`tests/fixtures/log-list-sweep.json`; the fixture carries the fetch timestamp and the list version
(96.2, `log_list_timestamp` 2026-11-05T13:36:08Z) so a future run can tell whether the world moved.

## A production consistency proof, verified

`tests/fixtures/production-proofs.json` holds a real `get-sth-consistency?first=1&second=<N>`
response from Google Xenon2026h2, where N is a little over 3 billion, the signed head it was issued
against (fetched twice, bracketing the proof, and identical both times), and the raw entry 0 whose leaf
hash is the older root. My verifier reproduces the signed root from 32 audit nodes. The older root
requires no trust in anything but the hash function, which is what makes the check self-evident rather
than circular.

Three things this measurement produced:

1. **`get-sth-consistency` answers with the field `consistency`.** RFC 6962 section 4.6 names it
   `audit_consistency`. A client written against the specification alone fails against every log that
   was asked. The fixture records which name each response used.
2. **For `first == 1` the proof does not contain the leaf hash**, and step 2's "if first is an exact
   power of 2, prepend `first_hash`" therefore applies to 1 as well, not only to 2, 4, 8. Verified by
   the fact that the prepended fold lands exactly on the root the log signed.
3. **No deployed log served an inclusion proof.** All 23 operational logs were asked for
   `get-inclusion-proof-by-hash`: **20 answered 404, two answered 403**, and one answered 429 (a
   throttle, not an answer about the endpoint, so it is not counted either way). Either the RFC 6962
   section 4.5 endpoint is not deployed, or these operators expose audit paths some other way.
   `test_no_deployed_log_would_give_an_inclusion_proof` pins the absence *with the reasons*, so the gap
   is visible in the suite rather than remembered by whoever found it. Inclusion is currently pinned by
   the specification's worked example only (`test_merkle.py`).

## My tree hash, checked against production data

`tests/fixtures/production-tree.json` holds the first **41 real entries** of Google Xenon2026h2, the
signed head at tree size ~3.02 billion, and a `get-sth-consistency` proof for each of five prefixes of
that entry block: 2, 3, 8, 13 and 41 entries. Each prefix root is computed by `ctspy` from the leaf
bytes; the log then has to tie it to its own signature, and does, all five times.

This is the evidence that the *tree hash* - not merely the proof verifier - matches a production
implementation. Sizes 2 and 8 exercise section 2.1.4.2 step 2's prepend branch (which, it turns out,
applies to `first == 1` as well); 13 and 41 are ragged, which is where split-point arithmetic is
usually wrong. The test also flips one byte in the entry block and confirms the log's own proof stops
verifying, so the five accepts are not a formality.

Two deployment details the sweep produced:

- **`get-entries` is capped at 32 entries per response** by Google's servers. RFC 6962 section 4.3
  permits returning fewer than requested, and a client that assumes it received all 41 it asked for
  computes the root of a 32-entry tree and reports it as the root of 41 - wrong in the direction that
  looks entirely plausible. `fetch_leaves` observes the actual page size and asserts the count.
- **The live head advanced during the sweep** (3,024,290,326 to 3,024,290,413), which the fixture
  records rather than hides. It does not weaken anything: `second` was named explicitly in every
  request, and a proof for the newer tree could not have folded onto the older signed root.

## SCTs from the live Web: parsed, not verified, and why those are different claims

`tests/fixtures/live-scts.json` holds six leaf certificates taken from public services over read-only
TLS handshakes, with their embedded `SignedCertificateTimestampList` bytes: **15 SCTs**, at least eight
of which name a log present in the fleet sweep. `tests/test_production_scts.py` confirms each parses
with nothing left over, re-serialises to the same bytes, and that each matched `log_id` equals SHA-256
over that log's published key. That is evidence about the wire format and the identity binding.

Those signatures are **not** verified, and the reason is worth writing down because it is the sort of
thing that quietly turns a green suite into a false claim. The embedded certificate extension carries
*precert* SCTs. Their transcript is `issuer_key_hash | TBSCertificate-without-the-SCT-extension`, and a
handshake supplies neither piece: the hash is of the precertificate signing certificate, which the
final chain is not obliged to contain. The test therefore asserts the negative - each of those SCTs
must be **refused** when handed the `x509_entry` transcript built from the certificate - which is the
failure mode a verifier with the wrong transcript would have shown instead.

The route that would close it, recorded so the next person does not re-derive it: fetch a **merged
log's** `get-entries` for an older entry. Its `extra_data` contains the stored precert *and* the issuer
chain, including the precertificate signing certificate. Strip the SCT extension from the precert's TBS
(the reconstruction RFC 6962 section 3.2 itself describes), hash the signing certificate's SPKI, and the
SCTs embedded in that precert - issued by the source logs - become verifiable. It needs DER surgery,
which is why it is the next task rather than this one.

Two format findings from the same run:

- **The X.509 form double-wraps.** The extension value is a `digitally-signed struct`, which RFC 5246
  encodes as an OCTET STRING, nested inside the OCTET STRING that carries every X.509 extension value.
  The TLS extension has neither wrapper. Strip only one layer and a parser reads `0x0481` - a tag and a
  length - as a list length of 1153, and the error looks like corrupt data rather than a missing
  wrapper. `sct.parse_list`'s docstring says so; the tool does the stripping.
- **The embedded extension's OID is `06 0A 2B 06 01 04 01 D6 79 02 04 02`.** Hand-encoding
  1.3.6.1.4.1.11129.2.4.2 is where the 11129 → `D6 79` base-128 arithmetic bites; the first attempt at
  this constant found nothing on any host, which is the failure mode of getting it wrong.

## A property of the algorithm, found by accident and pinned on purpose

With `first == 1`, section 2.1.4.2's loop leaves `fn` at 0, so `fr` never moves and `second` ends up
constrained only by how far it shifts toward 0. A proof for the live tree also folds when `second` is
claimed as a few entries less - provided `second_hash` is still the root of the larger tree.

The expectation that caught this was mine, and it was the expectation that was wrong: the first version
of `test_the_same_proof_refuses_a_different_history` asserted the verifier would refuse a smaller
claimed size. To find out whether the library or the algorithm was at fault, I transcribed section
2.1.4.2 a second time in `sdk-forge/probe_consistency_soundness.py` and compared the two over every
honest small-tree pair: identical, and both accept. So this is the specification, not a transcription
error - and the reason it is not a forgery is that `tree_size` and `root_hash` are signed together, so
no caller that takes both from one verified head can be misled. Callers that take them from two places
can be, which is why `verify_consistency`'s docstring says so and `HeadStore` cannot be given a size
without its bound root.

