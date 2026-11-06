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

1. **The consistency-proof field is `consistency`, and both specifications agree on that name.** An earlier
   version of this item said deployment contradicted the specification here ("6962 section 4.6 names it
   `audit_consistency`") and was wrong twice over: section 4.6 is `get-entries`, and `audit_consistency`
   appears nowhere in RFC 6962 or RFC 9162 - the name carrying "audit" is `audit_path`, in section 4.5. What
   the two versions really differ on is the **value**: v1 (section 4.4) returns an array of base64 node
   hashes, v2 (section 5.3) a single base64 `TransItem` of type `consistency_proof_v2`. A client that reads
   one shape as the other is the one that fails against every log it asks, and the fixture still records which
   field name each response used.
2. **For `first == 1` the proof does not contain the leaf hash**, and step 2's "if first is an exact
   power of 2, prepend `first_hash`" therefore applies to 1 as well, not only to 2, 4, 8. Verified by
   the fact that the prepended fold lands exactly on the root the log signed.
3. **Retracted, then reversed: every deployed log serves inclusion proofs.** This item previously read "no
   deployed log served an inclusion proof" - 20 of 23 answered 404, two 403, one 429 - and that was an
   artifact of the probe rather than of the fleet. The sweep asked
   `/ct/v1/get-inclusion-proof-by-hash`, **a path defined in no RFC**, and sent only `hash` where section 4.5
   requires `hash` and `tree_size`. The logs were refusing a question nobody specifies.

   Asked at section 4.5's real path with both inputs, **every log that was asked returned an audit path that
   verified against the head that log signed** - 23 of 23 on the run that wrote the fixture, 22 of 23 on the
   run before it where one log throttled with 429 (a *different* log throttled on another run, so throttling
   is about rate limits and not about the endpoint). Proof lengths ran from 15 nodes on a freshly opened log
   to 33 on a 6.7-billion-entry static-merge tree. `tools/fetch_evidence.py inclusion_sweep()` writes
   `fixtures/production-inclusion.json`, so the evidence names a command that exists;
   `tests/test_production_inclusion.py` re-verifies it offline, and the old test now asserts the retraction
   rather than the disproof.

   Two things came out of getting this wrong. The first is the obvious one: **a measurement is only as good as
   the request**, and "measured, not read" is not a safety property if the request was written from memory -
   the sentence "the RFC says X stops being sufficient evidence the moment the fleet says Y" cuts both ways,
   and here the fleet never said Y at all. The second is a real trap for clients, found because the first
   re-run failed for reasons that had nothing to do with the fleet: `get-sth`'s `tree_head_signature` is RFC
   5246's `DigitallySigned` - hash algorithm, signature algorithm, a 2-byte length, then the DER signature -
   and the transcript was signed over the **inner** bytes. `SignedTreeHeadV1.from_v1_json` already unwraps it
   and refuses a wrapper that is missing or malformed; the failure came from a probe that bypassed that parser
   and built the dataclass by hand, which made 23 healthy logs look compromised. Two things worth keeping
   from that: use the parse path rather than assembling structs from JSON, and note that the mistake failed
   loudly - a `VerificationError`, not a wrong answer - which is the property the strict reader exists to
   have.

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

- **`get-entries` page size is an operator choice, not a protocol constant.** Measured 2026-11-05 by asking one
  log per operator for 4,096 entries in a single request: **Google and TrustAsia return 32; Cloudflare, DigiCert
  and Sectigo return 256.** One observation per operator, so these are *observed* caps rather than proven maxima.
  RFC 6962 section 4.3 permits returning fewer than requested, and a client that assumes it received all 41 it
  asked for computes the root of a 32-entry tree and reports it as the root of 41 - wrong in the direction that
  looks entirely plausible. `fetch_leaves` observes the actual page size and asserts the count, which is why this
  heterogeneity costs correctness nothing and request counts everything: a walk sized on Google's 32 overstates a
  Cloudflare log eightfold.
- **The live head advanced during the sweep** (3,024,290,326 to 3,024,290,413), which the fixture
  records rather than hides. It does not weaken anything: `second` was named explicitly in every
  request, and a proof for the newer tree could not have folded onto the older signed root.

## SCTs from the live Web: parsed, not verified, and why those are different claims

`tests/fixtures/live-scts.json` holds six leaf certificates taken from public services over read-only
TLS handshakes, with their embedded `SignedCertificateTimestampList` bytes: **15 SCTs**, at least eight
of which name a log present in the fleet sweep. `tests/test_production_scts.py` confirms each parses
with nothing left over, re-serialises to the same bytes, and that each matched `log_id` equals SHA-256
over that log's published key. That is evidence about the wire format and the identity binding.

Those signatures are **not** verified here, and the reason is worth writing down because it is the sort
of thing that quietly turns a green suite into a false claim. The embedded certificate extension carries
*precert* SCTs. Their transcript is `issuer_key_hash | TBSCertificate-without-the-SCT-extension`, and
`getpeercert` supplies neither piece. The test therefore asserts the negative - each of those SCTs must be
**refused** when handed the `x509_entry` transcript built from the certificate - which is the failure mode
a verifier with the wrong transcript would have shown instead. The positive case is
`tests/test_production_sct_signatures.py`.

Two format findings from the same run:

- **The X.509 form double-wraps.** The extension value is a `digitally-signed struct`, which RFC 5246
  encodes as an OCTET STRING, nested inside the OCTET STRING that carries every X.509 extension value.
  The TLS extension has neither wrapper. Strip only one layer and a parser reads `0x0481` - a tag and a
  length - as a list length of 1153, and the error looks like corrupt data rather than a missing
  wrapper. `sct.parse_list`'s docstring says so; the tool does the stripping.
- **The embedded extension's OID is `06 0A 2B 06 01 04 01 D6 79 02 04 02`.** Hand-encoding
  1.3.6.1.4.1.11129.2.4.2 is where the 11129 → `D6 79` base-128 arithmetic bites; the first attempt at
  this constant found nothing on any host, which is the failure mode of getting it wrong.

## Six log signatures, verified: how the precert transcript is actually rebuilt

The gap above is closed. `tools/fetch_evidence.py`'s `sct_signatures` now records cases in which this
library verified a **real log's real signature over a real certificate**: six certificates from six
public services, six different logs (`TrustAsia log2026a`, `Google Argon2027h1`, `Google Xenon2027h1`,
`DigiCert Sphinx2026h2`, `DigiCert Sphinx2027h1`, `Cloudflare Nimbus2027`), four operators. The
fixture is `tests/fixtures/live-sct-signatures.json` and the checks are offline.

The reconstruction is RFC 6962 section 3.2's own: take the certificate's `TBSCertificate`, delete the SCT
extension, and hash the **issuer's** `SubjectPublicKeyInfo`. Three things had to be got right, and each
was learned by failing:

1. **The issuer must come from the chain the server sent, not the chain OpenSSL built.**
   `get_unverified_chain`, not `get_verified_chain`. A CA that signs precertificates with a separate
   precertificate signing certificate leaves that certificate out of the built path, because path
   building has no use for it - and that certificate's key is precisely what the SCT's `issuer_key_hash`
   commits to. With the built path: 100 attempts, 0 verified. With the sent chain: 12 attempts, 6
   verified, every one at `chain[1]`, the leaf's issuer. The failures are kept in the fixture as
   `attempts`, and a test asserts that attempts exceed successes rather than letting a success-only
   capture look like a clean run.
2. **Deleting an extension means re-encoding three lengths** - the extension list, its `[3]` wrapper, and
   the TBS itself. The log hashed the shortened DER, not the original with a hole cut in it.
3. **`elements()` walks a list of TLVs, not one encoded value.** Passing it a TLV made it see a single
   element, report no extensions, and strip nothing - so every reconstruction came out exactly 21 bytes
   long (the poison extension's own DER size) and the mismatch looked like a protocol puzzle. The tell was
   that the delta was *constant*: real protocol variation is not that tidy, and a constant difference
   between two DER structures is a caller bug with high probability. Confirmed against ground truth before
   anything was claimed - see below.

**Ground truth, which is what made this trustworthy.** A log's precert entry stores both sides of the
question: `leaf_input` contains the `PreCert` it hashed (`issuer_key_hash` and the exact
`TBSCertificate`), while `extra_data` contains the precert as submitted plus the issuer chain. Stripping
the **poison** extension from that stored precert reproduces the logged `TBSCertificate` byte for byte, and
`issuer_key_hash` equals SHA-256 over the SPKI of `issuer_chain[0]`. That check needs no signature to
interpret, which is why it ran before any signature claim was written down - and it is now a tool rather
than a memory:

    python tools/check_precert_reconstruction.py --origin https://ct.cloudflare.com/logs/nimbus2026

Measured across three independent implementations: Google Argon2026h2 **8/8**, DigiCert Wyvern2026h2
**6/6**, Cloudflare Nimbus2026 **15/15** - **29 of 29**, exits non-zero on any mismatch. Cloudflare's Nimbus
is a separate codebase in C++, so the reconstruction rule is not a reading of one implementation's quirks.

**A claim of mine that measurement killed.** The earlier version of this file said the route to a
production SCT was "a merged log's `extra_data`, minus the SCT extension". Wrong: a stored precert is the
precert *as submitted*, which carries the **poison** extension and no SCTs at all, because the SCTs a CA
later embeds in the final certificate were never part of what the log received. Twenty recent entries
across two logs, none with an embedded list. The SCTs live on the final certificate, so the live
certificate is the only place to get one - and the reconstruction works there for the same reason it
works in the log: it is the same operation applied to the extension the CA swapped in.

A second finding from the same sweep, unexplained and recorded as such: for the **merged** entries at
Argon2026h2's indices 0-9, the stored `leaf_input` and `extra_data` do not correspond the way they do for
recently submitted entries - the logged TBS differs from the stored precert's by 11 bytes and diverges
from byte 4 onward, rather than by exactly one extension. Direct submissions reconstruct cleanly, so
nothing here depends on the merged case, but a client that assumes `extra_data` and `leaf_input` describe
the same structure in a static-merge log would be wrong, and nobody has told me why.

One more thing the real world threw up, filed because `certledger` will meet it: walking a chain served by
a production log produced a certificate whose **serial number is not positive**, which RFC 5280 forbids.
`cryptography` warns today and intends to raise; a strict parser will refuse to load a certificate that a
log accepted, stored, and hashed into its tree. Whether such an entry's leaf hash is even well-defined
for a verifier depends on which parser was used, so the answer belongs in the fetch layer's threat model
rather than in a warning nobody reads.


## `extra_data` is two structures, not one (2026-11-05)

RFC 6962 section 3.1 defines `X509ChainEntry` and `PrecertChainEntry` side by side, each a certificate
followed by a chain of certificates. A reader written from that section alone treats them alike, and that
reader is silently wrong for every x509 entry. Section 4.6 is the one that says what `get-entries` puts in
`extra_data`:

> extra_data: The base64-encoded unsigned data pertaining to the log entry. In the case of an X509ChainEntry,
> this is the "certificate_chain". In the case of a PrecertChainEntry, this is the whole "PrecertChainEntry".

The asymmetry is not an oversight. An x509 entry's `signed_entry` **is** the DER certificate
([§3.4](https://www.rfc-editor.org/rfc/rfc6962#section-3.4)), so the log already commits to it in the tree
and `extra_data` carries only the issuer chain; a precert entry's `signed_entry` is a `PreCert` - an issuer
key hash plus a TBSCertificate with the poison extension removed - so the submitted precertificate exists
nowhere else. Two logs were checked for the consequence and both behave this way: the leaf certificate never
appears in an x509 entry's `extra_data`, while the precertificate always appears in a precert entry's.

Measured over 736 entries from 23 operational logs, all read with no refusals: 452 precert entries, 284 x509.
The chain histogram is the reason the naive reader is dangerous rather than merely wrong:

| entry type | 1 chain cert | 2 | 3 or more |
|---|---|---|---|
| precert | 32 | 253 | 167 |
| x509 | 35 | 249 | 0 |

Reading an x509 blob as "certificate then vector" consumes the vector's total length as a certificate length,
lands exactly on the end of the blob, and reports **an empty chain and no error** - on 284 of 284 x509
entries, which is the only place the issuer intermediates appear. `parse_extra_data` takes the
`MerkleTreeLeaf` as an argument rather than an entry-type integer, so the caller cannot ask for a layout
without saying which entry the bytes belong to, and it returns `StoredChain` with `authenticated` set: for an
x509 entry the certificate is the leaf's, which the tree hashes, while the chain beside it is unsigned data
that section 4.6 explicitly declines to sign. A monitor that hashes the `extra_data` copy of an x509
certificate and calls it verified is claiming an integrity property the protocol does not have.

Two wrong turns on the way here are worth recording, because both produced confident answers. The first
survey bucketed the x509 blobs as "wrapped" and concluded that framing differed by implementation - Google
bare, Sectigo wrapped, DigiCert neither - which was an artifact of testing byte arithmetic without testing
DER structure. The corrected model that followed ("an extra length layer, then certificate then vector")
passed on all 284 x509 entries, and was still wrong: it happens to be exactly right when the chain holds one
certificate, which 249 of those 284 entries do not contradict because the shape it expects *is* two
certificates. The reading was only falsified by going to the section that defines the field.

## A precert entry's TBSCertificate is the precertificate's, minus the poison, minus two more things

An earlier note here recorded that at Argon2026h2 indices 0-9 the logged `TBSCertificate` differed from the
stored precert's by 11 bytes and diverged from byte 4 onward, while 13 recently submitted entries in the same
log reconstructed byte for byte, and it called this specific to static-merge logs. **Both halves of that
claim were wrong.** Three of those ten entries are x509 entries, whose `extra_data` contains no
precertificate at all, so part of the "divergence" was a real TBSCertificate compared against an issuer's.
And re-measured over 494 precerts in five logs, the remainder fails in *live* logs at the same rate as in
merged ones: 321 reconstruct and 173 do not, in Argon2027h1 as much as in Argon2026h2.

The rest is the specification, in RFC 6962 [§3.2¶9](https://www.rfc-editor.org/rfc/rfc6962#section-3.2),
which defines the logged `tbs_certificate` as the precertificate's TBS "without the signature and the poison
extension" and then adds, for a precertificate not signed by the CA that will issue the final certificate -
that is, signed by a Precertificate Signing Certificate (§3.1¶2):

> the TBSCertificate also has its issuer changed to that of the CA that will issue the final certificate ...
> the TBSCertificate also has its Authority Key Identifier changed to match the final issuer.

The prediction that follows is checkable and checked: for a precertificate signed by a PSC, the leaf's
`issuer_key_hash` is the hash of the *issuing CA's* SPKI, so it must match `chain[1]` and not `chain[0]`.
Cross-tabulated over all 494 precerts, the two classifications are perfectly diagonal with no exceptions:

| reconstruction | `issuer_key_hash` matches | precerts |
|---|---|---|
| poison removal alone | `chain[0]` | 321 |
| issuer and AKI also rewritten | `chain[1]` | 173 |

The rewritten ones carry a `chain[0]` whose subject says it, for instance
`O=Google Certificate Transparency (Precert Signing)`. The consequence for anything that builds an issuer
graph is immediate: **attribute a precert entry to `issuer_key_hash`, never to `chain[0]`.** A third of
`chain[0]` values are CT-only signing certificates that are not CAs in any sense a browser would recognise,
and a graph built from them would report phantom issuers holding a third of the world's issuance - and since
`extra_data` is unsigned while `issuer_key_hash` sits inside the hashed leaf, the authenticated field is also
the one that is merely correct.

Reproduce with `sdk-forge/probe_psc_rewriting.py` and `sdk-forge/probe_leaf_repetition.py`; the survey is
regenerated by `python tools/fetch_evidence.py --only-layout` into
`tests/fixtures/extra-data-layout.json` and asserted by `tests/test_production_extra_data.py`.

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

