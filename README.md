# ctspy

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

ctspy -- certificate transparency verification in Python

CT is the audit trail for the whole Web PKI and Python cannot read it. Verifying that a certificate really is in a log means parsing an SCT, checking a signed tree head, and validating Merkle inclusion and consistency proofs over the tile layout logs publish. RFC 9162 defines version 2.0 and it is worth saying plainly that the RFC Editor records it as Experimental, obsoleting RFC 6962, which is why deployment policy rather than the RFC is the real compatibility target. Nothing on PyPI does any of this: ctlog is a combinatorial testing tool, ctkit is medical image processing, sct is a radar calibration toolbox, and transparency is a model explanation library.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| ctlog | 0.7.1 | 2026-06-14 | SAT based combinatorial testing, unrelated |
| ctkit | 0.1.1 | 2026-09-11 | CT image processing, unrelated |
| Trillian, tombstone, ct-go | - | - | the Go tooling that actually runs the logs; no Python equivalent |

What this project intends to add:

- SCT parsing from the TLS extension, from X.509 and from OCSP, and signature verification against log keys
- signed tree head verification and the static Merkle tree with hashed leaf prefixes
- inclusion and consistency proof validation, including the empty tree and single leaf edges
- log storage tile fetching with cache control and mirror fallback
- a monitor that watches issued certificates and diffs them against what logs claim

What works today, as of 2026-11-05 - the list above is the plan, this is the code:

- v1 and v2 signed tree heads, parsed and verified: transcript, ECDSA P-256 in pure Python, no
  third-party crypto
- the static Merkle tree, both algorithms the specification gives, plus inclusion and consistency proof
  validation with the ragged-tree edges covered
- v1 tree leaves (`MerkleTreeLeaf`, x509 and precert entries) and v1 SCTs: wire parsing, list parsing,
  and signature verification against a log key
- evidence rather than assertions: 23 operational logs' heads verified under their published keys,
  consistency proofs tying roots this library computed to a signed 3-billion-entry tree, six SCT
  signatures from six logs across four operators, and the precert reconstruction checked against entries
  three independent implementations serve. See [docs/interop.md](docs/interop.md).
- Chrome's signed CT log list, verified offline: `loglist` checks the published RSASSA-PKCS1-v1_5/SHA-256
  signature with a pure-Python RSA public operation, so a journaled snapshot stays checkable without trusting the
  transport. It verifies a document and says nothing about whether a certificate is compliant - deciding that is
  the platform's job, see "What it does not do".

Not built: v2 `TransItem` and v2 SCTs, tile fetching, submission, monitoring, and policy - partly
because RFC 9162's v2 has no deployed log to verify against yet.

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9162 | Experimental | 2021-12 | CT 2.0: SCTs, signed tree heads, the two proof types and the TLS extension |
| RFC 6962 | Obsolete | 2013-07 | version 1.0, still what many logs and captures emit |

### Errata watch

- RFC 9162 is Experimental with 1 erratum on file and none verified: expect variation between implementations and pin tests to real logs.
- RFC 9162 obsoletes RFC 6962; log artifacts from 2013 deployments still follow 6962 shapes, so the reader must accept both.

## Module layout

| Module | Responsibility |
|---|---|
| `sct` | timestamp structure, versions and signature verification (RFC 9162) |
| `sth` | signed tree heads, timestamps and the STH consistency rule (RFC 9162) |
| `merkle` | static Merkle trees, leaf and node hash prefixes, proof validation (RFC 9162) |
| `tiles` | log storage layout, fetching and caching (RFC 9162) |
| `client` | add chain, add prechain, get sth and the submission endpoints (RFC 9162) |
| `monitor` | stream reading, diffing and alerting on unexpected issuance |
| `policy` | which logs and which artifacts a deployment will accept |
| `loglist` | verifying Chrome's signed log list (not RFC 9162 - a platform mechanism a monitor has to check) |

## What it does not do

- running a log: the audit trail needs independent operators, not another client library
- browser policy decisions about which logs are accepted, which belong to the platform
- certificate issuance, which is enrollkit and pkix


## Install

```bash
git clone https://github.com/b1tninja/ctspy ctspy
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

Every gate in [AGENTS.md](AGENTS.md) must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy ctspy tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
