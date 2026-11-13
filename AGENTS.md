# Instructions for coding agents

Certificate Transparency to RFC 9162: signed certificate timestamps, Merkle inclusion and consistency proofs, log storage tiles, and monitoring.

Primary documents are listed in `docs/rfc-map.md` with statuses and known errata.
The obligation table in `ROADMAP.md` is the work queue, and `README.md` explains
what the library is for. Read those three before changing anything.

## Finding work

If the person gave you a task, do that task.

If you arrived with nothing to do, run this from this directory:

    python -m projecthub pickup --who <your name> --project ctspy

Its output is your assignment: one row, already claimed for you, with what to build, the commands that prove
it and the ways to end it. The board decides the order of work, so the row it gives you is the row to work,
even if it is in another project. `NO WORK` is a real answer: ask the person what to work on.

Without the workspace beside this repository, read `.projecthub/packet.md` if it exists. If it does not, ask what
to work on.

## Commands

    python -m pip install -e ".[dev]"
    python -m pytest -q
    python -m pytest -q tests/test_roadmap_rows.py
    python -m pytest -q tests/test_public_api.py::test_stubs_are_loud
    python -m ruff check .
    python -m ruff format --check .
    python -m mypy ctspy tests

The first line installs the dev extras. The six commands after it are the gates,
and all six must pass before a change is finished. CI runs the same set on Linux
and Windows, plus the suite under `python -O`.

`python tools/fetch_evidence.py` is deliberately not in that list. It reaches the network and
rewrites the fixtures under `tests/fixtures/`, so it is run on purpose rather than incidentally - by a
person deciding the evidence should be refreshed, never by CI. The tests read those fixtures offline,
which is what keeps a log operator's bad afternoon from turning into a red build here.
`tools/check_precert_reconstruction.py` is the same kind of tool: also networked, also not a gate, but it
exits non-zero on a mismatch, so run it after touching anything under `tools/` that walks DER.

## Invariants

These are the points where a plausible-looking change makes the project wrong
rather than merely incomplete.

1. **Roadmap honesty.** Never change a `ROADMAP.md` row from `[ ]` to `[x]` unless
   the test named in its `Evidence` cell exists and passes. `tests/test_roadmap_rows.py`
   fails on any row that claims done without a named test, and that check is the
   reason the roadmap can be trusted. Do not weaken it, skip it, or delete it to
   get a green run.
2. **No silent stubs.** Code that is not implemented raises `NotImplementedError`.
   Never return an empty value, an empty collection, or a result object that reports
   success. A protocol library that answers nothing is worse than one that refuses
   to answer, and `tests/test_public_api.py` enforces that every stub is loud.
3. **Normative text is never paraphrased from memory.** Fetch it with `rfclib` and
   cite the section. If the text you fetch does not say what the obligation claims,
   the obligation is wrong: fix the roadmap row and say so in the commit.
4. **Dependencies.** Portfolio rule: the standard library, plus the `cryptography` package for
   cryptographic primitives only; ASN.1, X.509 and every wire format are our own code (`asn1core` by sibling
   path if ever needed, never `asn1crypto` or `pyasn1`). `pyproject.toml` here declares no runtime
   dependencies, and `certscan` walks DER in-tree. Adding a runtime
   dependency needs a paragraph of justification in `docs/strategy.md` explaining
   why the standard library is not enough.
5. **Scope.** What is deliberately absent is listed under Non-goals in `README.md`.
   An agent that "helpfully" implements a non-goal has expanded the API surface that
   has to be supported forever.

## Read before implementing

- RFC 9162 is Experimental with 1 erratum on file and none verified: expect variation between implementations and pin tests to real logs.
- RFC 6962 has a verified erratum, 3686 (only the first element of a precert chain may be a precertificate),
  applied in `entry.parse_extra_data`; see `docs/rfc-map.md`.
- Never locate a certificate extension by searching bytes for its OID; use `ctspy.certscan`.
- RFC 9162 obsoletes RFC 6962; log artifacts from 2013 deployments still follow 6962 shapes, so the reader must accept both.

## Protocol work

`.clinerules/10-rfclib.md` describes the `rfclib` calls to make for each obligation
and lists the section refs for this project. If you are not running in Cline, the
same procedure applies: confirm the document, read its errata, pull the normative
statements, then write code.
