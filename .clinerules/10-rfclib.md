---
description: Fetch the specification text before changing protocol code
paths:
  - "ctspy/**"
  - "tests/**"
---

# Working from the RFC with rfclib

The `rfclib` MCP server is the authority for what a specification says. Model
knowledge of RFC numbers and wording is not reliable here, and this portfolio has
already had to correct numbers that looked right (DHCPv6 is RFC 9915, not 8415;
RRDP is RFC 8182, not 9183).

Work through the obligations in `ROADMAP.md` one row at a time. For each row:

1. **Confirm the document.** `rfclib.info("RFC9162")` returns status,
   publication date, the updates/obsoletes graph and an errata summary. If the
   document is obsolete or has a successor, stop and flag the roadmap row before
   writing any code.
2. **Read the errata.** `rfclib.errata("RFC9162")` gives the verified
   corrections with their replacement text. A verified erratum is the
   specification: an implementation that follows the original text is wrong.
   RFC 4795 carries six, RFC 9162 one, RFC 6960 one.
3. **Pull only the normative statements.** `rfclib.read("RFC9162",
   view="normative")` returns the MUST, SHOULD and MAY sentences in that scope.
   Read them before choosing a data structure, not after.
4. **Find the specific rule instead of guessing its name.**
   `rfclib.grep("RFC9162", pattern="parse")` searches one document for a
   field name, ABNF rule or error code, which is cheaper than reading a section.
5. **Cite rather than paraphrase.** `rfclib.cite("RFC9162",
   style="verbose")` yields label, title, date, status, anchor URL and errata
   status. Put that in the docstring or the commit message. Never restate normative
   prose in your own words.

Refs accept a bare document (`RFC9162`), a section (append the section symbol and
number), a paragraph within a section, a line range like `RFC9162:120-140`, and a
table like `RFC9162#table-2`. Reads end with `next: <ref>` when the scope exceeds the
budget, so page through rather than guessing. Paragraph markers are printed on each
paragraph so a single one can be quoted exactly.

To decide *which* document applies, `rfclib.search("...", scope="documents")`
matches titles and abstracts while `scope="sections"` says which passage answers the
question. `rfclib.outline("RFC9162", contains="security")` lists sections
with their line ranges.

## Section refs for this project

- RFC 9162 (Experimental, 2021-12)
- RFC 6962 (Obsolete, 2013-07)

## Traps that have already bitten this portfolio

- A status of `INFORMATIONAL` means the document contains no protocol requirements,
  however normative its prose reads. Check before quoting a MUST.
- Numbers move: 6486 became 9286, 8941 became 9651, 4210 became 9810, 7752 became
  9552. Re-read `docs/rfc-map.md` rather than trusting an older note.
- An empty response is a protocol outcome, not a success value. Distinguish "the
  server said no" from "nothing arrived", or you reproduce the RFC 9849 compression
  failure, where a silent empty value made an optional extension load-bearing.
