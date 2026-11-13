---
description: Implement one ROADMAP.md obligation, correctly and verifiably
---

Implement the next unchecked row of `ROADMAP.md` in this project, working from
`docs/rfc-map.md` for the document and section.

1. Read the row and quote its spec anchor and evidence cells back. Confirm the
   document with `rfc_info` and `rfc_errata` before writing code, and stop if
   it turns out to be obsolete or superseded.
2. Fetch the normative text with `rfc_read(..., view="normative")`. If what you
   fetch does not state what the row claims, say so and fix the row rather than
   coding to a wrong requirement.
3. Write the test first, using recorded fixtures rather than a live endpoint. Run it
   and watch it fail.
4. Implement the minimum that makes it pass. Anything left unimplemented keeps
   raising `NotImplementedError`.
5. Flip the row to done and name the test in its evidence cell. Do not flip the row
   if the test does not exist and pass.
6. Run every gate listed in `AGENTS.md` and fix what fails.
7. Commit with the citation from `rfc_cite` in the message body. No
   `Co-Authored-By` trailer.
