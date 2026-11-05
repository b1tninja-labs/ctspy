# Security policy

## What this project treats as a security property

- **Hostile input is the normal case.** Every decoder has to refuse truncation, over-long
  lengths, nested structures and contradictory fields without raising anything a caller
  cannot name.
- **Bounds before cleverness.** Size, count and depth limits exist on every parse path, and
  they are configuration rather than suggestions.
- **No silent crypto policy.** Weak or deprecated algorithms are refused by an explicit
  policy object rather than accepted because they happen to parse.
- **Provenance is part of the answer.** A result states what was verified, what was cached
  and what was skipped, so a caller cannot mistake an unchecked field for a checked one.

## assert is not a safety mechanism

`python -O` strips asserts. Any invariant that protects a parser boundary or a verification
result must be expressed as a raised exception. CI runs the suite under `-O` for exactly
this reason.

## Reporting

Open a private security advisory on the repository rather than a public issue. The policy is
the Apache Software Foundation's: security support for the main branch and the most recent
release. Because this repository is a pre-alpha shell, a report will often be answered with
"that code does not exist yet", which is a different thing from "it will not be fixed".
