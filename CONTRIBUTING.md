# Contributing

Short version: four gates, and they all have to pass on Linux and Windows.

```bash
ruff check . && ruff format --check .
mypy ctspy
pytest -q --cov
python -O -m pytest -q
```

## The three rules that cause the most arguments

1. **`assert` belongs in tests and nowhere on a wire path.** The fourth gate strips
   asserts, and a parser whose bounds checks were asserts stops being a parser in
   production. On a parse path, raise a named exception.
2. **A behaviour change updates its ROADMAP row in the same commit.** The row flips to
   `[ok]` only with a named test. A row and a test drift apart within one release, and the
   matrix becomes useless exactly when someone needs it.
3. **Cite the document, not a blog post.** A section number is allowed only if that section
   was read. `docs/rfc-map.md` records what was verified and when.

## Layout

| Tier | Home | Rule |
|---|---|---|
| Core | `ctspy/` | specification behaviour only; dependency-free unless README says why not |
| Apps | `ctspy/apps/` | composes core pieces, adds no new protocol surface |
| Examples | `examples/` | one runnable script per use case; never restates library logic |

A pattern graduates from `examples/` to `apps/` on the second user, stated rather than
assumed.

## Tests

Protocol tests are vectors first: bytes in, structure out, with the source of the vector
cited. `hypothesis` is welcome for codecs, and every fuzz-found crash becomes a fixed
regression test rather than only a property.

## Milestones

Pick a row from the matrix, not a feature from your imagination. If the row you want is
missing, add it to the matrix first and argue for it there.
