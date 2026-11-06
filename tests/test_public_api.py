"""The shell contract: the surface exists, is documented, and refuses to lie.

These are the tests that must fail loudly if a stub ever starts returning a plausible
empty value instead of raising. That is how a protocol library quietly becomes wrong: a
decoder learns to return an empty object rather than refuse, and every caller downstream
reads confidence where there was only silence.
"""

from __future__ import annotations

import importlib
import pathlib

import pytest

import ctspy as package

SURFACE = [
    ("sct", "parse", "RFC 9162"),
    ("sct", "verify", "RFC 9162"),
    ("sth", "verify", "RFC 9162"),
    ("merkle", "verify_inclusion", "RFC 9162"),
    ("merkle", "verify_consistency", "RFC 9162"),
    ("tiles", "fetch_tile", "RFC 9162"),
    ("client", "add_chain", "RFC 9162"),
    ("monitor", "watch", "RFC 9162"),
    ("policy", "acceptable", "design"),
]


def test_version_is_a_string():
    assert isinstance(package.__version__, str)


def test_public_names_all_exist():
    missing = [name for name in package.__all__ if not hasattr(package, name)]
    assert not missing, "__all__ names things that do not exist: " + ", ".join(missing)


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_surface_is_documented(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    assert target.__doc__, fn + " needs a docstring"
    assert cite in target.__doc__, fn + " must cite the document that defines it"


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_stubs_are_loud(module_name, fn, cite):
    """A stub must raise; an implementation must be claimed in the roadmap. No third state.

    This used to `pytest.skip` once a function was implemented, which quietly removed three checks
    from the run and left the obligation matrix free to lag: code lands, the row still says `[ ]`,
    and nothing notices because the test that could have noticed had skipped itself. The row is now
    part of the assertion, so the matrix cannot drift from the surface without going red.
    """
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    label = f"`{module_name}.{fn}()`"
    if "Not implemented yet" not in (target.__doc__ or ""):
        status = roadmap_status(label)
        assert status == "[ok]", (
            f"{label} is implemented but ROADMAP.md records it as {status!r}; close the row with "
            "the test that pins it, or make the stub loud again"
        )
        return
    with pytest.raises((NotImplementedError, TypeError)):
        target()


def roadmap_status(label: str) -> str | None:
    """The status cell of this obligation's row in ROADMAP.md, or None if it has no row."""
    roadmap = pathlib.Path(package.__file__).resolve().parents[1] / "ROADMAP.md"
    for line in roadmap.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0] == label:
            return cells[2].strip("`")
    return None


def test_every_error_this_package_raises_is_a_ctspyerror() -> None:
    """One `except CtspyError` must catch everything this package rejects, and nothing else.

    The docstring in `errors.py` has claimed `CtspyError` is the base for all of it since the first draft,
    while `TranscriptError`, `ProofFormatError` and `SignatureDecodeError` subclassed `ValueError` instead.
    `certledger` wrote `except CtspyError` around entry parsing, believed the claim, and let a malformed leaf
    escape - which is how a consumer discovers that an error hierarchy is documentation rather than code.

    The structural errors stay `ValueError`s too, so anything already catching bad bytes keeps catching
    them. `VerificationError` is deliberately not one: a log that signed something bogus is not a caller that
    passed a bad argument, and a handler written for the second must not swallow the first.
    """
    from ctspy import ecdsa, errors, merkle, transcript

    structural = (transcript.TranscriptError, merkle.ProofFormatError, ecdsa.SignatureDecodeError)
    for error in (*structural, errors.VerificationError):
        assert issubclass(error, errors.CtspyError), error
    for error in structural:
        assert issubclass(error, ValueError), error
    assert not issubclass(errors.VerificationError, ValueError)
