"""ctspy -- certificate transparency verification in Python.

CT is the audit trail for the whole Web PKI and Python cannot read it.
"""

from __future__ import annotations

from . import (
    apps,
    cli,
    client,
    ecdsa,
    entry,
    errors,
    merkle,
    monitor,
    policy,
    sct,
    sth,
    tiles,
    transcript,
)
from .client import add_chain
from .ecdsa import EcdsaKey
from .entry import MerkleTreeLeaf
from .errors import CtspyError, VerificationError
from .merkle import verify_consistency, verify_inclusion
from .monitor import watch
from .policy import acceptable
from .sct import SignedCertificateTimestamp, parse, parse_list, verify
from .sth import SignedTreeHeadV1, SignedTreeHeadV2
from .tiles import fetch_tile
from .transcript import Extension, Reader, TranscriptError, Writer

__version__ = "0.1.0"

__all__ = [
    "CtspyError",
    "EcdsaKey",
    "Extension",
    "MerkleTreeLeaf",
    "Reader",
    "SignedCertificateTimestamp",
    "SignedTreeHeadV1",
    "SignedTreeHeadV2",
    "TranscriptError",
    "VerificationError",
    "Writer",
    "__version__",
    "acceptable",
    "add_chain",
    "apps",
    "cli",
    "client",
    "ecdsa",
    "entry",
    "errors",
    "fetch_tile",
    "merkle",
    "monitor",
    "parse",
    "parse_list",
    "policy",
    "sct",
    "sth",
    "tiles",
    "transcript",
    "verify",
    "verify_consistency",
    "verify_inclusion",
    "watch",
]
