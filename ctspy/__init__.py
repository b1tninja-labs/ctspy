"""ctspy -- certificate transparency verification in Python.

CT is the audit trail for the whole Web PKI and Python cannot read it.
"""

from __future__ import annotations

from . import apps, cli, client, merkle, monitor, policy, sct, sth, tiles
from .client import add_chain
from .merkle import verify_consistency, verify_inclusion
from .monitor import watch
from .policy import acceptable
from .sct import parse, verify
from .tiles import fetch_tile

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "acceptable",
    "add_chain",
    "apps",
    "cli",
    "client",
    "fetch_tile",
    "merkle",
    "monitor",
    "parse",
    "policy",
    "sct",
    "sth",
    "tiles",
    "verify",
    "verify_consistency",
    "verify_inclusion",
    "watch",
]
