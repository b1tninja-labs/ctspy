"""Tiled logs: tile paths, data-tile parsing and tile fetching as functions of bytes.

C2SP's ``tlog-tiles`` (the layout) and ``static-ct-api`` (what a Certificate Transparency log puts in it),
both read at commit ``09f3e519fe79bcbdccadcf821182e3b488a14d71`` from the editor's copies, files pinned by
sha256 (``951b7c96...`` and ``e7173ca6...``). Neither is an RFC; RFC 9162 specifies no tiles (its outline
has no tile section), and RFC 6962 only supplies the hashing, which both specifications adopt: "all Merkle
tree cryptographic operations are as specified by RFC 6962" with SHA-256.

Nothing here touches the network. Paths and widths are computed, bytes are parsed and checked, and
:func:`fetch_tile` gets its bytes from a ``get`` callable the caller supplies, so the policy of the
specification (try another URL prefix on failure, never follow redirects, fall back to the full tile when a
partial one is gone) is testable without a socket. What is *not* done here is verification of a tile against
a checkpoint; :func:`verify_data_tile` ties a data tile to its level-0 hash tile, and
:func:`subtree_hash` computes the hash a tile contributes to the level above.

The layout, as the two documents state it:

* ``<prefix>/tile/<L>/<N>[.p/<W>]`` holds ``W`` (1..255, partial) or 256 consecutive Merkle Tree Hashes of
  32 bytes. ``L`` is 0 to 63 in tlog-tiles and 0 to 5 in static-ct-api. ``N`` is a path of 3-digit elements,
  all but the last prefixed ``x``.
* ``<prefix>/tile/data/<N>[.p/<W>]`` (tlog-tiles calls the directory ``entries``) holds the entries whose hashes
  the level-0 tile at the same ``N`` and ``W`` holds. In static-ct-api each is a ``TileLeaf``.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Literal

from . import merkle
from .entry import MAX_ENTRY, V1_LEAF_TYPE, V1_PRECERT_ENTRY, V1_VERSION, TimestampedEntry
from .errors import CtspyError, VerificationError
from .transcript import Reader, TranscriptError

__all__ = [
    "FULL_WIDTH",
    "HASH_SIZE",
    "TileLeaf",
    "TileNotFoundError",
    "TileRef",
    "TiledLog",
    "fetch_tile",
    "format_index",
    "leaf_index_of",
    "parse_data_tile",
    "parse_hash_tile",
    "parse_index",
    "parse_tile_path",
    "subtree_hash",
    "tile_path",
    "tile_width",
    "tiles_for_tree",
    "verify_data_tile",
]

FULL_WIDTH = 256  # tlog-tiles, "Merkle Tree": full tiles are exactly 256 hashes wide
HASH_SIZE = 32  # SHA-256
MAX_LEVEL_TLOG_TILES = 63  # tlog-tiles: "a decimal ASCII integer between 0 and 63"
MAX_LEVEL_STATIC_CT = 5  # static-ct-api: "between 0 and 5"

Kind = Literal["hash", "data", "entries"]


class TileNotFoundError(CtspyError):
    """A ``get`` callable raises this for a tile the log does not serve (a 404, a pruned tile)."""


class TiledLog:
    """The parameters of a tiled log that fetching needs: its URL prefixes.

    ``prefixes`` are the log's alternate serving URLs, each without a trailing slash ("The resources at
    each URL prefix MUST serve the same content"). ``max_level`` is 5 for a static-ct-api log and 63 for any
    other tlog-tiles log. The checkpoint origin and keys are the checkpoint module's business.
    """

    __slots__ = ("max_level", "prefixes")

    def __init__(self, prefixes: Sequence[str], *, max_level: int = MAX_LEVEL_STATIC_CT) -> None:
        if not prefixes:
            raise ValueError("a tiled log has at least one URL prefix")
        if not 0 <= max_level <= MAX_LEVEL_TLOG_TILES:
            raise ValueError(f"max_level {max_level} is outside 0..{MAX_LEVEL_TLOG_TILES}")
        self.prefixes = tuple(prefix.rstrip("/") for prefix in prefixes)
        self.max_level = max_level


# ---- paths ---------------------------------------------------------------------------------------


def format_index(index: int) -> str:
    """The ``<N>`` path of tile ``index``: 3-digit elements, all but the last prefixed ``x``.

    tlog-tiles' example: 1234067 is ``x001/x234/067``.
    """
    if index < 0:
        raise ValueError("a tile index is a non-negative integer")
    elements = []
    while True:
        elements.append(f"{index % 1000:03d}")
        index //= 1000
        if index == 0:
            break
    elements.reverse()
    return "/".join([*(f"x{e}" for e in elements[:-1]), elements[-1]])


def parse_index(text: str) -> int:
    """The index a ``<N>`` path names; anything but the one canonical spelling is refused.

    Canonical means no leading zero element (index 1 is ``001``, never ``x000/001``), which is this
    library's reading: the text asks for "zero-padded 3-digit path elements" and gives one encoding.
    """
    elements = text.split("/")
    if not all(re.fullmatch(r"x?[0-9]{3}", element) for element in elements):
        raise TranscriptError(f"{text!r} is not a tile index path of 3-digit elements")
    if elements[-1].startswith("x") or not all(e.startswith("x") for e in elements[:-1]):
        raise TranscriptError(
            f"{text!r}: every element but the last begins with x, and the last does not"
        )
    if len(elements) > 1 and elements[0] == "x000":
        raise TranscriptError(f"{text!r} has a leading zero element; the index has one spelling")
    return int("".join(e.removeprefix("x") for e in elements))


def tile_path(
    level: int,
    index: int,
    width: int = FULL_WIDTH,
    *,
    kind: Kind = "hash",
    max_level: int = MAX_LEVEL_STATIC_CT,
) -> str:
    """The path below a prefix of a tile: ``tile/<L>/<N>`` or ``tile/data/<N>``, ``.p/<W>`` if partial.

    ``kind`` is ``hash`` for a Merkle tile, ``data`` for static-ct-api's data tile and ``entries`` for
    tlog-tiles' entry bundle (the same position, a different directory name). Data and entry tiles have no level.
    """
    if not 1 <= width <= FULL_WIDTH:
        raise ValueError(f"a tile is 1 to {FULL_WIDTH} hashes wide, not {width}")
    suffix = "" if width == FULL_WIDTH else f".p/{width}"
    if kind == "hash":
        if not 0 <= level <= max_level:
            raise ValueError(f"level {level} is outside 0..{max_level}")
        return f"tile/{level}/{format_index(index)}{suffix}"
    if level != 0:
        raise ValueError("data tiles and entry bundles are level 0")
    return f"tile/{kind}/{format_index(index)}{suffix}"


@dataclass(frozen=True, slots=True)
class TileRef:
    """A parsed tile path: which tile, and how wide."""

    kind: Kind
    level: int
    index: int
    width: int

    @property
    def partial(self) -> bool:
        return self.width != FULL_WIDTH


def parse_tile_path(path: str, *, max_level: int = MAX_LEVEL_STATIC_CT) -> TileRef:
    """The inverse of :func:`tile_path`, strict: a width of ``256``, a leading zero or a stray level fail."""
    match = re.fullmatch(
        r"tile/(?P<kind>data|entries|[0-9]+)/(?P<index>[x0-9/]+?)(?:\.p/(?P<width>[0-9]+))?", path
    )
    if match is None:
        raise TranscriptError(f"{path!r} is not a tile path")
    width = FULL_WIDTH
    if match["width"] is not None:
        text = match["width"]
        if text != str(int(text)) or not 1 <= int(text) <= FULL_WIDTH - 1:
            raise TranscriptError(
                f"{path!r}: a partial tile is 1 to 255 hashes wide, no leading zero"
            )
        width = int(text)
    index = parse_index(match["index"])
    name = match["kind"]
    if name == "data":
        return TileRef("data", 0, index, width)
    if name == "entries":
        return TileRef("entries", 0, index, width)
    if name != str(int(name)) or int(name) > max_level:
        raise TranscriptError(
            f"{path!r}: level {name} is not 0..{max_level} without leading zeroes"
        )
    return TileRef("hash", int(name), index, width)


def tile_width(tree_size: int, level: int, index: int) -> int:
    """The width the tile ``(level, index)`` has in a tree of ``tree_size`` leaves (tlog-tiles, Partial Tiles).

    A tile whose entries all lie inside the tree is full; the one tile at the edge has
    ``floor(size / 256**level) mod 256`` hashes; a tile beyond the edge does not exist (``ValueError``),
    because "Empty tiles MUST NOT be served".
    """
    span = FULL_WIDTH**level
    if (index + 1) * FULL_WIDTH * span <= tree_size:
        return FULL_WIDTH
    edge = tree_size // (FULL_WIDTH * span)
    width = (tree_size // span) % FULL_WIDTH
    if index != edge or width == 0:
        raise ValueError(f"tile {level}/{index} does not exist in a tree of {tree_size} leaves")
    return width


def tiles_for_tree(tree_size: int, *, max_level: int = MAX_LEVEL_STATIC_CT) -> Iterator[TileRef]:
    """Every hash tile a tree of ``tree_size`` leaves is made of, full tiles then the partial one, per level.

    tlog-tiles' example: 70,000 leaves is 273 full and one partial (112 wide) at level 0, one full and one
    partial (17) at level 1, one partial (1) at level 2.
    """
    for level in range(max_level + 1):
        span = FULL_WIDTH**level
        full = tree_size // (FULL_WIDTH * span)
        for index in range(full):
            yield TileRef("hash", level, index, FULL_WIDTH)
        partial = (tree_size // span) % FULL_WIDTH
        if partial:
            yield TileRef("hash", level, full, partial)
        if tree_size < span:
            break


# ---- hash tiles ----------------------------------------------------------------------------------


def parse_hash_tile(data: bytes, width: int) -> list[bytes]:
    """The ``width`` 32-byte hashes of a tile; any other length is refused (full: 8,192 bytes)."""
    if len(data) != width * HASH_SIZE:
        raise TranscriptError(
            f"a tile {width} hashes wide is {width * HASH_SIZE} bytes, this one is {len(data)}"
        )
    return [data[i : i + HASH_SIZE] for i in range(0, len(data), HASH_SIZE)]


def subtree_hash(hashes: Sequence[bytes]) -> bytes:
    """The Merkle Tree Hash of the subtree whose leaves are ``hashes`` (RFC 6962 sec. 2.1, SHA-256).

    For the hashes of a *full* level-``l`` tile this is the hash that sits in the tile above ("each hash in a
    tile is the Merkle Tree Hash of a full tile at the level below"); a partial tile is never hashed upward.
    """
    if not hashes:
        raise ValueError("an empty tile has no subtree hash")
    if len(hashes) == 1:
        return hashes[0]
    split = 1 << ((len(hashes) - 1).bit_length() - 1)
    return merkle.node_hash(subtree_hash(hashes[:split]), subtree_hash(hashes[split:]))


# ---- data tiles ----------------------------------------------------------------------------------


def leaf_index_of(extensions: bytes) -> int | None:
    """Read a ``CtExtensions`` body as static-ct-api defines it: one-byte type, two-byte length.

    ``leaf_index`` (type 0) carries a big-endian 40-bit index. Duplicate types and a ``leaf_index`` of any
    other length are refused (``MUST NOT``, ``MUST``); other types are skipped, their order ignored.
    """
    reader = Reader(extensions, what="CtExtensions")
    seen: set[int] = set()
    found: int | None = None
    while reader.remaining():
        kind = reader.uint8()
        body = reader.opaque(length_bytes=2, minimum=0, maximum=0xFFFF)
        if kind in seen:
            raise TranscriptError(f"CtExtensions: extension type {kind} appears twice")
        seen.add(kind)
        if kind == 0:
            if len(body) != 5:
                raise TranscriptError(
                    f"a leaf_index is a 40-bit integer, this one is {len(body)} bytes"
                )
            found = int.from_bytes(body, "big")
    return found


@dataclass(frozen=True, slots=True)
class TileLeaf:
    """One ``TileLeaf`` of static-ct-api's data tile.

    ``timestamped_entry`` is RFC 6962's ``TimestampedEntry``, ``raw_entry`` the exact bytes it was parsed from
    (the hash is over those, not over a re-encoding), ``pre_certificate`` the submitted precertificate when
    the entry is a ``precert_entry`` and ``None`` for an ``x509_entry`` ("Empty"), and ``chain`` the SHA-256
    fingerprints of the issuers, each of which the log serves at ``issuer/<fingerprint>``.
    """

    timestamped_entry: TimestampedEntry
    raw_entry: bytes
    pre_certificate: bytes | None
    chain: tuple[bytes, ...]

    @property
    def merkle_tree_leaf(self) -> bytes:
        """The ``MerkleTreeLeaf`` of RFC 6962 sec. 3.4: version v1, ``timestamped_entry``, then the entry."""
        return bytes([V1_VERSION, V1_LEAF_TYPE]) + self.raw_entry

    def leaf_hash(self) -> bytes:
        """The hash the level-0 tile holds for this entry: ``SHA-256(0x00 || MerkleTreeLeaf)``."""
        return merkle.leaf_hash(self.merkle_tree_leaf)

    @property
    def leaf_index(self) -> int | None:
        """The ``leaf_index`` extension of static-ct-api in the entry's extensions, if there is one."""
        return leaf_index_of(self.timestamped_entry.extensions)


def parse_data_tile(data: bytes) -> tuple[TileLeaf, ...]:
    """Every ``TileLeaf`` of a data tile (static-ct-api, "Log entries"), strictly.

    A tile is a bare sequence of leaves with no count and no padding, so the parse runs to the last byte; a
    truncated leaf, an undefined ``entry_type``, an empty certificate, a chain that is not whole
    fingerprints or trailing bytes raise :class:`~ctspy.transcript.TranscriptError`. An empty tile is
    refused: "Empty tiles MUST NOT be served".
    """
    if not data:
        raise TranscriptError("a data tile has at least one entry")
    reader = Reader(data, what="data tile")
    leaves: list[TileLeaf] = []
    while reader.remaining():
        start = len(data) - reader.remaining()
        entry = TimestampedEntry.parse(reader)
        raw_entry = data[start : len(data) - reader.remaining()]
        pre_certificate = None
        if entry.entry.entry_type == V1_PRECERT_ENTRY:
            pre_certificate = reader.opaque(length_bytes=3, minimum=1, maximum=MAX_ENTRY)
        chain_bytes = reader.opaque(length_bytes=2, minimum=0, maximum=0xFFFF)
        if len(chain_bytes) % HASH_SIZE:
            raise TranscriptError(
                f"certificate_chain is {len(chain_bytes)} bytes, not whole 32-byte fingerprints"
            )
        chain = tuple(chain_bytes[i : i + HASH_SIZE] for i in range(0, len(chain_bytes), HASH_SIZE))
        leaves.append(TileLeaf(entry, raw_entry, pre_certificate, chain))
    return tuple(leaves)


def verify_data_tile(data: bytes, level0_hashes: bytes) -> tuple[TileLeaf, ...]:
    """Parse a data tile and check each entry hashes to the hash the level-0 tile holds at its position.

    "Each entry in a bundle hashes to the corresponding entry in the corresponding level 0 Merkle Tree
    tile." Both arguments are the raw bytes of the tiles at the same index and width. Raises
    :class:`~ctspy.errors.VerificationError` on the first position that disagrees, and when the tiles
    differ in width. This ties the entries to the hashes; tying the hashes to a checkpoint is the caller's
    (and needs the level-above tiles and a verified checkpoint).
    """
    leaves = parse_data_tile(data)
    hashes = parse_hash_tile(level0_hashes, len(level0_hashes) // HASH_SIZE)
    if len(leaves) != len(hashes):
        raise VerificationError(
            f"the data tile has {len(leaves)} entries, the hash tile {len(hashes)}"
        )
    for position, (leaf, expected) in enumerate(zip(leaves, hashes, strict=True)):
        if leaf.leaf_hash() != expected:
            raise VerificationError(f"entry {position} does not hash to the level-0 tile's hash")
    return leaves


# ---- fetching ------------------------------------------------------------------------------------

Getter = Callable[[str], Awaitable[bytes]]


async def fetch_tile(
    log: TiledLog,
    index: int,
    width: int,
    *,
    get: Getter,
    level: int = 0,
    kind: Kind = "hash",
) -> bytes:
    """Fetch tile ``index`` of ``level`` through ``get`` and return its checked bytes (C2SP tlog-tiles, not RFC 9162).

    ``get(url)`` is the caller's transport: it returns the body, raises :class:`TileNotFoundError` when the
    resource is absent, and must not follow redirects ("MUST NOT serve redirect responses"). The URL prefixes
    are tried in order, which is the specified recovery ("If fetching a resource fails, clients SHOULD try
    fetching the corresponding resource on another URL prefix"); balancing between them is the transport's.
    A partial tile (``width`` under 256) that no prefix serves is looked for as the full tile, which tlog-tiles
    allows a log to have replaced it with; the caller tells which it got by the length. A hash tile must be
    ``32 * width`` bytes and a data tile must parse to ``width`` entries, or the answer is rejected and the next
    prefix tried. When every prefix fails, the last failure is raised.

    Only call this for a partial tile when a verified checkpoint requires it: "Clients MUST NOT fetch
    arbitrary partial tiles without verifying a checkpoint with a size that requires their existence".
    """
    wanted = [width] if width == FULL_WIDTH else [width, FULL_WIDTH]
    failure: Exception = TileNotFoundError("no URL prefix served the tile")
    for attempt in wanted:
        path = tile_path(level, index, attempt, kind=kind, max_level=log.max_level)
        for prefix in log.prefixes:
            try:
                body = await get(f"{prefix}/{path}")
            except TileNotFoundError as error:
                failure = error
                continue
            try:
                _check(body, attempt, kind)
            except TranscriptError as error:
                failure = error
                continue
            return body
    raise failure


def _check(body: bytes, width: int, kind: Kind) -> None:
    if kind == "hash":
        parse_hash_tile(body, width)
        return
    count = len(parse_data_tile(body))
    if count != width:
        raise TranscriptError(f"a data tile of width {width} holds {count} entries")
