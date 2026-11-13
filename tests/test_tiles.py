"""Tiled logs: C2SP tlog-tiles and static-ct-api at commit 09f3e519fe79bcbdccadcf821182e3b488a14d71.

The specifications' own examples are used as the vectors: index 1234067 is ``x001/x234/067``, and a tree of
70,000 leaves is 273 full level-0 tiles, a partial one 112 wide, a full and a partial (17) level-1 tile and a
partial (1) level-2 tile. The tile contents are INVENTED: neither specification has a sample tile, the
entries are built here with ``struct`` (not ctspy's writer) from RFC 6962 sec. 3.4 and static-ct-api's
``TileLeaf``, and the hashes are cross-checked against ctspy's independent Merkle code.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct

import pytest

from ctspy import merkle, tiles
from ctspy.errors import VerificationError
from ctspy.tiles import TiledLog, TileNotFoundError
from ctspy.transcript import TranscriptError


def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_index_extension(index: int) -> bytes:
    body = index.to_bytes(5, "big")
    return b"\x00" + struct.pack(">H", len(body)) + body


def tile_leaf(
    n: int, *, precert: bool = False, chain: int = 2, extensions: bytes | None = None
) -> bytes:
    """Bytes of one TileLeaf, built field by field from static-ct-api and RFC 6962 sec. 3.4."""
    ext = leaf_index_extension(n) if extensions is None else extensions
    cert = bytes([0x30, 0x03, 0x02, 0x01, n % 256])
    if precert:
        signed = (
            struct.pack(">H", 1)
            + sha(b"issuer key %d" % n)
            + struct.pack(">I", len(cert))[1:]
            + cert
        )
    else:
        signed = struct.pack(">H", 0) + struct.pack(">I", len(cert))[1:] + cert
    entry = struct.pack(">Q", 1_700_000_000_000 + n) + signed + struct.pack(">H", len(ext)) + ext
    out = entry
    if precert:
        pre = b"precert-" + cert
        out += struct.pack(">I", len(pre))[1:] + pre
    fingerprints = b"".join(sha(b"issuer %d" % i) for i in range(chain))
    return out + struct.pack(">H", len(fingerprints)) + fingerprints


# ---- paths -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("index", "text"),
    [
        (0, "000"),
        (67, "067"),
        (999, "999"),
        (1000, "x001/000"),
        (1234067, "x001/x234/067"),  # tlog-tiles' example
        (1_000_000, "x001/x000/000"),
    ],
)
def test_tile_index_paths(index: int, text: str) -> None:
    assert tiles.format_index(index) == text
    assert tiles.parse_index(text) == index


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "1",
        "0001",
        "x001",
        "001/002",
        "x000/001",
        "x001/x234/x067",
        "x01/001",
        "001/",
        "X001/001",
    ],
)
def test_malformed_index_paths_are_refused(bad: str) -> None:
    with pytest.raises(TranscriptError):
        tiles.parse_index(bad)


def test_tile_paths_for_hash_data_and_entry_tiles() -> None:
    assert tiles.tile_path(0, 0) == "tile/0/000"
    assert tiles.tile_path(2, 1234067, 17) == "tile/2/x001/x234/067.p/17"
    assert tiles.tile_path(0, 5, kind="data") == "tile/data/005"
    assert tiles.tile_path(0, 5, 255, kind="data") == "tile/data/005.p/255"
    assert tiles.tile_path(0, 5, kind="entries") == "tile/entries/005"
    for bad in (
        lambda: tiles.tile_path(6, 0),  # static-ct-api: levels 0 to 5
        lambda: tiles.tile_path(-1, 0),
        lambda: tiles.tile_path(0, 0, 0),
        lambda: tiles.tile_path(0, 0, 257),
        lambda: tiles.tile_path(1, 0, kind="data"),
        lambda: tiles.tile_path(0, -1),
    ):
        with pytest.raises(ValueError, match=r"."):
            bad()
    assert tiles.tile_path(63, 0, max_level=63) == "tile/63/000"  # tlog-tiles allows 63
    with pytest.raises(ValueError, match=r"."):
        tiles.tile_path(64, 0, max_level=63)


@pytest.mark.parametrize(
    "path",
    [
        "tile/0/000",
        "tile/3/x001/x234/067.p/1",
        "tile/data/x001/000.p/255",
        "tile/entries/012",
    ],
)
def test_parse_tile_path_inverts_tile_path(path: str) -> None:
    ref = tiles.parse_tile_path(path)
    assert tiles.tile_path(ref.level, ref.index, ref.width, kind=ref.kind) == path
    assert ref.partial == (".p/" in path)


@pytest.mark.parametrize(
    "bad",
    [
        "tile/00/000",  # leading zero in the level
        "tile/6/000",  # past static-ct-api's levels
        "tile/0/000.p/0",
        "tile/0/000.p/256",  # a full tile has no suffix
        "tile/0/000.p/01",
        "tile/0/000.p/",
        "tile/data/000/extra",
        "tiles/0/000",
        "tile/0/x000/001",
    ],
)
def test_malformed_tile_paths_are_refused(bad: str) -> None:
    with pytest.raises(TranscriptError):
        tiles.parse_tile_path(bad)


def test_the_specifications_example_tree_of_70000_leaves() -> None:
    refs = list(tiles.tiles_for_tree(70_000))
    level0 = [r for r in refs if r.level == 0]
    assert sum(not r.partial for r in level0) == 273
    assert [r.width for r in level0 if r.partial] == [112]
    level1 = [r for r in refs if r.level == 1]
    assert [r.width for r in level1] == [256, 17]
    assert [r.width for r in refs if r.level == 2] == [1]
    assert not [r for r in refs if r.level > 2]
    assert tiles.tile_width(70_000, 0, 272) == 256
    assert tiles.tile_width(70_000, 0, 273) == 112
    assert tiles.tile_width(70_000, 1, 1) == 17
    assert tiles.tile_width(70_000, 2, 0) == 1
    with pytest.raises(ValueError, match="does not exist"):
        tiles.tile_width(70_000, 0, 274)


def test_a_tree_of_256_is_a_full_level_0_tile_and_a_partial_level_1_tile_of_width_1() -> None:
    refs = list(tiles.tiles_for_tree(256))
    assert [(r.level, r.index, r.width) for r in refs] == [(0, 0, 256), (1, 0, 1)]
    assert list(tiles.tiles_for_tree(0)) == []
    assert [(r.level, r.width) for r in tiles.tiles_for_tree(1)] == [(0, 1)]


# ---- hash tiles --------------------------------------------------------------------------------


def test_a_tile_hash_is_the_merkle_tree_hash_of_the_leaf_range() -> None:
    entries = [b"entry %d" % i for i in range(300)]
    leaf_hashes = [merkle.leaf_hash(e) for e in entries]
    full = tiles.parse_hash_tile(b"".join(leaf_hashes[:256]), 256)
    assert tiles.subtree_hash(full) == merkle.tree_hash(entries[:256])
    partial = tiles.parse_hash_tile(b"".join(leaf_hashes[256:300]), 44)
    assert tiles.subtree_hash(partial) == merkle.tree_hash(entries[256:300])
    for count in (1, 2, 3, 5, 8, 9):
        assert tiles.subtree_hash(leaf_hashes[:count]) == merkle.tree_hash(entries[:count])
    with pytest.raises(ValueError, match="empty"):
        tiles.subtree_hash([])


def test_hash_tiles_have_exactly_the_width_they_claim() -> None:
    assert len(tiles.parse_hash_tile(bytes(8192), 256)) == 256
    for data, width in ((bytes(8191), 256), (bytes(33), 1), (b"", 1), (bytes(64), 1)):
        with pytest.raises(TranscriptError):
            tiles.parse_hash_tile(data, width)


# ---- data tiles --------------------------------------------------------------------------------


def test_a_data_tile_is_parsed_and_each_entry_hashes_to_the_level_0_tile() -> None:
    parts = [tile_leaf(n, precert=n % 2 == 1, chain=n % 3) for n in range(7)]
    data = b"".join(parts)
    leaves = tiles.parse_data_tile(data)
    assert len(leaves) == 7
    assert [leaf.leaf_index for leaf in leaves] == list(range(7))
    assert [len(leaf.chain) for leaf in leaves] == [n % 3 for n in range(7)]
    assert [leaf.pre_certificate is not None for leaf in leaves] == [n % 2 == 1 for n in range(7)]
    assert leaves[1].pre_certificate == b"precert-" + bytes([0x30, 0x03, 0x02, 0x01, 1])
    assert leaves[2].chain == (sha(b"issuer 0"), sha(b"issuer 1"))
    # the Merkle leaf is 0x00 0x00 then the TimestampedEntry: the bytes up to the precertificate and chain
    for leaf in leaves:
        assert leaf.raw_entry == leaf.timestamped_entry.transcript()
        assert leaf.merkle_tree_leaf == b"\x00\x00" + leaf.raw_entry
        assert leaf.leaf_hash() == merkle.leaf_hash(leaf.merkle_tree_leaf)
    hash_tile = b"".join(leaf.leaf_hash() for leaf in leaves)
    assert len(tiles.verify_data_tile(data, hash_tile)) == 7
    # a different entry, a different order and a different count all fail
    tampered = bytearray(data)
    tampered[8 + 2 + 6] ^= 1  # inside the first certificate
    with pytest.raises(VerificationError, match="entry 0"):
        tiles.verify_data_tile(bytes(tampered), hash_tile)
    swapped = hash_tile[32:64] + hash_tile[:32] + hash_tile[64:]
    with pytest.raises(VerificationError, match="entry 0"):
        tiles.verify_data_tile(data, swapped)
    with pytest.raises(VerificationError, match="7 entries"):
        tiles.verify_data_tile(data, hash_tile[:-32])


@pytest.mark.parametrize("chain_bytes", [1, 31, 33, 65])
def test_a_certificate_chain_that_is_not_whole_fingerprints_is_refused(chain_bytes: int) -> None:
    good = tile_leaf(0, chain=0)
    bad = good[:-2] + struct.pack(">H", chain_bytes) + bytes(chain_bytes)
    with pytest.raises(TranscriptError, match="fingerprints"):
        tiles.parse_data_tile(bad)


def test_malformed_data_tiles_are_refused() -> None:
    good = tile_leaf(3, precert=True)
    assert len(tiles.parse_data_tile(good)) == 1
    for cut in range(1, len(good)):
        with pytest.raises(TranscriptError):
            tiles.parse_data_tile(good[:cut])  # every truncation, including between leaves' fields
    with pytest.raises(TranscriptError, match=r"unconsumed|wanted"):
        tiles.parse_data_tile(good + b"\x00")
    with pytest.raises(TranscriptError, match="at least one"):
        tiles.parse_data_tile(b"")
    undefined = bytearray(good)
    undefined[9] = 2  # entry_type 2 is not defined by RFC 6962
    with pytest.raises(TranscriptError, match="not defined"):
        tiles.parse_data_tile(bytes(undefined))


def test_leaf_index_extension_rules() -> None:
    assert tiles.leaf_index_of(b"") is None
    assert tiles.leaf_index_of(leaf_index_extension(2**40 - 1)) == 2**40 - 1
    other = b"\x07\x00\x01\xff"
    assert (
        tiles.leaf_index_of(other + leaf_index_extension(9)) == 9
    )  # order is arbitrary and ignored
    with pytest.raises(TranscriptError, match="twice"):
        tiles.leaf_index_of(leaf_index_extension(1) + leaf_index_extension(2))
    with pytest.raises(TranscriptError, match="40-bit"):
        tiles.leaf_index_of(b"\x00\x00\x04\x00\x00\x00\x01")
    with pytest.raises(TranscriptError):
        tiles.leaf_index_of(b"\x00\x00")  # a type with no length


# ---- fetching ----------------------------------------------------------------------------------


class Transport:
    """A ``get`` made of a dict; records every URL asked for."""

    def __init__(self, served: dict[str, bytes]) -> None:
        self.served = served
        self.asked: list[str] = []

    async def __call__(self, url: str) -> bytes:
        self.asked.append(url)
        if url not in self.served:
            raise TileNotFoundError(url)
        return self.served[url]


def run(coroutine):
    return asyncio.run(coroutine)


def test_fetch_tile() -> None:
    """tiles.fetch_tile: the spec's path, the width check, the fallback prefix and the full-tile fallback."""
    log = TiledLog(["https://a.example/log/", "https://b.example/log"])
    hashes = b"".join(sha(b"%d" % i) for i in range(17))
    path = "tile/1/x001/000.p/17"
    transport = Transport({f"https://a.example/log/{path}": hashes})
    assert run(tiles.fetch_tile(log, 1000, 17, get=transport, level=1)) == hashes
    assert transport.asked == [f"https://a.example/log/{path}"]  # the trailing slash is not doubled
    # the first prefix is down: the second is tried, with the same path
    transport = Transport({f"https://b.example/log/{path}": hashes})
    assert run(tiles.fetch_tile(log, 1000, 17, get=transport, level=1)) == hashes
    assert transport.asked == [f"https://a.example/log/{path}", f"https://b.example/log/{path}"]
    # a prefix that answers a body of the wrong width is not believed
    liar = Transport(
        {f"https://a.example/log/{path}": hashes[:-32], f"https://b.example/log/{path}": hashes}
    )
    assert run(tiles.fetch_tile(log, 1000, 17, get=liar, level=1)) == hashes
    assert len(liar.asked) == 2


def test_fetch_tile_falls_back_to_the_full_tile_when_the_partial_is_gone() -> None:
    log = TiledLog(["https://a.example"])
    full = bytes(8192)
    transport = Transport({"https://a.example/tile/0/005": full})
    assert run(tiles.fetch_tile(log, 5, 100, get=transport)) == full
    assert transport.asked == ["https://a.example/tile/0/005.p/100", "https://a.example/tile/0/005"]
    nothing = Transport({})
    with pytest.raises(TileNotFoundError):
        run(tiles.fetch_tile(log, 5, 100, get=nothing))
    assert len(nothing.asked) == 2
    with pytest.raises(TileNotFoundError):  # a full tile has no fallback
        run(tiles.fetch_tile(log, 5, 256, get=Transport({})))


def test_fetch_tile_checks_data_tiles_by_entry_count() -> None:
    log = TiledLog(["https://a.example"])
    data = b"".join(tile_leaf(n) for n in range(3))
    transport = Transport({"https://a.example/tile/data/007.p/3": data})
    assert run(tiles.fetch_tile(log, 7, 3, get=transport, kind="data")) == data
    wrong = Transport({"https://a.example/tile/data/007.p/2": data})
    with pytest.raises(TileNotFoundError):  # the body was refused, then the full tile was not there
        run(tiles.fetch_tile(log, 7, 2, get=wrong, kind="data"))
    assert wrong.asked == ["https://a.example/tile/data/007.p/2", "https://a.example/tile/data/007"]
    with pytest.raises(ValueError, match="level"):
        run(tiles.fetch_tile(log, 0, 256, get=Transport({}), level=6))
    with pytest.raises(ValueError, match="prefix"):
        TiledLog([])
