# Binary resource loader — heap out-of-bounds write (Godot 4.x)

`ResourceLoaderBinary::get_unicode_string` (`core/io/resource_format_binary.cpp:864`) reads a 32-bit string length from the file into a signed `int` with no masking. A length with the high bit set (`0x80000000`) is negative, so the `len > str_buf.size()` guard passes and the buffer is never grown; the same value then reaches `FileAccess::get_buffer` as an unsigned count, sign-extended to `0xFFFFFFFF80000000`, and the copy writes the file tail past the end of the undersized heap buffer. Both the overflow length and the written bytes are attacker-controlled. The adjacent `_get_string()` helper already masks the same field; `get_unicode_string()` and the static `get_ustring()` (line 856) do not.

## Files

- `godot47_binres_oob_repro.zip` — original archive, distributed 2026-06-23 and linked from the disclosure post since 2026-09-21.
  SHA-256: `920daf712f53fd8e0085bfc148c5ea5c6839d4136bf6e0d13a14a3e4385a4620`
  Mirror: https://drive.google.com/file/d/1GdgzHu4YFGx1DYjLWz7CuqMBfNQcjC_n/view?usp=sharing
- `extracted/` — the archive's contents: `README.md` (step-by-step repro), `bug_analysis.md` (full technical write-up), `make_repro.py` (regenerates the crafted resource), `proj/` with `project.godot`, `test.gd`, `evil.res` (8 MiB crafted resource).

## How to run

Two trigger paths, both in the archive's README:

1. Editor: place `evil.res` in a project folder before opening it — the editor's startup dependency scan loads it and crashes with `STATUS_HEAP_CORRUPTION` (`0xC0000374`), no user action required.
2. Headless: `godot --path <project> --headless --script res://test.gd` — exits `0xC0000374` on Godot 4.7-stable Windows.

Regenerate a smaller payload for AddressSanitizer or PageHeap with `python make_repro.py evil.res --payload-size 4096`; 4 KiB suffices for an immediate `heap-buffer-overflow WRITE` report at `resource_format_binary.cpp:872`.

## Trigger context

Any load of a crafted binary resource reaches the bug. Exported games that load player- or community-supplied `.res` files expose the path to untrusted content.

## Status

Unpatched as of 2026-10-13 (master, 4.7.2, 4.7.1, 4.7). A suggested patch is in the original report. Two independent fix attempts exist: godotengine/godot#121289 (third party, 2026-07-12, still unmerged) and godotengine/godot#123862 (volunteer, applying the suggested patches, closed unmerged 2026-09-26, the day it opened).

CVE: requested from the MITRE CNA-LR on 2026-09-20; pending as of 2026-10-14.

Full write-up and correspondence: https://axeghost.offprint.app/a/3mvs6zo4blo23-three-memory-safety-bugs-in-godots-untrusted-file-parsers
