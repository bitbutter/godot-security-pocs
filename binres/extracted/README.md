# Repro: heap OOB write in `ResourceLoaderBinary::get_unicode_string`

## Summary

Godot's resource format stores strings with a number that says how long the string is, followed by the string's bytes. When loading a resource file, the engine reads that length, allocates a buffer to hold the string, then copies the bytes in.

The bug: the length is read as a number that can be negative. When the length is negative, the size check that would grow the buffer is silently skipped (a negative number is never "bigger" than the current buffer size). The buffer stays small. But when the bytes are actually copied, the negative number gets reinterpreted as a huge positive number, so the copy runs off the end of the small buffer and overwrites whatever happens to be next in memory.

An attacker who can get a crafted `.res` file onto your machine can trigger this just by having you open a Godot project that contains the file — no scripts, no clicks, just the editor scanning files on startup. The attacker controls both how far the overflow goes and what bytes are written, making this a real memory-corruption primitive rather than just a crash.

See `bug_analysis.md` for the full write-up. This file covers only the steps to trigger the crash.

## Requirements

- Godot 4.7 stock binary (editor or export template)
- Python 3.8+ (to generate the malicious file)
- Optional but recommended: [AddressSanitizer build](https://docs.godotengine.org/en/stable/contributing/development/compiling/index.html) or Windows PageHeap for a clean report instead of a silent heap corruption

## Step 1 — generate `evil.res`

```
python make_repro.py
```

This writes `evil.res` (≈8 MiB) in the current directory. To use a smaller payload (sufficient under ASan/PageHeap):

```
python make_repro.py evil.res --payload-size 4096
```

### Why 8 MiB?

The bug makes `fread()` write the entire file tail into a 16-byte heap buffer, corrupting heap block metadata for every adjacent allocation.  The Windows heap manager detects this corruption and raises `STATUS_HEAP_CORRUPTION (0xC0000374)` when it next accesses a corrupted block — but only if those blocks are touched soon enough.

In a minimal headless process even the default 256 KiB payload crashes reliably (confirmed: Godot 4.7-stable, `0xC0000374` on both payload sizes in the headless Trigger B test).  In the full editor the heap has many more live allocations; the corrupted blocks may not be accessed until much later (or at all during the session), so the crash can be delayed or suppressed entirely.  8 MiB is a safe default that saturates the heap quickly enough to crash even in the editor context.

Under ASan or Windows PageHeap the guard page sits immediately after the 16-byte `str_buf`, so even 4096 bytes triggers a `heap-buffer-overflow WRITE` at line 872.

## Step 2 — choose a trigger path

### Trigger A: editor filesystem scan (no GDScript, no user action beyond opening the project)

1. Create a new Godot 4.7 project (or use any existing one).
2. **Copy** `evil.res` into the project folder **before** opening it in the editor.
   (Dropping the file into an already-running editor triggers a live rescan with
   a different heap state; copying it first ensures the file is scanned during
   the initial `EditorFileSystem` startup sweep.)
3. Open the project in the Godot editor.
4. `EditorFileSystem` scans dependencies on startup — `ResourceLoader::get_dependencies` →
   `ResourceLoaderBinary::get_dependencies` → `open(f, false, true)` → string-table loop →
   `get_unicode_string()` → crash.

Expected: Godot crashes on startup with `STATUS_HEAP_CORRUPTION` or, under ASan, prints
`heap-buffer-overflow WRITE` pointing to `resource_format_binary.cpp:872`.

### Trigger B: headless runtime load (confirmed working)

1. Place `evil.res` in a project's `res://` directory.
2. Add a script that calls `ResourceLoader.load("res://evil.res")` from `_initialize()`.
3. Run headless: `godot --path <project> --headless --script res://test.gd`

Confirmed exit code on Godot 4.7.stable (Windows): `0xC0000374` (`STATUS_HEAP_CORRUPTION`).

Example `test.gd`:
```gdscript
extends SceneTree

func _initialize():
    ResourceLoader.load("res://evil.res")
    quit()
```

## What to look for (stock binary, no ASan)

The process terminates with Windows exception code `0xC0000374` (`STATUS_HEAP_CORRUPTION`).
The call stack at the point of detection will include the heap manager internals,
but the overflow itself happens at:

```
FileAccessWindows::get_buffer
ResourceLoaderBinary::get_unicode_string  (resource_format_binary.cpp:872)
ResourceLoaderBinary::open
```

## What to look for (ASan / PageHeap build)

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size 1 at ...
    #0 ... fread
    #1 ... FileAccess::get_buffer
    #2 ... ResourceLoaderBinary::get_unicode_string
    #3 ... ResourceLoaderBinary::open
```

The overflowing allocation is the `str_buf` `Vector<char>` sized to 16 bytes by the
benign `type` string read earlier in `open()`.
