# Heap buffer overflow in Godot's binary resource loader (`get_unicode_string`)

**Engine:** Godot 4.7 (official build); the pattern is older and present in earlier 4.x.
**Component:** `core/io/resource_format_binary.cpp` — `ResourceLoaderBinary::get_unicode_string()` (line 864).
**Class:** heap out-of-bounds **write** (attacker-controlled length and bytes) — `memory_corruption_security`.
**Status:** second of two attacker-controlled heap *write* primitives surfaced by the audit (the first being the HDR RLE overflow). Every other memory-corruption survivor is an OOB *read*, which is why this is the next-most-serious finding.

## The bug

```cpp
String ResourceLoaderBinary::get_unicode_string() {
    int len = f->get_32();              // (1) SIGNED int, no mask
    if (len > str_buf.size()) {         // (2) str_buf.size() is int64_t -> signed compare
        str_buf.resize(len);            //     skipped when len is negative
    }
    if (len == 0) {
        return String();
    }
    f->get_buffer((uint8_t *)&str_buf[0], len);   // (3) len sign-extends to uint64_t
    return String::utf8(&str_buf[0], len);
}
```

1. `len` is read into a **signed** `int` with no masking. The sibling helper `_get_string()`
   (line 144) correctly masks `id & 0x7FFFFFFF`; this function does not.
2. `str_buf` is a `Vector<char>`; `Vector::size()` returns `int64_t`. So
   `len > str_buf.size()` is a **signed** comparison. A `len` of `0x80000000`
   is `-2147483648` as an `int`, so `-2147483648 > 16` is **false** and the buffer is
   **not** resized. `len == 0` is also false.
3. `FileAccess::get_buffer(uint8_t *, uint64_t)` takes an **unsigned 64-bit** length, so the
   negative `int` **sign-extends** to ~`0xFFFFFFFF80000000`. The disk backends
   (`FileAccessWindows`/`FileAccessUnix`) call `fread(dst, 1, len, f)` with **no
   destination-size clamp**, so `fread` copies every remaining file byte into `&str_buf[0]`.

`str_buf` is a reused member. The resource `type` string is read first (line 968) and sizes
`str_buf` to, e.g., 16 bytes. The malicious string-table entry then writes the entire file
tail into that 16-byte heap allocation — both the overflow length and the written bytes are
attacker-controlled.

(If `str_buf` were still empty, `&str_buf[0]` would `CRASH_BAD_INDEX` — a controlled abort —
so a real attack reads a non-empty `type` first, which the repro does.)

## Reachability (stock binary, no custom build)

Two paths, both confirmed by the audit's verifiers:

- **Runtime, exported game:** `ResourceLoader.load("res://evil.res")` →
  `ResourceFormatLoaderBinary::load` (line 1148) → `loader.open(f)` (line 1180,
  `p_no_resources=false`) → string-table loop (lines 1001–1006) → `get_unicode_string()`.
- **Editor, no explicit load / no victim GDScript:** dropping `evil.res` into a project and
  opening it triggers `EditorFileSystem` dependency scanning →
  `ResourceLoader::get_dependencies` → `ResourceLoaderBinary::get_dependencies` →
  `open(p_f, false, true)` (line 892) → the same loop.

The only EOF check (`f->eof_reached()`, line 1049) runs **after** the string-table loop, so it
cannot prevent the line-872 write. The version gate (line 962) only checks `ver_format`/`ver_major`.

## Severity

**High.** A real memory-corruption primitive (heap OOB write of attacker bytes) reachable from
untrusted resources with **no user interaction in the editor**. Not rated critical because the
write is forward-only/sequential from a fixed file buffer (not arbitrary write-what-where) and
weaponizing to RCE depends on heap layout/allocator; the common stock-build outcome is
corruption/segfault. The overwrite length is bounded by bytes remaining in the file — fully
attacker-controlled and easily large enough to smash adjacent heap or cross into a guard page.

## Repro

See `make_repro.py` in this folder — it emits a byte-exact `evil.res`. Summary of the layout
(little-endian, `big_endian=0`):

| Field | Bytes | Value |
|---|---|---|
| magic | `RSRC` | |
| big_endian | u32 | 0 |
| use_real64 | u32 | 0 |
| ver_major | u32 | 4 |
| ver_minor | u32 | 7 |
| ver_format | u32 | 6 (≤ `FORMAT_VERSION`) |
| type string | u32 len=16 + 16 bytes | resizes `str_buf` to 16 |
| importmd_ofs | u64 | 0 |
| flags | u32 | 0 (no UIDS / SCRIPT_CLASS / NAMED_SCENE_IDS) |
| uid field | u64 | 0 (skipped, `using_uids=false`) |
| reserved | 11 × u32 | 0 (`RESERVED_FIELDS = 11`) |
| string_table_size | u32 | 1 |
| **malicious string** | u32 len=`0x80000000` + payload | negative len → resize skipped → sign-extended `fread` overflows the 16-byte buffer |

Trigger A (runtime): `ResourceLoader.load("res://evil.res")` in an exported game.
Trigger B (editor): drop `evil.res` into a project and open it (filesystem scan reads dependencies).

To make the crash deterministic without ASan, enlarge the payload to tens/hundreds of KB so the
over-write crosses into unmapped/guard pages; under ASan/PageHeap a few KB reports immediately
(`heap-buffer-overflow WRITE` at `resource_format_binary.cpp:872`).

## The fix

Mirror the masking `_get_string()` already uses — read into an unsigned 32-bit length and keep
the comparison signed-safe:

```cpp
String ResourceLoaderBinary::get_unicode_string() {
    uint32_t len = f->get_32();
    if (len == 0) {
        return String();
    }
    if ((int64_t)len > str_buf.size()) {
        Error err = str_buf.resize(len);
        ERR_FAIL_COND_V(err != OK, String());
    }
    uint64_t read = f->get_buffer((uint8_t *)&str_buf[0], len);
    ERR_FAIL_COND_V(read != len, String());
    return String::utf8(&str_buf[0], len);
}
```

Defense in depth: bound `len` against remaining file size
(`f->get_length() - f->get_position()`) and check the `get_buffer` return count to fail loudly
on short reads. Apply the same hardening to the static `get_ustring()` helper (line 856), which
has the identical unmasked-signed-int pattern.
