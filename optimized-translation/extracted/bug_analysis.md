# Heap OOB read in `OptimizedTranslation::get_message` (and `get_translated_message_list`)

**Engine:** Godot 4.7 (all official binaries, editor and export templates).
**Component:** `core/string/optimized_translation.cpp` — `OptimizedTranslation::get_message()` (line 234) and `get_translated_message_list()` (line 286).
**Class:** heap out-of-bounds **read** (attacker-controlled offset and length) from a loaded translation resource.
**Impact:** reliable crash (Variant 1) or info-leak where `tr()` returns raw heap bytes to the caller (Variant 2).

---

## The bug

`OptimizedTranslation` stores its data in three flat arrays: `hash_table` (a `PackedInt32Array`), `bucket_table` (a `PackedInt32Array`), and `strings` (a `PackedByteArray`). These are plain storage properties: `_set()` writes them verbatim from the resource file with zero validation (lines 202–217), and `_get_property_list()` declares them `PROPERTY_USAGE_NO_EDITOR` (line 337–339), which is an alias for `PROPERTY_USAGE_STORAGE`, meaning they are serialized to and restored from disk by the resource loaders without any additional validation step.

`get_message()` looks up a translated string through a two-level hash:

```cpp
// core/string/optimized_translation.cpp
StringName OptimizedTranslation::get_message(
        const StringName &p_src_text, const StringName &p_context) const {

    int htsize = hash_table.size();
    if (htsize == 0) { return StringName(); }                        // line 239

    CharString str = p_src_text.operator String().utf8();
    uint32_t h = hash(0, str.get_data());

    const uint32_t *htptr = (const uint32_t *)hash_table.ptr();
    const uint32_t *btptr = (const uint32_t *)bucket_table.ptr();
    const char     *sptr  = (const char *)strings.ptr();

    uint32_t p = htptr[h % htsize];                                  // line 253

    if (p == 0xFFFFFFFF) { return StringName(); }                    // line 255  ← ONLY guard

    const Bucket &bucket = *(const Bucket *)&btptr[p];               // line 259  ← NO bounds check on p
    h = hash(bucket.func, str.get_data());                           // line 261  ← first OOB dereference

    int idx = -1;
    for (int i = 0; i < bucket.size; i++) {                          // line 265  ← bucket.size also OOB
        if (bucket.elem[i].key == h) { idx = i; break; }
    }
    if (idx == -1) { return StringName(); }

    if (bucket.elem[idx].comp_size == bucket.elem[idx].uncomp_size) {          // line 276
        return String::utf8(&sptr[bucket.elem[idx].str_offset],                // line 277  ← strings OOB
                             bucket.elem[idx].uncomp_size);
    } else {
        CharString uncomp;
        uncomp.resize_uninitialized(bucket.elem[idx].uncomp_size + 1);
        smaz_decompress(&sptr[bucket.elem[idx].str_offset],                    // line 281  ← strings OOB
                         bucket.elem[idx].comp_size, uncomp.ptrw(),
                         bucket.elem[idx].uncomp_size);
        return String::utf8(uncomp.get_data());
    }
}
```

`p` is read verbatim from `hash_table` (fully attacker-controlled). The only guard rejects the sentinel `0xFFFFFFFF`. Any other value — including `0x40000000` or any value >= `bucket_table.size()` — is used directly as a `uint32_t` element index into `bucket_table` with no bounds check. The cast on line 259 forms a pointer `4 * p` bytes into the allocation, then immediately reads `bucket.func` from that address (line 261). Because `bucket_table` is a normal heap allocation of only `bucket_table.size() * 4` bytes, a large `p` dereferences memory far outside it.

The identical pattern appears in `get_translated_message_list()` at line 299:

```cpp
const Bucket &bucket = *(const Bucket *)&btptr[p];   // line 299 — same missing check
```

---

## Bucket layout (optimized_translation.h:52)

```cpp
struct Bucket {
    int      size;        // 4 bytes — number of Elem entries
    uint32_t func;        // 4 bytes — hash seed for second-level lookup
    struct Elem {
        uint32_t key;         // 4 bytes
        uint32_t str_offset;  // 4 bytes — index into `strings`
        uint32_t comp_size;   // 4 bytes
        uint32_t uncomp_size; // 4 bytes
    } elem[1];
};
```

A bucket holding one entry occupies `2 + 4 = 6` `uint32_t` values in `bucket_table`. There is no separate allocation; `btptr[p]` is the start of the bucket header (size, func) and `btptr[p+2]` onward are the Elem array. None of these offsets are validated.

---

## Reachability (stock binary, no custom build)

A crafted `OptimizedTranslation` resource reaches `get_message()` through this call chain:

```
Object::tr()                              (object.cpp:1728)
  -> TranslationDomain::translate()       (translation_domain.cpp:357,
                                           uses TranslationServer's active locale)
  -> get_message_from_translations()      (translation_domain.cpp:202)
  -> [locale comparison passes]
  -> Translation::get_message()           (virtual, dispatches to OptimizedTranslation)
  -> OptimizedTranslation::get_message()  (optimized_translation.cpp:234)
```

The locale comparison (`compare_locales(active_locale, resource_locale) > 0`) is satisfied when the active locale matches the resource's stored `locale` property. An attacker who controls the resource controls the locale string, so setting it to `"en"` and calling `TranslationServer::set_locale("en")` (or relying on the default English locale) is sufficient.

**Auto-load path (no explicit load in GDScript):** `TranslationServer::load_project_translations()` (translation_server.cpp:758) calls `ResourceLoader::load(path)` followed by `add_translation()` for every entry in the project setting `internationalization/locale/translations`, with no validation of the loaded object's internal arrays. Placing a crafted `.translation` or `.tres` file there and making any `tr()` call completes the attack with no further user action.

**Editor path (no running game):** The CSV translation importer (`editor/import/resource_importer_csv_translation.cpp`) produces `OptimizedTranslation` resources saved as `.translation` files — the same class. Substituting a project's `.translation` file with a crafted one is the most realistic supply-chain vector.

---

## Variant 1 — crash (reliable on any stock binary)

`hash_table = [0x40000000]` (one entry).

For any query string, `h % 1 == 0`, so `p = htptr[0] = 0x40000000`. The sentinel check fails (`p != 0xFFFFFFFF`). Line 259 computes `&btptr[0x40000000]`, a byte offset of `0x40000000 * 4 = 4 GiB` past the start of a 2-element (8-byte) allocation. On a 64-bit process, this address is unmapped. Reading `bucket.func` at line 261 produces an access violation / SIGSEGV.

The crash is deterministic: 4 GiB past a heap allocation is reliably unmapped on 64-bit Linux and Windows.

---

## Variant 2 — info-leak (`tr()` returns heap bytes to the caller)

Keep `p` in range (`hash_table = [0]`, so `p = 0` — the start of `bucket_table`). Craft `bucket_table` as a valid-looking single-entry bucket:

```
bucket_table[0] = 1              # bucket.size = 1
bucket_table[1] = func           # bucket.func (hash seed for second level)
bucket_table[2] = key            # elem[0].key = hash(func, QUERY)
bucket_table[3] = 4096           # elem[0].str_offset — far past end of `strings`
bucket_table[4] = 64             # elem[0].comp_size  = LEAK_LEN
bucket_table[5] = 64             # elem[0].uncomp_size = LEAK_LEN (uncompressed path)
```

With `func = 0`, `key = hash(0, QUERY)` is deterministic and can be precomputed. When `get_message()` queries `QUERY`, the second-level hash matches `elem[0].key` and `idx = 0`. Because `comp_size == uncomp_size`, the uncompressed path (line 276) executes:

```cpp
return String::utf8(&sptr[4096], 64);
```

`strings` is a 5-byte allocation (`b"godot"`). This reads 64 bytes starting 4096 bytes into the allocation from heap memory following `strings` and returns them as the translation result. That string value reaches the GDScript caller of `tr()` and can be printed, written to a log, sent over the network, or displayed in game UI.

The hash function is available in plain form in `optimized_translation.h:74`:

```cpp
_FORCE_INLINE_ uint32_t hash(uint32_t d, const char *p_str) const {
    if (d == 0) { d = 0x1000193; }
    while (*p_str) {
        d = (d * 0x1000193) ^ static_cast<uint8_t>(*p_str);
        p_str++;
    }
    return d;
}
```

`make_repro.py` contains a byte-exact Python replica (`godot_hash()`) and precomputes `key` for `QUERY = "LEAK_ME"`.

---

## Severity

**Medium–High.** Two usable primitives from a single crafted text resource:

- **Crash**: reliable on any stock 64-bit binary, editor and export template.
- **Info-leak**: `tr()` return value is attacker-readable; no memory safety tooling required on the attacker's side to construct it, though confirming it on a victim machine without tooling requires observing the translated string value.

The realistic attack surface is **supply-chain substitution of `.translation` files** (the output of the CSV importer) or malicious asset distribution (mods, downloaded projects). Both reach the bug with no victim action beyond running a game or opening a project.

---

## The fix

Add bounds validation at the start of the vulnerable block in both `get_message()` and `get_translated_message_list()`. The bucket header is 2 `uint32_t` words (`size` + `func`); a single-entry bucket needs `2 + 4 = 6` words minimum.

```cpp
// Before line 259 in get_message() (and equivalently in get_translated_message_list()):
uint32_t btsize = (uint32_t)bucket_table.size();
ERR_FAIL_COND_V((uint64_t)p + 2 > (uint64_t)btsize, StringName());

const Bucket &bucket = *(const Bucket *)&btptr[p];

ERR_FAIL_COND_V((uint64_t)p + 2 + (uint64_t)bucket.size * 4 > (uint64_t)btsize, StringName());
```

Additionally, guard each `sptr` read before using `str_offset`:

```cpp
uint32_t ssize = (uint32_t)strings.size();
ERR_FAIL_COND_V(
    (uint64_t)bucket.elem[idx].str_offset + bucket.elem[idx].comp_size > (uint64_t)ssize,
    StringName());
```

Apply both guards to `get_translated_message_list()` at line 299 identically.

Defense in depth: `_set()` (lines 202–217) could validate the logical consistency of the three arrays at load time (size of `bucket_table` consistent with entries in `hash_table`, all `str_offset + comp_size` in range) rather than deferring validation to `get_message()`, but the `ERR_FAIL_COND_V` guards above are the minimal correct fix.
