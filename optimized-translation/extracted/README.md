# Repro: heap OOB read in `OptimizedTranslation::get_message`

**Plain-English summary:** Godot's translation system (the thing that swaps text into different languages) trusts a number stored inside a translation file without checking whether it's valid. A crafted translation file can make that number point gigabytes past the end of a real memory buffer. Any game or editor that loads the file and then looks up a translated string will immediately crash. With a more carefully crafted file the call returns raw memory from the process instead of the translation — bytes the game code may then display, log, or transmit. The fix is to add a bounds check on that number before using it as an array index.

See `bug_analysis.md` for the full write-up. This file covers only the steps to trigger the crash or info-leak.

## Requirements

- Godot 4.7 stock binary (editor or export template)
- Python 3.8+ (to generate the project files)
- Optional but recommended for Variant 2: [AddressSanitizer build](https://docs.godotengine.org/en/stable/contributing/development/compiling/index.html) or Windows PageHeap

## Step 1 — generate the repro project

```
python make_repro.py
```

This writes five files under `./proj/`:

| File | Purpose |
|---|---|
| `bad_translation.tres` | Crafted `OptimizedTranslation` — crash payload |
| `leak_translation.tres` | Crafted `OptimizedTranslation` — info-leak payload |
| `project.godot` | Minimal Godot project wiring |
| `main.tscn` | Empty main scene (required for the project to run) |
| `trigger.gd` | Autoload that loads the translation and calls `tr()` |

## Step 2 — open the project and run it

Open the project in the Godot 4.7 editor (double-click `project.godot`, or use the Project Manager). Then press **F5** or click the play button.

Alternatively, run headless:

```
Godot_v4.7.exe --path proj/
```

### Variant 1 — crash (default)

`trigger.gd` is configured with `VARIANT = "crash"`. The autoload loads `bad_translation.tres`, registers it, sets locale to `"en"`, and calls `tr("LEAK_ME")`.

`get_message()` computes `h % htsize == 0`, reads `p = 0x40000000` from `hash_table[0]`, finds `p != 0xFFFFFFFF`, and executes:

```cpp
const Bucket &bucket = *(const Bucket *)&btptr[0x40000000];  // byte offset 4 GiB
h = hash(bucket.func, ...);                                   // dereferences unmapped memory
```

Expected output: **access violation / SIGSEGV**. The process crashes before the `print()` statement executes.

Under AddressSanitizer or Windows PageHeap, the report points to `optimized_translation.cpp:259` (the `const Bucket &bucket` cast line) with a READ of size 4 at `btptr + 4 GiB`.

### Variant 2 — info-leak

Edit `proj/trigger.gd` and change line 4 to:

```gdscript
const VARIANT = "leak"
```

Re-run the project. `get_message()` receives a crafted `bucket` at `p = 0`:

- `bucket.elem[0].key` matches `hash(0, "LEAK_ME")` — the lookup succeeds.
- `bucket.elem[0].str_offset = 4096` — far past the 5-byte `strings` allocation.
- `comp_size == uncomp_size = 64` — uncompressed path.

`get_message()` returns `String::utf8(&sptr[4096], 64)`: 64 bytes read from heap memory following `strings`, returned as the `tr()` result. `print(tr("LEAK_ME"))` then prints those raw bytes.

Under AddressSanitizer: `heap-buffer-overflow READ` at `optimized_translation.cpp:277`.  
On a stock binary: `print()` outputs whatever bytes happen to follow the `strings` allocation; content varies by run and platform but the call succeeds.

## What to look for (ASan / PageHeap build)

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 4 at ...
    #0 OptimizedTranslation::get_message
    #1 TranslationDomain::get_message_from_translations
    #2 TranslationDomain::translate
    #3 Object::tr
```

For Variant 2 the size is `64` (the `uncomp_size` value) and the location is the `String::utf8(...)` call at line 277.

## What to look for (stock binary)

Variant 1 produces a hard crash. The OS crash report / Windows Error Reporting dialog shows a fault address roughly 4 GiB past the `bucket_table` heap base. On Windows, WER points to `OptimizedTranslation::get_message` or its inlined caller.

Variant 2 on a stock binary: `print()` outputs garbage bytes. The length (64) and offset (4096) in `leak_translation.tres` can be adjusted in `make_repro.py` to target specific heap regions.
