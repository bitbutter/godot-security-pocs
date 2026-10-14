# OptimizedTranslation — heap out-of-bounds read and information disclosure (Godot 4.x)

`OptimizedTranslation::get_message` (`core/string/optimized_translation.cpp`, function begins at line 259) uses a `uint32_t` value read verbatim from the resource's `hash_table` array as a direct index into `bucket_table`, with no bounds check; only the sentinel `0xFFFFFFFF` is rejected. All three backing arrays (`hash_table`, `bucket_table`, `strings`) are loaded verbatim from the file by `_set()` (lines 202-217) with no validation, so a crafted translation resource is a full control surface. Under AddressSanitizer the report points at `optimized_translation.cpp:277`, `heap-buffer-overflow READ`.

Two primitives from one crafted file:

1. Crash: a hash-table entry far out of range faults on first `tr()` call — deterministic on any stock 64-bit binary (editor and export templates).
2. Information disclosure: a crafted bucket with an out-of-range string offset makes `get_message()` return attacker-chosen heap bytes as the translated string, reaching GDScript callers, game UI, logs, or network output. Confirmed on an official 4.7 build without instrumentation.

The identical pattern appears in `get_translated_message_list()` (line 299).

## Files

- `godot47_optimized_translation_oob_repro.zip` — original archive, distributed 2026-06-23 and linked from the disclosure post since 2026-09-21.
  SHA-256: `19cc54698b40c15e214ce310307fc854b58e631e577c61647aca12ab442d0a70`
  Mirror: https://drive.google.com/file/d/1PMewCT6wDOdyS-hF-l_H0yQMCizO0_sI/view?usp=sharing
- `extracted/` — the archive's contents: `README.md` (step-by-step repro), `bug_analysis.md` (full technical write-up), `make_repro.py` (regenerates all project files), `proj/` with `project.godot`, `main.tscn`, `trigger.gd`, `bad_translation.tres` (crash payload), `leak_translation.tres` (info-leak payload).

## How to run

Open the extracted `proj/` in Godot 4.7-stable and run. The crash variant faults on the first `tr()` call. For the leak variant, set `VARIANT = "leak"` in `proj/trigger.gd` and run again: `tr("LEAK_ME")` returns heap bytes instead of the fallback string. Details in the archive's README.

## Trigger context

The realistic vector is substitution of a project's `.translation` files (the output of the CSV translation importer) or malicious asset distribution — the bug fires with no victim action beyond running the game or opening the project, on the first lookup through a crafted entry.

## Status

Unpatched as of 2026-10-13 (master, 4.7.2, 4.7.1, 4.7). A suggested patch (bounds checks in both `get_message()` and `get_translated_message_list()`) is in the original report. Volunteer fix PR godotengine/godot#123862 was closed unmerged on 2026-09-26, the day it opened.

CVE: requested from the MITRE CNA-LR on 2026-09-20; pending as of 2026-10-14.

Full write-up and correspondence: https://axeghost.offprint.app/a/3mvs6zo4blo23-three-memory-safety-bugs-in-godots-untrusted-file-parsers
