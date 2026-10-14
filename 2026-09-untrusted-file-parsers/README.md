# Godot 4.x untrusted-file parser PoCs — three memory-safety bugs

Reproduction material for three memory-safety bugs in Godot 4's file parsers. Reported privately to security@godotengine.org on 2026-06-22 and 2026-06-23 with reproductions and suggested patches; publicly disclosed with full correspondence on 2026-09-21 (link below). None was patched as of 2026-10-13 (checked on master, 4.7.2, 4.7.1, 4.7).

## Bug map

| Directory | Bug | Vulnerable code | Crafted file |
|---|---|---|---|
| [`hdr/`](hdr/) | heap out-of-bounds write | `ImageLoaderHDR::load_image`, `modules/hdr/image_loader_hdr.cpp` | `.hdr` image |
| [`binres/`](binres/) | heap out-of-bounds write | `ResourceLoaderBinary::get_unicode_string`, `core/io/resource_format_binary.cpp:864` | `.res` binary resource |
| [`optimized-translation/`](optimized-translation/) | heap out-of-bounds read, information disclosure via `tr()` | `OptimizedTranslation::get_message`, `core/string/optimized_translation.cpp` | `.translation` / `.tres` translation resource |

## Archives and integrity

Each directory contains the original reproduction archive exactly as distributed (and linked from the disclosure post since 2026-09-21), plus its extracted contents. Verify before use:

- `hdr/godot47_hdr_oob_repro.zip` — SHA-256 `604982a1d0f8b0b7f19ec9a75d565f51a7879f2cdddf898c58234bef6e54f380`
- `binres/godot47_binres_oob_repro.zip` — SHA-256 `920daf712f53fd8e0085bfc148c5ea5c6839d4136bf6e0d13a14a3e4385a4620`
- `optimized-translation/godot47_optimized_translation_oob_repro.zip` — SHA-256 `19cc54698b40c15e214ce310307fc854b58e631e577c61647aca12ab442d0a70`

Two of the archives contain generator scripts (`make_repro.py`), so the crafted inputs can be regenerated rather than trusted; `hdr/extras/gen_hdr.py` serves the same purpose for the HDR bug.

## Shared background

The bugs were found in an LLM-directed source audit (Claude Code; Opus 4.8 for discovery, Sonnet 4.6 for report and reproduction) and verified by Tomasz Kaye against official release binaries. The binary resource parser and the translation loader have been in the engine since the initial 2014 import (commit 0b806ee0fc); the HDR loader was added in May 2017 (commit bb20f230ad). An exported Godot game that loads player- or community-supplied files of these kinds (mods, downloads, uploads) exposes each path to untrusted content.

Timeline: reported 2026-06-22/23; public notice godotengine/godot#123608 on 2026-09-18; the maintainer response of 2026-09-19 classified the issues as not security issues; public disclosure 2026-09-21 (https://axeghost.offprint.app/a/3mvs6zo4blo23-three-memory-safety-bugs-in-godots-untrusted-file-parsers); volunteer fix PR godotengine/godot#123862 applying the suggested patches closed unmerged on 2026-09-26, the day it opened; independent binres fix godotengine/godot#121289 unmerged since 2026-07-12. CVE identifiers were requested from the MITRE CNA-LR on 2026-09-20 and are pending as of 2026-10-14.

oss-security discussion threads — all three live 2026-10-14:
- "Godot 4.x: heap out-of-bounds read in OptimizedTranslation message lookup" — https://www.openwall.com/lists/oss-security/2026/10/14/6 (first Godot post in the list's history)
- "Godot 4.x: heap out-of-bounds write via negative string length in binary resource loader" — https://www.openwall.com/lists/oss-security/2026/10/14/8
- "Godot 4.x: heap out-of-bounds write in Radiance HDR image loader" — https://www.openwall.com/lists/oss-security/2026/10/14/9

## Handling

These are crash and information-leak proofs of concept, not working exploits. Use them only against Godot installations you own. The crafted files intentionally corrupt heap memory in the target process.

## License

MIT — see [LICENSE](LICENSE).
