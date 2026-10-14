# HDR image loader — heap out-of-bounds write (Godot 4.x)

`ImageLoaderHDR::load_image` (`modules/hdr/image_loader_hdr.cpp`, lines 104-118) decodes Radiance HDR run-length data. Run and pixel counts read from the file are trusted without checking them against the reserved image buffer. A crafted `.hdr` file directs the decoder to write attacker-controlled data past the end of the heap buffer.

## Files

- `godot47_hdr_oob_repro.zip` — original archive, distributed 2026-06-22 and linked from the disclosure post since 2026-09-21.
  SHA-256: `604982a1d0f8b0b7f19ec9a75d565f51a7879f2cdddf898c58234bef6e54f380`
  Mirror: https://drive.google.com/file/d/1JvgN0Tobio83skfaIRJGYzSL08__hyKC/view?usp=sharing
- `extracted/` — the archive's contents: `evil4ch.hdr` (crafted, 746 bytes), `ok.hdr` (valid baseline), `repro.gd`, `verify.ps1`, `project.godot`.
- `extras/gen_hdr.py` — generator script that produces the crafted file; a provided extra alongside the original archive.

## How to run

Unzip the archive and run from PowerShell:

```
.\verify.ps1 -Godot "<path-to-Godot_v4.7-stable_win64.exe>"
```

`verify.ps1` runs both files through the official build (`repro.gd` calls `Image.new().load(path)`). Expected: the valid baseline exits 0; the crafted file exits with `STATUS_HEAP_CORRUPTION` (`0xC0000374`).

## Trigger context

Godot imports `.hdr` files automatically during asset import. An exported game that loads player- or community-supplied `.hdr` files exposes the same path to untrusted content.

## Status

The loader was added in May 2017 (commit bb20f230ad). Unpatched as of 2026-10-13 (master, 4.7.2, 4.7.1, 4.7). A suggested patch is in the original report (see the disclosure post's correspondence). Volunteer fix PR godotengine/godot#123862 was closed unmerged on 2026-09-26, the day it opened.

CVE: requested from the MITRE CNA-LR on 2026-09-20; pending as of 2026-10-14.

Full write-up and correspondence: https://axeghost.offprint.app/a/3mvs6zo4blo23-three-memory-safety-bugs-in-godots-untrusted-file-parsers
