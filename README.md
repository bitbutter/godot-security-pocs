# Godot security PoCs

Reproduction material for security vulnerabilities in Godot Engine, published at each bug's disclosure. One directory per disclosure, named by disclosure date and topic.

## Index

| Disclosure | Directory | Bugs |
|---|---|---|
| 2026-09-21 — untrusted-file parsers | [`2026-09-untrusted-file-parsers/`](2026-09-untrusted-file-parsers/) | 3 (HDR image loader, binary resource loader, OptimizedTranslation) |
| 2026-10-26 — .po Plural-Forms code execution | [`2026-10-po-plural-forms-gdscript-execution/`](2026-10-po-plural-forms-gdscript-execution/) | 1 (translation Plural-Forms header → GDScript execution) |
| 2026-10-27 — multiplayer spawn packet overflow | [`2026-10-spawn-sync-len-oob/`](2026-10-spawn-sync-len-oob/) | 1 (`sync_len*4` integer overflow → out-of-bounds read, `on_spawn_receive`) |
| 2026-10-27 — DTLS receive-callback heap overflow | [`2026-10-dtls-bio-recv-overflow/`](2026-10-dtls-bio-recv-overflow/) | 1 (unauthenticated datagram → heap buffer overflow, `bio_recv`) |

## Integrity

The 2026-09 directory carries the original reproduction archives exactly as distributed at disclosure, plus the extracted contents. The 2026-10 directories carry the disclosure kit files directly, each with a `SHA256SUMS.txt` manifest (`sha256sum -c SHA256SUMS.txt`); their READMEs state exactly how the kit differs from the archive sent to the vendor. Verify downloads against the stated hashes; several kits also carry generator scripts that rebuild the crafted inputs from scratch.

## Handling

These are crash and information-disclosure proofs of concept, not working exploits. Use them only against Godot installations you own. The crafted files intentionally corrupt memory in the target process.

## License

MIT — see [LICENSE](LICENSE).
