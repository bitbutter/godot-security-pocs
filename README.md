# Godot security PoCs

Reproduction material for security vulnerabilities in Godot Engine, published at each bug's disclosure. One directory per disclosure, named by disclosure date and topic.

## Index

| Disclosure | Directory | Bugs |
|---|---|---|
| 2026-09-21 — untrusted-file parsers | [`2026-09-untrusted-file-parsers/`](2026-09-untrusted-file-parsers/) | 3 (HDR image loader, binary resource loader, OptimizedTranslation) |

## Integrity

Every directory contains the original reproduction archives exactly as distributed at disclosure, with SHA-256 hashes stated in its README, plus the extracted contents. Verify downloads against the stated hashes; several archives also carry generator scripts that rebuild the crafted inputs from scratch.

## Handling

These are crash and information-disclosure proofs of concept, not working exploits. Use them only against Godot installations you own. The crafted files intentionally corrupt memory in the target process.

## License

MIT — see [LICENSE](LICENSE).
