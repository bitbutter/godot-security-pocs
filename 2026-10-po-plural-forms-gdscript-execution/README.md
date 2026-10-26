# Godot .po Plural-Forms code execution — reproduction artifacts

Reproduction for a code-execution vulnerability in Godot 4.x disclosed on 2026-10-27: the `Plural-Forms` header of a `.po` translation file is evaluated by the engine's general `Expression` evaluator, which exposes registered Variant utility functions and, through `bytes_to_var_with_objects()`, deserialization of a serialized `GDScript` object whose `script/source` property is attacker-supplied; decoding compiles and statically initializes that script at the first plural lookup (`tr_n()`).

Demonstration video: https://youtu.be/LnNNx1F2aGo

## rng-proof/

Proves that a translation header reaches the general expression evaluator with side effects, on a stock export.

- `ordinary_plural_rule.po` — control: the ordinary header `plural=(n != 1)`.
- `rng_reset_plural_rule.po` — candidate: `plural=seed(123456789)`, illegal under the GNU gettext grammar.
- `main.gd`, `main.tscn`, `project.godot`, `export_presets.cfg` — the probe game. It loads an external `.po` as a `Translation`, registers it with `TranslationServer`, calls `tr_n()`, then reads the next global `randi()`.
- `verify_results.ps1` — compares the two result JSON files.

Open the project in Godot 4.7-stable, export for Windows Desktop, and run the exported executable once per fixture:

```
CommunityTranslationPluralRuleProbe.exe --headless -- <absolute .po path> <absolute result.json path>
```

Expected: the ordinary fixture yields the game's own RNG value; the candidate yields the attacker-chosen value. Verified 10/10 runs vs 10/10 controls in the original sandbox runs (2026-09-23).

## code-execution-gate/

Proves GDScript execution, with a payload whose only permitted effect is an in-memory marker.

- `code_execution_plural_rule.po` — candidate: the header decodes a 180-byte Variant record through `bytes_to_var_with_objects()`. The record contains one object, a `GDScript` whose `script/source` property is attacker-supplied source; its static initializer sets `Engine.set_meta("confirmed")` and does nothing else.
- `ordinary_plural_rule.po` — control.
- `main.gd`, `main.tscn`, `project.godot`, `export_presets.cfg` — the gate game (same innocent shape as rng-proof; marker observed before load, after load, and after `tr_n()`).
- `verify_code_execution_gate.ps1` — verifies the 20-process result set (marker absent in all controls; present only after `tr_n()` in all candidates; every process exits normally).

Verified 10/10 vs 10/10 with clean export and runtime logs in the retained sandbox run of 2026-09-23. That evidence set is retained privately; in this public tree, run `verify_code_execution_gate.ps1 -StructureOnly` to check the published fixtures' structure and payload bytes.

## Integrity

`SHA256SUMS.txt` lists the SHA-256 of every fixture, script, and project file in this directory (this README and the manifest itself excepted). The two `rng-proof` fixtures are byte-identical to the fixtures sent to security@godotengine.org on 2026-09-23.

Found and verified during an LLM-directed security audit of Godot, directed by Tomasz Kaye. These artifacts and this README were prepared with LLM assistance under his direction and approved by him.
