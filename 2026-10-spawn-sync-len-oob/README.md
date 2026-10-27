# Godot multiplayer spawn packet `sync_len*4` integer overflow — reproduction artifacts

Reproduction for an out-of-bounds-read vulnerability in Godot 4.x disclosed on 2026-10-27: the spawn-packet bounds check in `SceneReplicationInterface::on_spawn_receive` (`modules/multiplayer/scene_replication_interface.cpp:586`) computes `name_len + (sync_len * 4)` in 32-bit unsigned arithmetic. A crafted `sync_len` of `0x40000000` wraps that product to 0, defeats the check, and the sync-ids loop that follows reads past the packet buffer until the client process faults. One crafted packet from a peer holding multiplayer spawn authority — the game server by default — reliably crashes joining clients running the stock engine. Present in every stable release 4.0 through 4.7.2 and on master (introduced in commit `32a62af648`, 2022-10-03); confirmed at runtime on the official 4.7-stable build.

## The demonstration

`server.py` (the attacker) is a Python WebSocket game server. `proj/victim_client.gd` (the victim) is the standard Godot docs setup for server-authoritative spawning: a `SceneMultiplayer` + `WebSocketMultiplayerPeer` client with a `MultiplayerSpawner` node. The server sends three binary WebSocket messages: a 4-byte peer id (the normal handshake), a `NETWORK_COMMAND_SIMPLIFY_PATH` that caches the client's spawner (normal cache traffic), then one crafted `NETWORK_COMMAND_SPAWN` whose `sync_len = 0x40000000`. The only malicious value in the exchange is that field.

Expected on the official 4.7-stable Windows binary: the client terminates with `STATUS_ACCESS_VIOLATION`, exit code 3221225477 (`0xC0000005`), about one second after connecting. Reproduced 5/5 runs on fresh ports; the captured crash and control output of 2026-10-07 is `proj/stock_binary_proof.txt`.

Control case, proving the overflow is the cause: with `sync_len = 0x10000000` (product `0x40000000`, no wrap) the same bounds check correctly rejects the packet (`Invalid spawn packet size`), and the client disconnects cleanly without crashing. The only difference between the crashing and non-crashing packets is whether `sync_len * 4` wraps.

## Reproduce

Requirements: the Godot 4.7-stable executable (on `PATH` as `godot`, or set the `GODOT` environment variable to its full path), Python 3.8+ with `websockets` (`pip install websockets`).

```
python server.py                                                # terminal 1: malicious game server
godot --headless --path proj --script res://victim_client.gd    # terminal 2: victim client
```

Or capture both cases in one run: `python capture_proof.py` (regenerates `proj/stock_binary_proof.txt`). `SPAWN_SYNC_LEN` and `LISTEN_PORT` environment variables override the default payload and port; see `killer_packets.txt` for five independently fuzz-found killer packets (two distinct `sync_len` values: `0x80000000`, `0x80000001`).

## Files

| Path | Description |
|---|---|
| `bug_analysis.md` | Full technical write-up: root cause, reachability, severity reasoning, suggested fix |
| `server.py` | The malicious WebSocket server (attacker side) |
| `capture_proof.py` | Runs crash case + control case, writes the proof file |
| `make_repro.py` | Regenerates the kit from scratch (generator retained from the vendor report) |
| `killer_packets.txt` | Five fuzz-derived trigger variants with bisected minimal forms |
| `proj/victim_client.gd` | Minimal stock Godot 4.7 multiplayer client (victim) |
| `proj/project.godot` | Minimal Godot 4.7 project |
| `proj/stock_binary_proof.txt` | Captured crash + control output on the stock 4.7 binary (2026-10-07) |

## Integrity

`SHA256SUMS.txt` lists the SHA-256 of every file in this directory (this README and the manifest itself excepted). The kit — the eight files listed in the manifest — is the archive sent to security@godotengine.org on 2026-10-07 with three documented changes: (1) the researcher's local Godot executable path, hardcoded in `capture_proof.py` and `make_repro.py` and printed in the proof-file header, was replaced by the `GODOT` environment variable / redacted to the binary name; (2) references in `bug_analysis.md` to findings not yet published — their names, their ordinal slots, and range comparisons that included them — were removed before publication; (3) two stale facts in `bug_analysis.md` were corrected before publication: the state of PR #118043 (it was closed unmerged on 2026-07-06) and the Windows exit code (3221225477, not 139). No other byte differs from the vendor-sent archive. The code comments and output banners retain the researcher's internal working number `006` for this disclosure; it is a working ordinal, not a count of published disclosures.

Found and verified during an LLM-directed security audit of Godot, directed by Tomasz Kaye. These artifacts and this README were prepared with LLM assistance under his direction and approved by him.
