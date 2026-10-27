# Integer-overflow / out-of-bounds read in `SceneReplicationInterface::on_spawn_receive` (network-reachable)

**Engine:** Godot 4.7 (official stable build); identical pattern on `master`
(`3df26a02c4`, 2026-06-26), `4.7-stable`. (`4.6.3-stable` uses the same file.)
**Component:** `modules/multiplayer/scene_replication_interface.cpp` —
`SceneReplicationInterface::on_spawn_receive()`, the spawn-packet bounds check and
sync-ids loop.
**Lines:** master `586` (the check) / `588-591` (the loop); `4.7-stable` `586` / `588-591`.
**Class:** `uint32` multiplication overflow defeating a length check → unbounded loop
with out-of-bounds heap reads → access violation. `memory_corruption_security`.
**Status:** disclosure in this set (#1 HDR RLE write, #2 binary-resource write,
#3 translation OOB read
precede this).

> **Threat-model note (read first).** This is the first disclosure in this set whose
> demo is **not** "you opened/loaded a bad file." A remote attacker pops a running
> Godot multiplayer **client** with a single crafted packet — no `.scn`/`.res`/`.pck`,
> no `@tool`, no autoload beyond the client connecting to the attacker's server. The
> victim's only action is "connect to a game server." This is a different threat model
> than #1–#3 (untrusted file) and, per the severity filter, clears it on all three axes.

## The bug

```cpp
// modules/multiplayer/scene_replication_interface.cpp — on_spawn_receive()
// (master 569-591, identical on 4.7-stable)
Error SceneReplicationInterface::on_spawn_receive(int p_from, const uint8_t *p_buffer, int p_buffer_len) {
    ERR_FAIL_COND_V_MSG(p_buffer_len < 18, ERR_INVALID_DATA, "Invalid spawn packet received");
    int ofs = 1;                       // ofs == 1
    uint8_t scene_id = p_buffer[ofs]; ofs += 1;        // ofs == 2
    uint32_t node_target = decode_uint32(&p_buffer[ofs]); ofs += 4;   // ofs == 6
    ... // spawner lookup + authority gate
    uint32_t net_id   = decode_uint32(&p_buffer[ofs]); ofs += 4;      // ofs == 10
    uint32_t sync_len = decode_uint32(&p_buffer[ofs]); ofs += 4;      // ofs == 14  ATTACKER-CONTROLLED
    uint32_t name_len = decode_uint32(&p_buffer[ofs]); ofs += 4;      // ofs == 18  ATTACKER-CONTROLLED
    ERR_FAIL_COND_V_MSG(
        name_len + (sync_len * 4) > uint32_t(p_buffer_len - ofs),     // (A) BUG
        ERR_INVALID_DATA, vformat("Invalid spawn packet size: %d, wants: %d",
                                  p_buffer_len, ofs + name_len + (sync_len * 4)));
    List<uint32_t> sync_ids;
    for (uint32_t i = 0; i < sync_len; i++) {                          // (B) runs sync_len times
        sync_ids.push_back(decode_uint32(&p_buffer[ofs]));            // (C) OOB heap read
        ofs += 4;
    }
    ...
```

`sync_len` and `name_len` come straight from the attacker-controlled `NETWORK_COMMAND_SPAWN`
packet (`decode_uint32`). The bounds check **(A)** is meant to ensure the packet is large
enough to hold the sync-ids array (`sync_len * 4` bytes) plus the name (`name_len` bytes).
But the arithmetic is done in `uint32_t`, and **`sync_len * 4` overflows**:

- `sync_len = 0x40000000` → `sync_len * 4 = 0x1_0000_0000`, which **wraps to `0`** in 32-bit.
- The check becomes `name_len + 0 > uint32_t(p_buffer_len - 18)`. With `name_len = 1` and
  any packet `>= 19` bytes, this is **false** — the check **passes**.
- The loop **(B)** then runs `sync_len` (= 2³⁰) times. Each iteration calls
  `decode_uint32(&p_buffer[ofs])` and does `ofs += 4`. After `ofs` exceeds `p_buffer_len`,
  every read **(C)** is an **out-of-bounds heap read** past the packet's `Vector<uint8_t>`
  backing buffer; `ofs` (a signed `int`) walks forward in 4-byte steps until it lands on
  an unmapped page and the process faults — `STATUS_ACCESS_VIOLATION` / SIGSEGV (signal 11).

`decode_uint32` (`core/io/marshalls.h:167`) performs no bounds checking of its own — it
reads 4 bytes from the pointer it is handed, period. So nothing downstream re-validates;
the only thing standing between an attacker and the OOB loop is the overflowing check at (A).

## Why this is genuinely an overflow, not an underflow (distinct from #118043)

A public, **unmerged** PR — [#118043 "Security: Add bounds checks to prevent integer
underflow in packet size validation"](https://github.com/godotengine/godot/pull/118043)
(opened 2026-03-31; closed unmerged on 2026-07-06) — already
flags **the same function** as having a bounds-check problem. **This disclosure is a
different bug in the same check, and the PR does not fix it.** The distinction matters:

- **#118043's bug** is the `uint32_t(p_buffer_len - ofs)` **subtraction underflow**: if
  `ofs > p_buffer_len`, the subtraction wraps to ~4 billion and the check passes. Its
  proposed fix adds `ofs > p_buffer_len ||` in front of the existing check.
- **This disclosure's bug** is the `sync_len * 4` **multiplication overflow**: `ofs`
  (=18) is **not** greater than `p_buffer_len`, so the `ofs > p_buffer_len` guard that
  #118043 adds is **false** and does nothing; `sync_len * 4` still wraps to 0 and the
  check still passes. **Even with #118043 merged exactly as proposed, this PoC still
  crashes.** (Verified by reading the PR diff against the master source; the PR leaves
  the `sync_len * 4` term untouched.) The fix for *this* bug must clamp/validate
  `sync_len` itself (see "The fix" below), which #118043 does not do.

The file is therefore already on the maintainer radar, which **lowers the novelty** of an
independent report (see Severity). But the specific primitive — the multiplication
overflow, with a working one-packet remote crash — is **distinct and unfixed** on `master`
and `4.7-stable`.

## Reachability (stock binary, remote attacker, no file)

`on_spawn_receive` is reached from `SceneMultiplayer::_process_packet` when a connected
peer sends a `NETWORK_COMMAND_SPAWN` (command byte `0x04`), dispatched at
`scene_multiplayer.cpp:238`. The MultiplayerAPI command layer is transport-agnostic —
the same packet bytes are delivered over ENet or WebSocket. The demo uses **WebSocket**
(the docs-friendly high-level path).

**The sympathetic demo — "the server you connect to hacks the player":** a Python
WebSocket server (`server.py`, the attacker) accepts a connection from a stock Godot 4.7
multiplayer **client** (`proj/victim_client.gd`, the victim) and sends three binary
WebSocket messages:

1. a 4-byte little-endian peer id (`2`) — the `WebSocketMultiplayerPeer` handshake
   (`_poll_server` sends this on connect);
2. a `NETWORK_COMMAND_SIMPLIFY_PATH` caching the client's `MultiplayerSpawner` under cache
   id `1` (so `on_spawn_receive`'s `get_cached_object(p_from=1, node_target=1)` returns
   the spawner and the authority gate passes);
3. **one** crafted `NETWORK_COMMAND_SPAWN` with `sync_len = 0x40000000`.

The client's only setup is the stock docs pattern for server-authoritative spawning: a
`MultiplayerSpawner` node with `spawn_path` set and `multiplayer_authority = 1` (the
server). That is exactly what a real multiplayer game does — the attacker needs no special
cooperation from the victim beyond "the client uses `MultiplayerSpawner` and connects to
my server."

Verified end-to-end on the stock Godot 4.7 Windows binary
(`Godot_v4.7-stable_win64.exe`): **SIGSEGV (signal 11) / `STATUS_ACCESS_VIOLATION`, exit
code 3221225477 (0xC0000005)**, ~1 second after connecting, inside `mp.poll()` in the client's
`_process`. Reproduced 5/5 on fresh ports. The crash backtrace is in
`proj/stock_binary_proof.txt`.

**Control (proves the overflow is the cause):** with `sync_len = 0x10000000` (which does
**not** overflow: `0x10000000 * 4 = 0x40000000`), the same packet is correctly rejected
by the bounds check — `on_spawn_receive` prints `Invalid spawn packet size` and the client
disconnects cleanly (exit 3, no crash). The only difference between the crashing and
non-crashing packet is whether `sync_len * 4` wraps. See CASE A vs CASE B in
`stock_binary_proof.txt`.

## Plausible real-world scenario (why "a remote crash" matters in practice)

The victim action this bug rides on — "join a multiplayer server" — is something players
do constantly and without suspicion, the way they'd join any game server. That is what makes
a remote crash, which for an in-editor/`@tool` bug would be a nuisance, into a genuine
user-experience attack surface here:

- **Griefing / service denial against a player base.** An attacker lists attractively-named
  servers in a game's server browser (or compromises a single popular community server
  real players already use). Every client that joins dies to desktop ~1 second after
  connecting — before they ever see a game world. Re-connectors get killed again. For a
  small multiplayer game whose community lives on a handful of community-run servers, that
  is enough to make the game effectively unplayable for as long as the attacker cares to
  keep it up. No exploit chain, no compromising individual players' machines — just
  standing at the door every player walks through.
- **Competitive disruption.** A rival operator, or a bad actor during a tournament /
  launch-window, can take a server (or a cluster of servers) offline-on-join for the
  affected player pool without ever touching the players' machines.
- **Stock-build reachability is what makes it bite.** This is not "a badly-coded game got
  it wrong." It fires against the unmodified Godot 4.7 engine, so it affects *every*
  shipped Godot-4.7 multiplayer title that uses the standard `MultiplayerSpawner`
  server-authoritative setup — until Godot ships a fix and each game updates its
  export templates.

This is the *proven* capability. The honest ceiling: it is a crash / OOB-read, not a
demonstrated code-execution primitive (see "What the crash is and is not" below). The
griefing/DoS scenario above stands within that proven ceiling; anything past it (running
code, stealing data) would require an exploit chain not built here and is not claimed.

## What the crash is and is not (honest)

- **Demonstrated impact: remote crash / DoS via out-of-bounds read.** The fast (~1s)
  SIGSEGV is an OOB read faulting on an unmapped page, **not** an OOM. (The
  `List<uint32_t> sync_ids` does grow per iteration, so an OOM abort is a *possible*
  secondary outcome on hosts where the OOB reads happen to stay in committed memory;
  on the stock 4.7 Windows build the OOB read reaches an unmapped page first and
  faults. Either way the attacker kills the process.)
- **OOB read, not a proven write.** The loop only *reads* `decode_uint32(&p_buffer[ofs])`
  and pushes the value into a `List<uint32_t>`. It does not write attacker bytes to an
  attacker-chosen address. So this is an **info-leak / crash** primitive, not a
  write-what-where. There is no demonstrated type-confusion or RCE here; the OOB bytes are not reinterpreted as a `Variant::OBJECT` pointer. Do **not** read
  RCE into this.
- **Reliability.** 5/5 crashes on fresh ports with the overflow value; the control
  (non-overflow) value reliably does not crash. The single observable flakiness is
  client-side timing: occasionally the client's poll loop disconnects before the SPAWN
  frame is processed (exit 3 instead of a crash). This is a demo-timing artifact, not
  instability of the bug itself — re-running crashes. A real victim (a shipped game
  polling every frame) would not have this window.

## Severity — assessed honestly against the "`@tool` baseline" filter

This set applies a filter: a candidate is "significantly higher risk" than the existing
threat model only if it (a) fires independently of `@tool`/autoload, **or** (b) grants a
capability `@tool` cannot, **or** (c) is reachable with no project open.

This bug **passes the filter on (a), (b), and (c) simultaneously** — and unlike the file
bugs, the threat model itself is different:

- **(c) Reachable with no project open / no file at all.** This is the headline difference
  from #1–#3. The victim runs a game (shipped, exported, or in-editor) and connects to a
  server. The attacker is **remote** — not someone handing the victim a file. No `.scn`,
  `.res`, `.pck`, `.hdr`, `.translation` is involved. A player who never opens the editor
  and never imports anything is still a target.
- **(b) Grants a capability `@tool` cannot.** `@tool` GDScript runs *valid* script
  in-process; it cannot perform a raw-pointer out-of-bounds heap read. This bug reads
  attacker-steered offsets past a buffer into heap memory — an OOB-read / info-leak
  primitive `@tool` is structurally incapable of producing. (It is *not* a write or type
  confusion — see above — so "High," not "Critical.")
- **(a) Fires independently of `@tool`.** It is pure network input to a running
  `MultiplayerAPI`; no `@tool` script and no autoload executes on the attacker's behalf.
  The victim's GDScript is the normal docs connect-and-spawn pattern.

**Rating: High.** It is a genuine memory-corruption primitive (OOB heap read) reachable
**remotely** from a server a client connects to, with a one-packet crash and a control
proving the overflow is the cause. It is **not Critical** because: (i) the demonstrated
outcome is a crash / OOB-read, not a controlled write or RCE; (ii) reachability requires
the victim to use `MultiplayerSpawner` and to connect to the attacker's server (the
attacker is not arbitrary on the network — they must be the server the client chose);
and (iii) **novelty is reduced** because the same function is already publicly flagged by
unmerged PR #118043 (a different overflow in the same check). What is new here is the
*specific* multiplication-overflow primitive and the remote-client PoC; the file/surface
was already known to have bounds-check gaps.

Even with the reduced novelty, the bug is **unfixed on `master` and `4.7-stable`** and
**#118043 would not fix it**, so a disclosure adds concrete value: it points the
maintainers at a second, distinct overflow and a verified remote reachability path
(WebSocket multiplayer client) that the PR's write-up does not demonstrate.

## The fix

Validate `sync_len` (and `name_len`) so the multiplication cannot overflow and the claimed
total cannot exceed the buffer. Mirror the overflow-guard pattern the rest of the file
already uses for packed-array counts (`ERR_FAIL_MUL_OF` in `marshalls.cpp`; note this macro is file-local to marshalls.cpp, so it would need to be hoisted into a header before use in scene_replication_interface.cpp):

```cpp
// on_spawn_receive, after reading sync_len and name_len (master:584-585)
ERR_FAIL_COND_V_MSG(ofs > p_buffer_len, ERR_INVALID_DATA, "Invalid spawn packet.");   // #118043's guard
ERR_FAIL_MUL_OF(sync_len, 4, ERR_INVALID_DATA);                                        // <-- fixes THIS bug
ERR_FAIL_COND_V_MSG(sync_len > (uint32_t)(p_buffer_len - ofs) / 4
                        || name_len > (uint32_t)(p_buffer_len - ofs) - sync_len * 4,
                    ERR_INVALID_DATA, "Invalid spawn packet size.");
```

The robust formulation is to check `sync_len * 4` via a non-overflowing comparison
(`sync_len > (len - ofs) / 4`) rather than the multiplying form. The same
multiplication-overflow shape should be audited in the `name_len`/`sync_len` reads of
`on_spawn_receive` and in any sibling `count * elem_size` checks in
`on_delta_receive` / `on_sync_receive` (those use `size > p_buffer_len - ofs`, which
#118043's subtraction-underflow guard already addresses, but a multiplication overflow
audit is warranted where a count is multiplied).

Note: #118043's `ofs > p_buffer_len` guard is still worth merging (it fixes the
subtraction underflow), but it is **not sufficient** on its own — it must be paired with
the `sync_len` validation above.

## Repro

`make_repro.py` regenerates `server.py`, `proj/victim_client.gd`, `proj/project.godot`,
and `capture_proof.py` from scratch. Then:

```
python server.py                                   # malicious server (attacker)
# another terminal:
godot --headless --path proj --script res://victim_client.gd   # victim client
# -> access violation (exit 3221225477 / 0xC0000005) ~1s after connecting
```

`capture_proof.py` runs CASE A (overflow → crash) and CASE B (control, no overflow →
clean reject) and writes `proj/stock_binary_proof.txt`.

The crafted `NETWORK_COMMAND_SPAWN` (27 bytes, little-endian):

| Offset | Field | Value |
|---|---|---|
| 0 | cmd | `0x04` (NETWORK_COMMAND_SPAWN) |
| 1 | scene_id | `0x00` (moot; overflow fires before `instantiate_*`) |
| 2..5 | node_target | `0x00000001` (cache id 1 → the spawner) |
| 6..9 | net_id | `0x00000001` |
| 10..13 | **sync_len** | **`0x40000000`**  ← `*4` wraps to `0`, defeating the check |
| 14..17 | name_len | `0x00000001` |
| 18 | name | `'a'` |
| 19..26 | slack | zeros |

The single malicious value is `sync_len = 0x40000000`. Every other field is valid; only
the multiplication overflows.
