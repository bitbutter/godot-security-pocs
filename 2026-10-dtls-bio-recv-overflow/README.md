# Godot DTLS receive-callback heap buffer overflow — reproduction artifacts

Reproduction for an unauthenticated heap buffer overflow in Godot's DTLS networking, disclosed 2026-10-27: the DTLS receive callback `PacketPeerMbedDTLS::bio_recv` (`modules/mbedtls/packet_peer_mbed_dtls.cpp:75`) ignores the buffer capacity that mbedTLS passes it and copies the entire received UDP datagram — up to 65,507 bytes over IPv4 — into a 16,765-byte heap input buffer, before certificate verification or any authentication. One datagram kills a game server using the documented `UDPServer` + `DTLSServer` community-server pattern when a player joins, and kills a player who joins a hostile server. Present in every tag inspected (3.2.2, 4.7, 4.7.1, 4.7.2) and master; runtime-confirmed on the official 4.7-stable Windows release template.

Demonstration video: https://www.youtube.com/watch?v=Outi7jvU2VY

## The demonstration

`server/` is the victim: a minimal Godot 4.7 project running the documented community-server pattern — `UDPServer.listen` on UDP port 4243 wrapped in `DTLSServer` with a self-signed certificate. It adds a HUD, some heap activity a busy server would have, keep-alive, timeouts, and a 30-minute auto-exit; none of that is required for the crash.

`join.ps1` is the attack. It probes that the server answers DTLS handshakes, sends one 65,507-byte join datagram from an ordinary UDP socket, and probes again: a healthy DTLS server answers every ClientHello with a cookie challenge; a dead one answers nothing. The attacker side needs no Godot tooling — the script runs in plain PowerShell.

Expected on the official 4.7-stable Windows template: the host process dies at the join. In the original verification this killed the host in 20 of 21 fresh runs; the remaining run left a process whose main loop was dead. The kill threshold measured on 4.7 sits where the allocator detects the overwrite: 16,776-byte datagrams were processed cleanly, 16,777 bytes killed in every run. An AddressSanitizer build of the exact 4.7 tag shows the underlying write directly: `heap-buffer-overflow WRITE of size 65507`, at the buffer's end.

## Files

| Path | Description |
|---|---|
| `server/` | The victim Godot 4.7 project (`main.gd`, `main.tscn`, `project.godot`) — documented community-server pattern plus non-essential demo additions |
| `join.ps1` | The attack script: probe, one oversized join datagram, confirm the kill |

## Reproduce

1. Open `server/project.godot` in the Godot 4.7 editor and run the main scene, or export it with a Windows Desktop preset and run the exe. The event line shows `listening on port 4243`.
2. From any machine that can reach the server, in this directory:

```
powershell -ExecutionPolicy Bypass -File join.ps1 -Server <host>
```

`-Port` defaults to 4243 and `-Bytes` to 65507. A control run with `-Bytes 1200` is expected to end on the script's `server is still answering` line — that is the control passing.

## Integrity

`SHA256SUMS.txt` lists the SHA-256 of every file in this directory (this README and the manifest itself excepted). All five kit files are byte-identical to the archive sent to security@godotengine.org on 2026-09-26. The vendor archive's own README (which linked the demonstration video through a private Google Drive URL) is replaced by this public README; the public video is linked above.

Found and verified during an LLM-directed security audit of Godot, directed by Tomasz Kaye. These artifacts and this README were prepared with LLM assistance under his direction and approved by him.
