extends SceneTree

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
