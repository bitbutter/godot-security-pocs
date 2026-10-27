extends Node

# Orbitia — Community Server. A stock-exported Godot game running the
# community-server pattern (UDPServer + DTLSServer) from the Godot
# documentation. A join is one UDP datagram. Beyond the documented pattern
# this build adds a visual HUD and orbiting world, plus heap furniture a busy
# server would have (64 world entities touched per frame, rolling 64 KB work
# buffers). None of these additions are required to reach the vulnerable
# copy: the unchecked memcpy is in the engine's DTLS receive path, not in
# this script. The server also answers client keep-alives, forgets peers
# that vanish silently or never finish joining, and exits by itself after
# 30 minutes.

const COMMUNITY_SERVER_PORT := 4243
const MAX_PLAYERS := 64
const MAX_LIFETIME_SECONDS := 1800.0
const PLAYER_SILENCE_TIMEOUT := 5.0
const HANDSHAKE_TIMEOUT := 10.0

var community_udp_server := UDPServer.new()
var community_dtls_server := DTLSServer.new()
var connected_players: Array[PacketPeerDTLS] = []
var peer_joined_at: Array[float] = []
var peer_last_heard: Array[float] = []
var peer_was_connected: Array[bool] = []
var world_entities: Array[Node] = []
var elapsed_seconds := 0.0
var next_work_alloc := 0.0
var server_work_buffers: Array[PackedByteArray] = []
var join_events: Array[String] = []
var hud_label: Label
var hud_events_label: Label

class OrbitWorld extends Node2D:
	var time := 0.0
	const ORBS := 14

	func _process(delta: float) -> void:
		time += delta
		queue_redraw()

	func _draw() -> void:
		var center := Vector2(400, 235)
		draw_circle(center, 96.0, Color(0.07, 0.09, 0.13))
		for i in ORBS:
			var ring := 40.0 + 14.0 * (i % 5)
			var speed := 0.35 + 0.12 * (i % 7)
			var phase := time * speed + i * 0.7
			var pos := center + Vector2(cos(phase), sin(phase * 0.8)) * ring
			var col := Color.from_hsv(fmod(0.08 * i, 1.0), 0.55, 0.95)
			draw_circle(pos, 9.0, col)
		draw_circle(center, 12.0, Color(0.95, 0.85, 0.4))

const ACCENT := Color(0.95, 0.85, 0.4)   # shared Orbitia amber
const LINK_BLUE := Color(0.13, 0.17, 0.30)   # shared "connected" blue (client bg while linked)
var server_address := "127.0.0.1"

func _pick_own_address() -> String:
	# Community hosts publish the address players should join on; print the
	# machine's LAN address so the demo attacker knows what to target.
	for a in IP.get_local_addresses():
		if a.begins_with("192.168.") or a.begins_with("10.") or a.begins_with("172."):
			if a != "127.0.0.1":
				return a
	return "127.0.0.1"

func _record_event(text: String) -> void:
	# Every join/drop event goes to the HUD line and to engine output, so
	# headless validation runs can read the same history the window shows.
	join_events.append(text)
	print("COMMUNITY HOST: ", text)

func _ready() -> void:
	RenderingServer.set_default_clear_color(LINK_BLUE)
	server_address = _pick_own_address()
	DisplayServer.window_set_title("Orbitia — Server")
	DisplayServer.window_set_position(Vector2i(640, 120))
	var world := OrbitWorld.new()
	add_child(world)

	hud_label = Label.new()
	hud_label.position = Vector2(12, 10)
	hud_label.add_theme_font_size_override("font_size", 18)
	hud_label.add_theme_color_override("font_color", ACCENT)
	add_child(hud_label)

	hud_events_label = Label.new()
	hud_events_label.position = Vector2(12, 40)
	hud_events_label.add_theme_font_size_override("font_size", 14)
	hud_events_label.modulate = Color(0.8, 0.8, 0.85)
	add_child(hud_events_label)

	var host_crypto := Crypto.new()
	var host_key := host_crypto.generate_rsa(2048)
	var host_cert := host_crypto.generate_self_signed_certificate(host_key, "CN=Community Host,O=Community")
	var host_options := TLSOptions.server(host_key, host_cert)
	if community_dtls_server.setup(host_options) != OK:
		push_error("COMMUNITY HOST: DTLS setup failed")
		get_tree().quit(2)
		return
	if community_udp_server.listen(COMMUNITY_SERVER_PORT, "0.0.0.0") != OK:
		push_error("COMMUNITY HOST: UDP listen failed")
		get_tree().quit(3)
		return
	community_udp_server.set_max_pending_connections(16)
	for i in 64:
		var entity := Node.new()
		entity.name = "Entity%d" % i
		add_child(entity)
		world_entities.append(entity)
	_record_event("listening on port %d" % COMMUNITY_SERVER_PORT)

func _process(delta: float) -> void:
	elapsed_seconds += delta
	community_udp_server.poll()
	while community_udp_server.is_connection_available():
		var joining_udp := community_udp_server.take_connection()
		_record_event("join attempt from %s" % joining_udp.get_packet_ip())
		var joining_dtls := community_dtls_server.take_connection(joining_udp)
		if joining_dtls.is_null():
			_record_event("join rejected")
			continue
		connected_players.append(joining_dtls)
		peer_joined_at.append(elapsed_seconds)
		peer_last_heard.append(elapsed_seconds)
		peer_was_connected.append(false)
		_record_event("player join started (%d players)" % connected_players.size())
	var connected_now := 0
	for i in connected_players.size():
		var player := connected_players[i]
		player.poll()
		# Answer client keep-alive packets (only for fully connected players).
		# The reply carries the live player count, so clients display the same
		# numbers the server HUD shows. A client that stops hearing answers
		# knows the server died.
		if player.get_status() == PacketPeerDTLS.STATUS_CONNECTED:
			if not peer_was_connected[i]:
				peer_was_connected[i] = true
				peer_last_heard[i] = elapsed_seconds
			connected_now += 1
			while player.get_available_packet_count() > 0:
				var pkt := player.get_packet()
				peer_last_heard[i] = elapsed_seconds
				if pkt.size() >= 1 and pkt[0] == 1:
					var reply := PackedByteArray([1, connected_now, MAX_PLAYERS])
					player.put_packet(reply)
				else:
					player.put_packet(pkt)
	# A real server forgets peers that vanish: sockets that errored, joins
	# whose handshake never completes, and players that go silent (a closed
	# game window sends no goodbye over UDP). Without this, every re-take
	# leaves a ghost peer and the player count only ever climbs.
	for i in range(connected_players.size() - 1, -1, -1):
		var st := connected_players[i].get_status()
		var expired_handshake := st == PacketPeerDTLS.STATUS_HANDSHAKING \
				and elapsed_seconds - peer_joined_at[i] > HANDSHAKE_TIMEOUT
		var silent_player := st == PacketPeerDTLS.STATUS_CONNECTED \
				and elapsed_seconds - peer_last_heard[i] > PLAYER_SILENCE_TIMEOUT
		if st == PacketPeerDTLS.STATUS_ERROR or st == PacketPeerDTLS.STATUS_DISCONNECTED \
				or expired_handshake or silent_player:
			var was_player := st == PacketPeerDTLS.STATUS_CONNECTED
			connected_players.remove_at(i)
			peer_joined_at.remove_at(i)
			peer_last_heard.remove_at(i)
			peer_was_connected.remove_at(i)
			if was_player:
				_record_event("player dropped (%d players)" % connected_players.size())
			else:
				_record_event("join timed out")
	for entity in world_entities:
		var _cls := entity.get_class()
	if elapsed_seconds >= next_work_alloc:
		next_work_alloc = elapsed_seconds + 0.4
		server_work_buffers.append(PackedByteArray())
		server_work_buffers[server_work_buffers.size() - 1].resize(65536)
		if server_work_buffers.size() > 40:
			server_work_buffers.remove_at(0)
	hud_label.text = "ORBITIA SERVER   %s:%d   players %d   %d:%02d" % [
		server_address, COMMUNITY_SERVER_PORT, connected_now,
		int(elapsed_seconds / 60), int(elapsed_seconds) % 60
	]
	if join_events.size() > 2:
		join_events = join_events.slice(join_events.size() - 2)
	hud_events_label.text = " > ".join(join_events)
	if elapsed_seconds >= MAX_LIFETIME_SECONDS:
		print("COMMUNITY HOST: lifetime limit reached, quitting cleanly")
		get_tree().quit(0)
