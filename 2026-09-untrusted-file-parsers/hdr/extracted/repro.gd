extends SceneTree
func _initialize():
	var args := OS.get_cmdline_user_args()
	var path := "res://evil4ch.hdr" if args.is_empty() else args[0]
	Image.new().load(path)
	quit(0)
