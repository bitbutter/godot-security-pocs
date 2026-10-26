extends Node

const EXPECTED_COMMUNITY_TRANSLATION_LOCALE := "en_US"
const HARMLESS_EXECUTION_MARKER_NAME := &"po_plural_expression_code_execution_gate"
const HARMLESS_EXECUTION_MARKER_VALUE := "confirmed"
const PLURAL_MESSAGE_ID := &"COMMUNITY_APPLE"
const PLURAL_MESSAGE_FALLBACK := &"COMMUNITY_APPLES"


func _ready() -> void:
	var arguments := OS.get_cmdline_user_args()
	if arguments.size() != 2:
		push_error("Expected <external community PO path> <result JSON path>")
		get_tree().quit(2)
		return

	var community_translation_path := arguments[0]
	var result_path := arguments[1]
	var marker_present_before_loading := Engine.has_meta(HARMLESS_EXECUTION_MARKER_NAME)
	var marker_value_before_loading: Variant = null
	if marker_present_before_loading:
		marker_value_before_loading = Engine.get_meta(HARMLESS_EXECUTION_MARKER_NAME)

	var community_translation := ResourceLoader.load(
		community_translation_path,
		"Translation",
		ResourceLoader.CACHE_MODE_IGNORE
	) as Translation
	if community_translation == null:
		push_error("Could not load external community PO translation")
		get_tree().quit(3)
		return
	if community_translation.locale != EXPECTED_COMMUNITY_TRANSLATION_LOCALE:
		push_error(
			"Expected community translation locale %s, got %s" % [
				EXPECTED_COMMUNITY_TRANSLATION_LOCALE,
				community_translation.locale,
			]
		)
		get_tree().quit(4)
		return

	var marker_present_after_loading_before_plural_lookup := Engine.has_meta(
		HARMLESS_EXECUTION_MARKER_NAME
	)
	var marker_value_after_loading_before_plural_lookup: Variant = null
	if marker_present_after_loading_before_plural_lookup:
		marker_value_after_loading_before_plural_lookup = Engine.get_meta(
			HARMLESS_EXECUTION_MARKER_NAME
		)

	TranslationServer.clear()
	TranslationServer.add_translation(community_translation)
	TranslationServer.set_locale(community_translation.locale)

	var translated_plural_text := tr_n(
		PLURAL_MESSAGE_ID,
		PLURAL_MESSAGE_FALLBACK,
		2
	)
	var marker_present_after_plural_lookup := Engine.has_meta(
		HARMLESS_EXECUTION_MARKER_NAME
	)
	var marker_value_after_plural_lookup: Variant = null
	if marker_present_after_plural_lookup:
		marker_value_after_plural_lookup = Engine.get_meta(HARMLESS_EXECUTION_MARKER_NAME)

	var result := {
		"community_translation_locale": community_translation.locale,
		"community_translation_path": community_translation_path,
		"expected_harmless_execution_marker_value": HARMLESS_EXECUTION_MARKER_VALUE,
		"marker_present_after_loading_before_plural_lookup": marker_present_after_loading_before_plural_lookup,
		"marker_present_after_plural_lookup": marker_present_after_plural_lookup,
		"marker_present_before_loading": marker_present_before_loading,
		"marker_value_after_loading_before_plural_lookup": marker_value_after_loading_before_plural_lookup,
		"marker_value_after_plural_lookup": marker_value_after_plural_lookup,
		"marker_value_before_loading": marker_value_before_loading,
		"process_survived_after_plural_translation": true,
		"translated_plural_text": translated_plural_text,
	}

	var result_file := FileAccess.open(result_path, FileAccess.WRITE)
	if result_file == null:
		push_error("Could not create result JSON")
		get_tree().quit(5)
		return
	result_file.store_string(JSON.stringify(result, "  ") + "\n")
	result_file.close()
	print("PO_PLURAL_CODE_EXECUTION_GATE_RESULT ", JSON.stringify(result))
	get_tree().quit(0)
