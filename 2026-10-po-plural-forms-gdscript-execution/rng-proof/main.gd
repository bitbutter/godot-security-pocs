extends Node

const ATTACKER_CHOSEN_RNG_SEED := 123456789
const INNOCENT_GAME_RNG_SEED := 987654321
const EXPECTED_COMMUNITY_TRANSLATION_LOCALE := "en_US"
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

	TranslationServer.clear()
	TranslationServer.add_translation(community_translation)
	TranslationServer.set_locale(community_translation.locale)

	seed(ATTACKER_CHOSEN_RNG_SEED)
	var expected_next_random_value_after_attacker_seed := randi()

	seed(INNOCENT_GAME_RNG_SEED)
	var expected_next_random_value_without_translation_side_effect := randi()

	seed(INNOCENT_GAME_RNG_SEED)
	var translated_plural_text := tr_n(
		PLURAL_MESSAGE_ID,
		PLURAL_MESSAGE_FALLBACK,
		2
	)
	var actual_next_random_value_after_plural_translation := randi()

	var result := {
		"actual_next_random_value_after_plural_translation": actual_next_random_value_after_plural_translation,
		"attacker_chosen_rng_seed": ATTACKER_CHOSEN_RNG_SEED,
		"community_translation_locale": community_translation.locale,
		"community_translation_path": community_translation_path,
		"expected_next_random_value_after_attacker_seed": expected_next_random_value_after_attacker_seed,
		"expected_next_random_value_without_translation_side_effect": expected_next_random_value_without_translation_side_effect,
		"innocent_game_rng_seed": INNOCENT_GAME_RNG_SEED,
		"matches_attacker_chosen_rng_sequence": actual_next_random_value_after_plural_translation == expected_next_random_value_after_attacker_seed,
		"matches_innocent_game_rng_sequence": actual_next_random_value_after_plural_translation == expected_next_random_value_without_translation_side_effect,
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
	print("PO_PLURAL_EXPRESSION_RESULT ", JSON.stringify(result))
	get_tree().quit(0)
