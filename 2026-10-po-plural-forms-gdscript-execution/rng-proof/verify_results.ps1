param(
    [Parameter(Mandatory = $true)]
    [string]$OrdinaryResultPath,

    [Parameter(Mandatory = $true)]
    [string]$RngResetResultPath
)

$ordinary = Get-Content -LiteralPath $OrdinaryResultPath -Raw | ConvertFrom-Json
$rngReset = Get-Content -LiteralPath $RngResetResultPath -Raw | ConvertFrom-Json

$failures = [System.Collections.Generic.List[string]]::new()

if ($ordinary.community_translation_locale -ne "en_US") {
    $failures.Add("Ordinary control locale was not parsed as en_US.")
}
if (-not $ordinary.process_survived_after_plural_translation) {
    $failures.Add("Ordinary control process did not survive.")
}
if (-not $ordinary.matches_innocent_game_rng_sequence) {
    $failures.Add("Ordinary plural rule changed the innocent game's RNG sequence.")
}
if ($ordinary.matches_attacker_chosen_rng_sequence) {
    $failures.Add("Ordinary control unexpectedly matched the attacker-chosen RNG sequence.")
}
if ($rngReset.community_translation_locale -ne "en_US") {
    $failures.Add("RNG-reset candidate locale was not parsed as en_US.")
}
if (-not $rngReset.process_survived_after_plural_translation) {
    $failures.Add("RNG-reset candidate process did not survive.")
}
if (-not $rngReset.matches_attacker_chosen_rng_sequence) {
    $failures.Add("RNG-reset candidate did not select the attacker-chosen RNG sequence.")
}
if ($rngReset.matches_innocent_game_rng_sequence) {
    $failures.Add("RNG-reset candidate retained the innocent game's RNG sequence.")
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

[ordered]@{
    ordinary_control_preserved_game_rng = $true
    rng_reset_rule_selected_attacker_rng = $true
    both_exported_processes_survived = $true
} | ConvertTo-Json
