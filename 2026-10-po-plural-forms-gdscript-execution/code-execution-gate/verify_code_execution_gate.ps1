param(
    [string]$OrdinaryFixturePath = "$PSScriptRoot\ordinary_plural_rule.po",
    [string]$CandidateFixturePath = "$PSScriptRoot\code_execution_plural_rule.po",
    [string]$ResultsDirectory = "$PSScriptRoot\results",
    [switch]$StructureOnly
)

$ErrorActionPreference = "Stop"
$ExpectedLocale = "en_US"
$ExpectedMarker = "confirmed"
$ExpectedSource = @"
extends RefCounted
static func _static_init() -> void:
`tEngine.set_meta("po_plural_expression_code_execution_gate", "confirmed")

"@ -replace "`r`n", "`n"

function Add-UInt32LittleEndian {
    param(
        [System.Collections.Generic.List[byte]]$Destination,
        [uint32]$Value
    )
    $Destination.AddRange([BitConverter]::GetBytes($Value))
}

function Add-PaddedUtf8String {
    param(
        [System.Collections.Generic.List[byte]]$Destination,
        [string]$Value
    )
    $utf8 = [Text.Encoding]::UTF8.GetBytes($Value)
    Add-UInt32LittleEndian -Destination $Destination -Value $utf8.Length
    $Destination.AddRange($utf8)
    $paddingLength = (4 - ($utf8.Length % 4)) % 4
    for ($paddingIndex = 0; $paddingIndex -lt $paddingLength; $paddingIndex++) {
        $Destination.Add(0)
    }
}

function New-ExpectedVariantObjectRecord {
    $record = [System.Collections.Generic.List[byte]]::new()
    Add-UInt32LittleEndian -Destination $record -Value 24
    Add-PaddedUtf8String -Destination $record -Value "GDScript"
    Add-UInt32LittleEndian -Destination $record -Value 1
    Add-PaddedUtf8String -Destination $record -Value "script/source"
    Add-UInt32LittleEndian -Destination $record -Value 4
    Add-PaddedUtf8String -Destination $record -Value $ExpectedSource
    return $record.ToArray()
}

function Read-UInt32LittleEndian {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )
    if ($Offset.Value + 4 -gt $Bytes.Length) {
        throw "Variant object record ended before a uint32 field."
    }
    $value = [BitConverter]::ToUInt32($Bytes, $Offset.Value)
    $Offset.Value += 4
    return $value
}

function Read-PaddedUtf8String {
    param(
        [byte[]]$Bytes,
        [ref]$Offset
    )
    $length = Read-UInt32LittleEndian -Bytes $Bytes -Offset $Offset
    if ($Offset.Value + $length -gt $Bytes.Length) {
        throw "Variant object record ended inside a UTF-8 string."
    }
    $value = [Text.Encoding]::UTF8.GetString($Bytes, $Offset.Value, $length)
    $Offset.Value += $length
    $paddingLength = (4 - ($length % 4)) % 4
    if ($Offset.Value + $paddingLength -gt $Bytes.Length) {
        throw "Variant object record ended inside string padding."
    }
    for ($paddingIndex = 0; $paddingIndex -lt $paddingLength; $paddingIndex++) {
        if ($Bytes[$Offset.Value + $paddingIndex] -ne 0) {
            throw "Variant object record contains nonzero string padding."
        }
    }
    $Offset.Value += $paddingLength
    return $value
}

function Assert-ExactVariantObjectRecord {
    param([byte[]]$Bytes)

    $expectedBytes = New-ExpectedVariantObjectRecord
    if ($Bytes.Length -ne $expectedBytes.Length) {
        throw "Variant record length $($Bytes.Length) did not equal expected length $($expectedBytes.Length)."
    }
    for ($byteIndex = 0; $byteIndex -lt $expectedBytes.Length; $byteIndex++) {
        if ($Bytes[$byteIndex] -ne $expectedBytes[$byteIndex]) {
            throw "Variant record byte $byteIndex differed from the exact allowlisted record."
        }
    }

    $offset = 0
    if ((Read-UInt32LittleEndian -Bytes $Bytes -Offset ([ref]$offset)) -ne 24) {
        throw "Top-level Variant type is not an unflagged OBJECT record."
    }
    if ((Read-PaddedUtf8String -Bytes $Bytes -Offset ([ref]$offset)) -cne "GDScript") {
        throw "Object class is not exactly GDScript."
    }
    if ((Read-UInt32LittleEndian -Bytes $Bytes -Offset ([ref]$offset)) -ne 1) {
        throw "Object record must contain exactly one property."
    }
    if ((Read-PaddedUtf8String -Bytes $Bytes -Offset ([ref]$offset)) -cne "script/source") {
        throw "The only object property is not exactly script/source."
    }
    if ((Read-UInt32LittleEndian -Bytes $Bytes -Offset ([ref]$offset)) -ne 4) {
        throw "script/source value is not exactly a STRING Variant."
    }
    if ((Read-PaddedUtf8String -Bytes $Bytes -Offset ([ref]$offset)) -cne $ExpectedSource) {
        throw "Decoded GDScript source differs from the harmless marker allowlist."
    }
    if ($offset -ne $Bytes.Length) {
        throw "Variant object record contains trailing bytes."
    }
}

function Get-PluralExpression {
    param([string]$FixturePath)
    $rawFixture = Get-Content -LiteralPath $FixturePath -Raw
    $match = [regex]::Match(
        $rawFixture,
        '(?m)^"Plural-Forms: nplurals=2; plural=(?<expression>.+);\\n"$'
    )
    if (-not $match.Success) {
        throw "Could not find exactly formatted Plural-Forms header in $FixturePath."
    }
    return $match.Groups['expression'].Value
}

function Read-StrictIntegerFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required integer evidence file is missing: $Path"
    }
    $rawFileValue = Get-Content -LiteralPath $Path -Raw
    if ($null -eq $rawFileValue) {
        throw "Integer evidence is blank or non-numeric: $Path"
    }
    $rawValue = $rawFileValue.Trim()
    if ($rawValue -notmatch '^-?[0-9]+$') {
        throw "Integer evidence is blank or non-numeric: $Path"
    }
    $parsedValue = [int]0
    if (-not [int]::TryParse($rawValue, [ref]$parsedValue)) {
        throw "Integer evidence is outside the Int32 range: $Path"
    }
    return $parsedValue
}

function Assert-NoUnexpectedEngineError {
    param(
        [string]$Path,
        [string]$EvidenceLabel
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$EvidenceLabel is missing: $Path"
    }
    $logText = Get-Content -LiteralPath $Path -Raw
    if ($null -ne $logText -and $logText -match 'ERROR:') {
        throw "$EvidenceLabel contains an unexpected ERROR: line: $Path"
    }
}

$ordinaryExpression = Get-PluralExpression -FixturePath $OrdinaryFixturePath
if ($ordinaryExpression -cne '(n != 1)') {
    throw "Ordinary control plural expression changed."
}

$candidateExpression = Get-PluralExpression -FixturePath $CandidateFixturePath
$candidateMatch = [regex]::Match(
    $candidateExpression,
    '^\(bytes_to_var_with_objects\(PackedByteArray\(\[(?<bytes>[0-9,]+)\]\)\) != null\) && \(n != 1\)$'
)
if (-not $candidateMatch.Success) {
    throw "Candidate expression differs from the single allowlisted decode-and-normal-plural form."
}
$candidateBytes = [byte[]]($candidateMatch.Groups['bytes'].Value.Split(',') | ForEach-Object {
    $parsedByte = [byte]0
    if (-not [byte]::TryParse($_, [ref]$parsedByte)) {
        throw "Candidate record contains a value outside the byte range: $_"
    }
    $parsedByte
})
Assert-ExactVariantObjectRecord -Bytes $candidateBytes

$candidateFixtureText = Get-Content -LiteralPath $CandidateFixturePath -Raw
$forbiddenPayloadTokens = @(
    'FileAccess',
    'DirAccess',
    'HTTPRequest',
    'HTTPClient',
    'StreamPeer',
    'PacketPeer',
    'ResourceSaver',
    'ProjectSettings',
    'GDExtension',
    'shell_open',
    'create_process',
    'execute(',
    'preload('
)
foreach ($forbiddenToken in $forbiddenPayloadTokens) {
    if ($candidateFixtureText.Contains($forbiddenToken)) {
        throw "Candidate fixture contains forbidden token: $forbiddenToken"
    }
}

if ($StructureOnly) {
    [ordered]@{
        candidate_variant_record_bytes = $candidateBytes.Length
        candidate_variant_record_structure = "OBJECT(GDScript){script/source: STRING}"
        candidate_payload_exactly_allowlisted = $true
        result_files_examined = 0
    } | ConvertTo-Json
    return
}

$latestRunPointerPath = Join-Path $ResultsDirectory "latest_run_name.txt"
if (Test-Path -LiteralPath $latestRunPointerPath -PathType Leaf) {
    $latestRunName = (Get-Content -LiteralPath $latestRunPointerPath -Raw).Trim()
    if ($latestRunName -notmatch '^run_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{32}$') {
        throw "Latest-run pointer contains an unexpected directory name."
    }
    $ResultsDirectory = Join-Path $ResultsDirectory $latestRunName
}

$exportExitCode = Read-StrictIntegerFile -Path (Join-Path $ResultsDirectory "export_exit_code.txt")
$exportTimedOut = [bool]::Parse(
    (Get-Content -LiteralPath (Join-Path $ResultsDirectory "export_timed_out.txt") -Raw).Trim()
)
if ($exportTimedOut -or $exportExitCode -ne 0) {
    throw "Guest export did not finish normally."
}
$exportedProbeHash = (
    Get-Content -LiteralPath (Join-Path $ResultsDirectory "exported_probe_sha256.txt") -Raw
).Trim()
if ($exportedProbeHash -notmatch '^[0-9a-f]{64}$') {
    throw "Exported probe SHA-256 record is missing or malformed."
}
$requiredHarnessEvidence = @(
    "sandbox_test_started.txt",
    "sandbox_test_finished.txt",
    "sandbox_harness_exit_code.txt",
    "mapped_tool_sha256.txt",
    "export_godot.log",
    "export_stdout.txt",
    "export_stderr.txt"
)
foreach ($requiredEvidenceName in $requiredHarnessEvidence) {
    if (-not (Test-Path -LiteralPath (Join-Path $ResultsDirectory $requiredEvidenceName) -PathType Leaf)) {
        throw "Required guest evidence is missing: $requiredEvidenceName"
    }
}
foreach ($exportDiagnosticName in @("export_stdout.txt", "export_stderr.txt", "export_godot.log")) {
    Assert-NoUnexpectedEngineError `
        -Path (Join-Path $ResultsDirectory $exportDiagnosticName) `
        -EvidenceLabel "Export diagnostic"
}
if (Test-Path -LiteralPath (Join-Path $ResultsDirectory "sandbox_harness_error.txt") -PathType Leaf) {
    throw "Guest harness recorded an error."
}
$harnessExitCode = Read-StrictIntegerFile -Path (
    Join-Path $ResultsDirectory "sandbox_harness_exit_code.txt"
)
if ($harnessExitCode -ne 0) {
    throw "Guest harness exit code was nonzero."
}
$sandboxStartEvidence = Get-Content -LiteralPath (Join-Path $ResultsDirectory "sandbox_test_started.txt") -Raw
if (-not $sandboxStartEvidence.Contains("wer_dont_show_ui=1")) {
    throw "Guest evidence does not prove WER DontShowUI was set before export."
}
if (-not $sandboxStartEvidence.Contains("networking=disabled_by_wsb_configuration")) {
    throw "Guest evidence does not record the network-disabled configuration."
}
if (-not $sandboxStartEvidence.Contains("process_api=System.Diagnostics.Process")) {
    throw "Guest evidence does not record the reviewed direct process API."
}
$mappedToolHashLines = @(
    Get-Content -LiteralPath (Join-Path $ResultsDirectory "mapped_tool_sha256.txt")
)
$expectedToolHashPath = "$PSScriptRoot\EXPECTED_GUEST_TOOL_SHA256SUMS.txt"
if (Test-Path -LiteralPath $expectedToolHashPath) {
    $expectedMappedToolHashLines = @(
        Get-Content -LiteralPath $expectedToolHashPath
    )
    $toolHashDifferences = @(
        Compare-Object `
            -ReferenceObject $expectedMappedToolHashLines `
            -DifferenceObject $mappedToolHashLines `
            -CaseSensitive
    )
    if ($toolHashDifferences.Count -ne 0) {
        throw "Mapped engine/template hashes differ from the exact reviewed binaries."
    }
} else {
    Write-Warning "EXPECTED_GUEST_TOOL_SHA256SUMS.txt not present; mapped-tool hash comparison skipped (public release mode)."
}
$retainedProbeExecutablePath = Join-Path $ResultsDirectory "build\CommunityTranslationCodeExecutionGate.exe"
if (-not (Test-Path -LiteralPath $retainedProbeExecutablePath -PathType Leaf)) {
    throw "Retained guest-exported probe executable is missing."
}
$retainedProbeExecutable = Get-Item -LiteralPath $retainedProbeExecutablePath
if ($retainedProbeExecutable.Length -le 0) {
    throw "Retained guest-exported probe executable is empty."
}
$retainedProbeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $retainedProbeExecutablePath).Hash.ToLowerInvariant()
if ($retainedProbeHash -cne $exportedProbeHash) {
    throw "Retained guest-exported probe hash differs from recorded export hash."
}

$ordinaryResults = @(Get-ChildItem -LiteralPath $ResultsDirectory -Filter 'ordinary_*_result.json' -File)
$candidateResults = @(Get-ChildItem -LiteralPath $ResultsDirectory -Filter 'candidate_*_result.json' -File)
if ($ordinaryResults.Count -ne 10 -or $candidateResults.Count -ne 10) {
    throw "Expected exactly 10 ordinary and 10 candidate result files."
}

foreach ($resultFile in $ordinaryResults) {
    $attemptPrefix = $resultFile.BaseName -replace '_result$', ''
    foreach ($attemptLogName in @(
        "${attemptPrefix}_stdout.txt",
        "${attemptPrefix}_stderr.txt",
        "${attemptPrefix}_godot.log"
    )) {
        Assert-NoUnexpectedEngineError `
            -Path (Join-Path $ResultsDirectory $attemptLogName) `
            -EvidenceLabel "$($resultFile.Name) runtime diagnostic"
    }
    $attemptExitCode = Read-StrictIntegerFile -Path (
        Join-Path $ResultsDirectory "${attemptPrefix}_exit_code.txt"
    )
    $attemptTimedOut = [bool]::Parse(
        (Get-Content -LiteralPath (Join-Path $ResultsDirectory "${attemptPrefix}_timed_out.txt") -Raw).Trim()
    )
    if ($attemptTimedOut -or $attemptExitCode -ne 0) {
        throw "$($resultFile.Name): exported process timed out or exited nonzero."
    }
    $result = Get-Content -LiteralPath $resultFile.FullName -Raw | ConvertFrom-Json
    if ($result.community_translation_locale -cne $ExpectedLocale) {
        throw "$($resultFile.Name): locale was not exactly $ExpectedLocale."
    }
    if (-not $result.process_survived_after_plural_translation) {
        throw "$($resultFile.Name): process did not report survival."
    }
    if ($result.marker_present_before_loading -or $result.marker_present_after_loading_before_plural_lookup) {
        throw "$($resultFile.Name): marker appeared before the plural lookup."
    }
    if ($result.marker_present_after_plural_lookup -or $null -ne $result.marker_value_after_plural_lookup) {
        throw "$($resultFile.Name): ordinary control unexpectedly set the marker."
    }
    if ($result.translated_plural_text -cne "many community apples") {
        throw "$($resultFile.Name): ordinary translated text was unexpected."
    }
    if ([IO.Path]::GetFileName($result.community_translation_path) -cne "ordinary_plural_rule.po") {
        throw "$($resultFile.Name): ordinary fixture path was unexpected."
    }
}

foreach ($resultFile in $candidateResults) {
    $attemptPrefix = $resultFile.BaseName -replace '_result$', ''
    foreach ($attemptLogName in @(
        "${attemptPrefix}_stdout.txt",
        "${attemptPrefix}_stderr.txt",
        "${attemptPrefix}_godot.log"
    )) {
        Assert-NoUnexpectedEngineError `
            -Path (Join-Path $ResultsDirectory $attemptLogName) `
            -EvidenceLabel "$($resultFile.Name) runtime diagnostic"
    }
    $attemptExitCode = Read-StrictIntegerFile -Path (
        Join-Path $ResultsDirectory "${attemptPrefix}_exit_code.txt"
    )
    $attemptTimedOut = [bool]::Parse(
        (Get-Content -LiteralPath (Join-Path $ResultsDirectory "${attemptPrefix}_timed_out.txt") -Raw).Trim()
    )
    if ($attemptTimedOut -or $attemptExitCode -ne 0) {
        throw "$($resultFile.Name): exported process timed out or exited nonzero."
    }
    $result = Get-Content -LiteralPath $resultFile.FullName -Raw | ConvertFrom-Json
    if ($result.community_translation_locale -cne $ExpectedLocale) {
        throw "$($resultFile.Name): locale was not exactly $ExpectedLocale."
    }
    if (-not $result.process_survived_after_plural_translation) {
        throw "$($resultFile.Name): process did not report survival."
    }
    if ($result.marker_present_before_loading -or $result.marker_present_after_loading_before_plural_lookup) {
        throw "$($resultFile.Name): marker appeared before the plural lookup."
    }
    if (-not $result.marker_present_after_plural_lookup) {
        throw "$($resultFile.Name): plural lookup did not set the marker."
    }
    if ($result.marker_value_after_plural_lookup -cne $ExpectedMarker) {
        throw "$($resultFile.Name): marker value was not exactly $ExpectedMarker."
    }
    if ($result.translated_plural_text -cne "many community apples") {
        throw "$($resultFile.Name): candidate translated text was unexpected."
    }
    if ([IO.Path]::GetFileName($result.community_translation_path) -cne "code_execution_plural_rule.po") {
        throw "$($resultFile.Name): candidate fixture path was unexpected."
    }
}

[ordered]@{
    candidate_variant_record_bytes = $candidateBytes.Length
    candidate_variant_record_structure = "OBJECT(GDScript){script/source: STRING}"
    candidate_payload_exactly_allowlisted = $true
    ordinary_control_runs = $ordinaryResults.Count
    candidate_runs = $candidateResults.Count
    candidate_marker_value = $ExpectedMarker
    exported_probe_sha256 = $exportedProbeHash
    guest_harness_exit_code = $harnessExitCode
    all_exported_processes_survived = $true
} | ConvertTo-Json
