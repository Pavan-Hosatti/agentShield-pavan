[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host.UI.RawUI.WindowTitle = "AgentShield V3 | [09] Pre_Flight_Security_Checks"
try { $host.UI.RawUI.BackgroundColor = "Black" } catch {}
Clear-Host

function Type-Cmd {
    param([string]$C)
    Write-Host ""
    Write-Host "  PS AgentShield> " -NoNewline -ForegroundColor Green
    foreach ($ch in $C.ToCharArray()) {
        Write-Host -NoNewline $ch -ForegroundColor White
        Start-Sleep -Milliseconds 32
    }
    Write-Host ""; Write-Host ""
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host "  |        AgentShield V3  --  REVA Cyber Hackathon Live Demo     |" -ForegroundColor Cyan
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  DEMO STEP 09 : 10 PRE-FLIGHT SECURITY INVARIANT CHECKS" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ---- WHAT TO TELL THE JUDGES ----------------------------------" -ForegroundColor Magenta
$judge = @"
Before every demo run, this automated pre-flight check validates 10 critical security properties across the system: digest mismatch, hard-deny non-overridability, approval digest binding, audit chain tamper detection, schema acceptance, OPA policy validation, and Ed25519 key verification.
"@
$judge -split "[\r\n]+" | ForEach-Object {
    $t = $_.Trim()
    if ($t) {
        $words = $t -split " "
        $line = "  "
        foreach ($w in $words) {
            if (($line.Length + $w.Length + 1) -gt 74) {
                Write-Host $line -ForegroundColor Gray
                $line = "  " + $w + " "
            } else {
                $line += $w + " "
            }
        }
        if ($line.Trim()) { Write-Host $line -ForegroundColor Gray }
    }
}
Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [AUTOMATION] Executing command in real terminal..." -ForegroundColor DarkYellow
Set-Location "D:\reva cyber hack-pavan\agentshield\backend"
$env:PYTHONPATH = "D:\reva cyber hack-pavan\agentshield;D:\reva cyber hack-pavan\agentshield\backend"

Type-Cmd "python -m app.security.invariant_checker --verbose"

python -m app.security.invariant_checker --verbose

Write-Host ""
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "  | Execution complete. Window stays open for judges to review.  |" -ForegroundColor DarkGray
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host ""