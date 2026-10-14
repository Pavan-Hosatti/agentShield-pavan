[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host.UI.RawUI.WindowTitle = "AgentShield V3 | [07] Generate_Proof_Bundle"
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
Write-Host "  DEMO STEP 07 : GENERATE CRYPTOGRAPHIC PROOF BUNDLE" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ---- WHAT TO TELL THE JUDGES ----------------------------------" -ForegroundColor Magenta
$judge = @"
This generates a cryptographically sealed proof bundle in under 1 second. It certifies that all 11 security invariants hold, all 8 attacks are blocked, and the OPA policy passes all 14 static checks with an HMAC seal.
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
Set-Location "D:\reva cyber hack-pavan\agentshield"
$env:PYTHONPATH = "D:\reva cyber hack-pavan\agentshield;D:\reva cyber hack-pavan\agentshield\backend"

Type-Cmd "python -m core.proof_export --out proof_bundle.json"

python -m core.proof_export --out proof_bundle.json

Write-Host ""
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "  | Execution complete. Window stays open for judges to review.  |" -ForegroundColor DarkGray
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host ""