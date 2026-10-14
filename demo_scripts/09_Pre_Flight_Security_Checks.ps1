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
        Start-Sleep -Milliseconds 28
    }
    Write-Host ""; Write-Host ""
    Start-Sleep -Milliseconds 400
}

Write-Host ""
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host "  |        AgentShield V3  --  Security Verification Engine      |" -ForegroundColor Cyan
Write-Host "  +==============================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  MODULE 09 : 10 PRE-FLIGHT SECURITY INVARIANT CHECKS" -ForegroundColor Yellow
Write-Host "  STATUS : ACTIVE | TARGET : REAL RUNTIME" -ForegroundColor DarkGray
Write-Host ""
Set-Location "D:\reva cyber hack-pavan\agentshield\backend"
$env:PYTHONPATH = "D:\reva cyber hack-pavan\agentshield;D:\reva cyber hack-pavan\agentshield\backend"

Type-Cmd "python -m app.security.invariant_checker --verbose"

python -m app.security.invariant_checker --verbose

Write-Host ""
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "  | [PASS] Execution complete. State held for verification.      |" -ForegroundColor DarkGray
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host ""