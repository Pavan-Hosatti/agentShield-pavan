# AgentShield V3 — Start Pavan's Services
# Run this from the agentshield/ directory

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Set-Location $PSScriptRoot
$env:PYTHONPATH = "$PSScriptRoot;$PSScriptRoot\backend"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AgentShield V3 -- Pavan's Module Startup" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Pre-flight security invariant check ─────────────────────────────
Write-Host "[1/3] Running security pre-flight check..." -ForegroundColor Yellow
Push-Location "$PSScriptRoot\backend"
python -m app.security.invariant_checker --verbose
if ($LASTEXITCODE -ne 0) {
    Write-Host "  PRE-FLIGHT FAILED -- fix errors before demo!" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host "  Pre-flight: ALL CLEAR" -ForegroundColor Green
Write-Host ""

# ── Step 2: Generate proof bundle ────────────────────────────────────────────
Write-Host "[2/3] Generating proof bundle..." -ForegroundColor Yellow
python -m core.proof_export --out proof_bundle.json
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Proof bundle generation FAILED" -ForegroundColor Red
    exit 1
}
Write-Host "  Proof bundle: OK -> proof_bundle.json" -ForegroundColor Green
Write-Host ""

# ── Step 3: Launch Attacker B API ────────────────────────────────────────────
Write-Host "[3/3] Starting Attacker B API on port 8003..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList `
    "-NoExit", `
    "-Command", `
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; `$env:PYTHONPATH='$PSScriptRoot;$PSScriptRoot\backend'; cd '$PSScriptRoot'; python -m attacker_b.server" `
    -WindowStyle Normal

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " PAVAN'S MODULES ARE RUNNING -- READY FOR DEMO" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Attacker B API  : http://0.0.0.0:8003" -ForegroundColor Cyan
Write-Host "  Quick test      : curl http://localhost:8003/all" -ForegroundColor Cyan
Write-Host "  Browser console : open attacker_b/console/index.html" -ForegroundColor Cyan
Write-Host "  Proof bundle    : proof_bundle.json (verified, HMAC-sealed)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  For Alok's laptop (Wi-Fi): update API_BASE in" -ForegroundColor Yellow
Write-Host "  attacker_b/console/index.html to http://<THIS_IP>:8003" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Demo commands:" -ForegroundColor White
Write-Host "    python -m core.scenarios.replay_scenarios   # 8/8 attacks blocked" -ForegroundColor Gray
Write-Host "    python -m core.delegation                   # delegation rules" -ForegroundColor Gray
Write-Host "    python -m core.policy_mutation              # 5/5 mutations caught" -ForegroundColor Gray
Write-Host "    python -m core.state_machine                # fail-closed demo" -ForegroundColor Gray
Write-Host "    python -m core.baselines                    # A=6% B=61% C=100%" -ForegroundColor Gray
Write-Host "    python -m core.proof_export --verify proof_bundle.json" -ForegroundColor Gray
Write-Host ""
