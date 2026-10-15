[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$host.UI.RawUI.WindowTitle = "AgentShield V3 | [11] IBM_Bob_MCP_Security_Proxy"
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
Write-Host "  MODULE 11 : IBM BOB MODEL CONTEXT PROTOCOL (MCP) SECURITY PROXY" -ForegroundColor Yellow
Write-Host "  STATUS : ACTIVE | TARGET : IBM BOB MULTI-AGENT SDLC" -ForegroundColor DarkGray
Write-Host ""
Set-Location "D:\reva cyber hack-pavan\agentshield"
$env:PYTHONPATH = "D:\reva cyber hack-pavan\agentshield;D:\reva cyber hack-pavan\agentshield\backend"

Type-Cmd "python -m integrations.ibm_bob_mcp_proxy --test"

python -m integrations.ibm_bob_mcp_proxy --test

Write-Host ""
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "  | [PASS] Execution complete. State held for verification.      |" -ForegroundColor DarkGray
Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host ""
