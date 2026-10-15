$Host.UI.RawUI.WindowTitle = "[11] IBM Bob MCP Security Proxy Verification"
Set-Location -Path "d:\reva cyber hack-pavan\agentshield"
Write-Host "===============================================================================" -ForegroundColor Blue
Write-Host "  AGENTSHIELD V3 - DEMO 11: IBM BOB MCP SECURITY PROXY VERIFICATION" -ForegroundColor Cyan
Write-Host "  Target: IBM Bob Autonomous Multi-Agent SDLC | Protocol: MCP JSON-RPC 2.0" -ForegroundColor DarkCyan
Write-Host "===============================================================================" -ForegroundColor Blue
Write-Host ""

python -m integrations.ibm_bob_mcp_proxy --test

Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Blue
Write-Host "[Process Complete - Press any key to close this console]" -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
