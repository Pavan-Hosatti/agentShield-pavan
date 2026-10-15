@echo off
title [11] IBM Bob MCP Security Proxy Verification
color 09
cd /d "d:\reva cyber hack-pavan\agentshield"
echo ===============================================================================
echo   AGENTSHIELD V3 - DEMO 11: IBM BOB MCP SECURITY PROXY VERIFICATION
echo   Target: IBM Bob Autonomous Multi-Agent SDLC ^| Protocol: MCP JSON-RPC 2.0
echo ===============================================================================
echo.
python -m integrations.ibm_bob_mcp_proxy --test
echo.
echo ===============================================================================
echo [Process Complete - Press any key to close this console]
pause >nul
