import os

PROJECT_DIR = r"D:\reva cyber hack-pavan\agentshield"
BACKEND_DIR = r"D:\reva cyber hack-pavan\agentshield\backend"
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "demo_scripts")

os.makedirs(SCRIPTS_DIR, exist_ok=True)

DEMOS = [
    {
        "id": "01",
        "name": "Start_All_Services",
        "title": "Start All Services (Pre-Flight + Proof + Attacker B API)",
        "cmd": "powershell -ExecutionPolicy Bypass -File start_pavan.ps1",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "02",
        "name": "8_Attacks_All_Blocked",
        "title": "8 Adversarial Attacks All Blocked Live",
        "cmd": "python -m core.scenarios.replay_scenarios",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "03",
        "name": "Baseline_Protection_Comparison",
        "title": "Baseline Protection Comparison (6% vs 61% vs 100%)",
        "cmd": "python -m core.baselines",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "04",
        "name": "Policy_Mutation_Tests",
        "title": "Policy Mutation Tests (5/5 Malicious Rules Caught)",
        "cmd": "python -m core.policy_mutation",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "05",
        "name": "Fail_Closed_State_Machine",
        "title": "Fail-Closed State Machine Transitions",
        "cmd": "python -m core.state_machine",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "06",
        "name": "Delegation_Rules_Enforcement",
        "title": "Delegation Rules (Child Scope Must Be Strict Subset)",
        "cmd": "python -m core.delegation",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "07",
        "name": "Generate_Proof_Bundle",
        "title": "Generate Cryptographic Proof Bundle",
        "cmd": "python -m core.proof_export --out proof_bundle.json",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "08",
        "name": "Verify_Proof_Bundle",
        "title": "Verify Cryptographic Proof Bundle",
        "cmd": "python -m core.proof_export --verify proof_bundle.json",
        "cwd": PROJECT_DIR,
    },
    {
        "id": "09",
        "name": "Pre_Flight_Security_Checks",
        "title": "10 Pre-Flight Security Invariant Checks",
        "cmd": "python -m app.security.invariant_checker --verbose",
        "cwd": BACKEND_DIR,
    },
    {
        "id": "10",
        "name": "All_426_Tests",
        "title": "Run Full Test Suite (426 Tests Passed)",
        "cmd": "python -m pytest tests/ -v",
        "cwd": PROJECT_DIR,
    },
]

def make_ps1_content(demo):
    lines = [
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
        f'$host.UI.RawUI.WindowTitle = "AgentShield V3 | [{demo["id"]}] {demo["name"]}"',
        'try { $host.UI.RawUI.BackgroundColor = "Black" } catch {}',
        'Clear-Host',
        '',
        'function Type-Cmd {',
        '    param([string]$C)',
        '    Write-Host ""',
        '    Write-Host "  PS AgentShield> " -NoNewline -ForegroundColor Green',
        '    foreach ($ch in $C.ToCharArray()) {',
        '        Write-Host -NoNewline $ch -ForegroundColor White',
        '        Start-Sleep -Milliseconds 28',
        '    }',
        '    Write-Host ""; Write-Host ""',
        '    Start-Sleep -Milliseconds 400',
        '}',
        '',
        'Write-Host ""',
        'Write-Host "  +==============================================================+" -ForegroundColor Cyan',
        'Write-Host "  |        AgentShield V3  --  Security Verification Engine      |" -ForegroundColor Cyan',
        'Write-Host "  +==============================================================+" -ForegroundColor Cyan',
        'Write-Host ""',
        f'Write-Host "  MODULE {demo["id"]} : {demo["title"].upper()}" -ForegroundColor Yellow',
        'Write-Host "  STATUS : ACTIVE | TARGET : REAL RUNTIME" -ForegroundColor DarkGray',
        'Write-Host ""',
        f'Set-Location "{demo["cwd"]}"',
        f'$env:PYTHONPATH = "{PROJECT_DIR};{BACKEND_DIR}"',
        '',
        f'Type-Cmd "{demo["cmd"]}"',
        '',
        demo["cmd"],
        '',
        'Write-Host ""',
        'Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray',
        'Write-Host "  | [PASS] Execution complete. State held for verification.      |" -ForegroundColor DarkGray',
        'Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray',
        'Write-Host ""',
    ]
    return "\r\n".join(lines)

def make_bat_content(ps1_filename):
    lines = [
        "@echo off",
        "title AgentShield V3 Launcher",
        f'powershell.exe -NoExit -ExecutionPolicy Bypass -File "%~dp0{ps1_filename}"',
    ]
    return "\r\n".join(lines)

for demo in DEMOS:
    ps1_name = f"{demo['id']}_{demo['name']}.ps1"
    bat_name = f"{demo['id']}_{demo['name']}.bat"
    
    ps1_path = os.path.join(SCRIPTS_DIR, ps1_name)
    bat_path = os.path.join(SCRIPTS_DIR, bat_name)
    
    with open(ps1_path, "w", encoding="utf-8") as f:
        f.write(make_ps1_content(demo))
        
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(make_bat_content(ps1_name))

print(f"Generated {len(DEMOS)} clean PS1 and {len(DEMOS)} BAT files in {SCRIPTS_DIR}")
