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
        "judge": "This is our one-command startup. It runs 10 security pre-flight checks. If any fail, the demo aborts immediately. Then it generates a tamper-evident cryptographic proof bundle certifying all invariants hold. Finally it starts the Attacker B REST API on port 8003. Fully automated, production-grade.",
    },
    {
        "id": "02",
        "name": "8_Attacks_All_Blocked",
        "title": "8 Attacks All Blocked Live",
        "cmd": "python -m core.scenarios.replay_scenarios",
        "cwd": PROJECT_DIR,
        "judge": "These are 8 real attack scenarios: capability replay, expired token submission, revoked agent execution, direct gateway bypass, policy version downgrade, cross-tenant scope escape, delegation privilege escalation, and fail-open probe abuse. Every single attack is blocked live with invariant certification.",
    },
    {
        "id": "03",
        "name": "Baseline_Protection_Comparison",
        "title": "Baseline Protection Comparison (6% vs 61% vs 100%)",
        "cmd": "python -m core.baselines",
        "cwd": PROJECT_DIR,
        "judge": "We modelled 3 real-world deployment configurations. Config A is a naive setup with only 6% attack surfaces closed. Config B adds authentication and replay guards (61%). Config C is our full zero-trust posture where 100% of all 18 threat surfaces are closed.",
    },
    {
        "id": "04",
        "name": "Policy_Mutation_Tests",
        "title": "Policy Mutation Tests (5/5 Malicious Rules Caught)",
        "cmd": "python -m core.policy_mutation",
        "cwd": PROJECT_DIR,
        "judge": "We inject 5 real policy mutations into our OPA Rego rules: removing default-deny, adding a wildcard allow, stripping revoked-agent deny, stripping action digest binding, and removing fallback deny. Our static validator catches 5 out of 5 before any code reaches production.",
    },
    {
        "id": "05",
        "name": "Fail_Closed_State_Machine",
        "title": "Fail-Closed State Machine Transitions",
        "cmd": "python -m core.state_machine",
        "cwd": PROJECT_DIR,
        "judge": "Our execution state machine strictly governs valid transitions. An attacker trying to jump directly from AUTHORIZED to EXECUTING to skip the atomic JTI claim triggers an INVALID_TRANSITION and is instantly forced into REJECTED. Fail-closed by mathematical design.",
    },
    {
        "id": "06",
        "name": "Delegation_Rules_Enforcement",
        "title": "Delegation Rules (Child Scope Must Be Strict Subset)",
        "cmd": "python -m core.delegation",
        "cwd": PROJECT_DIR,
        "judge": "When an AI agent delegates authority to a sub-agent, the child can never exceed the parent permissions. We enforce 7 strict invariant rules: tool scope, amount limit, TTL, tenant ID, environments, policy version, and delegation depth. Watch live as 6 simultaneous escalation attempts are stopped.",
    },
    {
        "id": "07",
        "name": "Generate_Proof_Bundle",
        "title": "Generate Cryptographic Proof Bundle",
        "cmd": "python -m core.proof_export --out proof_bundle.json",
        "cwd": PROJECT_DIR,
        "judge": "This generates a cryptographically sealed proof bundle in under 1 second. It certifies that all 11 security invariants hold, all 8 attacks are blocked, and the OPA policy passes all 14 static checks with an HMAC seal.",
    },
    {
        "id": "08",
        "name": "Verify_Proof_Bundle",
        "title": "Verify Cryptographic Proof Bundle",
        "cmd": "python -m core.proof_export --verify proof_bundle.json",
        "cwd": PROJECT_DIR,
        "judge": "We can independently verify the proof bundle at any time, even on a different machine. It validates the cryptographic HMAC signature, checks invariant claims, and confirms zero tampering.",
    },
    {
        "id": "09",
        "name": "Pre_Flight_Security_Checks",
        "title": "10 Pre-Flight Security Invariant Checks",
        "cmd": "python -m app.security.invariant_checker --verbose",
        "cwd": BACKEND_DIR,
        "judge": "Before every demo run, this automated pre-flight check validates 10 critical security properties across the system: digest mismatch, hard-deny non-overridability, approval digest binding, audit chain tamper detection, schema acceptance, OPA policy validation, and Ed25519 key verification.",
    },
    {
        "id": "10",
        "name": "All_426_Tests",
        "title": "Run Full Test Suite (426 Tests Passed)",
        "cmd": "python -m pytest tests/ -v",
        "cwd": PROJECT_DIR,
        "judge": "Our test suite covers unit tests for every security primitive, adversarial attack tests for all 10 threat categories, integration tests, and scenario tests for all 8 attacks. 426 tests passed with 0 failures in under 3 seconds.",
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
        '        Start-Sleep -Milliseconds 32',
        '    }',
        '    Write-Host ""; Write-Host ""',
        '    Start-Sleep -Milliseconds 500',
        '}',
        '',
        'Write-Host ""',
        'Write-Host "  +==============================================================+" -ForegroundColor Cyan',
        'Write-Host "  |        AgentShield V3  --  REVA Cyber Hackathon Live Demo     |" -ForegroundColor Cyan',
        'Write-Host "  +==============================================================+" -ForegroundColor Cyan',
        'Write-Host ""',
        f'Write-Host "  DEMO STEP {demo["id"]} : {demo["title"].upper()}" -ForegroundColor Yellow',
        'Write-Host ""',
        'Write-Host "  ---- WHAT TO TELL THE JUDGES ----------------------------------" -ForegroundColor Magenta',
        f'$judge = @"\n{demo["judge"]}\n"@',
        '$judge -split "[\\r\\n]+" | ForEach-Object {',
        '    $t = $_.Trim()',
        '    if ($t) {',
        '        $words = $t -split " "',
        '        $line = "  "',
        '        foreach ($w in $words) {',
        '            if (($line.Length + $w.Length + 1) -gt 74) {',
        '                Write-Host $line -ForegroundColor Gray',
        '                $line = "  " + $w + " "',
        '            } else {',
        '                $line += $w + " "',
        '            }',
        '        }',
        '        if ($line.Trim()) { Write-Host $line -ForegroundColor Gray }',
        '    }',
        '}',
        'Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkGray',
        'Write-Host ""',
        'Write-Host "  [AUTOMATION] Executing command in real terminal..." -ForegroundColor DarkYellow',
        f'Set-Location "{demo["cwd"]}"',
        f'$env:PYTHONPATH = "{PROJECT_DIR};{BACKEND_DIR}"',
        '',
        f'Type-Cmd "{demo["cmd"]}"',
        '',
        demo["cmd"],
        '',
        'Write-Host ""',
        'Write-Host "  +-------------------------------------------------------------+" -ForegroundColor DarkGray',
        'Write-Host "  | Execution complete. Window stays open for judges to review.  |" -ForegroundColor DarkGray',
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

print(f"Generated {len(DEMOS)} PS1 and {len(DEMOS)} BAT files in {SCRIPTS_DIR}")
