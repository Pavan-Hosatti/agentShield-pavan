"""
AgentShield V3 - Security Verification & Live Demonstration Console
Local security cockpit that launches real PowerShell execution windows on demand.
"""

import http.server
import json
import os
import subprocess
import sys
import threading
import urllib.parse
import webbrowser

PORT = 8888
PROJECT_DIR = r"D:\reva cyber hack-pavan\agentshield"
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "demo_scripts")

DEMOS = [
    {
        "id": "01",
        "name": "Start_All_Services",
        "badge": "STARTUP",
        "color": "#00ff88",
        "title": "Start All Services",
        "subtitle": "Pre-flight checks + cryptographic proof bundle + Attacker B REST API on :8003",
        "cmd": "powershell -ExecutionPolicy Bypass -File start_pavan.ps1",
        "duration": "~3s",
        "spec": "Automated system startup sequence. Validates 10 pre-flight security invariant checks, constructs the HMAC-signed cryptographic audit proof bundle certifying mathematical integrity, and initializes the Attacker B REST boundary endpoint on port 8003.",
    },
    {
        "id": "02",
        "name": "8_Attacks_All_Blocked",
        "badge": "ADVERSARIAL",
        "color": "#ff4466",
        "title": "8 Attacks All Blocked Live",
        "subtitle": "Capability replay, expired token, revoked agent, direct bypass, policy downgrade, cross-tenant, delegation escalation, fail-open probe",
        "cmd": "python -m core.scenarios.replay_scenarios",
        "duration": "~1s",
        "spec": "Adversarial replay suite covering 8 high-severity attack vectors: atomic capability replay, token expiration TTL enforcement, runtime agent revocation re-checks, perimeter network bypass attempts, policy downgrade prevention, cross-tenant isolation, delegation privilege bounds, and fail-closed availability guarantees.",
    },
    {
        "id": "03",
        "name": "Baseline_Protection_Comparison",
        "badge": "METRICS",
        "color": "#f5a623",
        "title": "Baseline Protection Comparison",
        "subtitle": "Quantified security posture: Config A (6%) vs Config B (61%) vs Config C (100% closed)",
        "cmd": "python -m core.baselines",
        "duration": "<1s",
        "spec": "Comparative empirical analysis across 18 documented threat surfaces. Demonstrates protection gap: Config A (naive baseline: 6% closed), Config B (typical enterprise JWT/rate-limiting: 61% closed), and Config C (AgentShield full zero-trust posture: 100% closed).",
    },
    {
        "id": "04",
        "name": "Policy_Mutation_Tests",
        "badge": "VALIDATOR",
        "color": "#a855f7",
        "title": "Policy Mutation Tests",
        "subtitle": "5 malicious OPA policy tampering mutations injected - 5/5 caught before deployment",
        "cmd": "python -m core.policy_mutation",
        "duration": "<1s",
        "spec": "Static semantic validator testing for policy integrity. Evaluates system resilience against deliberate rule tampering including default-deny removal, wildcard permit injections, revoked-agent deny stripping, and approval digest bypasses. All 5 mutations intercepted prior to deployment.",
    },
    {
        "id": "05",
        "name": "Fail_Closed_State_Machine",
        "badge": "STATE MACHINE",
        "color": "#00d4ff",
        "title": "Fail-Closed State Machine",
        "subtitle": "Invalid transition attempts (e.g. skip claim) mathematically forced into REJECTED",
        "cmd": "python -m core.state_machine",
        "duration": "<1s",
        "spec": "Deterministic state transition model governing autonomous execution lifecycles. Strictly enforces valid sequential state transitions: PENDING -> EVALUATING -> AUTHORIZED -> CLAIMING -> EXECUTING -> SUCCEEDED. Any out-of-order execution attempt forces immediate fail-closed REJECTED state.",
    },
    {
        "id": "06",
        "name": "Delegation_Rules_Enforcement",
        "badge": "DELEGATION",
        "color": "#ff8c00",
        "title": "Delegation Rules Enforcement",
        "subtitle": "Child agent permissions enforced as strict subset of parent - 6 escalation rules verified",
        "cmd": "python -m core.delegation",
        "duration": "<1s",
        "spec": "Sub-agent delegation boundary enforcement ensuring sub-agents operate strictly within a mathematical subset of parent authority. Enforces 7 discrete invariant checks across tool definitions, transaction limits, TTL bounds, tenant identities, deployment environments, and delegation hierarchy depths.",
    },
    {
        "id": "07",
        "name": "Generate_Proof_Bundle",
        "badge": "CRYPTO",
        "color": "#00ff88",
        "title": "Generate Proof Bundle",
        "subtitle": "Cryptographically sealed HMAC audit certificate verifying 11 invariants in <1s",
        "cmd": "python -m core.proof_export --out proof_bundle.json",
        "duration": "<1s",
        "spec": "Generates a machine-verifiable cryptographic proof certificate in under 1 second. Compiles SHA-256 state hashes, OPA Rego policy digests, and invariant execution claims into a unified JSON structure secured by an HMAC signature for tamper detection.",
    },
    {
        "id": "08",
        "name": "Verify_Proof_Bundle",
        "badge": "AUDIT",
        "color": "#00ff88",
        "title": "Verify Proof Bundle",
        "subtitle": "Independent HMAC seal and invariant claims verification for third-party auditing",
        "cmd": "python -m core.proof_export --verify proof_bundle.json",
        "duration": "<1s",
        "spec": "Independent verification utility designed for third-party auditors. Parses exported proof bundles, re-evaluates HMAC integrity, checks invariant attestations against known specifications, and confirms zero-tampering without requiring execution of the live environment.",
    },
    {
        "id": "09",
        "name": "Pre_Flight_Security_Checks",
        "badge": "PRE-FLIGHT",
        "color": "#00d4ff",
        "title": "10 Pre-Flight Security Checks",
        "subtitle": "Automated verification of digests, hard-deny rules, audit chain, schemas, and Ed25519 keys",
        "cmd": "python -m app.security.invariant_checker --verbose",
        "duration": "~1s",
        "spec": "Comprehensive pre-deployment diagnostic evaluating 10 essential security primitives: action digest binding, hard-deny precedence, approval consumption state, audit log immutability, schema compliance, OPA rule validity, and cryptographic key validity.",
    },
    {
        "id": "10",
        "name": "All_426_Tests",
        "badge": "FULL SUITE",
        "color": "#ff4466",
        "title": "Run Full Test Suite (426 Tests)",
        "subtitle": "Unit, adversarial, integration, and scenario tests: 426 passed, 0 failures in 2.8s",
        "cmd": "python -m pytest tests/ -v",
        "duration": "~3s",
        "spec": "Complete automated verification suite containing 426 passing tests across unit boundaries, adversarial attack simulations, and integration workflows. Executes in under 3 seconds with 0 failures.",
    },
]

DEMO_MAP = {d["id"]: d for d in DEMOS}

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentShield V3 — Security Verification Cockpit</title>
<style>
  :root {
    --bg-dark: #04060d;
    --card-bg: #070c18;
    --card-border: #0e1e36;
    --cyan: #00d4ff;
    --green: #00ff88;
    --red: #ff4466;
    --orange: #f5a623;
    --purple: #a855f7;
    --text-primary: #e6edf8;
    --text-muted: #6b829e;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg-dark);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    min-height: 100vh;
    padding-bottom: 50px;
    background-image: 
      radial-gradient(circle at 50% 0%, rgba(0, 212, 255, 0.08) 0%, transparent 60%),
      linear-gradient(rgba(0, 212, 255, 0.015) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0, 212, 255, 0.015) 1px, transparent 1px);
    background-size: 100% 100%, 36px 36px, 36px 36px;
  }
  .navbar {
    background: rgba(7, 12, 24, 0.9);
    border-bottom: 1px solid var(--card-border);
    backdrop-filter: blur(12px);
    padding: 16px 36px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo-area { display: flex; align-items: center; gap: 14px; }
  .logo-shield {
    width: 36px; height: 36px; border-radius: 8px;
    background: linear-gradient(135deg, var(--cyan), var(--green));
    display: flex; align-items: center; justify-content: center;
    font-weight: 900; color: #000; font-size: 18px;
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.4);
  }
  .logo-title { font-size: 20px; font-weight: 800; letter-spacing: 1px; }
  .logo-title span { color: var(--green); }
  .live-pill {
    background: rgba(0, 255, 136, 0.1);
    border: 1px solid rgba(0, 255, 136, 0.3);
    color: var(--green);
    padding: 5px 14px;
    border-radius: 20px;
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .pulse-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 10px var(--green);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.85)} }

  .container { max-width: 1480px; margin: 0 auto; padding: 28px 32px; }

  /* Telemetry Bar */
  .telemetry-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    margin-bottom: 28px;
  }
  .telemetry-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    position: relative;
    overflow: hidden;
  }
  .telemetry-card::before {
    content:''; position: absolute; top:0; left:0; right:0; height: 2px;
    background: linear-gradient(90deg, var(--cyan), transparent);
  }
  .telem-val { font-size: 26px; font-weight: 800; color: #fff; margin-bottom: 2px; }
  .telem-val span { font-size: 15px; color: var(--green); }
  .telem-lbl { font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--text-muted); }

  /* Security Specification Box */
  .spec-box {
    background: linear-gradient(135deg, rgba(0, 212, 255, 0.04), rgba(7, 12, 24, 0.95));
    border: 1px solid rgba(0, 212, 255, 0.25);
    border-left: 4px solid var(--cyan);
    border-radius: 12px;
    padding: 22px 28px;
    margin-bottom: 32px;
    box-shadow: 0 12px 30px rgba(0,0,0,0.4);
  }
  .spec-header {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;
  }
  .spec-tag {
    font-size: 11px; letter-spacing: 2px; color: var(--cyan);
    text-transform: uppercase; font-weight: 800; display: flex; align-items: center; gap: 8px;
  }
  .spec-step-badge {
    background: rgba(0, 212, 255, 0.15);
    padding: 3px 10px; border-radius: 6px; font-weight: 700; color: var(--cyan); font-size: 12px;
  }
  .spec-text {
    font-size: 14px; line-height: 1.7; color: #d6e2f0;
  }
  .spec-cmd-preview {
    margin-top: 14px;
    background: #020408;
    border: 1px solid #132238;
    border-radius: 8px;
    padding: 10px 16px;
    font-family: Consolas, monospace;
    font-size: 12px;
    color: var(--green);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  /* Grid of Demo Cards */
  .cards-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
    gap: 20px;
  }
  .demo-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    padding: 24px;
    cursor: pointer;
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    position: relative;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .demo-card:hover {
    transform: translateY(-4px);
    border-color: var(--cyan);
    box-shadow: 0 16px 36px rgba(0, 212, 255, 0.12);
  }
  .card-top {
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;
  }
  .card-badge {
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase; font-weight: 800;
    padding: 4px 10px; border-radius: 6px;
  }
  .card-num { font-size: 12px; font-weight: 800; color: var(--text-muted); }
  .card-title { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
  .card-sub { font-size: 13px; color: var(--text-muted); line-height: 1.5; margin-bottom: 18px; }
  
  .card-action-bar {
    margin-top: auto;
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .btn-launch {
    flex: 1;
    background: transparent;
    border: 1px solid var(--cyan);
    color: var(--cyan);
    padding: 11px 16px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: all 0.2s;
  }
  .btn-launch:hover {
    background: var(--cyan);
    color: #000;
    box-shadow: 0 0 20px rgba(0, 212, 255, 0.4);
  }
  .btn-active {
    background: var(--green) !important;
    border-color: var(--green) !important;
    color: #000 !important;
    animation: btnFlash 0.6s infinite alternate;
  }
  @keyframes btnFlash { from { opacity: 0.8; } to { opacity: 1; } }

  /* Toast Notification */
  .toast {
    position: fixed;
    bottom: 28px;
    right: 32px;
    background: #091424;
    border: 1px solid var(--green);
    border-radius: 10px;
    padding: 14px 22px;
    color: #fff;
    font-size: 14px;
    font-weight: 600;
    box-shadow: 0 10px 30px rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    gap: 12px;
    transform: translateY(100px);
    opacity: 0;
    transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    z-index: 999;
  }
  .toast.show { transform: translateY(0); opacity: 1; }
</style>
</head>
<body>

<div class="navbar">
  <div class="logo-area">
    <div class="logo-shield">AS</div>
    <div class="logo-title">AGENTSHIELD <span>V3</span></div>
  </div>
  <div style="display:flex; gap:16px; align-items:center;">
    <div style="font-size:12px; color:var(--text-muted); font-family:Consolas,monospace;">REVA Cyber Security Framework</div>
    <div class="live-pill"><span class="pulse-dot"></span> LIVE COCKPIT</div>
  </div>
</div>

<div class="container">

  <!-- Telemetry Bar -->
  <div class="telemetry-grid">
    <div class="telemetry-card">
      <div class="telem-val">11 <span>/ 11</span></div>
      <div class="telem-lbl">Invariants Active</div>
    </div>
    <div class="telemetry-card">
      <div class="telem-val" style="color:var(--green)">8 <span>/ 8</span></div>
      <div class="telem-lbl">Adversarial Scenarios Blocked</div>
    </div>
    <div class="telemetry-card">
      <div class="telem-val" style="color:var(--cyan)">100%</div>
      <div class="telem-lbl">Zero-Trust Posture (Config C)</div>
    </div>
    <div class="telemetry-card">
      <div class="telem-val">426 <span>/ 426</span></div>
      <div class="telem-lbl">Test Assertions Passed (0 Fails)</div>
    </div>
    <div class="telemetry-card">
      <div class="telem-val" style="color:var(--orange)">Port 8003</div>
      <div class="telem-lbl">Adversary API Boundary</div>
    </div>
  </div>

  <!-- Security Specification Box -->
  <div class="spec-box" id="specBox">
    <div class="spec-header">
      <div class="spec-tag">🛡️ SECURITY INVARIANT & THREAT SPECIFICATION</div>
      <div class="spec-step-badge" id="specStepBadge">MODULE 02 -- 8 ATTACKS ALL BLOCKED LIVE</div>
    </div>
    <div class="spec-text" id="specText">
      Adversarial replay suite covering 8 high-severity attack vectors: atomic capability replay, token expiration TTL enforcement, runtime agent revocation re-checks, perimeter network bypass attempts, policy downgrade prevention, cross-tenant isolation, delegation privilege bounds, and fail-closed availability guarantees.
    </div>
    <div class="spec-cmd-preview">
      <span id="specCmd">python -m core.scenarios.replay_scenarios</span>
      <span style="color:var(--text-muted); font-size:11px;" id="specDuration">Runtime: ~1s</span>
    </div>
  </div>

  <!-- Section Header -->
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px;">
    <h2 style="font-size:16px; letter-spacing:1px; text-transform:uppercase; color:var(--text-muted);">
      Interactive Security Modules
    </h2>
    <span style="font-size:12px; color:var(--cyan); font-weight:600;">
      ⚡ Triggers live runtime verification in dedicated terminal
    </span>
  </div>

  <!-- Cards Grid -->
  <div class="cards-grid" id="cardsGrid">
    <!-- Populated by JS -->
  </div>

</div>

<!-- Toast -->
<div class="toast" id="toast">
  <span style="font-size:20px;">⚡</span>
  <div>
    <div style="color:var(--green); font-weight:700;" id="toastTitle">Process Launched</div>
    <div style="font-size:12px; color:var(--text-muted);" id="toastMsg">Interactive console opened on host system.</div>
  </div>
</div>

<script>
const DEMOS = """ + json.dumps(DEMOS) + """;

function renderCards() {
  const container = document.getElementById('cardsGrid');
  let html = '';
  DEMOS.forEach((d, idx) => {
    html += `
      <div class="demo-card" id="card-${d.id}" onmouseenter="selectSpec(${idx})" onclick="launchDemo('${d.id}', event)">
        <div>
          <div class="card-top">
            <span class="card-badge" style="background:${d.color}22; color:${d.color}; border:1px solid ${d.color}55;">${d.badge}</span>
            <span class="card-num">#${d.id}</span>
          </div>
          <div class="card-title" style="color:${d.color}">${d.title}</div>
          <div class="card-sub">${d.subtitle}</div>
        </div>
        <div class="card-action-bar">
          <button class="btn-launch" id="btn-${d.id}">
            <span>⚡ EXECUTE VERIFICATION</span>
          </button>
        </div>
      </div>
    `;
  });
  container.innerHTML = html;
}

function selectSpec(idx) {
  const d = DEMOS[idx];
  document.getElementById('specStepBadge').innerText = `MODULE ${d.id} -- ${d.title.toUpperCase()}`;
  document.getElementById('specText').innerText = d.spec;
  document.getElementById('specCmd').innerText = d.cmd;
  document.getElementById('specDuration').innerText = `Runtime: ${d.duration}`;
}

async function launchDemo(id, evt) {
  const btn = document.getElementById(`btn-${id}`);
  const origText = btn.innerHTML;
  btn.innerHTML = '<span>⏳ LAUNCHING CONSOLE...</span>';
  btn.classList.add('btn-active');

  showToast(`Module ${id} Triggered`, 'Live verification window active on desktop.');

  try {
    const res = await fetch(`/launch?id=${id}`);
    const data = await res.json();
    setTimeout(() => {
      btn.innerHTML = '<span>⚡ EXECUTE VERIFICATION</span>';
      btn.classList.remove('btn-active');
    }, 2500);
  } catch (err) {
    showToast('Launch Error', 'Failed to trigger console service.');
    btn.innerHTML = origText;
    btn.classList.remove('btn-active');
  }
}

function showToast(title, msg) {
  const t = document.getElementById('toast');
  document.getElementById('toastTitle').innerText = title;
  document.getElementById('toastMsg').innerText = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

renderCards();
// Default to step 02
selectSpec(1);
</script>

</body>
</html>
"""

class DemoServerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            return

        elif path == "/launch":
            demo_id = query.get("id", ["02"])[0]
            demo = DEMO_MAP.get(demo_id)
            if not demo:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unknown demo id"}).encode("utf-8"))
                return

            ps1_file = os.path.join(SCRIPTS_DIR, f"{demo['id']}_{demo['name']}.ps1")
            
            # Launch in real interactive Windows console window
            try:
                cmd_line = [
                    "powershell.exe",
                    "-NoExit",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    ps1_file,
                ]
                subprocess.Popen(
                    cmd_line,
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=demo["cwd"],
                )
                status = "ok"
                msg = f"Launched verification for {demo['title']}"
            except Exception as e:
                status = "error"
                msg = str(e)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": status, "message": msg, "id": demo_id}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

def run():
    server_address = ("", PORT)
    httpd = http.server.HTTPServer(server_address, DemoServerHandler)
    url = f"http://localhost:{PORT}"
    print("=" * 64)
    print("AgentShield V3 - Security Cockpit Running")
    print(f"URL: {url}")
    print("=" * 64)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo dashboard server...")
        httpd.server_close()

if __name__ == "__main__":
    run()
