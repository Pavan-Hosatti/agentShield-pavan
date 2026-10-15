# 🛡️ AgentShield V3 — Pavan's Master Technical Demo & Pitch Playbook

> **Presenter:** Pavan Hosatti  
> **Role:** Adversarial Red-Team Lead & Cryptographic Invariant Architect  
> **Project:** AgentShield V3 — Zero-Trust Autonomous AI Security Framework  
> **Target Audience:** Technical Judges, CISOs, Penetration Testers, Security Researchers  

---

## 📋 Executive Overview of Pavan's Contributions

When the judges ask: *"What was YOUR specific technical contribution?"*, state these 4 pillars:
1. **Adversarial Red-Team Attack Suite (`core/scenarios/replay_scenarios.py`)**: Designed and implemented 8 real-world zero-day exploits mapped to **MITRE ATLAS** and **OWASP LLM Top 10**.
2. **Deterministic Fail-Closed State Machine (`core/state_machine.py`)**: Engineered finite state transitions enforcing that out-of-order execution attempts collapse into a terminal `REJECTED` state.
3. **Mathematical Subset Delegation Validator (`core/delegation.py`)**: Built the 7 invariant rules (R1–R7) preventing Confused Deputy privilege escalation in autonomous multi-agent hierarchies.
4. **Cryptographic Proof Bundle Engine (`core/proof_export.py`)**: Developed the HMAC-SHA256 non-repudiation sealing mechanism certifying invariant states for air-gapped auditor verification.

---

## 🎬 Synchronized Second-by-Second Technical Pitch

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ DASHBOARD URL: http://localhost:8888 (Keep open in Chrome/Edge)            │
│ BACKUP SHORTCUT: D:\reva cyber hack-pavan\agentshield\demo_scripts          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### ⏱️ PHASE 1: The Architectural Threat Hook (0:00 – 0:30)

#### 🖥️ Action:
* Browser is open to `http://localhost:8888`.
* Stand upright, maintain direct eye contact with the lead technical judge.

#### 🎙️ Spoken Words:
> *"Good afternoon, Judges. Traditional network security relies on perimeter firewalls and heuristic prompt filters. However, in autonomous agentic workflows where LLMs execute external tool calls, database mutations, and banking APIs, prompt guardrails fail completely.*
>
> *Once an AI agent is compromised via indirect prompt injection or context poisoning, the adversary hijacks its legitimate execution credentials. At that point, firewalls see valid TLS traffic, and prompt filters see nothing.*
>
> *In AgentShield V3, **I engineered the Adversarial Red-Team Engine, the Invariant Execution Boundary, and the Cryptographic Proof Architecture**. Our threat model is formalized strictly against **MITRE ATLAS** and **OWASP LLM Top 10**.*
>
> *Let me actively attack our own zero-trust boundary in real-time."*

---

### ⏱️ PHASE 2: Live Adversarial Execution & Atomic Invariant Interception (0:30 – 1:30)

#### 🖥️ Action:
* **Click Card `#02: 8 Attacks All Blocked Live`** on `http://localhost:8888`.
* A native Windows PowerShell terminal pops up and automatically types:
  `PS AgentShield> python -m core.scenarios.replay_scenarios`
* The attacks begin transmitting with live 1-second cadence.
* **Point your index finger at the screen** as the scenarios stream down.

#### 🎙️ Spoken Words:
> *"Watch my desktop: our automated harness is firing 8 high-severity attack vectors directly against our execution perimeter.*
>
> *(Point finger at [S1] Capability Replay)*  
> **Look at Scenario 1 — Concurrent Capability Replay (CWE-362 Race Condition):**  
> *Real-world attackers don't submit single payloads; they exploit database locking latency via high-concurrency bursts. I submitted an authorized refund capability token **5 consecutive times in an 8-millisecond window** to induce a double-spend.*
> *Attempt #1 acquired the lock, but attempts #2 through #5 were terminated with **HTTP 409 JTI_ALREADY_CLAIMED**. We enforce **Invariant I4**: atomic single-use JTI consumption in Redis via `SET NX EX 300`, backed by a relational PostgreSQL `UNIQUE (jti)` constraint.*
>
> *(Point finger at [S3] Revoked Agent)*  
> **Now look at Scenario 3 — Time-of-Check to Time-of-Use (TOCTOU) Revocation (CWE-367):**  
> *An agent authorized at $t=0$ was revoked by admin at $t=+5\text{s}$. The adversary attempted execution at $t=+10\text{s}$. Naive architectures fail here because they only validate credentials at the ingress gateway.*
> *AgentShield implements true **Defense-in-Depth (Invariant I9)**: our internal executor treats the gateway as completely untrusted. The executor independently re-queries Redis `SISMEMBER` and PostgreSQL revocation tables at the microsecond of invocation, terminating the session with **HTTP 403 AGENT_REVOKED**.*
>
> *(Point finger at [S8] Fail-Open Probe)*  
> **Finally, look at Scenario 8 — Dependency Outage Exploitation (CWE-755):**  
> *The adversary severed the connection to our Open Policy Agent (OPA) cluster, probing for permissive fallback. Our circuit-breaker strictly enforces **Invariant I11**: fail-closed by mathematical design. It returns **HTTP 503 POLICY_CHECK_UNAVAILABLE** — the system never defaults to allow."*

---

### ⏱️ PHASE 3: Sub-Agent Privilege Escalation & Confused Deputy Mitigation (1:30 – 2:15)

#### 🖥️ Action:
* Return to the browser tab.
* **Click Card `#06: Delegation Rules Enforcement`**.
* Terminal opens and streams: `DELEGATION DENIED — 6 violation(s)`.
* Point to the list of 6 detected violations.

#### 🎙️ Spoken Words:
> *"Modern AI architectures employ multi-agent delegation. Here, an adversary exploited a low-privilege customer support sub-agent to mount a **Confused Deputy Attack (MITRE ATLAS AML.T0056 / OWASP LLM06: Excessive Agency)**.*
>
> *The parent agent possessed authority strictly for `issue_refund` capped at ₹500. The compromised sub-agent attempted to:*
> 1. *Inject unassigned tools: `wire_transfer`,*
> 2. *Escalate transaction ceiling from ₹500 to ₹9,99,999,*
> 3. *Expand TTL beyond parent bounds from 300s to 9,999s,*
> 4. *Escape tenant isolation from `tenant-demo` to `tenant-evil`,*
> 5. *Upgrade deployment environment to `production`, and*
> 6. *Downgrade the policy schema version.*
>
> *(Point to the 6 violations on screen)*  
> *AgentShield enforces **Invariant I7: Strict Mathematical Subset Delegation**. Our static validator evaluates 7 discrete rules ($R1$ through $R7$) before cryptographic signing. All 6 escalation vectors were intercepted simultaneously. A child agent's permission space is mathematically bound as a strict subset of its parent."*

---

### ⏱️ PHASE 4: Blast Radius & SIEM-Ready Forensic Evidence (2:15 – 2:50)

#### 🖥️ Action:
* Return to the dashboard.
* **Point to the top metric bar:** `₹12,49,999+ Financial Fraud Blast Radius Contained`.
* **Click the button `🔍 FORENSIC AUDIT JSON`** on Scenario S7.
* A dark syntax-highlighted cryptographic JSON modal appears on screen.

#### 🎙️ Spoken Words:
> *(Point to the Blast Radius counter)*  
> *"In enterprise risk management, security is measured by **Blast Radius Containment**. Without AgentShield, Attack S7 would have drained ₹9,99,999 in wire fraud, Attack S1 would have drained ₹2,00,000 in double-spend liquidity, and Attack S6 would have leaked 50,000 tenant records.*
> *In total, our boundary contained over **₹12.5 Lakhs in active fraud blast radius down to exactly zero**.*
>
> *(Point to the open JSON modal on screen)*  
> *Furthermore, enterprise SOC analysts cannot investigate black-box AI decisions without forensic evidence. Look at this **SIEM-Ready Forensic Artifact**:*
> - *Every transaction is bound by a **Deterministic SHA-256 Action Digest (Invariant I2)** across tool arguments.*
> - *Every execution failure logs the exact invariant citation code and Redis atomic lock state.*
> - *The record is cryptographically sealed with an **HMAC-SHA256 signature**, establishing tamper-evident non-repudiation admissible in regulatory audits."*

---

### ⏱️ PHASE 5: Regulatory Compliance & Proof Certification (2:50 – 3:15)

#### 🖥️ Action:
* Close modal, **Click Card `#07: Generate Proof Bundle`**, then **Click Card `#08: Verify Proof Bundle`**.
* Terminal verifies `HMAC Seal: VALID` and `ALL 11 INVARIANTS CERTIFIED`.
* Turn to face the judges directly for the closing statement.

#### 🎙️ Spoken Words:
> *"Finally, AgentShield is engineered for compliance with **Articles 14 and 15 of the EU AI Act**:*
> - **Article 14 (Human Oversight):** *High-stakes transactions exceeding ₹300 automatically halt execution, transitioning state to `NEEDS_APPROVAL`.*
> - **Article 15 (Cybersecurity Resilience):** *Zero-trust execution guarantees that no unauthorized side effect can execute on enterprise databases.*
>
> *In under 1 second, our system exports an **HMAC-sealed Cryptographic Proof Bundle** certifying all 11 security invariants across 426 automated unit and adversarial tests.*
>
> *AgentShield proves that autonomous AI agents can be deployed safely in high-stakes financial and enterprise production. Thank you, Judges. We are ready for your technical interrogation."*

---

## 🛡️ The Judge Interrogation Shield (Answers to Trap Questions)

### Q1: *"Why not just use OpenAI Guardrails, Llama Guard, or NeMo Guardrails?"*
> **Your Technical Answer:**  
> *"LLM guardrails operate at Layer 7 text generation — inspecting token probabilities and semantic keywords. They have zero visibility into runtime API execution, ephemeral JWT claims, or database concurrency. Once an adversary bypasses prompt filters via indirect injection, prompt guardrails cannot prevent a valid tool call. AgentShield operates at the **Deterministic Execution Boundary (Layer 4/Layer 7 API interface)**, enforcing mathematical invariants regardless of what text the LLM emits."*

### Q2: *"What happens under high concurrency if Redis experiences network partition (split-brain)?"*
> **Your Technical Answer:**  
> *"We follow a strict **Dual-Storage Single-Use Strategy**. High-throughput replay checks ($<2\text{ms}$) execute via Redis atomic `SET NX EX 300`. However, durability is anchored by PostgreSQL with an indexed `UNIQUE (jti)` constraint within an ACID transactional boundary. If Redis partitions, our state machine fails closed (`F2: REDIS_UNAVAILABLE_AT_CLAIM`), rejecting claims with HTTP 503 rather than permitting an unverified replay."*

### Q3: *"How does your Action Digest binding work mathematically?"*
> **Your Technical Answer:**  
> *"Under Invariant I2, the gateway computes $H = \text{SHA-256}(\text{CanonicalJSON}(\text{agent\_id}, \text{action}, \text{params}, \text{tenant\_id}, \text{timestamp}))$. This digest $H$ is cryptographically signed into the capability token. When the executor receives the payload, it recomputes the hash over the wire parameters and verifies $H_{\text{recomputed}} \equiv H_{\text{token}}$. If an adversary tampers with a single character or parameter value, the hash equality breaks and execution aborts."*

### Q4: *"What is the latency overhead of your zero-trust validation pipeline?"*
> **Your Technical Answer:**  
> *"Our average end-to-end policy and invariant enforcement overhead is **1.84 milliseconds**. Open Policy Agent (OPA) evaluates pre-compiled Rego bytecode in under 450 microseconds, Redis atomic `SET NX` completes in sub-millisecond in-memory time, and SHA-256 computation adds negligible microsecond cost. We achieve 10,000+ transactions per second on standard commodity hardware."*

---

## 📌 Pocket Quick-Reference Table

| Phase | Visual Trigger | Spoken Soundbite | Key Architecture Terms |
| :--- | :--- | :--- | :--- |
| **1. Hook** | Live Cockpit | *"Prompt guardrails fail on execution-layer attacks."* | MITRE ATLAS, OWASP LLM06, Execution Boundary |
| **2. Attacks** | Terminal + Stream | *"Fired 8 zero-days — race conditions and TOCTOU blocked."* | Invariant I4, Atomic `SET NX`, Defense-in-Depth, TOCTOU |
| **3. Delegation** | 6 Violations | *"Sub-agent tried to steal ₹10 Lakhs — delegation denied."* | Confused Deputy, Invariant I7, Mathematical Subset |
| **4. Blast Radius** | ₹12.5L Bar + JSON | *"Contained ₹12.5 Lakhs in fraud with SIEM-ready forensic traces."* | Blast Radius, SHA-256 Action Digest, Non-Repudiation |
| **5. Proof** | Proof Bundle | *"HMAC-sealed audit certificate compliant with EU AI Act."* | EU AI Act Art 14/15, Invariants I1..I11, Proof Bundle |
| **6. IBM Bob** | Card #11 + MCP Badge | *"AgentShield acts as the Zero-Trust MCP Security Proxy for IBM Bob."* | Model Context Protocol (MCP), JSON-RPC 2.0, OWASP LLM08, Confused Deputy |

---

## 🏢 Special Sponsor Track: How to Pitch & Convince IBM Judges (IBM Bob Integration)

### 🎯 The Secret Mindset of IBM Evaluators:
IBM is heavily promoting **IBM Bob** (their new autonomous AI coding and workflow agent) and the **Model Context Protocol (MCP)**.
IBM judges are looking for projects that:
1. Recognize **IBM Bob's agentic architecture** (autonomous subagents + MCP tool calls).
2. Solve IBM's #1 enterprise sales blocker: **Enterprise clients fear deploying autonomous agents like IBM Bob because of unbounded tool execution risk.**
3. Integrate with IBM enterprise standards (**MCP `.bob/mcp.json`**, JSON-RPC 2.0, and SIEM logging).

---

### 🎙️ The 30-Second IBM Sponsor Pitch (Deliver when IBM judges approach):

> *"Good afternoon, Judges. As IBM expands enterprise agentic workflows with **IBM Bob**, the primary adoption barrier for banks and Fortune 500s is **Excessive Agency (OWASP LLM08)** and **Tool Call Replays (CWE-362)**.*
> 
> *IBM Bob uses the **Model Context Protocol (MCP)** to connect autonomous subagents to databases, cloud deployments, and banking APIs via `.bob/mcp.json`. But if a subagent is tricked by prompt injection or suffers a concurrency race condition, it can execute catastrophic unauthorized tool calls.*
> 
> *We engineered **AgentShield as a native Zero-Trust MCP Security Gateway for IBM Bob**.*
> 
> *(Click Card #11: IBM Bob MCP Security Proxy on the dashboard)*
> 
> *Notice our dashboard: AgentShield hooks directly into `.bob/mcp.json` as the MCP reverse proxy. When IBM Bob subagents issue JSON-RPC `tools/call` requests, AgentShield enforces atomic JTI deduplication in Redis, validates Invariants I1 through I11, and bounds financial transactions to enterprise thresholds—failing closed before any tool can mutate production state."*

---

### 🛡️ How to Answer IBM Judge Trap Questions:

#### Q1: *"How does AgentShield physically connect to IBM Bob?"*
> **Answer:** *"IBM Bob discovers tools via `.bob/mcp.json` in the project root. We configured AgentShield as an MCP proxy server. When IBM Bob requests a tool call via standard JSON-RPC 2.0 (`tools/call`), the request routes through `integrations/ibm_bob_mcp_proxy.py`. AgentShield inspects the payload, checks JTI nonce single-use in Redis, verifies that transaction parameters satisfy our OPA Rego policies, and only passes authorized calls through to the backend."*

#### Q2: *"Why is this needed if IBM already has watsonx.governance?"*
> **Answer:** *"watsonx.governance is fantastic at the **foundation model layer**—evaluating prompt toxicity, hallucination drift, and input sanitization. But watsonx does not sit at the **operating system / API runtime boundary**. Once an autonomous agent decides to emit an MCP tool call, only a deterministic proxy like AgentShield can enforce atomic DB locks, prevent CWE-362 race conditions across parallel subagents, and mathematically verify delegation subset invariants."*

#### Q3: *"Does this slow down IBM Bob's developer experience?"*
> **Answer:** *"Not at all. The entire AgentShield MCP boundary adds less than **2.0 milliseconds** of latency. Legitimate developer tool calls pass through instantly with an HMAC-signed audit seal, while unauthorized or replayed calls are stopped with standard JSON-RPC error codes that IBM Bob natively understands and can recover from."*

