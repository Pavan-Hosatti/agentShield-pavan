import { useState, useEffect, useRef, useCallback } from 'react'
import {
  evaluatePolicy,
  simulateDigest,
  ATTACK_PRESETS,
  type PolicyDecision,
  type ActionInput,
  type AttackPreset,
} from './engine/policyEngine'
import BaselinesTab from './components/BaselinesTab'
import StateMachineTab from './components/StateMachineTab'
import ThreatMapTab from './components/ThreatMapTab'
import MutationsTab from './components/MutationsTab'
import './App.css'

// ── Types ─────────────────────────────────────────────────────
interface LogEntry {
  id: number
  ts: string
  level: 'INFO' | 'WARN' | 'DENY' | 'ALLOW' | 'ATTACK' | 'SYS'
  msg: string
}

interface TestResult {
  preset: AttackPreset
  decision: PolicyDecision
  passed: boolean // expected == actual
  digest_before: string
  digest_after: string
}

// ── Helpers ───────────────────────────────────────────────────
const now = () => new Date().toISOString().replace('T', ' ').substring(0, 23)

let logId = 0
const mkLog = (level: LogEntry['level'], msg: string): LogEntry => ({
  id: ++logId, ts: now(), level, msg,
})

const rupeeFmt = (paise: number) =>
  `₹${(paise / 100).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`

// ── Main App ──────────────────────────────────────────────────
export default function App() {
  const [activeTab, setActiveTab] = useState<'console' | 'matrix' | 'digest' | 'policy' | 'baselines' | 'statemachine' | 'threatmap' | 'mutations'>('console')
  const [logs, setLogs] = useState<LogEntry[]>([
    mkLog('SYS', 'AgentShield Security Console v2.0 initialised'),
    mkLog('SYS', 'OPA Policy Engine: LOADED  |  Policy: agentshield.rego v3'),
    mkLog('SYS', 'Default stance: DENY  |  Fail-closed: ENABLED'),
    mkLog('INFO', 'Ready. Select an attack preset or configure a custom action.'),
  ])
  const [form, setForm] = useState<ActionInput>(ATTACK_PRESETS[0].input)
  const [lastDecision, setLastDecision] = useState<PolicyDecision | null>(null)
  const [running, setRunning] = useState(false)
  const [testResults, setTestResults] = useState<TestResult[]>([])
  const [batchRunning, setBatchRunning] = useState(false)
  const [selectedPreset, setSelectedPreset] = useState<string>('legit-small')
  const logEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
  logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const addLog = useCallback((level: LogEntry['level'], msg: string) => {
    setLogs(prev => [...prev, mkLog(level, msg)])
  }, [])

  const loadPreset = (id: string) => {
    const p = ATTACK_PRESETS.find(x => x.id === id)
    if (p) { setForm(p.input); setSelectedPreset(id) }
  }

  const runEval = () => {
    setRunning(true)
    const preset = ATTACK_PRESETS.find(x => x.id === selectedPreset)
    const label = preset ? preset.label : 'Custom'

    addLog('INFO', `──────────────────────────────────────────`)
    addLog('INFO', `Evaluating: ${label}`)
    addLog('INFO', `  tool=${form.tool}  tenant=${form.tenant_id}  amount=${rupeeFmt(form.amount_minor)}`)
    addLog('INFO', `  env=${form.environment}  policy_v=${form.policy_version}`)

    setTimeout(() => {
      const d = evaluatePolicy(form)

      d.checks_run.forEach(c => {
        addLog(c.passed ? 'INFO' : 'WARN', `  [${c.id}] ${c.name}: ${c.passed ? 'PASS' : 'FAIL'} — ${c.detail}`)
      })

      if (d.result === 'allow') {
        addLog('ALLOW', `DECISION: ALLOW  (${d.reason})  [${d.latency_ms.toFixed(2)}ms]`)
      } else if (d.result === 'deny') {
        addLog('DENY', `DECISION: DENY  (${d.reason})  [${d.latency_ms.toFixed(2)}ms]`)
        if (d.hard_denies.length > 0) {
          addLog('DENY', `  Hard-deny rules fired: ${d.hard_denies.join(', ')}`)
          addLog('DENY', `  ↳ Cannot be overridden by any approval`)
        }
      } else {
        addLog('WARN', `DECISION: NEEDS_APPROVAL  (${d.reason})  [${d.latency_ms.toFixed(2)}ms]`)
        addLog('WARN', `  ↳ Amount ≥ ₹300.00 — manager approval required`)
      }

      setLastDecision(d)
      setRunning(false)
    }, 400)
  }

  const runBatchTest = () => {
    setBatchRunning(true)
    setTestResults([])
    addLog('SYS', '══════════════════════════════════════════')
    addLog('SYS', 'RUNNING FULL ATTACK MATRIX TEST SUITE...')
    addLog('SYS', '══════════════════════════════════════════')

    const results: TestResult[] = []
    let i = 0

    const runNext = () => {
      if (i >= ATTACK_PRESETS.length) {
        const passed = results.filter(r => r.passed).length
        addLog('SYS', `──────────────────────────────────────────`)
        addLog(passed === results.length ? 'ALLOW' : 'DENY',
          `SUITE COMPLETE: ${passed}/${results.length} tests passed`)
        setTestResults(results)
        setActiveTab('matrix')
        setBatchRunning(false)
        return
      }

      const preset = ATTACK_PRESETS[i]
      const decision = evaluatePolicy(preset.input)
      const passed = decision.result === preset.expectedResult

      const d_before = simulateDigest(preset.input)
      const tampered = { ...preset.input, amount_minor: preset.input.amount_minor * 10 }
      const d_after = simulateDigest(tampered)

      results.push({ preset, decision, passed, digest_before: d_before, digest_after: d_after })

      addLog(
        passed ? 'ALLOW' : 'DENY',
        `  [${passed ? 'PASS' : 'FAIL'}] ${preset.label} → ${decision.result.toUpperCase()} (expected: ${preset.expectedResult.toUpperCase()})`
      )

      i++
      setTimeout(runNext, 80)
    }

    setTimeout(runNext, 200)
  }

  const clearLogs = () => {
    setLogs([mkLog('SYS', 'Log cleared — AgentShield Security Console ready')])
    setLastDecision(null)
  }

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <span className="logo">⬡ AGENTSHIELD</span>
          <span className="logo-sub">SECURITY CONSOLE v2.0</span>
          <span className="blink">▮</span>
        </div>
        <div className="header-right">
          <StatusBadge label="OPA ENGINE" status="ONLINE" />
          <StatusBadge label="POLICY" status="v3-LOADED" />
          <StatusBadge label="STANCE" status="DENY-ALL" color="red" />
        </div>
      </header>

      {/* ── Tabs ── */}
      <nav className="tabs">
        {[
          { id: 'console',      label: '[ POLICY CONSOLE ]' },
          { id: 'matrix',       label: '[ ATTACK MATRIX ]' },
          { id: 'digest',       label: '[ DIGEST DEMO ]' },
          { id: 'policy',       label: '[ REGO POLICY ]' },
          { id: 'baselines',    label: '[ A/B/C BASELINES ]' },
          { id: 'statemachine', label: '[ STATE MACHINE ]' },
          { id: 'threatmap',    label: '[ THREAT MAP ]' },
          { id: 'mutations',    label: '[ POLICY MUTATIONS ]' },
        ].map(t => (
          <button
            key={t.id}
            className={`tab ${activeTab === t.id ? 'tab-active' : ''}`}
            onClick={() => setActiveTab(t.id as typeof activeTab)}          >
            {t.label}
          </button>
        ))}
      </nav>

      {/* ── Body ── */}
      <div className="body">
        {activeTab === 'console' && (
          <ConsoleTab
            form={form}
            setForm={setForm}
            lastDecision={lastDecision}
            logs={logs}
            logEndRef={logEndRef}
            running={running}
            batchRunning={batchRunning}
            selectedPreset={selectedPreset}
            onLoadPreset={loadPreset}
            onRun={runEval}
            onBatch={runBatchTest}
            onClear={clearLogs}
          />
        )}
        {activeTab === 'matrix' && <MatrixTab results={testResults} onRun={runBatchTest} batchRunning={batchRunning} />}
        {activeTab === 'digest' && <DigestTab />}
        {activeTab === 'policy' && <PolicyTab />}
        {activeTab === 'baselines' && <BaselinesTab />}
        {activeTab === 'statemachine' && <StateMachineTab />}
        {activeTab === 'threatmap' && <ThreatMapTab />}
        {activeTab === 'mutations' && <MutationsTab />}
      </div>
    </div>
  )
}

// ── Status Badge ──────────────────────────────────────────────
function StatusBadge({ label, status, color = 'green' }: { label: string; status: string; color?: 'green' | 'red' | 'yellow' }) {
  return (
    <div className={`badge badge-${color}`}>
      <span className="badge-dot">●</span>
      <span className="badge-label">{label}</span>
      <span className="badge-val">{status}</span>
    </div>
  )
}

// ── Console Tab ───────────────────────────────────────────────
function ConsoleTab({
  form, setForm, lastDecision, logs, logEndRef, running, batchRunning,
  selectedPreset, onLoadPreset, onRun, onBatch, onClear
}: {
  form: ActionInput
  setForm: (f: ActionInput) => void
  lastDecision: PolicyDecision | null
  logs: LogEntry[]
  logEndRef: React.RefObject<HTMLDivElement>
  running: boolean
  batchRunning: boolean
  selectedPreset: string
  onLoadPreset: (id: string) => void
  onRun: () => void
  onBatch: () => void
  onClear: () => void
}) {
  const baselines = ATTACK_PRESETS.filter(p => p.category === 'BASELINE')
  const attacks = ATTACK_PRESETS.filter(p => p.category === 'ATTACK')

  return (
    <div className="console-layout">
      {/* ── Left: Controls ── */}
      <div className="controls-panel">
        <div className="panel-title">▶ ATTACK PRESETS</div>

        <div className="preset-group-label">── BASELINE ──</div>
        {baselines.map(p => (
          <button
            key={p.id}
            className={`preset-btn ${selectedPreset === p.id ? 'preset-active' : ''} preset-baseline`}
            onClick={() => onLoadPreset(p.id)}
          >
            {p.label}
          </button>
        ))}

        <div className="preset-group-label">── ATTACKS ──</div>
        {attacks.map(p => (
          <button
            key={p.id}
            className={`preset-btn ${selectedPreset === p.id ? 'preset-active' : ''} preset-attack`}
            onClick={() => onLoadPreset(p.id)}
          >
            {p.label}
          </button>
        ))}

        <div className="divider" />

        <div className="panel-title">▶ ACTION PARAMS</div>
        <FieldRow label="tool">
          <select className="inp" value={form.tool} onChange={e => setForm({ ...form, tool: e.target.value })}>
            <option>issue_refund</option>
            <option>wire_transfer</option>
            <option>delete_account</option>
          </select>
        </FieldRow>
        <FieldRow label="tenant_id">
          <input className="inp" value={form.tenant_id} onChange={e => setForm({ ...form, tenant_id: e.target.value })} />
        </FieldRow>
        <FieldRow label="agent_tenant">
          <input className="inp" value={form.agent_tenant_id} onChange={e => setForm({ ...form, agent_tenant_id: e.target.value })} />
        </FieldRow>
        <FieldRow label="amount (₹)">
          <input className="inp" type="number" value={form.amount_minor / 100}
            onChange={e => setForm({ ...form, amount_minor: Math.round(parseFloat(e.target.value || '0') * 100) })} />
        </FieldRow>
        <FieldRow label="environment">
          <select className="inp" value={form.environment} onChange={e => setForm({ ...form, environment: e.target.value })}>
            <option>demo</option>
            <option>staging</option>
            <option>production</option>
            <option>localhost</option>
            <option>dev</option>
          </select>
        </FieldRow>
        <FieldRow label="policy_version">
          <input className="inp" type="number" min={1} max={5} value={form.policy_version}
            onChange={e => setForm({ ...form, policy_version: parseInt(e.target.value || '1') })} />
        </FieldRow>
        <FieldRow label="resource_owner">
          <input className="inp" value={form.resource_owner_tenant} onChange={e => setForm({ ...form, resource_owner_tenant: e.target.value })} />
        </FieldRow>

        <div className="preset-group-label">── APPROVAL STATE ──</div>
        <CheckField label="approval present" checked={form.approval_present} onChange={v => setForm({ ...form, approval_present: v })} />
        <CheckField label="digest matches" checked={form.approval_digest_matches} onChange={v => setForm({ ...form, approval_digest_matches: v })} />
        <CheckField label="consumed (replayed)" checked={form.approval_consumed} onChange={v => setForm({ ...form, approval_consumed: v })} />
        <FieldRow label="decision">
          <select className="inp" value={form.approval_decision} onChange={e => setForm({ ...form, approval_decision: e.target.value })}>
            <option>approved</option>
            <option>rejected</option>
            <option>none</option>
          </select>
        </FieldRow>

        <div className="divider" />
        <button className="btn btn-primary" onClick={onRun} disabled={running || batchRunning}>
          {running ? '⟳ EVALUATING...' : '▶ EVALUATE POLICY'}
        </button>
        <button className="btn btn-secondary" onClick={onBatch} disabled={running || batchRunning}>
          {batchRunning ? '⟳ RUNNING SUITE...' : '⚡ RUN ALL ATTACKS'}
        </button>
        <button className="btn btn-ghost" onClick={onClear}>✕ CLEAR LOG</button>
      </div>

      {/* ── Right: Log + Decision ── */}
      <div className="right-panel">
        {/* Decision banner */}
        {lastDecision && <DecisionBanner decision={lastDecision} amount={form.amount_minor} />}

        {/* Log */}
        <div className="log-panel">
          <div className="panel-title">▶ POLICY EVALUATION LOG</div>
          <div className="log-scroll">
            {logs.map(l => (
              <div key={l.id} className={`log-line log-${l.level.toLowerCase()}`}>
                <span className="log-ts">{l.ts}</span>
                <span className={`log-level lv-${l.level.toLowerCase()}`}>[{l.level}]</span>
                <span className="log-msg">{l.msg}</span>
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>

        {/* Checks detail */}
        {lastDecision && (
          <div className="checks-panel">
            <div className="panel-title">▶ CHECKS RUN ({lastDecision.checks_run.length})</div>
            <div className="checks-grid">
              {lastDecision.checks_run.map(c => (
                <div key={c.id} className={`check-item ${c.passed ? 'check-pass' : 'check-fail'}`}>
                  <span className="check-icon">{c.passed ? '✓' : '✗'}</span>
                  <span className="check-id">{c.id}</span>
                  <span className="check-name">{c.name}</span>
                  <span className="check-detail">{c.detail}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      {children}
    </div>
  )
}

function CheckField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="field-row">
      <span className="field-label">{label}</span>
      <button className={`toggle ${checked ? 'toggle-on' : 'toggle-off'}`} onClick={() => onChange(!checked)}>
        {checked ? 'TRUE ' : 'FALSE'}
      </button>
    </div>
  )
}

function DecisionBanner({ decision, amount }: { decision: PolicyDecision; amount: number }) {
  const cls = decision.result === 'allow' ? 'banner-allow'
    : decision.result === 'deny' ? 'banner-deny' : 'banner-needs'
  const icon = decision.result === 'allow' ? '✓ ALLOW'
    : decision.result === 'deny' ? '✗ DENY' : '⚠ NEEDS APPROVAL'

  return (
    <div className={`banner ${cls}`}>
      <span className="banner-icon">{icon}</span>
      <span className="banner-reason">{decision.reason}</span>
      <span className="banner-amount">{(amount / 100).toLocaleString('en-IN', { style: 'currency', currency: 'INR' })}</span>
      <span className="banner-latency">{decision.latency_ms.toFixed(2)}ms</span>
    </div>
  )
}

// ── Attack Matrix Tab ─────────────────────────────────────────
function MatrixTab({ results, onRun, batchRunning }: {
  results: TestResult[]
  onRun: () => void
  batchRunning: boolean
}) {
  const passed = results.filter(r => r.passed).length

  return (
    <div className="matrix-tab">
      <div className="matrix-header">
        <div className="panel-title">▶ ATTACK MATRIX — {ATTACK_PRESETS.length} TEST CASES</div>
        {results.length > 0 && (
          <div className={`matrix-score ${passed === results.length ? 'score-pass' : 'score-fail'}`}>
            {passed}/{results.length} PASSED {passed === results.length ? '— ALL ATTACKS BLOCKED ✓' : '— FAILURES DETECTED ✗'}
          </div>
        )}
        <button className="btn btn-secondary" onClick={onRun} disabled={batchRunning} style={{ marginLeft: 'auto' }}>
          {batchRunning ? '⟳ RUNNING...' : '⚡ RUN FULL SUITE'}
        </button>
      </div>

      {results.length === 0 ? (
        <div className="matrix-empty">
          <p>No results yet. Click RUN FULL SUITE to execute all {ATTACK_PRESETS.length} test cases.</p>
          <p style={{ marginTop: '8px', color: 'var(--text-dim)' }}>
            Tests cover: hard-deny rules, cross-tenant attacks, action substitution, approval replay, policy staleness.
          </p>
        </div>
      ) : (
        <div className="matrix-table-wrap">
          <table className="matrix-table">
            <thead>
              <tr>
                <th>TEST CASE</th>
                <th>CATEGORY</th>
                <th>EXPECTED</th>
                <th>ACTUAL</th>
                <th>REASON</th>
                <th>HARD DENIES</th>
                <th>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {results.map(r => (
                <tr key={r.preset.id} className={r.passed ? 'row-pass' : 'row-fail'}>
                  <td className="td-name">{r.preset.label}</td>
                  <td><span className={`cat-badge cat-${r.preset.category.toLowerCase()}`}>{r.preset.category}</span></td>
                  <td><span className={`result-badge rb-${r.preset.expectedResult}`}>{r.preset.expectedResult.toUpperCase()}</span></td>
                  <td><span className={`result-badge rb-${r.decision.result}`}>{r.decision.result.toUpperCase()}</span></td>
                  <td className="td-reason">{r.decision.reason}</td>
                  <td className="td-harddenies">
                    {r.decision.hard_denies.length > 0
                      ? r.decision.hard_denies.map(h => <span key={h} className="hard-deny-tag">{h}</span>)
                      : <span className="td-none">—</span>
                    }
                  </td>
                  <td><span className={`status-badge ${r.passed ? 'sb-pass' : 'sb-fail'}`}>{r.passed ? '✓ PASS' : '✗ FAIL'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {results.length === 0 && (
        <div className="preset-cards">
          {ATTACK_PRESETS.map(p => (
            <div key={p.id} className={`preset-card ${p.category === 'ATTACK' ? 'card-attack' : 'card-baseline'}`}>
              <div className="card-label">{p.label}</div>
              <div className="card-desc">{p.description}</div>
              <div className={`card-expected rb-${p.expectedResult}`}>→ {p.expectedResult.toUpperCase()}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Digest Demo Tab ───────────────────────────────────────────
function DigestTab() {
  const [amount1, setAmount1] = useState(500)   // ₹500
  const [amount2, setAmount2] = useState(5000)  // ₹5000

  const baseAction = {
    tool: 'issue_refund', tenant_id: 'tenant-demo',
    agent_tenant_id: 'tenant-demo', environment: 'demo',
    policy_version: 3, amount_minor: amount1 * 100,
    resource_owner_tenant: 'tenant-demo', approval_present: false,
    approval_digest_matches: false, approval_consumed: false, approval_decision: 'none',
  } as Parameters<typeof simulateDigest>[0]

  const tamperedAction = { ...baseAction, amount_minor: amount2 * 100 }
  const d1 = simulateDigest(baseAction)
  const d2 = simulateDigest(tamperedAction)
  const match = d1 === d2

  // Show canonical JSON
  const canonical1 = JSON.stringify({
    arguments: { amount_minor: amount1 * 100, order_id: 'ORDER-SIM' },
    environment: 'demo', policy_version: 3,
    tenant_id: 'tenant-demo', tool: 'issue_refund',
  }, null, 2)
  const canonical2 = JSON.stringify({
    arguments: { amount_minor: amount2 * 100, order_id: 'ORDER-SIM' },
    environment: 'demo', policy_version: 3,
    tenant_id: 'tenant-demo', tool: 'issue_refund',
  }, null, 2)

  return (
    <div className="digest-tab">
      <div className="panel-title">▶ ACTION DIGEST DEMO — Anti-Action-Substitution</div>
      <p className="digest-explainer">
        Every action is SHA-256 hashed with prefix <code>AGENTSHIELD-ACTION-V1\x00</code> over sorted canonical JSON.
        Changing even one field produces a completely different digest.
        An approval is bound to the <strong>exact digest</strong> — a tampered action invalidates the approval.
      </p>

      <div className="digest-grid">
        {/* Original */}
        <div className="digest-card">
          <div className="dc-title">ORIGINAL ACTION</div>
          <div className="dc-field">
            <span className="dc-label">amount_minor</span>
            <input className="inp dc-inp" type="number" value={amount1}
              onChange={e => setAmount1(parseInt(e.target.value || '0'))} />
            <span className="dc-rupee">= {(amount1).toLocaleString('en-IN', { style: 'currency', currency: 'INR' })}</span>
          </div>
          <div className="dc-json">{canonical1}</div>
          <div className="dc-digest-label">SHA-256 DIGEST (simulated):</div>
          <div className="dc-digest">{d1}</div>
          <div className="dc-note">Approval is bound to this digest ↑</div>
        </div>

        {/* Arrow */}
        <div className="digest-arrow">
          <div className="arrow-label">ATTACKER TAMPERS</div>
          <div className="arrow-sym">⟶</div>
          <div className={`arrow-result ${match ? 'ar-match' : 'ar-mismatch'}`}>
            {match ? '⚠ SAME DIGEST (attack succeeds)' : '✓ DIGEST MISMATCH (attack blocked)'}
          </div>
        </div>

        {/* Tampered */}
        <div className="digest-card digest-card-tampered">
          <div className="dc-title">TAMPERED ACTION</div>
          <div className="dc-field">
            <span className="dc-label">amount_minor</span>
            <input className="inp dc-inp" type="number" value={amount2}
              onChange={e => setAmount2(parseInt(e.target.value || '0'))} />
            <span className="dc-rupee">= {(amount2).toLocaleString('en-IN', { style: 'currency', currency: 'INR' })}</span>
          </div>
          <div className="dc-json">{canonical2}</div>
          <div className="dc-digest-label">SHA-256 DIGEST (simulated):</div>
          <div className={`dc-digest ${match ? 'digest-match' : 'digest-diff'}`}>{d2}</div>
          <div className="dc-note">Approval checks this digest ↑ — mismatch = REJECT</div>
        </div>
      </div>

      <div className="digest-fact-row">
        <div className="fact">
          <div className="fact-icon">⬡</div>
          <div className="fact-text">Digest prefix: <code>AGENTSHIELD-ACTION-V1\x00</code> — prevents cross-protocol attacks</div>
        </div>
        <div className="fact">
          <div className="fact-icon">⬡</div>
          <div className="fact-text">Keys are sorted alphabetically — field ordering cannot affect the digest</div>
        </div>
        <div className="fact">
          <div className="fact-icon">⬡</div>
          <div className="fact-text">Integers only — float amounts like 500.0 are rejected at schema validation</div>
        </div>
        <div className="fact">
          <div className="fact-icon">⬡</div>
          <div className="fact-text">Constant-time comparison (hmac.compare_digest) — no timing side-channel</div>
        </div>
      </div>
    </div>
  )
}

// ── Policy Tab ────────────────────────────────────────────────
function PolicyTab() {
  const regoPolicy = `package agentshield.authz

# ============================================================
# AgentShield V2 — Default-Deny Authorization Policy
# Owner: Pavan (policy design)
# ============================================================

# Default: deny everything.
default allow = false
default needs_approval = false
default deny_reason = "DEFAULT_DENY"

# ─────────────────────────────────────────────────────────────
# Section 1: Hard Deny Rules
# (cannot be overridden by approval — ever)
# ─────────────────────────────────────────────────────────────

hard_deny[reason] {
    not input.agent.registered
    reason := "AGENT_NOT_REGISTERED"
}

hard_deny[reason] {
    input.agent.revoked == true
    reason := "AGENT_REVOKED"
}

hard_deny[reason] {
    input.action.tenant_id != input.agent.tenant_id
    reason := "CROSS_TENANT_ACCESS"
}

hard_deny[reason] {
    not input.action.tool in input.agent.permitted_tools
    reason := "TOOL_NOT_PERMITTED"
}

hard_deny[reason] {
    not input.action.environment in {"demo", "staging", "production"}
    reason := "INVALID_ENVIRONMENT"
}

hard_deny[reason] {
    input.action.policy_version < 2
    reason := "POLICY_VERSION_STALE"
}

hard_deny[reason] {
    input.action.tool == "issue_refund"
    input.action.arguments.amount_minor > 1000000
    reason := "AMOUNT_EXCEEDS_HARD_MAXIMUM"
}

# ─────────────────────────────────────────────────────────────
# Section 2: Needs Approval Rules
# ─────────────────────────────────────────────────────────────

needs_approval {
    count(hard_deny) == 0
    input.action.tool == "issue_refund"
    input.action.arguments.amount_minor >= 30000
    input.action.arguments.amount_minor <= 1000000
}

# ─────────────────────────────────────────────────────────────
# Section 3: Allow Rules
# ─────────────────────────────────────────────────────────────

allow {
    count(hard_deny) == 0
    not needs_approval
    input.action.tool == "issue_refund"
    input.action.arguments.amount_minor > 0
    input.action.arguments.amount_minor < 30000
    resource_owned_by_tenant
}

allow {
    count(hard_deny) == 0
    needs_approval
    input.approval.valid == true
    input.approval.action_digest == input.action.action_digest
    input.approval.tenant_id == input.action.tenant_id
    input.approval.consumed == false
    input.approval.decision == "approved"
    resource_owned_by_tenant
}

# ─────────────────────────────────────────────────────────────
# Section 4: Decision Output
# ─────────────────────────────────────────────────────────────

decision = result {
    count(hard_deny) > 0
    result := { "result": "deny", "reason": concat(", ", hard_deny) }
} else = result {
    needs_approval
    not allow
    result := { "result": "needs_approval", "approval_type": "manager_approval",
                "reason": "APPROVAL_REQUIRED_FOR_AMOUNT" }
} else = result {
    allow
    result := { "result": "allow", "reason": "POLICY_ALLOW" }
} else = result {
    result := { "result": "deny", "reason": "DEFAULT_DENY" }
}`

  const validatorChecks = [
    { id: 'V1', sev: 'CRITICAL', desc: 'default allow = false', status: 'PASS' },
    { id: 'V2', sev: 'HIGH', desc: 'default deny_reason present', status: 'PASS' },
    { id: 'V3', sev: 'CRITICAL', desc: 'No wildcard allow { true }', status: 'PASS' },
    { id: 'V4a', sev: 'CRITICAL', desc: 'AGENT_REVOKED hard deny', status: 'PASS' },
    { id: 'V4b', sev: 'CRITICAL', desc: 'AGENT_NOT_REGISTERED hard deny', status: 'PASS' },
    { id: 'V4c', sev: 'CRITICAL', desc: 'CROSS_TENANT_ACCESS hard deny', status: 'PASS' },
    { id: 'V5', sev: 'HIGH', desc: 'action_digest in approval path', status: 'PASS' },
    { id: 'V6', sev: 'HIGH', desc: 'Monetary hard maximum present', status: 'PASS' },
    { id: 'V7', sev: 'MEDIUM', desc: 'No suspicious commented allows', status: 'PASS' },
    { id: 'V8', sev: 'HIGH', desc: 'POLICY_VERSION_STALE check', status: 'PASS' },
    { id: 'V9', sev: 'HIGH', desc: 'INVALID_ENVIRONMENT check', status: 'PASS' },
    { id: 'V10', sev: 'HIGH', desc: 'DEFAULT_DENY fallback present', status: 'PASS' },
    { id: 'V11', sev: 'CRITICAL', desc: 'Allow rules check count(hard_deny)==0', status: 'PASS' },
    { id: 'V12', sev: 'HIGH', desc: 'needs_approval checks hard_deny first', status: 'PASS' },
  ]

  return (
    <div className="policy-tab">
      <div className="policy-split">
        {/* Rego source */}
        <div className="policy-left">
          <div className="panel-title">▶ agentshield.rego — LIVE POLICY SOURCE</div>
          <pre className="rego-code">{regoPolicy}</pre>
        </div>

        {/* Validator results */}
        <div className="policy-right">
          <div className="panel-title">▶ STATIC POLICY VALIDATOR — 14/14 PASS</div>
          <p className="validator-desc">
            <code>opa_validator.py</code> runs in CI before any policy deployment.
            Checks 12 security properties across CRITICAL / HIGH / MEDIUM severities.
          </p>
          <div className="validator-list">
            {validatorChecks.map(c => (
              <div key={c.id} className="vc-row">
                <span className="vc-icon">✓</span>
                <span className={`vc-sev sev-${c.sev.toLowerCase()}`}>{c.sev}</span>
                <span className="vc-id">{c.id}</span>
                <span className="vc-desc">{c.desc}</span>
                <span className="vc-status">PASS</span>
              </div>
            ))}
          </div>
          <div className="validator-footer">
            14 / 14 checks passed — policy cleared for deployment ✓
          </div>
        </div>
      </div>
    </div>
  )
}
