import { useState } from 'react'
import { POLICY_MUTATIONS, type PolicyMutation } from '../engine/v3Engine'
import './MutationsTab.css'

export default function MutationsTab() {
  const [running, setRunning] = useState(false)
  const [revealed, setRevealed] = useState<Set<string>>(new Set())
  const [allRun, setAllRun] = useState(false)

  const reveal = async (id: string) => {
    setRunning(true)
    await new Promise(r => setTimeout(r, 350))
    setRevealed(prev => new Set([...prev, id]))
    setRunning(false)
  }

  const runAll = async () => {
    setRunning(true)
    for (const m of POLICY_MUTATIONS) {
      await new Promise(r => setTimeout(r, 200))
      setRevealed(prev => new Set([...prev, m.id]))
    }
    setAllRun(true)
    setRunning(false)
  }

  const reset = () => { setRevealed(new Set()); setAllRun(false) }

  const allCaught = POLICY_MUTATIONS.every(m => m.violations.length > 0)

  return (
    <div className="mu-tab">
      <div className="mu-header">
        <div className="mu-title">▶ LIVE POLICY MUTATION DEMO — Static Validator as CI Gate</div>
        <div className="mu-subtitle">
          5 security flaws injected into the real Rego policy. The validator catches each one before deployment.
        </div>
        <div className="mu-actions">
          <button className="mu-btn mu-btn-run" onClick={runAll} disabled={running || allRun}>
            {running ? '⟳ RUNNING...' : allRun ? '✓ ALL RUN' : '⚡ INJECT ALL MUTATIONS'}
          </button>
          <button className="mu-btn mu-btn-reset" onClick={reset} disabled={running}>✕ RESET</button>
          {allRun && (
            <div className={`mu-score ${allCaught ? 'score-all' : 'score-fail'}`}>
              {POLICY_MUTATIONS.length}/{POLICY_MUTATIONS.length} MUTATIONS DETECTED — DEPLOYMENT BLOCKED ✓
            </div>
          )}
        </div>
      </div>

      <div className="mu-grid">
        {POLICY_MUTATIONS.map(m => (
          <MutationCard
            key={m.id}
            mutation={m}
            revealed={revealed.has(m.id)}
            onReveal={() => reveal(m.id)}
          />
        ))}
      </div>

      <div className="mu-explainer">
        <div className="me-title">▶ HOW THIS WORKS IN PRODUCTION</div>
        <div className="me-steps">
          <div className="me-step">
            <span className="mes-num">1</span>
            <div className="mes-text">Developer edits <code>agentshield.rego</code> — adds feature, removes rule, refactors</div>
          </div>
          <div className="me-arrow">→</div>
          <div className="me-step">
            <span className="mes-num">2</span>
            <div className="mes-text">Git push triggers CI pipeline — <code>python -m app.security.opa_validator</code> runs</div>
          </div>
          <div className="me-arrow">→</div>
          <div className="me-step">
            <span className="mes-num">3</span>
            <div className="mes-text">Validator checks 14 properties in milliseconds — CRITICAL/HIGH violations block deploy</div>
          </div>
          <div className="me-arrow">→</div>
          <div className="me-step">
            <span className="mes-num">4</span>
            <div className="mes-text">PR is rejected with exact violation ID, severity, and fix suggestion — developer fixes</div>
          </div>
        </div>
      </div>
    </div>
  )
}

function MutationCard({ mutation, revealed, onReveal }: {
  mutation: PolicyMutation
  revealed: boolean
  onReveal: () => void
}) {
  const hasCritical = mutation.violations.some(v => v.severity === 'CRITICAL')

  return (
    <div className={`mc-card ${revealed ? (hasCritical ? 'mc-critical' : 'mc-high') : 'mc-hidden'}`}>
      <div className="mc-header">
        <span className="mc-id">{mutation.id}</span>
        <span className="mc-name">{mutation.name}</span>
        {revealed && (
          <span className={`mc-status ${hasCritical ? 'mcs-critical' : 'mcs-high'}`}>
            ✓ CAUGHT — DEPLOY BLOCKED
          </span>
        )}
      </div>

      <div className="mc-desc">{mutation.description}</div>

      {!revealed ? (
        <button className="mc-inject-btn" onClick={onReveal}>
          ⚡ INJECT MUTATION
        </button>
      ) : (
        <>
          <div className="mc-change">
            <span className="mcc-label">CHANGE:</span>
            <span className="mcc-text">{mutation.whatChanged}</span>
          </div>
          <div className="mc-attack">
            <span className="mca-label">ATTACK ENABLED:</span>
            <span className="mca-text">{mutation.attackEnabled}</span>
          </div>
          <div className="mc-violations">
            {mutation.violations.map(v => (
              <div key={v.id} className={`mc-viol ${v.severity === 'CRITICAL' ? 'mv-critical' : 'mv-high'}`}>
                <span className="mv-sev">[{v.severity}]</span>
                <span className="mv-id">{v.id}</span>
                <span className="mv-msg">Validator check failed — deployment blocked</span>
              </div>
            ))}
          </div>
          <div className="mc-score">
            Score: <span className="ms-orig">{mutation.originalScore}</span>
            <span className="ms-arrow"> → </span>
            <span className="ms-new">{mutation.mutatedScore}</span>
            <span className="ms-label"> checks passing</span>
          </div>
        </>
      )}
    </div>
  )
}
