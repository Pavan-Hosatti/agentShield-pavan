import { useState } from 'react'
import {
  type Baseline,
  CONFIGS,
  SURFACE_MAP,
  getProtectionScore,
  getOpenSurfaces,
  getClosedSurfaces,
} from '../engine/v3Engine'
import './BaselinesTab.css'

const BASELINE_META: Record<Baseline, { name: string; color: string; desc: string }> = {
  A: {
    name: 'Config A — Minimal',
    color: 'red',
    desc: 'Perimeter check only. No re-verification. No hash binding. Deliberately weak — shows what breaks without layered defense. Config A represents a naive implementation.',
  },
  B: {
    name: 'Config B — Gateway-Only',
    color: 'yellow',
    desc: "Gateway enforces everything. Executor trusts the gateway's prior decision. Action substitution in transit and revocation race still succeed. Missing executor-side re-checks.",
  },
  C: {
    name: 'Config C — Full Zero-Trust',
    color: 'green',
    desc: 'Every plane independently enforces. Executor re-verifies independently of the gateway. No service trusts another\'s prior decision. This is the only configuration that holds all 11 security invariants.',
  },
}

const FLAG_GROUPS = [
  {
    label: 'CONTROL PLANE (Gateway)',
    keys: ['schema_validation', 'identity_from_credentials', 'resource_ownership_check', 'opa_policy_evaluation', 'rate_limiting'] as const,
    labels: {
      schema_validation:         'Schema validation (Pydantic strict)',
      identity_from_credentials: 'Identity from JWT, never from body',
      resource_ownership_check:  'Resource ownership check',
      opa_policy_evaluation:     'OPA policy evaluation (default-deny)',
      rate_limiting:             'Per-agent rate limiting',
    },
  },
  {
    label: 'EXECUTION PLANE (Executor)',
    keys: ['capability_sig_verify', 'digest_recompute', 'revocation_recheck', 'replay_prevention', 'approval_recheck', 'opa_recheck_executor', 'atomic_state_claim'] as const,
    labels: {
      capability_sig_verify:  'Capability signature verify (Ed25519)',
      digest_recompute:       '⬡ Digest recompute at executor  ←T2',
      revocation_recheck:     '⬡ Revocation re-check at executor ←T7',
      replay_prevention:      '⬡ Replay prevention (Redis SET NX)',
      approval_recheck:       '⬡ Approval re-verify + atomic consume',
      opa_recheck_executor:   '⬡ OPA re-query at executor ←T19',
      atomic_state_claim:     '⬡ Atomic jti claim (PG UNIQUE)',
    },
  },
  {
    label: 'EVALUATION PLANE (Audit)',
    keys: ['audit_hash_chain', 'receipt_signing', 'independent_verifier', 'drift_detection'] as const,
    labels: {
      audit_hash_chain:    'Hash-chained audit records',
      receipt_signing:     'Signed execution receipts (Ed25519)',
      independent_verifier:'Independent chain verifier',
      drift_detection:     'Config/policy drift detection',
    },
  },
  {
    label: 'DELEGATION CONTROLS',
    keys: ['delegation_scope_bound', 'policy_version_enforce'] as const,
    labels: {
      delegation_scope_bound:  'Child scope ⊆ parent scope (T16)',
      policy_version_enforce:  'Minimum policy version enforced (T19)',
    },
  },
]

export default function BaselinesTab() {
  const [selected, setSelected] = useState<Baseline>('C')
  const flags = CONFIGS[selected]
  const score = getProtectionScore(selected)
  const openSurfaces = getOpenSurfaces(selected)
  const closedSurfaces = getClosedSurfaces(selected)
  const meta = BASELINE_META[selected]

  return (
    <div className="bl-tab">
      {/* Selector row */}
      <div className="bl-header">
        <div className="bl-title">▶ SECURITY BASELINE COMPARISON — A / B / C</div>
        <div className="bl-selector">
          {(['A', 'B', 'C'] as Baseline[]).map(b => {
            const s = getProtectionScore(b)
            const barColor = s === 1 ? 'var(--green-bright)' : s > 0.5 ? 'var(--yellow-bright)' : 'var(--red-bright)'
            return (
              <button
                key={b}
                className={`bl-btn bl-btn-${BASELINE_META[b].color} ${selected === b ? 'bl-btn-active' : ''}`}
                onClick={() => setSelected(b)}
              >
                <span className="bl-btn-name">CONFIG {b}</span>
                <span className="bl-btn-score">{Math.round(s * 100)}% protected</span>
                <div className="bl-btn-bar">
                  <div className="bl-btn-fill" style={{ width: `${s * 100}%`, background: barColor }} />
                </div>
              </button>
            )
          })}
        </div>
      </div>

      <div className="bl-body">
        {/* Left: enforcement flags */}
        <div className="bl-left">
          <div
            className="bl-meta-box"
            style={{
              borderColor: meta.color === 'green'
                ? 'var(--green-mid)'
                : meta.color === 'yellow'
                ? 'var(--yellow-mid)'
                : 'var(--red-mid)',
            }}
          >
            <div className="bl-meta-name">{meta.name}</div>
            <div className="bl-meta-desc">{meta.desc}</div>
            <div className="bl-score-row">
              <span className="bl-score-label">PROTECTION SCORE</span>
              <span className={`bl-score-val ${score === 1 ? 'sv-full' : score > 0.5 ? 'sv-mid' : 'sv-low'}`}>
                {Math.round(score * 100)}%  ({closedSurfaces.length}/{SURFACE_MAP.length} surfaces closed)
              </span>
            </div>
          </div>

          {FLAG_GROUPS.map(group => (
            <div key={group.label} className="bl-group">
              <div className="bl-group-label">{group.label}</div>
              {group.keys.map(key => {
                const active = flags[key]
                return (
                  <div key={key} className={`bl-flag ${active ? 'flag-on' : 'flag-off'}`}>
                    <span className="flag-icon">{active ? '✓' : '✗'}</span>
                    <span className="flag-name">{group.labels[key]}</span>
                    <span className={`flag-badge ${active ? 'fb-on' : 'fb-off'}`}>
                      {active ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </div>
                )
              })}
            </div>
          ))}
        </div>

        {/* Right: open/closed surfaces + comparison */}
        <div className="bl-right">
          {openSurfaces.length > 0 && (
            <div className="bl-surfaces">
              <div className="bl-surf-title surf-open">▶ OPEN ATTACK SURFACES ({openSurfaces.length})</div>
              <div className="bl-surf-list">
                {openSurfaces.map(s => (
                  <div key={s.flag} className="surf-item surf-item-open">
                    <span className="surf-threat">{s.threat}</span>
                    <span className="surf-plane">[{s.plane}]</span>
                    <span className="surf-desc">{s.description}</span>
                    <span className="surf-status">UNPROTECTED</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="bl-surfaces">
            <div className="bl-surf-title surf-closed">▶ CLOSED SURFACES ({closedSurfaces.length})</div>
            <div className="bl-surf-list">
              {closedSurfaces.map(s => (
                <div key={s.flag} className="surf-item surf-item-closed">
                  <span className="surf-threat">{s.threat}</span>
                  <span className="surf-plane">[{s.plane}]</span>
                  <span className="surf-desc">{s.description}</span>
                  <span className="surf-status surf-closed-badge">PROTECTED</span>
                </div>
              ))}
            </div>
          </div>

          {/* Score comparison bars */}
          <div className="bl-compare">
            <div className="bl-compare-title">▶ SIDE-BY-SIDE COMPARISON</div>
            {(['A', 'B', 'C'] as Baseline[]).map(b => {
              const s = getProtectionScore(b)
              const open = getOpenSurfaces(b).length
              const barColor = s === 1 ? 'var(--green-bright)' : s > 0.5 ? 'var(--yellow-bright)' : 'var(--red-bright)'
              return (
                <div key={b} className="compare-row">
                  <span className="compare-label">Config {b}</span>
                  <div className="compare-bar-wrap">
                    <div className="compare-bar" style={{ width: `${s * 100}%`, background: barColor }} />
                  </div>
                  <span className="compare-pct">{Math.round(s * 100)}%</span>
                  <span className="compare-open" style={{ color: open > 0 ? 'var(--red-bright)' : 'var(--green-bright)' }}>
                    {open > 0 ? `${open} open` : '0 open ✓'}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
