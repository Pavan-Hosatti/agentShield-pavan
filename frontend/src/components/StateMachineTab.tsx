import { useState } from 'react'
import {
  runStateMachineScenario,
  FAILURE_MODES,
  TERMINAL_STATES,
  type ExecState,
  type ScenarioType,
  type SimulatedExecution,
} from '../engine/v3Engine'
import './StateMachineTab.css'

const SCENARIOS: { id: ScenarioType; label: string; isAttack: boolean; desc: string }[] = [
  { id: 'happy_path',          label: 'Happy Path',            isAttack: false, desc: 'Valid small refund — full authorized flow' },
  { id: 'needs_approval',      label: 'Needs Approval',        isAttack: false, desc: 'Large refund requiring manager approval' },
  { id: 'opa_deny',            label: 'OPA Deny (Revoked)',    isAttack: false, desc: 'Revoked agent — hard deny at policy evaluation' },
  { id: 'attack_skip_claim',   label: 'ATK: Skip Claim',       isAttack: true,  desc: 'Attacker tries to skip jti claim step → REJECTED' },
  { id: 'attack_direct_execute',label: 'ATK: Direct Execute',  isAttack: true,  desc: 'Jump straight to EXECUTING from PENDING → REJECTED' },
  { id: 'executor_crash',      label: 'Executor Crash (F4)',   isAttack: false, desc: 'Crash mid-execution → UNKNOWN → reconciliation' },
  { id: 'capability_expired',  label: 'Capability Expired',    isAttack: false, desc: 'TTL elapsed → REJECTED at executor' },
]

const ALL_STATES: { state: ExecState; label: string; bad?: boolean }[] = [
  { state: 'PENDING',       label: 'PENDING' },
  { state: 'EVALUATING',    label: 'EVALUATING' },
  { state: 'DENIED',        label: 'DENIED',        bad: true },
  { state: 'NEEDS_APPROVAL',label: 'NEEDS_APPROVAL' },
  { state: 'APPROVED',      label: 'APPROVED' },
  { state: 'AUTHORIZED',    label: 'AUTHORIZED' },
  { state: 'CLAIMING',      label: 'CLAIMING' },
  { state: 'EXECUTING',     label: 'EXECUTING' },
  { state: 'SUCCEEDED',     label: 'SUCCEEDED' },
  { state: 'FAILED_FINAL',  label: 'FAILED_FINAL',  bad: true },
  { state: 'UNKNOWN',       label: 'UNKNOWN',        bad: true },
  { state: 'REJECTED',      label: 'REJECTED',       bad: true },
]

function getFinalClass(state: ExecState) {
  if (state === 'SUCCEEDED') return 'fb-success'
  if (state === 'REJECTED')  return 'fb-rejected'
  if (state === 'UNKNOWN')   return 'fb-unknown'
  if (state === 'DENIED')    return 'fb-denied'
  return 'fb-other'
}

function getStateNodeClass(state: ExecState, isFinal: boolean, wasAttack: boolean) {
  if (isFinal) {
    if (state === 'SUCCEEDED') return 'state-node sn-final sn-success'
    if (state === 'REJECTED')  return 'state-node sn-final sn-rejected'
    if (state === 'UNKNOWN')   return 'state-node sn-final sn-unknown'
    if (state === 'DENIED')    return 'state-node sn-final sn-denied'
  }
  if (wasAttack) return 'state-node sn-attack'
  return 'state-node sn-normal'
}

export default function StateMachineTab() {
  const [selected, setSelected] = useState<ScenarioType>('happy_path')
  const [result, setResult] = useState<SimulatedExecution | null>(() =>
    runStateMachineScenario('happy_path')
  )

  const run = (id: ScenarioType) => {
    setSelected(id)
    setResult(runStateMachineScenario(id))
  }

  return (
    <div className="sm-tab">
      {/* Scenario selector */}
      <div className="sm-header">
        <div className="sm-title">▶ EXECUTION STATE MACHINE</div>
        {SCENARIOS.map(s => (
          <button
            key={s.id}
            className={`scenario-pill ${selected === s.id ? 'sp-active' : ''} ${s.isAttack ? 'sp-attack' : ''}`}
            onClick={() => run(s.id)}
            title={s.desc}
          >
            {s.isAttack ? '⚡ ' : ''}{s.label}
          </button>
        ))}
      </div>

      <div className="sm-body">
        {/* Left: execution trace */}
        <div className="sm-left">
          {result && (
            <>
              {/* State flow path */}
              <div className="state-path-box">
                <div className="sp-title">▶ STATE PATH</div>
                <div className="state-flow">
                  {/* Build path from events */}
                  {(() => {
                    const states: ExecState[] = ['PENDING']
                    result.events.forEach(e => {
                      if (e.allowed) states.push(e.to)
                      else { states.push(e.to); states.push('REJECTED') }
                    })
                    const unique = states.filter((s, i) => i === 0 || s !== states[i - 1])
                    return unique.map((state, i) => {
                      const isFinal = i === unique.length - 1
                      const isInvalid = result.events.find(e => !e.allowed && e.to === state)
                      return (
                        <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          {i > 0 && (
                            <span className={isInvalid ? 'state-arrow-bad' : 'state-arrow'}>
                              {isInvalid ? '⚡' : '→'}
                            </span>
                          )}
                          <span className={getStateNodeClass(state, isFinal, !!isInvalid)}>
                            {state}
                          </span>
                        </span>
                      )
                    })
                  })()}
                </div>
                <div className={`final-badge ${getFinalClass(result.finalState)}`}>
                  {result.finalState}
                </div>
              </div>

              {/* Event log */}
              <div className="sp-title" style={{ marginTop: 4 }}>▶ TRANSITION LOG ({result.events.length} events)</div>
              <div className="events-list">
                {result.events.map((e, i) => (
                  <div key={i} className={`event-row ${e.allowed ? 'er-allowed' : 'er-blocked'}`}>
                    <span className="er-icon">{e.allowed ? '✓' : '✗'}</span>
                    <span className="er-from">{e.from}</span>
                    <span className="er-arrow">→</span>
                    <span className="er-to">{e.to}</span>
                    <span className="er-trigger">[{e.trigger}]</span>
                    <span className="er-detail">{e.detail}</span>
                  </div>
                ))}
              </div>

              {/* State diagram — highlights active state */}
              <div className="state-diagram">
                <div className="sd-title">▶ ALL STATES</div>
                <div className="sd-grid">
                  {ALL_STATES.map(({ state, bad }) => {
                    const isActive = result.finalState === state
                    const isTerminal = TERMINAL_STATES.includes(state)
                    let cls = 'sd-state'
                    if (isActive) cls += ' sd-active'
                    else if (bad) cls += ' sd-bad'
                    else if (isTerminal) cls += ' sd-terminal'
                    else cls += ' sd-normal'
                    return (
                      <div key={state} className={cls}>
                        {state}
                      </div>
                    )
                  })}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Right: failure modes */}
        <div className="sm-right">
          <div className="sp-title">▶ FAIL-CLOSED FAILURE MODES ({FAILURE_MODES.length} defined)</div>
          <div className="fm-grid">
            {FAILURE_MODES.map(fm => (
              <div key={fm.id} className={`fm-item ${fm.failClosed ? 'fm-closed' : 'fm-unknown-state'}`}>
                <div className="fm-header">
                  <span className="fm-id">{fm.id}</span>
                  <span className="fm-trigger">{fm.trigger}</span>
                  <span className={`fm-badge ${fm.failClosed ? 'fmb-closed' : 'fmb-unknown'}`}>
                    {fm.failClosed ? 'FAIL-CLOSED' : 'UNKNOWN STATE'}
                  </span>
                </div>
                <div className="fm-desc">{fm.description}</div>
                <div className="fm-response">→ {fm.response}</div>
                <div className="fm-recovery">↺ {fm.recovery}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
