// ============================================================
// AgentShield V3 — Baselines, State Machine, Delegation Engine
// Mirrors core/baselines.py, core/state_machine.py, core/delegation.py
// Owner: Pavan
// ============================================================

// ── Baselines ─────────────────────────────────────────────────

export type Baseline = 'A' | 'B' | 'C'

export interface EnforcementFlags {
  // Gateway (Control Plane)
  schema_validation: boolean
  identity_from_credentials: boolean
  resource_ownership_check: boolean
  opa_policy_evaluation: boolean
  rate_limiting: boolean
  // Executor (Execution Plane)
  capability_sig_verify: boolean
  digest_recompute: boolean
  revocation_recheck: boolean
  replay_prevention: boolean
  approval_recheck: boolean
  opa_recheck_executor: boolean
  atomic_state_claim: boolean
  // Audit (Evaluation Plane)
  audit_hash_chain: boolean
  receipt_signing: boolean
  independent_verifier: boolean
  drift_detection: boolean
  // Delegation
  delegation_scope_bound: boolean
  policy_version_enforce: boolean
}

export const CONFIG_A: EnforcementFlags = {
  schema_validation: true,
  identity_from_credentials: false,
  resource_ownership_check: false,
  opa_policy_evaluation: false,
  rate_limiting: false,
  capability_sig_verify: false,
  digest_recompute: false,
  revocation_recheck: false,
  replay_prevention: false,
  approval_recheck: false,
  opa_recheck_executor: false,
  atomic_state_claim: false,
  audit_hash_chain: false,
  receipt_signing: false,
  independent_verifier: false,
  drift_detection: false,
  delegation_scope_bound: false,
  policy_version_enforce: false,
}

export const CONFIG_B: EnforcementFlags = {
  schema_validation: true,
  identity_from_credentials: true,
  resource_ownership_check: true,
  opa_policy_evaluation: true,
  rate_limiting: true,
  capability_sig_verify: true,
  digest_recompute: false,
  revocation_recheck: false,
  replay_prevention: true,
  approval_recheck: false,
  opa_recheck_executor: false,
  atomic_state_claim: true,
  audit_hash_chain: true,
  receipt_signing: false,
  independent_verifier: false,
  drift_detection: false,
  delegation_scope_bound: true,
  policy_version_enforce: true,
}

export const CONFIG_C: EnforcementFlags = {
  schema_validation: true,
  identity_from_credentials: true,
  resource_ownership_check: true,
  opa_policy_evaluation: true,
  rate_limiting: true,
  capability_sig_verify: true,
  digest_recompute: true,
  revocation_recheck: true,
  replay_prevention: true,
  approval_recheck: true,
  opa_recheck_executor: true,
  atomic_state_claim: true,
  audit_hash_chain: true,
  receipt_signing: true,
  independent_verifier: true,
  drift_detection: true,
  delegation_scope_bound: true,
  policy_version_enforce: true,
}

export const CONFIGS: Record<Baseline, EnforcementFlags> = {
  A: CONFIG_A, B: CONFIG_B, C: CONFIG_C,
}

interface SurfaceEntry { flag: keyof EnforcementFlags; threat: string; description: string; plane: string }

export const SURFACE_MAP: SurfaceEntry[] = [
  { flag: 'schema_validation',          threat: 'T10', description: 'Malformed schema / float amounts',    plane: 'Gateway' },
  { flag: 'identity_from_credentials',  threat: 'T4',  description: 'Identity spoofing via request body', plane: 'Gateway' },
  { flag: 'resource_ownership_check',   threat: 'T5',  description: 'Cross-tenant resource access',       plane: 'Gateway' },
  { flag: 'opa_policy_evaluation',      threat: 'T1',  description: 'Policy bypass / default-allow',       plane: 'Gateway' },
  { flag: 'rate_limiting',              threat: 'T12', description: 'Rate abuse / enumeration',            plane: 'Gateway' },
  { flag: 'capability_sig_verify',      threat: 'T8',  description: 'Capability token forgery',            plane: 'Executor' },
  { flag: 'digest_recompute',           threat: 'T2',  description: 'Action substitution attack',          plane: 'Executor' },
  { flag: 'revocation_recheck',         threat: 'T7',  description: 'Revocation race window',              plane: 'Executor' },
  { flag: 'replay_prevention',          threat: 'T3',  description: 'Capability replay (Redis SET NX)',    plane: 'Executor' },
  { flag: 'approval_recheck',           threat: 'T6',  description: 'Approval replay / substitution',     plane: 'Executor' },
  { flag: 'opa_recheck_executor',       threat: 'T19', description: 'Policy drift / downgrade attack',    plane: 'Executor' },
  { flag: 'atomic_state_claim',         threat: 'T12', description: 'Concurrent replay race condition',   plane: 'Executor' },
  { flag: 'audit_hash_chain',           threat: 'T13', description: 'Audit record tampering',             plane: 'Audit' },
  { flag: 'receipt_signing',            threat: 'T13', description: 'Receipt forgery / result spoofing',  plane: 'Audit' },
  { flag: 'independent_verifier',       threat: 'T13', description: 'Audit chain integrity verification', plane: 'Audit' },
  { flag: 'drift_detection',            threat: 'T19', description: 'Config/policy drift detection',      plane: 'Audit' },
  { flag: 'delegation_scope_bound',     threat: 'T16', description: 'Delegation scope escalation',        plane: 'Delegation' },
  { flag: 'policy_version_enforce',     threat: 'T19', description: 'Policy version downgrade',           plane: 'Delegation' },
]

export function getProtectionScore(b: Baseline): number {
  const flags = CONFIGS[b]
  const active = SURFACE_MAP.filter(s => flags[s.flag]).length
  return active / SURFACE_MAP.length
}

export function getOpenSurfaces(b: Baseline): SurfaceEntry[] {
  return SURFACE_MAP.filter(s => !CONFIGS[b][s.flag])
}

export function getClosedSurfaces(b: Baseline): SurfaceEntry[] {
  return SURFACE_MAP.filter(s => CONFIGS[b][s.flag])
}

// ── State Machine ──────────────────────────────────────────────

export type ExecState =
  | 'PENDING' | 'EVALUATING' | 'DENIED' | 'NEEDS_APPROVAL'
  | 'APPROVED' | 'AUTHORIZED' | 'CLAIMING' | 'EXECUTING'
  | 'SUCCEEDED' | 'FAILED_FINAL' | 'UNKNOWN' | 'REJECTED'

export interface StateEvent {
  from: ExecState
  to: ExecState
  trigger: string
  detail: string
  allowed: boolean
}

const VALID_TRANSITIONS: Record<ExecState, ExecState[]> = {
  PENDING:       ['EVALUATING', 'REJECTED'],
  EVALUATING:    ['DENIED', 'NEEDS_APPROVAL', 'AUTHORIZED', 'REJECTED'],
  DENIED:        [],
  NEEDS_APPROVAL:['APPROVED', 'DENIED', 'REJECTED'],
  APPROVED:      ['AUTHORIZED', 'REJECTED'],
  AUTHORIZED:    ['CLAIMING', 'REJECTED'],
  CLAIMING:      ['EXECUTING', 'REJECTED'],
  EXECUTING:     ['SUCCEEDED', 'FAILED_FINAL', 'UNKNOWN'],
  SUCCEEDED:     [],
  FAILED_FINAL:  [],
  UNKNOWN:       ['REJECTED'],
  REJECTED:      [],
}

export const TERMINAL_STATES: ExecState[] = ['DENIED', 'SUCCEEDED', 'FAILED_FINAL', 'REJECTED']

export interface SimulatedExecution {
  id: string
  events: StateEvent[]
  finalState: ExecState
  succeeded: boolean
  wasAttack: boolean
}

export type ScenarioType =
  | 'happy_path'
  | 'needs_approval'
  | 'opa_deny'
  | 'attack_skip_claim'
  | 'attack_direct_execute'
  | 'executor_crash'
  | 'capability_expired'

export function runStateMachineScenario(scenario: ScenarioType): SimulatedExecution {
  const events: StateEvent[] = []
  let current: ExecState = 'PENDING'
  let wasAttack = false

  const transition = (to: ExecState, trigger: string, detail: string): boolean => {
    const allowed = (VALID_TRANSITIONS[current] || []).includes(to)
    events.push({ from: current, to, trigger, detail, allowed })
    if (allowed) {
      current = to
    } else {
      wasAttack = true
      events.push({
        from: current, to: 'REJECTED',
        trigger: 'INVALID_TRANSITION',
        detail: `${current}→${to} not in valid transitions — fail-closed`,
        allowed: true,
      })
      current = 'REJECTED'
    }
    return allowed
  }

  switch (scenario) {
    case 'happy_path':
      transition('EVALUATING',  'GATEWAY_RECEIVED',   'Schema validated, identity from JWT')
      transition('AUTHORIZED',  'OPA_ALLOW',          'Policy: ALLOW — amount=₹299.99 < ₹300 threshold')
      transition('CLAIMING',    'EXECUTOR_RECEIVED',  'Sig verified, digest recomputed & matched')
      transition('EXECUTING',   'JTI_CLAIMED',        'Redis SET NX success — atomic single-use claim')
      transition('SUCCEEDED',   'MOCK_TOOL_SUCCESS',  'Receipt signed, audit appended')
      break

    case 'needs_approval':
      transition('EVALUATING',    'GATEWAY_RECEIVED',  'Schema validated')
      transition('NEEDS_APPROVAL','OPA_NEEDS_APPROVAL','Amount=₹500 ≥ ₹300 threshold')
      transition('APPROVED',      'MANAGER_APPROVED',  'Manager submitted approval — digest binding verified')
      transition('AUTHORIZED',    'CAPABILITY_ISSUED', 'Capability issued with approval_id bound')
      transition('CLAIMING',      'EXECUTOR_RECEIVED', 'Approval re-verified, not consumed')
      transition('EXECUTING',     'JTI_CLAIMED',       'Approval atomically marked consumed')
      transition('SUCCEEDED',     'MOCK_TOOL_SUCCESS', 'Receipt signed')
      break

    case 'opa_deny':
      transition('EVALUATING', 'GATEWAY_RECEIVED', 'Schema validated')
      transition('DENIED',     'OPA_DENY',         'AGENT_REVOKED — hard deny fires, approval cannot override')
      break

    case 'attack_skip_claim':
      wasAttack = true
      transition('EVALUATING', 'GATEWAY_RECEIVED', '')
      transition('AUTHORIZED', 'OPA_ALLOW', '')
      transition('EXECUTING',  'SKIP_CLAIM_ATTACK', 'Attacker skips jti claim step — tries direct execution')
      // Will be auto-rejected by invalid transition
      break

    case 'attack_direct_execute':
      wasAttack = true
      transition('EXECUTING', 'DIRECT_ATTACK', 'Attacker sends request directly to executor, skipping ALL checks')
      break

    case 'executor_crash':
      transition('EVALUATING', 'GATEWAY_RECEIVED', '')
      transition('AUTHORIZED', 'OPA_ALLOW', '')
      transition('CLAIMING',   'EXECUTOR_RECEIVED', '')
      transition('EXECUTING',  'JTI_CLAIMED', '')
      transition('UNKNOWN',    'EXECUTOR_CRASH', 'Process crashed mid-execution — state unknown, blind retry PROHIBITED')
      transition('REJECTED',   'RECONCILIATION',  'Reconciler: cannot confirm result without idempotency key check')
      break

    case 'capability_expired':
      transition('EVALUATING', 'GATEWAY_RECEIVED', '')
      transition('AUTHORIZED', 'OPA_ALLOW', '')
      transition('REJECTED',   'CAPABILITY_EXPIRED', 'exp < now — TTL exceeded, no grace allowed')
      break
  }

  return {
    id: `sim-${scenario}-${Date.now()}`,
    events,
    finalState: current as ExecState,
    succeeded: (current as string) === 'SUCCEEDED',
    wasAttack,
  }
}

// ── Failure modes ──────────────────────────────────────────────

export interface FailureMode {
  id: string
  trigger: string
  description: string
  response: string
  finalState: ExecState
  failClosed: boolean
  recovery: string
}

export const FAILURE_MODES: FailureMode[] = [
  { id: 'F1', trigger: 'OPA_UNAVAILABLE',           description: 'OPA unreachable during evaluation',                  response: '503 POLICY_CHECK_UNAVAILABLE',  finalState: 'REJECTED',  failClosed: true,  recovery: 'OPA restored — agent retries' },
  { id: 'F2', trigger: 'REDIS_UNAVAILABLE_AT_CLAIM', description: 'Redis unreachable at jti claim',                    response: '503 — cannot guarantee single-use', finalState: 'REJECTED', failClosed: true,  recovery: 'Redis restored — retry with same cap if not expired' },
  { id: 'F3', trigger: 'DB_UNAVAILABLE_AT_RECORD',  description: 'PostgreSQL unavailable at CLAIMED record',           response: '503 — no durable record possible',  finalState: 'REJECTED', failClosed: true,  recovery: 'DB restored — retry with fresh capability' },
  { id: 'F4', trigger: 'EXECUTOR_CRASH_MID_EXEC',   description: 'Executor crashes after tool invoked, before receipt', response: 'State: UNKNOWN — blind retry PROHIBITED', finalState: 'UNKNOWN', failClosed: false, recovery: 'Reconciler checks idempotency key before state update' },
  { id: 'F5', trigger: 'CAPABILITY_EXPIRED',        description: 'Capability TTL expired before executor',             response: '401 CAPABILITY_EXPIRED',         finalState: 'REJECTED',  failClosed: true,  recovery: 'Agent re-authorizes for fresh capability' },
  { id: 'F6', trigger: 'REVOCATION_UNAVAILABLE',    description: 'Revocation store unavailable at executor',           response: '503 — cannot confirm agent active', finalState: 'REJECTED', failClosed: true,  recovery: 'Service restored — agent retries' },
  { id: 'F7', trigger: 'DIGEST_MISMATCH',           description: 'Execution digest ≠ capability digest',               response: '403 DIGEST_MISMATCH',            finalState: 'REJECTED',  failClosed: true,  recovery: 'Agent submits unmodified action' },
  { id: 'F8', trigger: 'APPROVAL_CONSUMED_RACE',    description: 'Two concurrent requests race on approval consume',   response: '403 APPROVAL_ALREADY_CONSUMED',  finalState: 'REJECTED',  failClosed: true,  recovery: 'New approval required' },
]

// ── Policy Mutations ──────────────────────────────────────────

export interface PolicyMutation {
  id: string
  name: string
  description: string
  whatChanged: string
  attackEnabled: string
  violations: { id: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' }[]
  originalScore: number
  mutatedScore: number
}

export const POLICY_MUTATIONS: PolicyMutation[] = [
  {
    id: 'M1', name: 'Remove default allow = false',
    description: 'Developer accidentally deletes the default-deny line during a refactor.',
    whatChanged: "Removed: 'default allow = false'",
    attackEnabled: 'Without default-deny, any request not explicitly denied may be allowed. OPA returns undefined → complete policy bypass possible.',
    violations: [{ id: 'V1', severity: 'CRITICAL' }],
    originalScore: 14, mutatedScore: 13,
  },
  {
    id: 'M2', name: 'Inject wildcard allow { true }',
    description: "Developer adds 'allow { true }' for debugging and forgets to remove it.",
    whatChanged: "Added: 'allow { true }' — unconditional allow rule",
    attackEnabled: 'Every single request is allowed regardless of any other rule. Complete policy bypass — 100% attack success rate.',
    violations: [{ id: 'V3', severity: 'CRITICAL' }],
    originalScore: 14, mutatedScore: 13,
  },
  {
    id: 'M3', name: 'Remove AGENT_REVOKED hard deny',
    description: 'Developer refactors hard_deny rules and accidentally removes revocation check.',
    whatChanged: 'Removed the hard_deny block for AGENT_REVOKED',
    attackEnabled: 'Revoked agents can now execute actions. Invariant I6 breaks. T7 (revocation race) becomes permanently exploitable.',
    violations: [{ id: 'V4a', severity: 'CRITICAL' }],
    originalScore: 14, mutatedScore: 13,
  },
  {
    id: 'M4', name: 'Remove action_digest from approval path',
    description: 'Developer simplifies the approval check, removes digest binding.',
    whatChanged: "Removed: 'input.approval.action_digest == input.action.action_digest'",
    attackEnabled: 'Approval for action A now authorizes action B. T6 (approval substitution) succeeds. Invariant I5a breaks — attacker inflates amounts.',
    violations: [{ id: 'V5', severity: 'HIGH' }],
    originalScore: 14, mutatedScore: 13,
  },
  {
    id: 'M5', name: 'Remove DEFAULT_DENY fallback',
    description: 'Developer removes the else clause from the decision rule.',
    whatChanged: 'Removed the final else block — DEFAULT_DENY string gone',
    attackEnabled: 'If no rule matches, OPA returns undefined instead of deny. Caller behavior depends on null handling — trust boundary ambiguous.',
    violations: [{ id: 'V10', severity: 'HIGH' }],
    originalScore: 14, mutatedScore: 13,
  },
]

// ── Threat Map ────────────────────────────────────────────────

export interface ThreatEntry {
  id: string
  name: string
  method: string
  plane: 'Control' | 'Execution' | 'Evaluation' | 'Network'
  defendedBy: string
  invariant: string
  blockedInA: boolean
  blockedInB: boolean
  blockedInC: boolean
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
}

export const THREAT_MAP: ThreatEntry[] = [
  { id:'T1',  name:'Policy bypass',              method:'Request with no matching deny rule',         plane:'Control',   defendedBy:'OPA default-deny + V1 validator check',          invariant:'I3', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'CRITICAL' },
  { id:'T2',  name:'Action substitution',        method:'Change parameters after capability issued',  plane:'Execution', defendedBy:'Executor recomputes digest — DIGEST_MISMATCH',   invariant:'I2', blockedInA:false, blockedInB:false, blockedInC:true,  severity:'CRITICAL' },
  { id:'T3',  name:'Capability replay',          method:'Resubmit captured capability token N times', plane:'Execution', defendedBy:'Redis SET NX + PostgreSQL UNIQUE on jti',        invariant:'I4', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'CRITICAL' },
  { id:'T4',  name:'Identity spoofing',          method:'Forge principal_id/tenant_id in body',       plane:'Control',   defendedBy:'Identity resolved from JWT only, never body',    invariant:'I1', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'HIGH' },
  { id:'T5',  name:'Cross-tenant access',        method:'Agent-A accesses tenant-B resource',        plane:'Control',   defendedBy:'OPA hard_deny CROSS_TENANT_ACCESS',               invariant:'I8', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'CRITICAL' },
  { id:'T6',  name:'Approval substitution',      method:'Reuse approval from A to authorize B',       plane:'Execution', defendedBy:'Approval bound to exact action_digest',          invariant:'I5a',blockedInA:false, blockedInB:false, blockedInC:true,  severity:'HIGH' },
  { id:'T7',  name:'Revocation race',            method:'Revoke agent after cap issued, before exec', plane:'Execution', defendedBy:'Executor re-checks revocation independently',    invariant:'I6', blockedInA:false, blockedInB:false, blockedInC:true,  severity:'HIGH' },
  { id:'T8',  name:'Capability forgery',         method:'Craft unsigned or self-signed capability',   plane:'Execution', defendedBy:'Ed25519 signature verify — unknown kid → reject', invariant:'I1', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'CRITICAL' },
  { id:'T11', name:'Dependency outage abuse',    method:'Kill OPA/Redis, expect fail-open',           plane:'Control',   defendedBy:'Fail-closed: unavailable dep → 503, never allow', invariant:'I7', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'HIGH' },
  { id:'T13', name:'Audit tampering',            method:'Edit audit records in PostgreSQL',           plane:'Evaluation', defendedBy:'Hash-chain — modified record breaks chain',      invariant:'I10',blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'HIGH' },
  { id:'T14', name:'Direct tool access',         method:'POST directly to executor bypassing gateway',plane:'Network',   defendedBy:'Docker network isolation — no route exists',     invariant:'I9', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'HIGH' },
  { id:'T16', name:'Delegation escalation',      method:'Child requests scope > parent scope',        plane:'Control',   defendedBy:'validate_delegation() — 7 rules R1-R7',          invariant:'I7', blockedInA:false, blockedInB:true,  blockedInC:true,  severity:'HIGH' },
  { id:'T19', name:'Policy version downgrade',   method:'Present cap from old permissive policy',     plane:'Execution', defendedBy:'Executor re-queries OPA — POLICY_VERSION_STALE', invariant:'I8', blockedInA:false, blockedInB:false, blockedInC:true,  severity:'HIGH' },
]
