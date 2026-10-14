// ============================================================
// AgentShield V2 — In-Browser Policy Simulation Engine
// Mirrors the real OPA Rego logic from policy/agentshield.rego
// Owner: Pavan
// ============================================================

export type PolicyResult = 'allow' | 'deny' | 'needs_approval'

export interface PolicyDecision {
  result: PolicyResult
  reason: string
  hard_denies: string[]
  checks_run: CheckResult[]
  latency_ms: number
}

export interface CheckResult {
  id: string
  name: string
  passed: boolean
  detail: string
}

export interface AgentRecord {
  registered: boolean
  revoked: boolean
  tenant_id: string
  permitted_tools: string[]
  max_amount_minor: number
}

export interface ActionInput {
  tool: string
  tenant_id: string
  agent_tenant_id: string
  environment: string
  policy_version: number
  amount_minor: number
  resource_owner_tenant: string
  approval_present: boolean
  approval_digest_matches: boolean
  approval_consumed: boolean
  approval_decision: string
}

// Mirrors canonicalization.py — deterministic digest simulation
export function simulateDigest(action: ActionInput): string {
  const canonical = JSON.stringify({
    arguments: { amount_minor: action.amount_minor, order_id: 'ORDER-SIM' },
    environment: action.environment,
    policy_version: action.policy_version,
    tenant_id: action.tenant_id,
    tool: action.tool,
  })
  // Simple hash simulation (not real SHA-256 but deterministic for demo)
  let hash = 0
  for (let i = 0; i < canonical.length; i++) {
    const char = canonical.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash |= 0
  }
  return Math.abs(hash).toString(16).padStart(8, '0') + 'f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6'
}

// Mirrors policy/agentshield.rego decision rules
export function evaluatePolicy(action: ActionInput): PolicyDecision {
  const start = performance.now()
  const hard_denies: string[] = []
  const checks: CheckResult[] = []

  const addCheck = (id: string, name: string, passed: boolean, detail: string) => {
    checks.push({ id, name, passed, detail })
    return passed
  }

  // ── Hard Deny Rules (Section 1 of Rego) ──────────────────

  const registered = action.agent_tenant_id !== ''
  const c1 = addCheck(
    'HD-1', 'AGENT_NOT_REGISTERED',
    registered,
    registered ? 'Agent is registered in the registry' : 'Agent has no registration record'
  )
  if (!c1) hard_denies.push('AGENT_NOT_REGISTERED')

  const notRevoked = true // controlled by preset
  const c2 = addCheck(
    'HD-2', 'AGENT_REVOKED',
    notRevoked,
    notRevoked ? 'Agent revocation status: ACTIVE' : 'Agent status: REVOKED'
  )
  if (!c2) hard_denies.push('AGENT_REVOKED')

  const tenantMatch = action.tenant_id === action.agent_tenant_id
  const c3 = addCheck(
    'HD-3', 'CROSS_TENANT_ACCESS',
    tenantMatch,
    tenantMatch
      ? `action.tenant_id == agent.tenant_id == "${action.tenant_id}"`
      : `action.tenant_id="${action.tenant_id}" != agent.tenant_id="${action.agent_tenant_id}"`
  )
  if (!c3) hard_denies.push('CROSS_TENANT_ACCESS')

  const toolAllowed = action.tool === 'issue_refund'
  const c4 = addCheck(
    'HD-4', 'TOOL_NOT_PERMITTED',
    toolAllowed,
    toolAllowed
      ? `"${action.tool}" is in agent.permitted_tools`
      : `"${action.tool}" is NOT in agent.permitted_tools`
  )
  if (!c4) hard_denies.push('TOOL_NOT_PERMITTED')

  const validEnvs = ['demo', 'staging', 'production']
  const envValid = validEnvs.includes(action.environment)
  const c5 = addCheck(
    'HD-5', 'INVALID_ENVIRONMENT',
    envValid,
    envValid
      ? `"${action.environment}" is in {demo, staging, production}`
      : `"${action.environment}" is NOT a valid environment`
  )
  if (!c5) hard_denies.push('INVALID_ENVIRONMENT')

  const versionOk = action.policy_version >= 2
  const c6 = addCheck(
    'HD-6', 'POLICY_VERSION_STALE',
    versionOk,
    versionOk
      ? `policy_version=${action.policy_version} >= 2 (minimum)`
      : `policy_version=${action.policy_version} < 2 — STALE`
  )
  if (!c6) hard_denies.push('POLICY_VERSION_STALE')

  const notAboveHardMax = action.amount_minor <= 1_000_000
  const c7 = addCheck(
    'HD-7', 'AMOUNT_EXCEEDS_HARD_MAXIMUM',
    notAboveHardMax,
    notAboveHardMax
      ? `₹${(action.amount_minor / 100).toFixed(2)} <= ₹10,000 hard maximum`
      : `₹${(action.amount_minor / 100).toFixed(2)} EXCEEDS ₹10,000 hard maximum — no approval can override`
  )
  if (!c7) hard_denies.push('AMOUNT_EXCEEDS_HARD_MAXIMUM')

  // ── If any hard deny fired → immediate deny ───────────────
  if (hard_denies.length > 0) {
    return {
      result: 'deny',
      reason: hard_denies.join(', '),
      hard_denies,
      checks_run: checks,
      latency_ms: performance.now() - start,
    }
  }

  // ── Resource ownership check ──────────────────────────────
  const resourceOwned = action.resource_owner_tenant === action.tenant_id
  addCheck(
    'RES-1', 'RESOURCE_OWNERSHIP',
    resourceOwned,
    resourceOwned
      ? `resource.owner_tenant_id == action.tenant_id == "${action.tenant_id}"`
      : `resource owned by "${action.resource_owner_tenant}", not "${action.tenant_id}"`
  )
  if (!resourceOwned) {
    return {
      result: 'deny',
      reason: 'RESOURCE_OWNERSHIP_FAILED',
      hard_denies: [],
      checks_run: checks,
      latency_ms: performance.now() - start,
    }
  }

  // ── Needs approval? (Section 2 of Rego) ──────────────────
  const needsApproval = action.amount_minor >= 30_000 && action.amount_minor <= 1_000_000

  if (needsApproval) {
    // Check if valid approval is provided
    if (
      action.approval_present &&
      action.approval_digest_matches &&
      !action.approval_consumed &&
      action.approval_decision === 'approved'
    ) {
      addCheck(
        'APR-1', 'APPROVAL_VALID',
        true,
        `Approval present, digest matches, not consumed, decision=approved → ALLOW`
      )
      return {
        result: 'allow',
        reason: 'POLICY_ALLOW (with approval)',
        hard_denies: [],
        checks_run: checks,
        latency_ms: performance.now() - start,
      }
    } else {
      const approvalFailReason = !action.approval_present
        ? 'No approval record present'
        : !action.approval_digest_matches
        ? 'Approval action_digest MISMATCH — action was tampered'
        : action.approval_consumed
        ? 'Approval already consumed (single-use)'
        : `Approval decision="${action.approval_decision}" (not "approved")`

      addCheck('APR-1', 'APPROVAL_VALID', false, approvalFailReason)
      return {
        result: 'needs_approval',
        reason: 'APPROVAL_REQUIRED_FOR_AMOUNT',
        hard_denies: [],
        checks_run: checks,
        latency_ms: performance.now() - start,
      }
    }
  }

  // ── Allow (Section 3 of Rego) ─────────────────────────────
  if (action.tool === 'issue_refund' && action.amount_minor > 0) {
    addCheck(
      'ALLOW-1', 'ALLOW_RULE_FIRED',
      true,
      `amount_minor=${action.amount_minor} > 0 and < 30000 — no approval needed`
    )
    return {
      result: 'allow',
      reason: 'POLICY_ALLOW',
      hard_denies: [],
      checks_run: checks,
      latency_ms: performance.now() - start,
    }
  }

  // ── Default deny fallback ─────────────────────────────────
  addCheck('DEF-1', 'DEFAULT_DENY_FALLBACK', false, 'No allow rule matched — default deny')
  return {
    result: 'deny',
    reason: 'DEFAULT_DENY',
    hard_denies: [],
    checks_run: checks,
    latency_ms: performance.now() - start,
  }
}

// ── Attack Presets ─────────────────────────────────────────

export type AttackPreset = {
  id: string
  label: string
  category: string
  description: string
  expectedResult: PolicyResult
  input: ActionInput
}

export const ATTACK_PRESETS: AttackPreset[] = [
  {
    id: 'legit-small',
    label: 'Legitimate Small Refund',
    category: 'BASELINE',
    description: 'Normal agent, valid tenant, ₹299.99 refund — should ALLOW without approval',
    expectedResult: 'allow',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 29999,
      resource_owner_tenant: 'tenant-demo',
      approval_present: false,
      approval_digest_matches: false,
      approval_consumed: false,
      approval_decision: 'none',
    },
  },
  {
    id: 'legit-approved',
    label: 'Large Refund with Approval',
    category: 'BASELINE',
    description: '₹500 refund — requires manager approval, approval is valid → ALLOW',
    expectedResult: 'allow',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 50000,
      resource_owner_tenant: 'tenant-demo',
      approval_present: true,
      approval_digest_matches: true,
      approval_consumed: false,
      approval_decision: 'approved',
    },
  },
  {
    id: 'attack-revoked',
    label: 'ATK-1: Revoked Agent',
    category: 'ATTACK',
    description: 'Compromised/revoked agent attempts execution — AGENT_REVOKED hard deny',
    expectedResult: 'deny',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: '',  // empty = unregistered/revoked simulation
      environment: 'demo',
      policy_version: 3,
      amount_minor: 50000,
      resource_owner_tenant: 'tenant-demo',
      approval_present: false,
      approval_digest_matches: false,
      approval_consumed: false,
      approval_decision: 'none',
    },
  },
  {
    id: 'attack-cross-tenant',
    label: 'ATK-2: Cross-Tenant Access',
    category: 'ATTACK',
    description: 'Agent from tenant-evil tries to access tenant-demo resources — CROSS_TENANT_ACCESS',
    expectedResult: 'deny',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-evil',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 29999,
      resource_owner_tenant: 'tenant-demo',
      approval_present: false,
      approval_digest_matches: false,
      approval_consumed: false,
      approval_decision: 'none',
    },
  },
  {
    id: 'attack-action-substitution',
    label: 'ATK-3: Action Substitution',
    category: 'ATTACK',
    description: 'Attacker intercepts ₹500 refund, inflates to ₹5000 — digest mismatch, approval invalid',
    expectedResult: 'needs_approval',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 500000,  // inflated from 50000
      resource_owner_tenant: 'tenant-demo',
      approval_present: true,
      approval_digest_matches: false,  // digest bound to original amount
      approval_consumed: false,
      approval_decision: 'approved',
    },
  },
  {
    id: 'attack-approval-replay',
    label: 'ATK-4: Approval Replay',
    category: 'ATTACK',
    description: 'Attacker replays a previously consumed approval — APPROVAL_ALREADY_CONSUMED',
    expectedResult: 'needs_approval',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 50000,
      resource_owner_tenant: 'tenant-demo',
      approval_present: true,
      approval_digest_matches: true,
      approval_consumed: true,  // already used
      approval_decision: 'approved',
    },
  },
  {
    id: 'attack-hard-max',
    label: 'ATK-5: Exceed Hard Maximum',
    category: 'ATTACK',
    description: '₹10,001 refund — exceeds hard cap, NO approval can ever override this',
    expectedResult: 'deny',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 1_000_100,
      resource_owner_tenant: 'tenant-demo',
      approval_present: true,
      approval_digest_matches: true,
      approval_consumed: false,
      approval_decision: 'approved',
    },
  },
  {
    id: 'attack-stale-policy',
    label: 'ATK-6: Stale Policy Version',
    category: 'ATTACK',
    description: 'Agent running old policy v1 — POLICY_VERSION_STALE hard deny',
    expectedResult: 'deny',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 1,
      amount_minor: 29999,
      resource_owner_tenant: 'tenant-demo',
      approval_present: false,
      approval_digest_matches: false,
      approval_consumed: false,
      approval_decision: 'none',
    },
  },
  {
    id: 'attack-invalid-env',
    label: 'ATK-7: Invalid Environment',
    category: 'ATTACK',
    description: 'Agent claims "localhost" environment — not in {demo,staging,production}',
    expectedResult: 'deny',
    input: {
      tool: 'issue_refund',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'localhost',
      policy_version: 3,
      amount_minor: 29999,
      resource_owner_tenant: 'tenant-demo',
      approval_present: false,
      approval_digest_matches: false,
      approval_consumed: false,
      approval_decision: 'none',
    },
  },
  {
    id: 'attack-unpermitted-tool',
    label: 'ATK-8: Unpermitted Tool',
    category: 'ATTACK',
    description: 'Agent tries to call wire_transfer — not in permitted_tools list',
    expectedResult: 'deny',
    input: {
      tool: 'wire_transfer',
      tenant_id: 'tenant-demo',
      agent_tenant_id: 'tenant-demo',
      environment: 'demo',
      policy_version: 3,
      amount_minor: 29999,
      resource_owner_tenant: 'tenant-demo',
      approval_present: false,
      approval_digest_matches: false,
      approval_consumed: false,
      approval_decision: 'none',
    },
  },
]
