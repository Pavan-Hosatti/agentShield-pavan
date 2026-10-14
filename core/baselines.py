"""
AgentShield V3 — Security Baseline Configurations
Owner: Pavan (Architecture & Threat Modeling)

Defines three security configurations:
  Config A — Minimal    : perimeter check only, no re-verification, no hash binding
  Config B — Gateway    : gateway enforces policy, executor trusts gateway result
  Config C — Full       : independent re-verification at every plane (production posture)

Same interfaces for all three — only enforcement depth differs.
This allows Gururaj to run the same attack scenarios across A/B/C
and measure exactly what each baseline protects.

Design principle: Config C is NOT "secure + inconvenient".
  It is the ONLY configuration that maintains all security invariants.
  A and B are deliberately weakened to show what breaks without each layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─────────────────────────────────────────────────────────────
# Baseline identifiers
# ─────────────────────────────────────────────────────────────

class Baseline(str, Enum):
    A = "A"   # Minimal — perimeter only
    B = "B"   # Gateway-only enforcement
    C = "C"   # Full zero-trust (production)


# ─────────────────────────────────────────────────────────────
# Enforcement flags — what each baseline actually checks
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class EnforcementFlags:
    """
    Granular flags controlling which defenses are active.
    All flags True = Config C (full enforcement).
    """
    # Plane 1 — Control Plane (Gateway)
    schema_validation: bool          # Pydantic strict validation of ActionEnvelope
    identity_from_credentials: bool  # principal_id from JWT, never from body
    resource_ownership_check: bool   # tenant owns the resource
    opa_policy_evaluation: bool      # OPA default-deny policy decision
    rate_limiting: bool              # per-agent rate limits

    # Plane 2 — Execution Plane (Executor)
    capability_sig_verify: bool      # Ed25519 signature on capability token
    digest_recompute: bool           # recompute action_digest at execution time
    revocation_recheck: bool         # re-query revocation state at execution
    replay_prevention: bool          # Redis SET NX on jti
    approval_recheck: bool           # re-verify approval at executor
    opa_recheck_executor: bool       # executor independently re-queries OPA
    atomic_state_claim: bool         # PostgreSQL UNIQUE jti insert

    # Plane 3 — Evaluation Plane (Audit & Verification)
    audit_hash_chain: bool           # hash-chained audit records
    receipt_signing: bool            # signed execution receipts
    independent_verifier: bool       # offline chain verifier (detects tamper)
    drift_detection: bool            # detect config/policy drift between planes

    # Delegation controls
    delegation_scope_bound: bool     # child cannot exceed parent scope
    policy_version_enforce: bool     # minimum policy version enforced


# ─────────────────────────────────────────────────────────────
# Baseline definitions
# ─────────────────────────────────────────────────────────────

CONFIG_A = EnforcementFlags(
    # ── Minimal / Demo / "Trusting" ──────────────────────────
    # Represents a naive implementation — basic API with no
    # re-verification. All checks happen once at the perimeter.
    # What breaks: replay, action substitution, revocation race,
    #   delegation escalation, audit tampering undetected.
    schema_validation=True,          # basic JSON parsing
    identity_from_credentials=False, # trusts body-supplied principal_id
    resource_ownership_check=False,  # no ownership verification
    opa_policy_evaluation=False,     # no policy engine — trust the agent
    rate_limiting=False,

    capability_sig_verify=False,     # no signature check
    digest_recompute=False,          # NO digest re-check — action sub succeeds
    revocation_recheck=False,        # NO revocation at execution — revoked agents run
    replay_prevention=False,         # NO replay check — same cap runs 100×
    approval_recheck=False,
    opa_recheck_executor=False,
    atomic_state_claim=False,        # race condition possible

    audit_hash_chain=False,          # plain log — tamperable
    receipt_signing=False,
    independent_verifier=False,
    drift_detection=False,

    delegation_scope_bound=False,    # child can escalate scope
    policy_version_enforce=False,
)

CONFIG_B = EnforcementFlags(
    # ── Gateway-Only / Perimeter-Trust ───────────────────────
    # Gateway enforces everything. Executor trusts the gateway's
    # decision without independent verification.
    # What breaks: capability stolen after gateway auth (replay),
    #   action substitution in transit, revocation race window.
    schema_validation=True,
    identity_from_credentials=True,
    resource_ownership_check=True,
    opa_policy_evaluation=True,
    rate_limiting=True,

    capability_sig_verify=True,      # verifies cap but doesn't recompute digest
    digest_recompute=False,          # trusts gateway-bound digest — action sub still works
    revocation_recheck=False,        # checked at gateway, not at executor
    replay_prevention=True,          # has replay prevention
    approval_recheck=False,          # approval verified at gateway only
    opa_recheck_executor=False,      # policy checked once at gateway
    atomic_state_claim=True,

    audit_hash_chain=True,
    receipt_signing=False,           # no cryptographic receipt
    independent_verifier=False,
    drift_detection=False,

    delegation_scope_bound=True,
    policy_version_enforce=True,
)

CONFIG_C = EnforcementFlags(
    # ── Full Zero-Trust / Production ─────────────────────────
    # Every plane independently enforces. No service trusts another's
    # prior decision. The executor is the final enforcement boundary.
    schema_validation=True,
    identity_from_credentials=True,
    resource_ownership_check=True,
    opa_policy_evaluation=True,
    rate_limiting=True,

    capability_sig_verify=True,
    digest_recompute=True,           # BLOCKS action substitution
    revocation_recheck=True,         # BLOCKS revocation race
    replay_prevention=True,          # BLOCKS capability replay
    approval_recheck=True,           # BLOCKS approval replay
    opa_recheck_executor=True,       # BLOCKS policy drift attacks
    atomic_state_claim=True,

    audit_hash_chain=True,
    receipt_signing=True,
    independent_verifier=True,       # DETECTS audit tampering
    drift_detection=True,

    delegation_scope_bound=True,
    policy_version_enforce=True,
)

# Map for easy lookup
CONFIGS: dict[Baseline, EnforcementFlags] = {
    Baseline.A: CONFIG_A,
    Baseline.B: CONFIG_B,
    Baseline.C: CONFIG_C,
}


# ─────────────────────────────────────────────────────────────
# Attack surface analyser
# ─────────────────────────────────────────────────────────────

@dataclass
class AttackSurfaceReport:
    baseline: Baseline
    open_attack_surfaces: list[str]
    closed_attack_surfaces: list[str]
    protection_score: float          # 0.0 → 1.0

    def summary(self) -> str:
        lines = [
            f"Config {self.baseline.value} — Protection Score: {self.protection_score:.0%}",
            f"  Open surfaces  ({len(self.open_attack_surfaces)}): {', '.join(self.open_attack_surfaces) or 'none'}",
            f"  Closed surfaces({len(self.closed_attack_surfaces)}): {len(self.closed_attack_surfaces)} protections active",
        ]
        return "\n".join(lines)


def analyse_attack_surface(baseline: Baseline) -> AttackSurfaceReport:
    """
    Return a human-readable attack surface analysis for a given baseline.
    Maps each enforcement flag to the attack vectors it blocks.
    """
    flags = CONFIGS[baseline]
    open_surfaces: list[str] = []
    closed_surfaces: list[str] = []

    surface_map = [
        (flags.schema_validation,          "T10-MALFORMED_SCHEMA"),
        (flags.identity_from_credentials,  "T4-IDENTITY_SPOOFING"),
        (flags.resource_ownership_check,   "T5-CROSS_TENANT_RESOURCE"),
        (flags.opa_policy_evaluation,      "T1-POLICY_BYPASS"),
        (flags.rate_limiting,              "T12-RATE_ABUSE"),
        (flags.capability_sig_verify,      "T8-CAP_FORGERY"),
        (flags.digest_recompute,           "T2-ACTION_SUBSTITUTION"),
        (flags.revocation_recheck,         "T7-REVOCATION_RACE"),
        (flags.replay_prevention,          "T3-CAPABILITY_REPLAY"),
        (flags.approval_recheck,           "T6-APPROVAL_REPLAY"),
        (flags.opa_recheck_executor,       "T19-POLICY_DOWNGRADE"),
        (flags.atomic_state_claim,         "T12-CONCURRENT_REPLAY"),
        (flags.audit_hash_chain,           "T13-AUDIT_TAMPER_DETECT"),
        (flags.receipt_signing,            "T13-RECEIPT_FORGERY"),
        (flags.independent_verifier,       "T13-AUDIT_VERIFIER"),
        (flags.drift_detection,            "T19-POLICY_DRIFT"),
        (flags.delegation_scope_bound,     "T16-DELEGATION_ESCALATION"),
        (flags.policy_version_enforce,     "T19-VERSION_DOWNGRADE"),
    ]

    for active, name in surface_map:
        if active:
            closed_surfaces.append(name)
        else:
            open_surfaces.append(name)

    score = len(closed_surfaces) / len(surface_map)
    return AttackSurfaceReport(
        baseline=baseline,
        open_attack_surfaces=open_surfaces,
        closed_attack_surfaces=closed_surfaces,
        protection_score=score,
    )


def compare_baselines() -> str:
    """
    Print a side-by-side comparison of A/B/C protection scores.
    Used in the demo and by Gururaj's test harness.
    """
    lines = [
        "=" * 60,
        "AgentShield V3 — Baseline Protection Comparison",
        "=" * 60,
    ]
    for b in Baseline:
        report = analyse_attack_surface(b)
        lines.append(report.summary())
    lines.append("=" * 60)
    lines.append("Config C = zero-trust production posture (all surfaces closed)")
    return "\n".join(lines)


if __name__ == "__main__":
    print(compare_baselines())
