"""
AgentShield V2 — Security Invariant Pre-Flight Checker

Owner: Pavan

Run this BEFORE the demo to verify all security invariants are detectable.
This runs the unit-level checks (no live services needed).

Exit 0 = all invariants verifiable at unit level
Exit 1 = one or more invariants have issues

Usage:
    python -m app.security.invariant_checker
    python -m app.security.invariant_checker --verbose
"""
from __future__ import annotations

import sys
import os
import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class InvariantCheckResult:
    invariant_id: str
    description: str
    status: str       # PASS | FAIL | SKIP
    detail: str = ""


@dataclass
class PreFlightReport:
    checks: list[InvariantCheckResult] = field(default_factory=list)

    @property
    def passed(self) -> list[InvariantCheckResult]:
        return [c for c in self.checks if c.status == "PASS"]

    @property
    def failed(self) -> list[InvariantCheckResult]:
        return [c for c in self.checks if c.status == "FAIL"]

    @property
    def all_clear(self) -> bool:
        return len(self.failed) == 0

    def print_report(self, verbose: bool = False) -> None:
        print("=" * 60)
        print("AgentShield V2 — Security Invariant Pre-Flight Check")
        print("=" * 60)
        for c in self.checks:
            icon = "✅" if c.status == "PASS" else "❌" if c.status == "FAIL" else "⏭️ "
            print(f"  {icon} {c.invariant_id}: {c.description}")
            if verbose and c.detail:
                print(f"       {c.detail}")
        print("-" * 60)
        print(f"  Passed: {len(self.passed)}/{len(self.checks)}")
        if self.failed:
            print(f"  FAILED: {[c.invariant_id for c in self.failed]}")
        print("=" * 60)


def run_preflight(verbose: bool = False) -> PreFlightReport:
    report = PreFlightReport()

    # Add backend to path
    backend_path = os.path.join(os.path.dirname(__file__), '..', '..')
    sys.path.insert(0, backend_path)

    def check(inv_id: str, description: str, fn: Callable) -> None:
        try:
            fn()
            report.checks.append(InvariantCheckResult(inv_id, description, "PASS"))
        except AssertionError as e:
            report.checks.append(InvariantCheckResult(inv_id, description, "FAIL", str(e)))
        except Exception as e:
            report.checks.append(InvariantCheckResult(inv_id, description, "FAIL",
                                                       f"{type(e).__name__}: {e}"))

    # I2 — Digest mismatch detection
    def check_i2():
        from app.security.schemas import ActionEnvelope
        from app.security.canonicalization import calculate_action_digest, verify_digest_matches

        orig = ActionEnvelope(
            schema_version=1, tenant_id="tenant-demo", principal_id="agent-support-01",
            tool="issue_refund", resource="orders/ORDER-123",
            arguments={"order_id": "ORDER-123", "amount_minor": 50000},
            environment="demo", policy_version=3, intent_id="intent-demo-001",
        )
        tampered = ActionEnvelope(
            schema_version=1, tenant_id="tenant-demo", principal_id="agent-support-01",
            tool="issue_refund", resource="orders/ORDER-123",
            arguments={"order_id": "ORDER-123", "amount_minor": 500000},
            environment="demo", policy_version=3, intent_id="intent-demo-001",
        )
        orig_digest = calculate_action_digest(orig)
        assert orig_digest != calculate_action_digest(tampered), \
            "FAIL: Tampered amount produces same digest!"
        assert not verify_digest_matches(tampered, orig_digest), \
            "FAIL: verify_digest_matches accepted tampered action!"

    check("I2", "Digest mismatch correctly detected", check_i2)

    # Test vector matches authoritative value
    def check_vector():
        from app.security.schemas import ActionEnvelope
        from app.security.canonicalization import calculate_action_digest
        action = ActionEnvelope(
            schema_version=1, tenant_id="tenant-demo", principal_id="agent-support-01",
            tool="issue_refund", resource="orders/ORDER-123",
            arguments={"order_id": "ORDER-123", "amount_minor": 50000},
            environment="demo", policy_version=3, intent_id="intent-demo-001",
        )
        digest = calculate_action_digest(action)
        expected = "7b10052fc753b4b419c8040d0920768a429d897faced4c34c1fbab56eab5ed28"
        assert digest == expected, \
            f"FAIL: Test vector mismatch!\n  Got:      {digest}\n  Expected: {expected}"

    check("VECTOR", "Authoritative test vector matches", check_vector)

    # I3 — Hard-deny not overridable
    def check_i3():
        # Import policy simulator
        sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                        '..', '..', '..', 'tests', 'unit'))
        from test_policy import simulate_policy_decision

        result = simulate_policy_decision(
            action={"tool": "issue_refund", "tenant_id": "tenant-demo",
                    "environment": "demo", "policy_version": 3,
                    "action_digest": "x",
                    "arguments": {"amount_minor": 2_000_000}},  # hard-deny
            agent={"registered": True, "revoked": False,
                   "tenant_id": "tenant-demo", "permitted_tools": ["issue_refund"]},
            resource={"owner_tenant_id": "tenant-demo"},
            approval={"valid": True, "action_digest": "x",
                      "tenant_id": "tenant-demo", "consumed": False, "decision": "approved"},
        )
        assert result["result"] == "deny", \
            f"FAIL: Hard-deny overridden by approval! Got {result['result']}"

    check("I3", "Hard-deny not overridable by approval", check_i3)

    # I5a — Approval digest binding
    def check_i5a():
        from app.security.approval_binding import verify_approval
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        approval = {
            "approval_id": "test-ap-001",
            "tenant_id": "tenant-demo",
            "intent_id": "intent-001",
            "action_digest": "DIGEST_FOR_50000",
            "decision": "approved",
            "consumed": False,
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        }
        result = verify_approval(approval, "DIGEST_FOR_500000", "tenant-demo")
        assert not result.valid, "FAIL: Approval accepted for wrong digest!"
        assert result.reason == "APPROVAL_DIGEST_MISMATCH"

    check("I5a", "Approval bound to exact action digest", check_i5a)

    # I5b — Single-use consumption
    def check_i5b():
        from app.security.approval_binding import verify_approval
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        consumed_approval = {
            "approval_id": "test-ap-002",
            "tenant_id": "tenant-demo",
            "intent_id": "intent-001",
            "action_digest": "DIGEST",
            "decision": "approved",
            "consumed": True,  # Already consumed
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        }
        result = verify_approval(consumed_approval, "DIGEST", "tenant-demo")
        assert not result.valid, "FAIL: Consumed approval accepted!"
        assert result.reason == "APPROVAL_ALREADY_CONSUMED"

    check("I5b", "Consumed approval correctly rejected", check_i5b)

    # I10 — Audit tamper detection
    def check_i10():
        import copy
        from app.security.audit_chain import (
            build_audit_record, verify_audit_chain, GENESIS_PREV_HASH
        )
        r1 = build_audit_record(seq=1, event_type="A_AUTHORIZED",
                                 tenant_id="t", prev_hash=GENESIS_PREV_HASH)
        r2 = build_audit_record(seq=2, event_type="CAPABILITY_ISSUED",
                                 tenant_id="t", prev_hash=r1["record_hash"])
        r3 = build_audit_record(seq=3, event_type="EXECUTION_SUCCEEDED",
                                 tenant_id="t", prev_hash=r2["record_hash"])

        # Tamper
        tampered = [copy.deepcopy(r1), copy.deepcopy(r2), copy.deepcopy(r3)]
        tampered[1]["event_type"] = "TAMPERED"

        report = verify_audit_chain(tampered)
        assert not report.valid, "FAIL: Tampered chain not detected!"
        assert report.first_broken_seq == 2, \
            f"FAIL: Wrong first broken seq: {report.first_broken_seq}"

    check("I10", "Audit tampering detected by verifier", check_i10)

    # I11 — Benign action within schema
    def check_i11():
        from app.security.schemas import ActionEnvelope
        from app.security.canonicalization import calculate_action_digest
        action = ActionEnvelope(
            schema_version=1, tenant_id="tenant-demo", principal_id="agent-support-01",
            tool="issue_refund", resource="orders/ORDER-123",
            arguments={"order_id": "ORDER-123", "amount_minor": 29999},
            environment="demo", policy_version=3, intent_id="intent-demo-b1-001",
        )
        digest = calculate_action_digest(action)
        assert len(digest) == 64, "FAIL: Digest not 64 chars"
        assert action.arguments["amount_minor"] == 29999

    check("I11", "Valid benign action schema accepted", check_i11)

    # OPA policy validation
    def check_opa_policy():
        from app.security.opa_validator import validate_opa_policy
        policy_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..', 'policy', 'agentshield.rego'
        )
        result = validate_opa_policy(policy_path)
        failed_critical = [v for v in result.violations
                           if v.severity in ("CRITICAL", "HIGH")]
        assert not failed_critical, \
            f"FAIL: Policy has {len(failed_critical)} CRITICAL/HIGH violations: " \
            f"{[v.check_id for v in failed_critical]}"

    check("OPA", "OPA policy passes all security checks", check_opa_policy)

    # Key management
    def check_keys():
        from app.security.key_management import generate_demo_registry
        registry, priv_b64, pub_b64 = generate_demo_registry("key-v1")
        key = registry.get_signing_key()
        assert key.can_sign()
        assert key.kid == "key-v1"
        # Try sign/verify round-trip
        msg = b"agentshield-test-message"
        sig = key.private_key.sign(msg)
        pub = registry.get_verifying_key("key-v1")
        pub.verify(sig, msg)  # Should not raise

    check("KEYS", "Key registry sign/verify round-trip", check_keys)

    # Network topology
    def check_network():
        import yaml
        compose_path = os.path.join(
            os.path.dirname(__file__), '..', '..', '..', 'docker-compose.yml'
        )
        assert os.path.exists(compose_path), f"docker-compose.yml not found at {compose_path}"
        with open(compose_path) as f:
            compose = yaml.safe_load(f)
        services = compose.get("services", {})
        mock_nets = services.get("mock_tool", {}).get("networks", [])
        gw_nets   = services.get("gateway", {}).get("networks", [])
        ex_nets   = services.get("executor", {}).get("networks", [])

        assert "executor_net" in mock_nets, "mock_tool must be on executor_net"
        assert "agent_net" not in mock_nets, "mock_tool must NOT be on agent_net"
        assert "executor_net" not in gw_nets, "gateway must NOT be on executor_net"
        assert "executor_net" in ex_nets, "executor must be on executor_net"
        assert "internal_net" in ex_nets, "executor must be on internal_net"

    check("I1-NET", "Docker network topology isolates mock_tool", check_network)

    return report


if __name__ == "__main__":
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8")
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    report = run_preflight(verbose=verbose)
    report.print_report(verbose=verbose)
    sys.exit(0 if report.all_clear else 1)
