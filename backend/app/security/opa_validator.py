"""
AgentShield V2 — OPA Policy Security Validator

Owner: Pavan

Automated static analysis of the OPA/Rego policy bundle.
Run in CI before deploying any policy update.

Checks 12 security properties:
  V1  default allow = false            CRITICAL
  V2  default deny_reason present      HIGH
  V3  no wildcard allow { true }       CRITICAL
  V4a AGENT_REVOKED hard deny          CRITICAL
  V4b AGENT_NOT_REGISTERED hard deny   CRITICAL
  V4c CROSS_TENANT_ACCESS hard deny    CRITICAL
  V5  action_digest in approval path   HIGH
  V6  monetary hard maximum present    HIGH
  V7  no suspicious commented allows   MEDIUM
  V8  POLICY_VERSION_STALE present     HIGH
  V9  INVALID_ENVIRONMENT present      HIGH
  V10 DEFAULT_DENY fallback present    HIGH
  V11 allow rules check hard_deny      CRITICAL
  V12 needs_approval checks hard_deny  HIGH
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PolicyViolation:
    check_id: str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW
    description: str
    detail: str


@dataclass
class PolicyValidationResult:
    policy_file: str
    violations: list[PolicyViolation] = field(default_factory=list)
    passed_checks: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not any(v.severity in ("CRITICAL", "HIGH") for v in self.violations)

    def summary(self) -> str:
        total = len(self.passed_checks) + len(self.violations)
        lines = [
            f"Policy validation: {self.policy_file}",
            f"  Passed: {len(self.passed_checks)}/{total}",
        ]
        if self.violations:
            lines.append(f"  Violations ({len(self.violations)}):")
            for v in self.violations:
                lines.append(f"    [{v.severity}] {v.check_id}: {v.description}")
        return "\n".join(lines)


def validate_opa_policy(policy_path: str) -> PolicyValidationResult:
    result = PolicyValidationResult(policy_file=policy_path)

    if not Path(policy_path).exists():
        result.violations.append(PolicyViolation(
            "V0", "CRITICAL", "Policy file not found", f"Path: {policy_path}"
        ))
        return result

    text = Path(policy_path).read_text(encoding="utf-8")

    def check(cid: str, pattern: str, must_exist: bool,
              sev: str, desc: str, detail: str = "") -> None:
        found = bool(re.search(pattern, text, re.MULTILINE | re.DOTALL))
        if found == must_exist:
            result.passed_checks.append(cid)
        else:
            result.violations.append(PolicyViolation(cid, sev, desc, detail))

    check("V1",  r"^default\s+allow\s*=\s*false", True, "CRITICAL",
          "default allow must be false", "Add: default allow = false")
    check("V2",  r"default\s+deny_reason\s*=",   True, "HIGH",
          "default deny_reason missing", "Add: default deny_reason = \"DEFAULT_DENY\"")
    check("V3",  r"^allow\s*\{\s*true\s*\}",       False, "CRITICAL",
          "Wildcard allow { true } found", "Remove unconditional allow")
    check("V4a", r"AGENT_REVOKED",                True, "CRITICAL",
          "No AGENT_REVOKED hard deny")
    check("V4b", r"AGENT_NOT_REGISTERED",         True, "CRITICAL",
          "No AGENT_NOT_REGISTERED hard deny")
    check("V4c", r"CROSS_TENANT_ACCESS",          True, "CRITICAL",
          "No CROSS_TENANT_ACCESS hard deny")
    check("V5",  r"action_digest",                True, "HIGH",
          "Approval path missing action_digest check",
          "Approval must bind exact action_digest")
    check("V6",  r"AMOUNT_EXCEEDS_HARD_MAXIMUM",  True, "HIGH",
          "No monetary hard maximum found")
    check("V8",  r"POLICY_VERSION_STALE",         True, "HIGH",
          "No POLICY_VERSION_STALE check")
    check("V9",  r"INVALID_ENVIRONMENT",          True, "HIGH",
          "No environment validation")
    check("V10", r'"DEFAULT_DENY"',               True, "HIGH",
          "No DEFAULT_DENY fallback in decision output")
    check("V11", r"allow\s*\{[\s\S]*?count\(hard_deny\)\s*==\s*0",  True, "CRITICAL",
          "Allow rules don't check count(hard_deny) == 0",
          "Every allow rule must assert count(hard_deny) == 0 first")
    check("V12", r"needs_approval\s*\{[\s\S]*?count\(hard_deny\)\s*==\s*0",
          True, "HIGH",
          "needs_approval doesn't check count(hard_deny) == 0")

    # V7 — suspicious commented allows
    if re.search(r"#\s*allow\s*\{", text):
        result.violations.append(PolicyViolation(
            "V7", "MEDIUM",
            "Commented-out allow blocks found",
            "Review before re-enabling",
        ))
    else:
        result.passed_checks.append("V7")

    return result


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "policy/agentshield.rego"
    res = validate_opa_policy(path)
    print(res.summary())
    sys.exit(0 if res.valid else 1)
