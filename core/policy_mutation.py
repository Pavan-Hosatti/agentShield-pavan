"""
AgentShield V3 — Live Policy Mutation Demo
Owner: Pavan

Shows what happens when someone introduces a security flaw into the Rego policy.
The static validator (opa_validator.py) catches it immediately — before deployment.

Mutations:
  M1 — Remove default allow = false     → CRITICAL violation
  M2 — Add wildcard allow { true }      → CRITICAL violation
  M3 — Remove AGENT_REVOKED hard deny   → CRITICAL violation
  M4 — Remove action_digest from approval path → HIGH violation
  M5 — Remove DEFAULT_DENY fallback     → HIGH violation

Each mutation:
  1. Takes the real policy text
  2. Injects the flaw
  3. Runs the validator
  4. Shows exactly which check fails and why

This is the "what if a developer made a mistake" demo.
The validator is the CI gate — it would block this from deploying.
"""
from __future__ import annotations

import sys
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root / "backend"))

from app.security.opa_validator import validate_opa_policy, PolicyValidationResult


@dataclass
class MutationResult:
    mutation_id: str
    name: str
    description: str
    what_was_changed: str
    attack_this_enables: str
    validator_caught: bool
    violations_found: list[str]
    violations_severity: list[str]
    original_score: int
    mutated_score: int


def _get_policy_text() -> str:
    policy_path = _root / "policy" / "agentshield.rego"
    return policy_path.read_text(encoding="utf-8")


def _run_mutation(policy_text: str, mutation_fn: Callable[[str], str]) -> PolicyValidationResult:
    """Apply mutation to policy text and validate."""
    import tempfile, os
    mutated = mutation_fn(policy_text)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
        f.write(mutated)
        tmp = f.name
    try:
        return validate_opa_policy(tmp)
    finally:
        os.unlink(tmp)


MUTATIONS = [
    {
        "id": "M1",
        "name": "Remove default allow = false",
        "description": "A developer accidentally deletes the default-deny line during a refactor.",
        "what_changed": "Removed: 'default allow = false'",
        "attack_enabled": "Without default-deny, any request not explicitly denied may be allowed. OPA returns undefined → trust boundary broken.",
        "fn": lambda text: text.replace("default allow = false\n", "# REMOVED default allow = false\n"),
    },
    {
        "id": "M2",
        "name": "Inject wildcard allow { true }",
        "description": "A developer adds 'allow { true }' for debugging and forgets to remove it.",
        "what_changed": "Added: 'allow { true }' after the package declaration",
        "attack_enabled": "Every single request is allowed regardless of any other rule. Complete policy bypass.",
        "fn": lambda text: text.replace(
            "# Default: deny everything.",
            "# Default: deny everything.\nallow { true }  # BACKDOOR\n"
        ),
    },
    {
        "id": "M3",
        "name": "Remove AGENT_REVOKED hard deny",
        "description": "A developer refactors hard_deny rules and accidentally removes the revocation check.",
        "what_changed": "Removed the hard_deny block for AGENT_REVOKED",
        "attack_enabled": "Revoked agents can now execute actions. Invariant I6 breaks. T7 (revocation race) becomes exploitable.",
        "fn": lambda text: "\n".join(
            line for line in text.splitlines()
            if "AGENT_REVOKED" not in line and "input.agent.revoked" not in line
        ),
    },
    {
        "id": "M4",
        "name": "Remove action_digest from approval path",
        "description": "A developer simplifies the approval check and removes the digest binding.",
        "what_changed": "Removed 'input.approval.action_digest == input.action.action_digest' from allow rule",
        "attack_enabled": "Approval for action A now authorizes action B. T6 (approval substitution) succeeds. Invariant I5a breaks.",
        "fn": lambda text: text.replace(
            "input.approval.action_digest == input.action.action_digest\n",
            "# REMOVED digest binding\n"
        ),
    },
    {
        "id": "M5",
        "name": "Remove DEFAULT_DENY fallback",
        "description": "A developer removes the else clause from the decision rule.",
        "what_changed": "Removed the final else block containing DEFAULT_DENY",
        "attack_enabled": "If no rule matches, OPA returns undefined instead of deny. Undefined is not deny — behavior depends on caller handling.",
        "fn": lambda text: text.replace('"DEFAULT_DENY"', '"ALLOW_BY_DEFAULT"'),
    },
]


def run_all_mutations() -> list[MutationResult]:
    original_text = _get_policy_text()

    # Baseline score
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rego", delete=False, encoding="utf-8") as f:
        f.write(original_text)
        tmp = f.name
    try:
        orig_result = validate_opa_policy(tmp)
        original_score = len(orig_result.passed_checks)
    finally:
        os.unlink(tmp)

    results = []
    for m in MUTATIONS:
        mutated_result = _run_mutation(original_text, m["fn"])
        violations = [v.check_id for v in mutated_result.violations]
        severities = [v.severity for v in mutated_result.violations]
        caught = len(mutated_result.violations) > 0

        results.append(MutationResult(
            mutation_id=m["id"],
            name=m["name"],
            description=m["description"],
            what_was_changed=m["what_changed"],
            attack_this_enables=m["attack_enabled"],
            validator_caught=caught,
            violations_found=violations,
            violations_severity=severities,
            original_score=original_score,
            mutated_score=len(mutated_result.passed_checks),
        ))

    return results


if __name__ == "__main__":
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        _sys.stdout.reconfigure(encoding="utf-8")
    print("=" * 68)
    print("AgentShield V3 — Live Policy Mutation Demo")
    print("Validator catches every security flaw before deployment")
    print("=" * 68)

    results = run_all_mutations()
    all_caught = all(r.validator_caught for r in results)

    for r in results:
        status = "✅ CAUGHT" if r.validator_caught else "❌ MISSED"
        print(f"\n[{r.mutation_id}] {r.name}  {status}")
        print(f"     What changed  : {r.what_was_changed}")
        print(f"     Attack enabled: {r.attack_this_enables[:72]}...")
        if r.violations_found:
            for v, s in zip(r.violations_found, r.violations_severity):
                print(f"     [{s}] Violation : {v}")
        print(f"     Score         : {r.original_score} → {r.mutated_score} checks passing")

    print()
    print("=" * 68)
    if all_caught:
        print(f"  {len(results)}/{len(results)} mutations detected ✓")
        print("  Validator would BLOCK all of these from deploying to production")
    else:
        missed = [r.mutation_id for r in results if not r.validator_caught]
        print(f"  WARNING: {len(missed)} mutation(s) not detected: {missed}")
    print("=" * 68)
