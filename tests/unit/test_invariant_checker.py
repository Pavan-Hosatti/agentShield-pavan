"""
AgentShield V2 — Invariant Checker Tests

Owner: Pavan

Verifies that the pre-flight invariant checker itself works correctly.
All checks must pass against the current codebase.
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))


def test_preflight_all_pass():
    """All security invariants must pass pre-flight checks."""
    from app.security.invariant_checker import run_preflight
    report = run_preflight(verbose=True)

    if not report.all_clear:
        for f in report.failed:
            print(f"FAIL [{f.invariant_id}]: {f.description}")
            print(f"  Detail: {f.detail}")

    assert report.all_clear, (
        f"Pre-flight FAILED: {[c.invariant_id for c in report.failed]}"
    )


def test_preflight_covers_all_required_invariants():
    """Pre-flight must cover I2, I3, I5a, I5b, I10, I11, OPA, KEYS, I1-NET."""
    from app.security.invariant_checker import run_preflight
    report = run_preflight()
    ids = {c.invariant_id for c in report.checks}
    required = {"I2", "I3", "I5a", "I5b", "I10", "I11", "OPA", "KEYS", "I1-NET", "VECTOR"}
    missing = required - ids
    assert not missing, f"Pre-flight missing invariant checks: {missing}"


def test_preflight_report_summary():
    """Report summary must be a non-empty string."""
    from app.security.invariant_checker import run_preflight
    report = run_preflight()
    # Just verify it runs without error and has content
    assert len(report.checks) > 0
    assert len(report.passed) > 0
