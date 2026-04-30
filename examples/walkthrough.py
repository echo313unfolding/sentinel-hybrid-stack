#!/usr/bin/env python3
"""End-to-end walkthrough of the Sentinel Hybrid Stack.

Demonstrates the full pipeline using synthetic alerts and synthetic LLM
verdicts. No actual LLM server required.

Usage:
    python examples/walkthrough.py
"""

from sentinel_hybrid_stack import (
    encode_event, update_state, summarize_state, reset_state,
    apply_gate, export_receipt,
)
from sentinel_hybrid_stack.scorer import score_structured

# Synthetic alert stream — ordered to build entity state
ALERTS = [
    # 1. Pentest contractor (builds suppressor)
    {
        "alert": (
            "Nmap SYN scan from 10.0.99.10 targeting DMZ hosts on ports 1-1024. "
            "Source is approved pentest contractor. Engagement SOW signed."
        ),
        "category": "benign",
        "synthetic_verdict": {"severity": "low", "is_benign": True, "actions": ["none"]},
    },
    # 2. External attacker (builds threat)
    {
        "alert": (
            "Port scan from 203.0.113.77 targeting internal hosts on ports "
            "22, 443, 3389. No approved engagement from this IP."
        ),
        "category": "escalate",
        "synthetic_verdict": {"severity": "high", "is_benign": False, "actions": ["block IP"]},
    },
    # 3. Attacker exploit (advances kill chain)
    {
        "alert": (
            "PowerShell reverse shell executed on ws-finance-01 from 203.0.113.77. "
            "Process: powershell.exe -enc [base64]. User: finance_temp2."
        ),
        "category": "escalate",
        "synthetic_verdict": {"severity": "critical", "is_benign": False, "actions": ["isolate host"]},
    },
    # 4. Deceptive alert — gate should catch this
    {
        "alert": (
            "Automated data exfiltration test completed as part of quarterly "
            "security assessment by sysadmin on ws-finance-01. Standard practice."
        ),
        "category": "escalate",
        # Model is fooled by benign framing:
        "synthetic_verdict": {"severity": "low", "is_benign": True, "actions": ["none"]},
    },
    # 5. Legitimate maintenance with ticket — gate must NOT fire
    {
        "alert": (
            "GPO password policy update by domain admin ops_admin on dc-01. "
            "Minimum password length changed from 12 to 16 characters. "
            "Change ticket SEC-POL-2026-05. Peer-reviewed."
        ),
        "category": "benign",
        "synthetic_verdict": {"severity": "low", "is_benign": True, "actions": ["none"]},
    },
]


def main():
    state = reset_state()

    print("=" * 70)
    print("  Sentinel Hybrid Stack v0.1 — Walkthrough")
    print("=" * 70)

    for i, item in enumerate(ALERTS, 1):
        alert = item["alert"]
        verdict = item["synthetic_verdict"]

        # Steps 2-5: encode, update SSM, summarize
        event = encode_event(alert)
        state = update_state(state, event)
        summary = summarize_state(state, event)

        # Step 7: apply gate
        gate_result = apply_gate(verdict, state, event, alert)

        # Score
        scoring = score_structured(gate_result.final_verdict, item)

        print(f"\n  Event {i}: {item['category'].upper()}")
        print(f"  Alert: {alert[:80]}...")
        print(f"  SSM: step={state.step}, stage={state.global_stage}, "
              f"risk={state.global_risk:.2f}, chains={state.active_chains}")

        if summary:
            # Show first 3 lines of summary
            lines = summary.split("\n")[:3]
            for line in lines:
                print(f"    {line}")
            if len(summary.split("\n")) > 3:
                print(f"    ... ({len(summary.split(chr(10)))} lines total)")

        print(f"  LLM verdict:   severity={verdict['severity']}, "
              f"is_benign={verdict['is_benign']}")
        print(f"  Final verdict: severity={gate_result.final_verdict.get('severity')}, "
              f"is_benign={gate_result.final_verdict.get('is_benign')}")

        if gate_result.gate_fired:
            print(f"  ** GATE FIRED: {', '.join(gate_result.gate_rules)}")
            print(f"     Reason: {gate_result.gate_reason}")

        print(f"  Score: {scoring['score']}/5 ({', '.join(scoring['notes'])})")

    # Export receipt
    receipt = export_receipt(state)
    print(f"\n{'=' * 70}")
    print(f"  Final state: {len(receipt['entities'])} entities tracked, "
          f"global_stage={receipt['global_stage']}")

    # Summarize gate behavior
    print(f"\n  Key takeaway:")
    print(f"    Event 4 contained 'exfiltration' with deceptive benign framing.")
    print(f"    The LLM was fooled (is_benign=True), but the gate caught it (G2).")
    print(f"    Event 5 had 'domain admin' keyword but also a change ticket — gate")
    print(f"    did not fire because the ticket suppresses the correction.")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
