# Sentinel Hybrid Stack v0.1

An educational, auditable hybrid runtime for security alert triage.

Combines three layers — a handmade state-space model (SSM), a language model, and a conservative post-LLM gate — into an 8-step pipeline that processes sequential security alerts with per-entity memory.

## What This Is

This is a **reference implementation** for studying how deterministic safety layers can augment LLM-based security triage. All alert data is synthetic. No real infrastructure, credentials, or proprietary detection logic is included.

The core insight: a 3B parameter model can be fooled by deceptive benign framing ("standard compliance check", "routine diagnostic") even when dangerous keywords like "exfiltration" or "LSASS" appear in the alert text. A simple keyword-based gate catches these cases with zero false positives on authorized activity (change tickets, engagement reports).

## Architecture

```
Alert text
    |
    v
[1] Receive raw alert
[2] Extract Level 0 features (IPs, users, processes, CVEs)
[3] Encode codons (entity type, action, quality signals)
[4] Update SSM state (per-entity risk, kill-chain stage, suppressor)
[5] Generate suppressor-first summary for LLM context
[6] Query LLM (any OpenAI-compatible endpoint)
[7] Run post-LLM gate (G4 -> G1 -> G2 -> G6)
[8] Emit final verdict
```

### Gate Rules

The gate only fires when the LLM says `is_benign=True` AND the current alert contains high-risk keywords AND no change ticket is present.

| Rule | Condition | Action |
|------|-----------|--------|
| **G4** | Suppressed + no contradiction + (no keywords OR has ticket) | Allow benign through (evaluated first) |
| **G1** | Suppressed + keywords + no ticket | Override to not benign, severity=medium |
| **G2** | Compromised entity + keywords in current alert | Override to not benign, severity=high |
| **G6** | Keywords + no ticket + no other rule fired | Safety-net override, severity=medium |

## Installation

```bash
pip install -e .

# Run tests (no LLM required)
pip install -e ".[dev]"
pytest
```

## Quick Start

```python
from sentinel_hybrid_stack import (
    encode_event, update_state, reset_state,
    summarize_state, apply_gate, export_receipt,
)

# Initialize state
state = reset_state()

# Process alerts sequentially
alerts = [
    "Nmap scan from 10.0.99.10. Approved pentest. SOW signed.",
    "PowerShell reverse shell from 203.0.113.77 on ws-finance-01.",
    "Automated data exfiltration test. Standard compliance check.",
]

for alert in alerts:
    event = encode_event(alert)
    state = update_state(state, event)
    summary = summarize_state(state, event)
    print(f"Step {state.step}: stage={state.global_stage}, risk={state.global_risk:.2f}")
    print(f"Summary:\n{summary}\n")

# Apply gate to a synthetic LLM verdict
llm_verdict = {"severity": "low", "is_benign": True, "actions": ["none"]}
event = encode_event(alerts[-1])
gate_result = apply_gate(llm_verdict, state, event, alerts[-1])
print(f"Gate fired: {gate_result.gate_fired}")
print(f"Gate rules: {gate_result.gate_rules}")
print(f"Final verdict: {gate_result.final_verdict}")

# Export state as JSON receipt
receipt = export_receipt(state)
```

## Eval Results (Frozen v0.1)

All eval data is synthetic. Results from a Qwen 2.5 3B model.

| Eval | Events | SSM-only | Hybrid | Delta | Gates |
|------|--------|----------|--------|-------|-------|
| Audited scenarios | 20 | 84% | 84% | +0.0% | 0 |
| Extended stream | 60 | 92.3% | 92.3% | +0.0% | 0 |
| Adversarial stress | 20 | 65% | 89% | +24.0% | 6 (6 TP, 0 FP) |

The gate adds zero value on non-adversarial alerts (the SSM+LLM combination handles them correctly). Gate value appears only on deceptively-framed alerts containing dangerous keywords — exactly the failure mode it was designed to catch.

## Known Limits

1. **Keyword-only gate.** Novel attack vocabulary not in `HIGH_RISK_KEYWORDS` will not trigger the gate.
2. **Deceptive framing fools small models.** Strong benign language makes 3B models say `is_benign=True` despite dangerous keywords. The gate catches this, but a stronger model might not need it.
3. **Quality codons too noisy for gate triggers.** Early iterations used quality codons (Q_SUS) as gate inputs, causing false positives. Removed.
4. **Synthetic eval data only.** All alerts in this repo are synthetic. Real-world performance is untested.
5. **No cross-session persistence.** State resets between runs.

## Project Structure

```
src/sentinel_hybrid_stack/
    __init__.py         # Public API
    features.py         # Level 0 hand-feature extraction
    codons.py           # Entity/action/quality codon encoding
    ssm.py              # Handmade SSM state engine
    gate.py             # Post-LLM gate rules (G1/G2/G4/G6)
    scorer.py           # Verdict scoring (0-5 per event)
tests/
    test_features.py    # Feature extraction tests
    test_ssm.py         # SSM state update tests
    test_gate.py        # Gate rule tests (synthetic verdicts, no LLM)
examples/
    walkthrough.py      # End-to-end pipeline demo
```

## License

MIT
