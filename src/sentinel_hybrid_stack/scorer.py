"""Shared scorer for structured triage verdicts.

Scoring (0-5 per event):
  severity: +2 correct, +1 close, +0 wrong
  is_benign: +2 correct, +0 wrong
  actions:   +1 actionable (or correct "none" for benign)
"""

import json
import re
from typing import Optional


def extract_json(text: str) -> Optional[dict]:
    """Extract a JSON object from model output, handling markdown fences."""
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def score_structured(parsed: Optional[dict], scenario: dict) -> dict:
    """Score a parsed JSON triage response against expected category.

    Returns {"score": int, "max": 5, "notes": [str]}.
    """
    if parsed is None:
        return {"score": 0, "max": 5, "notes": ["parse_failed"]}

    score = 0
    notes = []
    cat = scenario["category"]

    sev = str(parsed.get("severity", "")).lower().strip()
    if cat == "escalate":
        if sev in ("critical", "high"):
            score += 2; notes.append("severity_correct")
        elif sev == "medium":
            score += 1; notes.append("severity_close")
        else:
            notes.append("severity_wrong")
    elif cat == "suspicious":
        if sev in ("medium", "high"):
            score += 2; notes.append("severity_correct")
        elif sev == "low":
            score += 1; notes.append("severity_close")
        else:
            notes.append("severity_wrong")
    elif cat == "benign":
        if sev in ("informational", "low"):
            score += 2; notes.append("severity_correct")
        elif sev == "medium":
            score += 1; notes.append("severity_close")
        else:
            notes.append("severity_wrong")

    is_benign = parsed.get("is_benign")
    if isinstance(is_benign, bool):
        expected_benign = (cat == "benign")
        if is_benign == expected_benign:
            score += 2; notes.append("benign_correct")
        else:
            if cat == "escalate" and is_benign:
                notes.append("false_negative")
            elif cat == "benign" and not is_benign:
                notes.append("false_positive")
            else:
                notes.append("benign_wrong")
    else:
        notes.append("benign_missing")

    actions = parsed.get("actions", [])
    if isinstance(actions, list) and len(actions) > 0:
        if cat == "benign":
            if any("none" in str(a).lower() for a in actions):
                score += 1; notes.append("correct_no_action")
            else:
                notes.append("unnecessary_action")
        else:
            action_text = " ".join(str(a).lower() for a in actions)
            if any(w in action_text for w in [
                "block", "isolate", "disable", "lock", "reset",
                "investigate", "quarantine", "terminate", "monitor",
                "verify", "check", "review", "alert", "scan", "contain",
            ]):
                score += 1; notes.append("actionable")
            else:
                notes.append("weak_actions")
    else:
        notes.append("no_actions")

    return {"score": score, "max": 5, "notes": notes}
