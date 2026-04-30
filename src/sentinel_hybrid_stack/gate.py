"""Post-LLM gate — conservative verdict correction layer.

FROZEN v0.1. Gate design principles:
  - Conservative by default — only fires when model says is_benign=True
    AND current alert text contains high-risk keywords AND no change ticket.
  - Gate decisions use only HIGH_RISK_KEYWORDS on the current alert text.
    Quality codons (Q_SUS etc.) are too noisy for gate triggers.
  - Change tickets and engagement scope phrases suppress gate corrections.
    Authorized activity (pentest, maintenance with ticket) must not be overridden.
  - Entity history from the SSM is already in the LLM prompt. The gate does NOT
    re-litigate entity history — it only catches cases where deceptive benign
    framing in the current alert fools the LLM despite dangerous keywords.

Active gate rules:
  G4: Clean suppressor passthrough (evaluated FIRST)
  G1: Suppressed entity + dangerous keywords + no ticket -> override
  G2: Compromised entity + current-alert keywords -> override
  G6: Safety-net keyword catch (no ticket, no other rule fired)
"""

import copy
import re
from dataclasses import dataclass
from typing import List, Optional, Set

from .ssm import SentinelState, EventCodons, STAGE_RANK


# Actions that should NEVER be suppressed
UNSUPPRESSIBLE_ACTIONS = {"A_EXF", "A_ESC", "A_LAT"}

# Curated keywords checked against current alert text only.
# Quality codons (Q_SUS etc.) were tested and removed — too noisy.
HIGH_RISK_KEYWORDS = {
    "domain admin", "domain admins", "exfiltrat", "exfil",
    "persistence", "scheduled task", "registry run key",
    "lsass", "credential dump", "mimikatz",
}


@dataclass
class GateResult:
    """Output of the post-LLM gate."""
    original_verdict: dict
    final_verdict: dict
    gate_fired: bool
    gate_rules: List[str]
    gate_reason: str


def _has_high_risk_action(state: SentinelState, entity_keys: Set[str]) -> Set[str]:
    """Check if any entity in the event has unsuppressible actions in history."""
    found = set()
    for key in entity_keys:
        ent = state.entities.get(key)
        if not ent:
            continue
        for i, dim_name in enumerate(["A_SCN", "A_AFL", "A_ASC", "A_EXC", "A_CRF",
                                       "A_MOD", "A_DEL", "A_TFR", "A_ESC", "A_LAT",
                                       "A_EXF", "A_INS", "A_MNT", "A_LGN", "A_CLN"]):
            if dim_name in UNSUPPRESSIBLE_ACTIONS and ent.action_vector[i] > 0.05:
                found.add(dim_name)
    return found


def _has_high_risk_keywords(alert_text: str) -> Set[str]:
    """Check alert text for high-risk keywords."""
    lower = alert_text.lower()
    return {kw for kw in HIGH_RISK_KEYWORDS if kw in lower}


def _entity_is_suppressed(state: SentinelState, entity_keys: Set[str]) -> bool:
    """Check if any event entity has suppressor_score > 0.3."""
    for key in entity_keys:
        ent = state.entities.get(key)
        if ent and ent.suppressor_score > 0.3:
            return True
    return False


def _entity_is_compromised(state: SentinelState, entity_keys: Set[str]) -> bool:
    """Check if any event entity is at exploit stage or beyond."""
    for key in entity_keys:
        ent = state.entities.get(key)
        if ent and ent.stage_rank >= STAGE_RANK["exploit"]:
            return True
    return False


def _has_change_ticket(alert_text: str) -> bool:
    """Check if alert mentions a change ticket or approved engagement scope.

    Change tickets and engagement scope phrases suppress gate false positives.
    If a dangerous action was pre-authorized (ticket, engagement report, approved
    scope), the gate must not override the LLM's benign verdict.
    """
    return bool(re.search(r'(?:change ticket|change request|CR-|CHG-|PATCH-|CERT-|'
                          r'DB-M-|NET-|SCAN-|SEC-POL-|DR-EX-|DEP-|CLOUD-|HOTFIX-|'
                          r'GRC-|TLS-REM-|'
                          r'approved.{0,20}scope|engagement report|within.{0,15}scope|'
                          r'approved.{0,15}engagement)', alert_text, re.I))


def _no_prior_risk(state: SentinelState, entity_keys: Set[str]) -> bool:
    """True if no event entity has risk_score >= 0.4 (prior to this event)."""
    for key in entity_keys:
        ent = state.entities.get(key)
        if ent and ent.risk_score >= 0.4:
            return False
    return True


def apply_gate(parsed: Optional[dict], state: SentinelState,
               event_codons: EventCodons, alert_text: str) -> GateResult:
    """Apply post-LLM gate rules to correct the verdict.

    Returns GateResult with original and (possibly corrected) final verdict.
    """
    if parsed is None:
        return GateResult(
            original_verdict={},
            final_verdict={},
            gate_fired=False,
            gate_rules=[],
            gate_reason="parse_failed",
        )

    final = copy.deepcopy(parsed)
    rules_fired = []
    reasons = []

    entity_keys = set(e["entity_key"] for e in event_codons.entities)
    is_suppressed = _entity_is_suppressed(state, entity_keys)
    is_compromised = _entity_is_compromised(state, entity_keys)
    high_risk_actions = _has_high_risk_action(state, entity_keys)
    high_risk_kws = _has_high_risk_keywords(alert_text)
    has_ticket = _has_change_ticket(alert_text)
    model_says_benign = parsed.get("is_benign", False) is True
    has_contradiction = any(
        state.entities.get(k) and state.entities[k].contradiction
        for k in entity_keys
    )

    # -- G4 FIRST: Suppressor + no contradiction + (no keywords OR has ticket) --
    # Clean suppression = allow benign through, skip G1/G2
    if (is_suppressed and not has_contradiction and model_says_benign
            and (not high_risk_kws or has_ticket)):
        pass  # early exit path

    # -- G1: SUPPRESSED + dangerous keywords + NO change ticket --
    elif is_suppressed and high_risk_kws and model_says_benign and not has_ticket:
        final["is_benign"] = False
        if final.get("severity", "").lower() in ("informational", "low"):
            final["severity"] = "medium"
        actions = final.get("actions", [])
        if not actions or (len(actions) == 1 and "none" in str(actions[0]).lower()):
            final["actions"] = ["verify scope with engagement lead",
                                "review against change ticket"]
        rules_fired.append("G1")
        reasons.append(f"G1: suppressed entity with high-risk indicators "
                       f"{sorted(high_risk_kws)} and no change ticket")

    # -- G2: COMPROMISED + NOT suppressed + current alert has threat signals --
    elif (is_compromised and not is_suppressed and model_says_benign
          and high_risk_kws):
        final["is_benign"] = False
        if final.get("severity", "").lower() in ("informational", "low", "medium"):
            final["severity"] = "high"
        actions = final.get("actions", [])
        if not actions or (len(actions) == 1 and "none" in str(actions[0]).lower()):
            final["actions"] = ["investigate compromised entity",
                                "check for lateral movement"]
        rules_fired.append("G2")
        reasons.append(f"G2: compromised entity + high-risk keywords in alert "
                       f"({sorted(high_risk_kws)}) -> override")

    # -- G6: High-risk keywords + no ticket + model says benign --
    if high_risk_kws and model_says_benign and not rules_fired and not has_ticket:
        final["is_benign"] = False
        if final.get("severity", "").lower() in ("informational", "low"):
            final["severity"] = "medium"
        rules_fired.append("G6")
        reasons.append(f"G6: high-risk keywords {sorted(high_risk_kws)} without change ticket")

    gate_fired = len(rules_fired) > 0
    gate_reason = "; ".join(reasons) if reasons else "no gate correction"

    return GateResult(
        original_verdict=parsed,
        final_verdict=final,
        gate_fired=gate_fired,
        gate_rules=rules_fired,
        gate_reason=gate_reason,
    )
