"""Handmade SSM state layer for security alert triage.

A recurrent state object that mimics what an SSM hidden state does:
fixed-size, decaying, recurrent updates. Not a prompt builder — a state
machine whose compact output feeds downstream (any LLM).

Core idea: real SSMs (Mamba, S4) maintain a fixed-size hidden state that
gets updated multiplicatively at each step. This module does the same thing
with interpretable, hand-engineered features instead of learned matrices.

State update rule per entity:
    h_t = decay * h_{t-1} + (1 - decay) * x_t

where x_t is the feature vector extracted from the current event.

API:
    encode_event(alert_text) -> EventCodons
    update_state(prev_state, event_codons) -> SentinelState
    summarize_state(state, current_event) -> str
    reset_state() -> SentinelState
    export_receipt(state) -> dict
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .features import (
    extract_ips, extract_users, extract_processes, extract_cves,
    extract_cvss, extract_time_signals, extract_authorization_signals,
    extract_threat_signals,
)
from .codons import (
    ENTITY_CODONS, ACTION_CODONS, QUALITY_CODONS, ESCALATION_PATTERNS,
    classify_ip, classify_user, detect_actions, detect_quality,
    _HOST_RE, _USER_STOPLIST,
)


# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

# Decay factor per step (0.85 = state retains 85% of previous value)
DECAY = 0.85

# Number of entity slots in the state vector (LRU eviction beyond this)
MAX_ENTITIES = 32

# Action dimension indices (fixed-size vector per entity)
ACTION_DIMS = {
    "A_SCN": 0, "A_AFL": 1, "A_ASC": 2, "A_EXC": 3, "A_CRF": 4,
    "A_MOD": 5, "A_DEL": 6, "A_TFR": 7, "A_ESC": 8, "A_LAT": 9,
    "A_EXF": 10, "A_INS": 11, "A_MNT": 12, "A_LGN": 13, "A_CLN": 14,
}
N_ACTION_DIMS = len(ACTION_DIMS)

# Kill-chain stages (ordered)
STAGES = ["idle", "recon", "weaponize", "exploit", "install", "c2", "exfil", "cleanup"]
STAGE_RANK = {s: i for i, s in enumerate(STAGES)}

# Stage advancement rules: if these action sets are present, entity advances
STAGE_TRANSITIONS = [
    ({"A_SCN"},  "recon"),
    ({"A_AFL"},  "weaponize"),
    ({"A_ASC"},  "exploit"),
    ({"A_EXC"},  "exploit"),
    ({"A_ESC"},  "exploit"),
    ({"A_LAT"},  "install"),
    ({"A_INS"},  "install"),
    ({"A_CRF"},  "install"),
    ({"A_TFR"},  "c2"),
    ({"A_EXF"},  "exfil"),
    ({"A_CLN"},  "cleanup"),
    ({"A_DEL"},  "cleanup"),
]

# Benign suppressor weights
SUPPRESSOR_WEIGHTS = {
    "pentest_ip": 0.9,
    "admin_user": 0.3,
    "service_account": 0.2,
    "maintenance_action": 0.4,
    "change_ticket": 0.5,
    "approved_engagement": 0.7,
    "dr_exercise": 0.6,
    "low_cvss": 0.1,
}


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EventCodons:
    """Output of encode_event: all entities and their codons for one alert."""
    entities: List[dict]
    raw_actions: Set[str]
    raw_quality: str
    auth_signals: List[str]
    threat_signals: List[str]
    cves: List[str]
    cvss: Optional[float]
    processes: List[str]
    time_signals: List[str]


@dataclass
class EntityState:
    """Fixed-size recurrent state for one entity."""
    entity_key: str
    entity_type: str
    action_vector: list
    quality_ema: float
    stage: str
    stage_rank: int
    risk_score: float
    confidence: float
    suppressor_score: float
    n_observations: int
    first_seen_step: int
    last_seen_step: int
    escalation_flags: Set[str]
    co_entities: Set[str]
    contradiction: bool


@dataclass
class SentinelState:
    """Full recurrent state — the SSM hidden vector."""
    entities: Dict[str, EntityState]
    step: int
    global_risk: float
    global_stage: str
    active_chains: int
    event_log_size: int


# ═══════════════════════════════════════════════════════════════════════════
# Core API
# ═══════════════════════════════════════════════════════════════════════════

def encode_event(alert_text: str) -> EventCodons:
    """Extract all codons from an alert. Pure function, no state."""
    ips = extract_ips(alert_text)
    users = extract_users(alert_text)
    auth_sigs = extract_authorization_signals(alert_text)
    threat_sigs = extract_threat_signals(alert_text)
    actions = detect_actions(alert_text)
    quality = detect_quality(auth_sigs, threat_sigs)
    cves = extract_cves(alert_text)
    cvss = extract_cvss(alert_text)
    processes = extract_processes(alert_text)
    time_sigs = extract_time_signals(alert_text)

    action_codes = sorted(ACTION_CODONS.get(a, a) for a in actions)
    quality_code = QUALITY_CODONS.get(quality, "Q_UNK")

    entities = []
    for ip in ips:
        if "/" in ip:
            continue
        entities.append({
            "entity_key": ip,
            "entity_codon": ENTITY_CODONS[classify_ip(ip)],
            "actions": action_codes,
            "quality": quality_code,
        })
    for user in users:
        user_clean = user.rstrip(".,;:!?")
        if user_clean.lower() in _USER_STOPLIST or not user_clean:
            continue
        entities.append({
            "entity_key": f"user:{user_clean}",
            "entity_codon": ENTITY_CODONS[classify_user(user_clean)],
            "actions": action_codes,
            "quality": quality_code,
        })
    for host in set(_HOST_RE.findall(alert_text)):
        entities.append({
            "entity_key": f"host:{host}",
            "entity_codon": ENTITY_CODONS["host"],
            "actions": action_codes,
            "quality": quality_code,
        })

    return EventCodons(
        entities=entities,
        raw_actions=set(action_codes),
        raw_quality=quality_code,
        auth_signals=auth_sigs,
        threat_signals=threat_sigs,
        cves=cves,
        cvss=cvss,
        processes=processes,
        time_signals=time_sigs,
    )


def reset_state() -> SentinelState:
    """Return a blank initial state."""
    return SentinelState(
        entities={},
        step=0,
        global_risk=0.0,
        global_stage="idle",
        active_chains=0,
        event_log_size=0,
    )


def _quality_to_score(q: str) -> float:
    return {"Q_AUT": 0.0, "Q_BEN": 0.1, "Q_UNK": 0.4, "Q_SUS": 0.7, "Q_MAL": 1.0}.get(q, 0.4)


def _compute_suppressor(entity_codon: str, actions: Set[str],
                        auth_signals: List[str], cvss: Optional[float]) -> float:
    score = 0.0
    if entity_codon == "E_PEN":
        score += SUPPRESSOR_WEIGHTS["pentest_ip"]
    if entity_codon == "E_ADM":
        score += SUPPRESSOR_WEIGHTS["admin_user"]
    if entity_codon == "E_SVC":
        score += SUPPRESSOR_WEIGHTS["service_account"]
    if "A_MNT" in actions:
        score += SUPPRESSOR_WEIGHTS["maintenance_action"]

    auth_lower = [a.lower() for a in auth_signals]
    if any("change ticket" in a or "change request" in a for a in auth_lower):
        score += SUPPRESSOR_WEIGHTS["change_ticket"]
    if any(w in a for a in auth_lower for w in ("engagement", "pentest", "red team", "sow")):
        score += SUPPRESSOR_WEIGHTS["approved_engagement"]
    if any(w in a for a in auth_lower for w in ("dr runbook", "dr exercise", "dr drill")):
        score += SUPPRESSOR_WEIGHTS["dr_exercise"]
    if cvss is not None and cvss < 4.0:
        score += SUPPRESSOR_WEIGHTS["low_cvss"]

    return min(score, 1.0)


def _advance_stage(current_stage: str, action_set: Set[str]) -> str:
    """Advance kill-chain stage based on observed actions. Never retreats."""
    best = STAGE_RANK.get(current_stage, 0)
    for required_actions, target_stage in STAGE_TRANSITIONS:
        if required_actions.issubset(action_set):
            rank = STAGE_RANK.get(target_stage, 0)
            if rank > best:
                best = rank
    return STAGES[best]


def _compute_risk(entity: EntityState) -> float:
    risk = entity.quality_ema
    stage_bonus = entity.stage_rank / (len(STAGES) - 1) * 0.3
    risk += stage_bonus
    if entity.escalation_flags:
        risk += 0.1 * min(len(entity.escalation_flags), 3)
    risk *= (1.0 - 0.7 * entity.suppressor_score)
    conf = min(entity.n_observations / 5.0, 1.0)
    risk = 0.5 * (1 - conf) + risk * conf
    return max(0.0, min(1.0, risk))


def update_state(prev_state: SentinelState, event: EventCodons,
                 timestamp: Optional[float] = None) -> SentinelState:
    """Recurrent state update. The core SSM step.

    h_t = decay * h_{t-1} + (1 - decay) * x_t
    """
    step = prev_state.step + 1
    entities = dict(prev_state.entities)

    for key, ent in entities.items():
        for i in range(N_ACTION_DIMS):
            ent.action_vector[i] *= DECAY

    event_keys = set(e["entity_key"] for e in event.entities)

    suppressor = _compute_suppressor(
        event.entities[0]["entity_codon"] if event.entities else "E_USR",
        event.raw_actions, event.auth_signals, event.cvss,
    )

    for codon in event.entities:
        key = codon["entity_key"]

        if key in entities:
            ent = entities[key]
        else:
            ent = EntityState(
                entity_key=key,
                entity_type=codon["entity_codon"],
                action_vector=[0.0] * N_ACTION_DIMS,
                quality_ema=0.5,
                stage="idle",
                stage_rank=0,
                risk_score=0.5,
                confidence=0.0,
                suppressor_score=0.0,
                n_observations=0,
                first_seen_step=step,
                last_seen_step=step,
                escalation_flags=set(),
                co_entities=set(),
                contradiction=False,
            )
            entities[key] = ent

        for action_code in codon["actions"]:
            dim = ACTION_DIMS.get(action_code)
            if dim is not None:
                ent.action_vector[dim] = DECAY * ent.action_vector[dim] + (1 - DECAY) * 1.0

        q_score = _quality_to_score(codon["quality"])
        ent.quality_ema = DECAY * ent.quality_ema + (1 - DECAY) * q_score

        entity_suppressor = _compute_suppressor(
            codon["entity_codon"], event.raw_actions, event.auth_signals, event.cvss,
        )
        ent.suppressor_score = DECAY * ent.suppressor_score + (1 - DECAY) * entity_suppressor

        all_actions = set()
        for i, dim_name in enumerate(ACTION_DIMS):
            if ent.action_vector[i] > 0.05:
                all_actions.add(dim_name)
        ent.stage = _advance_stage(ent.stage, all_actions)
        ent.stage_rank = STAGE_RANK.get(ent.stage, 0)

        for pattern, flag in ESCALATION_PATTERNS:
            if pattern.issubset(all_actions) and flag not in ent.escalation_flags:
                ent.escalation_flags.add(flag)

        ent.co_entities.update(event_keys - {key})
        ent.n_observations += 1
        ent.last_seen_step = step
        ent.contradiction = (ent.suppressor_score > 0.4 and ent.quality_ema > 0.5)
        ent.risk_score = _compute_risk(ent)

    if len(entities) > MAX_ENTITIES:
        sorted_ents = sorted(entities.items(), key=lambda kv: kv[1].last_seen_step)
        while len(entities) > MAX_ENTITIES:
            evict_key = sorted_ents.pop(0)[0]
            del entities[evict_key]

    global_risk = max((e.risk_score for e in entities.values()), default=0.0)
    global_stage = "idle"
    best_rank = 0
    active_chains = 0
    for e in entities.values():
        if e.stage_rank > best_rank:
            best_rank = e.stage_rank
            global_stage = e.stage
        if e.stage_rank > STAGE_RANK["recon"]:
            active_chains += 1

    return SentinelState(
        entities=entities,
        step=step,
        global_risk=global_risk,
        global_stage=global_stage,
        active_chains=active_chains,
        event_log_size=prev_state.event_log_size + 1,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Summarize: state -> compact text for LLM consumption
# ═══════════════════════════════════════════════════════════════════════════

_ENTITY_LABELS = {
    "E_INT": "INTERNAL", "E_EXT": "EXTERNAL", "E_PEN": "PENTEST",
    "E_ADM": "ADMIN", "E_SVC": "SERVICE", "E_USR": "USER",
    "E_HST": "HOST", "E_PRC": "PROCESS",
}

_ACTION_NAMES = {
    "A_SCN": "scan", "A_AFL": "auth_fail", "A_ASC": "auth_success",
    "A_EXC": "exec", "A_CRF": "create", "A_MOD": "modify",
    "A_DEL": "delete", "A_TFR": "transfer", "A_ESC": "priv_escalation",
    "A_LAT": "lateral_move", "A_EXF": "exfiltration", "A_INS": "install",
    "A_MNT": "maintenance", "A_LGN": "login", "A_CLN": "cleanup",
}

_RISK_LABELS = [
    (0.8, "CRITICAL"), (0.6, "HIGH"), (0.4, "ELEVATED"),
    (0.2, "LOW"), (0.0, "MINIMAL"),
]


def _risk_label(score: float) -> str:
    for threshold, label in _RISK_LABELS:
        if score >= threshold:
            return label
    return "MINIMAL"


def summarize_state(state: SentinelState, current_event: EventCodons) -> str:
    """Produce a compact state summary for LLM consumption.

    Uses suppressor-first ordering:
    1. AUTHORIZATION STATUS block (suppressed entities listed first)
    2. THREAT ENTITIES block (high-risk unsuppressed entities)
    3. Compact entity state details
    """
    if not state.entities:
        return ""

    current_keys = set(e["entity_key"] for e in current_event.entities)

    linked_keys = set()
    for key in current_keys:
        ent = state.entities.get(key)
        if ent:
            linked_keys.update(ent.co_entities)
    linked_keys -= current_keys

    direct = [(k, state.entities[k]) for k in sorted(current_keys)
              if k in state.entities and state.entities[k].n_observations > 0]
    linked = [(k, state.entities[k]) for k in sorted(linked_keys)
              if k in state.entities and state.entities[k].n_observations > 0]

    if not direct and not linked:
        return ""

    lines = []

    suppressed = [(k, e) for k, e in direct if e.suppressor_score > 0.3]
    if suppressed:
        lines.append("AUTHORIZATION STATUS:")
        for key, ent in suppressed:
            etype = _ENTITY_LABELS.get(ent.entity_type, "?")
            lines.append(f"  {key} ({etype}): AUTHORIZED/SUPPRESSED — "
                         f"approved activity, {ent.n_observations} prior observations")
        lines.append("Actions from SUPPRESSED entities are authorized test/maintenance activity.")
        lines.append("")

    all_check = set(current_keys) | linked_keys
    threats = []
    for key in sorted(all_check):
        ent = state.entities.get(key)
        if ent and ent.risk_score >= 0.5 and ent.suppressor_score < 0.3:
            threats.append((key, ent))
    if threats:
        lines.append("THREAT ENTITIES:")
        for key, ent in threats:
            etype = _ENTITY_LABELS.get(ent.entity_type, "?")
            rlabel = _risk_label(ent.risk_score)
            lines.append(f"  {key} ({etype}): {rlabel} risk, stage={ent.stage}")
        lines.append("")

    lines.append(f"SESSION STATE (step {state.step}, {state.active_chains} active threat chains):")

    for key, ent in direct:
        etype = _ENTITY_LABELS.get(ent.entity_type, "?")
        rlabel = _risk_label(ent.risk_score)

        active = []
        for dim_code, dim_idx in ACTION_DIMS.items():
            if ent.action_vector[dim_idx] > 0.05:
                active.append(_ACTION_NAMES.get(dim_code, dim_code))

        action_str = ", ".join(active) if active else "none"
        line = f"  {key} ({etype}, risk={rlabel}): stage={ent.stage}, actions=[{action_str}]"

        if ent.suppressor_score > 0.3:
            line += " [SUPPRESSED]"
        if ent.contradiction:
            line += " [CONTRADICTION]"

        lines.append(line)

        for lk, lent in linked:
            if lk in ent.co_entities:
                lt = _ENTITY_LABELS.get(lent.entity_type, "?")
                lr = _risk_label(lent.risk_score)
                lines.append(f"    -> {lk} ({lt}, risk={lr}, stage={lent.stage})")

    esc_warnings = []
    for key in current_keys | linked_keys:
        ent = state.entities.get(key)
        if ent and ent.escalation_flags:
            readable = [f.replace("_", " ") for f in sorted(ent.escalation_flags)]
            esc_warnings.append(f"{key}: {', '.join(readable)}")

    if esc_warnings:
        lines.append("ESCALATION DETECTED: " + "; ".join(esc_warnings))

    risk_alerts = []
    for key, ent in direct:
        if ent.risk_score >= 0.6 and ent.suppressor_score < 0.3:
            etype = _ENTITY_LABELS.get(ent.entity_type, "?")
            rlabel = _risk_label(ent.risk_score)
            risk_alerts.append(f"{key} is {etype} at {rlabel} risk (stage={ent.stage})")
    if risk_alerts:
        lines.append("RISK: " + ". ".join(risk_alerts) + ".")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Receipt export
# ═══════════════════════════════════════════════════════════════════════════

def export_receipt(state: SentinelState) -> dict:
    """Export current state as a JSON-serializable receipt."""
    entities = {}
    for key, ent in state.entities.items():
        entities[key] = {
            "entity_type": ent.entity_type,
            "stage": ent.stage,
            "stage_rank": ent.stage_rank,
            "risk_score": round(ent.risk_score, 4),
            "confidence": round(ent.confidence, 4),
            "suppressor_score": round(ent.suppressor_score, 4),
            "quality_ema": round(ent.quality_ema, 4),
            "n_observations": ent.n_observations,
            "first_seen_step": ent.first_seen_step,
            "last_seen_step": ent.last_seen_step,
            "escalation_flags": sorted(ent.escalation_flags),
            "contradiction": ent.contradiction,
            "action_vector": [round(v, 4) for v in ent.action_vector],
            "co_entities": sorted(ent.co_entities),
        }
    return {
        "step": state.step,
        "global_risk": round(state.global_risk, 4),
        "global_stage": state.global_stage,
        "active_chains": state.active_chains,
        "event_log_size": state.event_log_size,
        "entities": entities,
    }
