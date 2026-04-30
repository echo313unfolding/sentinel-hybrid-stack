"""Sentinel Hybrid Stack v0.1 — SSM + LLM + post-LLM gate runtime."""

__version__ = "0.1.0"

from .ssm import (
    SentinelState,
    EntityState,
    EventCodons,
    encode_event,
    update_state,
    summarize_state,
    reset_state,
    export_receipt,
    STAGE_RANK,
)
from .gate import (
    GateResult,
    apply_gate,
    HIGH_RISK_KEYWORDS,
    UNSUPPRESSIBLE_ACTIONS,
)
from .scorer import extract_json, score_structured
