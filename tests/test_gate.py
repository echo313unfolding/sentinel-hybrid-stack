"""Tests for post-LLM gate rules — no LLM required.

Uses synthetic LLM verdicts to verify gate logic in isolation.
"""

import pytest
from sentinel_hybrid_stack.ssm import (
    encode_event, update_state, reset_state, STAGE_RANK,
)
from sentinel_hybrid_stack.gate import (
    apply_gate, GateResult,
    _has_high_risk_keywords, _has_change_ticket,
    HIGH_RISK_KEYWORDS,
)


# ── Helpers ──

def _build_state_with_events(alerts):
    """Process a sequence of alerts and return final state + last event codons."""
    state = reset_state()
    ev = None
    for alert in alerts:
        ev = encode_event(alert)
        state = update_state(state, ev)
    return state, ev


def _make_verdict(severity="low", is_benign=True, actions=None):
    """Create a synthetic LLM verdict dict."""
    return {
        "severity": severity,
        "is_benign": is_benign,
        "actions": actions or ["none"],
    }


# ── Keyword detection ──

class TestHighRiskKeywords:
    def test_detects_domain_admin(self):
        kws = _has_high_risk_keywords("Added to Domain Admins group on dc-01")
        assert "domain admin" in kws

    def test_detects_exfiltration(self):
        kws = _has_high_risk_keywords("Data exfiltration via DNS tunnel detected")
        assert "exfiltrat" in kws

    def test_detects_lsass(self):
        kws = _has_high_risk_keywords("LSASS memory dump detected on workstation")
        assert "lsass" in kws

    def test_detects_mimikatz(self):
        kws = _has_high_risk_keywords("Mimikatz was executed by unknown user")
        assert "mimikatz" in kws

    def test_no_keywords_in_benign(self):
        kws = _has_high_risk_keywords("SSL certificate renewed successfully")
        assert len(kws) == 0


class TestChangeTicket:
    def test_detects_change_ticket(self):
        assert _has_change_ticket("Approved change ticket CHG-2026-01")

    def test_detects_patch_ticket(self):
        assert _has_change_ticket("Applied patches per PATCH-W22")

    def test_detects_engagement_report(self):
        assert _has_change_ticket("Finding documented in engagement report")

    def test_detects_approved_scope(self):
        assert _has_change_ticket("Action within approved scope")

    def test_no_ticket_in_plain_alert(self):
        assert not _has_change_ticket("Suspicious PowerShell execution detected")

    def test_cert_ticket(self):
        assert _has_change_ticket("Certificate renewal per CERT-2026-05")


# ── G4: Clean suppressor passthrough ──

class TestG4CleanSuppressor:
    def test_suppressed_benign_passes_through(self):
        """G4: suppressed entity + no keywords + model benign -> no gate fire."""
        # Need 3+ observations to build suppressor above 0.3
        state, ev = _build_state_with_events([
            "Nmap scan from 10.0.99.10. Approved pentest. SOW signed.",
            "Credential spray from 10.0.99.10. Within approved scope.",
            "Web app scan from 10.0.99.10. Approved pentest contractor.",
        ])
        # New alert: benign from suppressed IP, no dangerous keywords
        ev_new = encode_event("Network connectivity test from 10.0.99.10. All clear.")
        state = update_state(state, ev_new)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev_new,
                            "Network connectivity test from 10.0.99.10. All clear.")

        assert not result.gate_fired
        assert result.final_verdict["is_benign"] is True

    def test_suppressed_with_ticket_passes_despite_keywords(self):
        """G4: suppressed + keywords + ticket -> no gate fire."""
        state, _ = _build_state_with_events([
            "Nmap scan from 10.0.99.10. Approved pentest. SOW signed.",
            "Credential spray from 10.0.99.10. Within approved scope.",
            "Web app scan from 10.0.99.10. Approved pentest contractor.",
        ])
        alert = ("Red team from 10.0.99.10 tested data exfiltration. "
                 "Engagement report submitted. Within approved scope.")
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev, alert)

        assert not result.gate_fired


# ── G1: Suppressed + keywords + no ticket ──

class TestG1SuppressedKeywords:
    def test_g1_fires_on_suppressed_with_keywords_no_ticket(self):
        """G1: suppressed entity + dangerous keywords + no ticket -> override."""
        # Need 3+ observations to build suppressor above 0.3
        state, _ = _build_state_with_events([
            "Nmap scan from 10.0.99.10. Approved pentest. SOW signed.",
            "Credential spray from 10.0.99.10. Within approved scope.",
            "Web app scan from 10.0.99.10. Approved pentest contractor.",
        ])
        # Alert with high-risk keywords but NO ticket/engagement phrasing
        alert = ("IP 10.0.99.10 added account to Domain Admins group on dc-01. "
                 "Action was not pre-authorized.")
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev, alert)

        assert result.gate_fired
        assert "G1" in result.gate_rules
        assert result.final_verdict["is_benign"] is False


# ── G2: Compromised + keywords ──

class TestG2Compromised:
    def test_g2_fires_on_compromised_entity_with_keywords(self):
        """G2: compromised entity + keywords in current alert -> override."""
        state, _ = _build_state_with_events([
            "Port scan from 203.0.113.77 targeting internal hosts.",
            "PowerShell reverse shell from 203.0.113.77 executed payload.",
        ])
        # Verify entity is at exploit stage
        ent = state.entities.get("203.0.113.77")
        assert ent is not None
        assert ent.stage_rank >= STAGE_RANK["exploit"]

        # Deceptive alert with exfil keyword
        alert = ("Automated data exfiltration test by 203.0.113.77. "
                 "Standard compliance check.")
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev, alert)

        assert result.gate_fired
        assert "G2" in result.gate_rules
        assert result.final_verdict["is_benign"] is False
        assert result.final_verdict["severity"] == "high"

    def test_g2_does_not_fire_without_keywords(self):
        """G2: compromised entity + NO keywords -> no gate fire."""
        state, _ = _build_state_with_events([
            "Port scan from 203.0.113.77 targeting internal hosts.",
            "PowerShell reverse shell from 203.0.113.77 executed payload.",
        ])
        # Benign-looking alert from compromised IP, no danger keywords
        alert = "DNS query from 203.0.113.77 resolved successfully."
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev, alert)

        assert not result.gate_fired


# ── G6: Safety net ──

class TestG6SafetyNet:
    def test_g6_fires_on_keywords_no_ticket(self):
        """G6: keywords + model benign + no ticket -> override."""
        state = reset_state()
        alert = ("Automated scheduled task deployment for monitoring. "
                 "New persistence layer for alerting service. "
                 "Standard DevOps practice.")
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev, alert)

        assert result.gate_fired
        assert "G6" in result.gate_rules
        assert result.final_verdict["is_benign"] is False

    def test_g6_does_not_fire_with_ticket(self):
        """G6: keywords + ticket -> no gate fire.

        The ticket must suppress the gate even though danger keywords are present.
        We use 'domain admin' keyword (triggers G6) + a change ticket.
        The entity must NOT be at exploit stage (or G2 would fire instead).
        """
        state = reset_state()
        # Benign admin entity — only maintenance actions, stays below exploit stage
        ev_setup = encode_event("User ops_admin ran OS patching. Change ticket PATCH-01.")
        state = update_state(state, ev_setup)

        # Alert has 'domain admin' keyword but also has a change ticket
        alert = ("GPO password policy update by domain admin ops_admin. "
                 "Change ticket SEC-POL-2026-05.")
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="low", is_benign=True)
        result = apply_gate(verdict, state, ev, alert)

        assert not result.gate_fired

    def test_g6_does_not_fire_when_model_already_correct(self):
        """G6: model already says is_benign=False -> no gate fire needed."""
        state = reset_state()
        alert = "LSASS memory dump detected. No ticket."
        ev = encode_event(alert)
        state = update_state(state, ev)

        verdict = _make_verdict(severity="high", is_benign=False,
                                actions=["investigate"])
        result = apply_gate(verdict, state, ev, alert)

        assert not result.gate_fired


# ── Edge cases ──

class TestGateEdgeCases:
    def test_parse_failure_returns_empty(self):
        state = reset_state()
        ev = encode_event("Any alert text")
        state = update_state(state, ev)

        result = apply_gate(None, state, ev, "Any alert text")
        assert not result.gate_fired
        assert result.gate_reason == "parse_failed"

    def test_no_entities_in_event(self):
        """Alert with no extractable entities should not crash."""
        state = reset_state()
        ev = encode_event("General system notification.")
        if ev.entities:
            state = update_state(state, ev)
            verdict = _make_verdict()
            result = apply_gate(verdict, state, ev, "General system notification.")
            # Should not crash regardless of gate outcome
            assert isinstance(result, GateResult)

    def test_all_keywords_detected(self):
        """Verify all HIGH_RISK_KEYWORDS are actually matchable."""
        for kw in HIGH_RISK_KEYWORDS:
            found = _has_high_risk_keywords(f"Alert mentions {kw} in text")
            assert kw in found, f"Keyword '{kw}' not detected"
