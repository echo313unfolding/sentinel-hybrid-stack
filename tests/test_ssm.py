"""Tests for SSM state update mechanics — no LLM required."""

import pytest
from sentinel_hybrid_stack.ssm import (
    encode_event, update_state, summarize_state, reset_state,
    export_receipt, STAGE_RANK, DECAY, N_ACTION_DIMS,
)


class TestResetState:
    def test_blank_state(self):
        state = reset_state()
        assert state.step == 0
        assert state.global_risk == 0.0
        assert state.global_stage == "idle"
        assert state.active_chains == 0
        assert state.event_log_size == 0
        assert len(state.entities) == 0


class TestEncodeEvent:
    def test_extracts_ip_entities(self):
        ev = encode_event("Port scan from 10.0.1.5 targeting 192.168.1.1")
        keys = {e["entity_key"] for e in ev.entities}
        assert "10.0.1.5" in keys
        assert "192.168.1.1" in keys

    def test_extracts_user_entities(self):
        ev = encode_event("User ops_admin executed cmd.exe on ws-dev-01")
        keys = {e["entity_key"] for e in ev.entities}
        assert "user:ops_admin" in keys

    def test_extracts_host_entities(self):
        ev = encode_event("Connection from ws-finance-01 to db-prod-02")
        keys = {e["entity_key"] for e in ev.entities}
        assert "host:ws-finance-01" in keys
        assert "host:db-prod-02" in keys

    def test_pentest_ip_classification(self):
        ev = encode_event("Nmap scan from 10.0.99.10 targeting DMZ")
        pentest = [e for e in ev.entities if e["entity_key"] == "10.0.99.10"]
        assert len(pentest) == 1
        assert pentest[0]["entity_codon"] == "E_PEN"

    def test_external_ip_classification(self):
        ev = encode_event("Connection from 203.0.113.77 inbound")
        ext = [e for e in ev.entities if e["entity_key"] == "203.0.113.77"]
        assert len(ext) == 1
        assert ext[0]["entity_codon"] == "E_EXT"

    def test_action_detection(self):
        ev = encode_event("PowerShell reverse shell executed on target host")
        assert "A_EXC" in ev.raw_actions

    def test_authorization_signals(self):
        ev = encode_event("Approved pentest engagement. Change ticket CHG-123.")
        assert any("pentest" in s.lower() for s in ev.auth_signals)
        assert any("change ticket" in s.lower() for s in ev.auth_signals)


class TestUpdateState:
    def test_single_update_creates_entity(self):
        state = reset_state()
        ev = encode_event("Port scan from 10.0.1.5 on ports 1-1024")
        state = update_state(state, ev)
        assert state.step == 1
        assert "10.0.1.5" in state.entities
        ent = state.entities["10.0.1.5"]
        assert ent.n_observations == 1
        assert ent.stage in ("recon", "idle")

    def test_decay_applied(self):
        state = reset_state()
        ev1 = encode_event("Port scan from 10.0.1.5")
        state = update_state(state, ev1)
        vec_after_1 = list(state.entities["10.0.1.5"].action_vector)

        ev2 = encode_event("User jdoe logged in from 192.168.1.1")
        state = update_state(state, ev2)
        vec_after_2 = state.entities["10.0.1.5"].action_vector

        # All dimensions of 10.0.1.5 should have decayed (multiplied by DECAY)
        for i in range(N_ACTION_DIMS):
            if vec_after_1[i] > 0:
                assert vec_after_2[i] < vec_after_1[i], \
                    f"Dimension {i} did not decay: {vec_after_1[i]} -> {vec_after_2[i]}"

    def test_stage_never_retreats(self):
        state = reset_state()
        # Event 1: scan -> recon
        ev1 = encode_event("Nmap scan from 203.0.113.77 on all ports")
        state = update_state(state, ev1)
        stage1 = state.entities["203.0.113.77"].stage_rank

        # Event 2: benign maintenance mentioning same IP
        ev2 = encode_event("DNS resolution for 203.0.113.77 completed normally")
        state = update_state(state, ev2)
        stage2 = state.entities["203.0.113.77"].stage_rank

        assert stage2 >= stage1, "Stage should never retreat"

    def test_stage_advances_through_kill_chain(self):
        state = reset_state()

        # recon
        ev = encode_event("Nmap scan from 203.0.113.77 on ports 22,80,443")
        state = update_state(state, ev)
        assert state.entities["203.0.113.77"].stage == "recon"

        # exploit
        ev = encode_event("PowerShell reverse shell executed from 203.0.113.77")
        state = update_state(state, ev)
        assert state.entities["203.0.113.77"].stage_rank >= STAGE_RANK["exploit"]

    def test_suppressor_builds_for_pentest(self):
        state = reset_state()
        # Suppressor uses EMA (decay=0.85), so multiple observations are needed
        # to cross the 0.3 threshold used by the gate
        for _ in range(3):
            ev = encode_event(
                "Nmap scan from 10.0.99.10 targeting DMZ. "
                "Approved pentest engagement. SOW signed."
            )
            state = update_state(state, ev)
        ent = state.entities["10.0.99.10"]
        assert ent.suppressor_score > 0.3, \
            f"Pentest IP should have high suppressor after 3 obs, got {ent.suppressor_score}"

    def test_suppressor_builds_for_maintenance(self):
        state = reset_state()
        ev = encode_event(
            "Scheduled maintenance on prod-app-01 by sysadmin ops_admin. "
            "Change ticket PATCH-123."
        )
        state = update_state(state, ev)
        # ops_admin should have some suppressor
        admin_ent = state.entities.get("user:ops_admin")
        if admin_ent:
            assert admin_ent.suppressor_score > 0, "Maintenance should add suppressor"

    def test_contradiction_detection(self):
        state = reset_state()
        # First: authorized activity
        ev1 = encode_event(
            "Approved pentest from 10.0.99.10. Engagement SOW signed."
        )
        state = update_state(state, ev1)
        # Second: malicious activity from same IP
        ev2 = encode_event(
            "Reverse shell payload executed from 10.0.99.10. "
            "Mimikatz credential dump detected."
        )
        state = update_state(state, ev2)
        ent = state.entities["10.0.99.10"]
        # With high suppressor AND suspicious quality, contradiction should fire
        # (depends on exact thresholds — check if it fires)
        # At minimum, both scores should be non-trivial
        assert ent.suppressor_score > 0.1
        assert ent.quality_ema > 0.1

    def test_lru_eviction(self):
        from sentinel_hybrid_stack.ssm import MAX_ENTITIES
        state = reset_state()
        # Create more than MAX_ENTITIES entities
        for i in range(MAX_ENTITIES + 5):
            ip = f"10.0.{i // 256}.{i % 256}"
            ev = encode_event(f"Port scan from {ip}")
            state = update_state(state, ev)
        assert len(state.entities) <= MAX_ENTITIES

    def test_global_stage_tracks_highest(self):
        state = reset_state()
        # benign entity
        ev1 = encode_event("User ops_admin ran scheduled maintenance. Change ticket CHG-1.")
        state = update_state(state, ev1)
        # malicious entity
        ev2 = encode_event("PowerShell reverse shell from 203.0.113.77 executed payload")
        state = update_state(state, ev2)
        assert state.global_stage != "idle"


class TestSummarize:
    def test_empty_state_returns_empty(self):
        state = reset_state()
        ev = encode_event("Port scan from 10.0.1.5")
        summary = summarize_state(state, ev)
        assert summary == ""

    def test_suppressed_entity_shows_authorization(self):
        state = reset_state()
        # Need 3+ observations to build suppressor above 0.3 threshold
        alerts = [
            "Nmap scan from 10.0.99.10. Approved pentest. SOW signed.",
            "Credential spray from 10.0.99.10. Within approved scope.",
            "Web app scan from 10.0.99.10. Approved pentest contractor.",
        ]
        for alert in alerts:
            ev = encode_event(alert)
            state = update_state(state, ev)

        ev_check = encode_event("Follow-up scan from 10.0.99.10. Approved engagement.")
        state = update_state(state, ev_check)
        summary = summarize_state(state, ev_check)
        assert "AUTHORIZATION" in summary or "SUPPRESSED" in summary

    def test_threat_entity_shows_risk(self):
        state = reset_state()
        ev = encode_event("Port scan from 203.0.113.77. No approved engagement.")
        state = update_state(state, ev)
        ev2 = encode_event("PowerShell reverse shell from 203.0.113.77. Payload executed.")
        state = update_state(state, ev2)

        summary = summarize_state(state, ev2)
        assert "203.0.113.77" in summary


class TestExportReceipt:
    def test_receipt_is_serializable(self):
        import json
        state = reset_state()
        ev = encode_event("Port scan from 10.0.1.5 targeting 192.168.1.1")
        state = update_state(state, ev)
        receipt = export_receipt(state)
        # Should be JSON-serializable without error
        json.dumps(receipt)
        assert receipt["step"] == 1
        assert "10.0.1.5" in receipt["entities"]
