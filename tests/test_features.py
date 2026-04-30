"""Tests for Level 0 feature extraction."""

from sentinel_hybrid_stack.features import (
    extract_ips, extract_users, extract_processes, extract_cves,
    extract_cvss, extract_time_signals, extract_authorization_signals,
    extract_threat_signals, build_structured_context,
)


class TestExtractIPs:
    def test_single_ip(self):
        assert "10.0.1.5" in extract_ips("Connection from 10.0.1.5 detected")

    def test_multiple_ips(self):
        ips = extract_ips("Traffic from 10.0.1.5 to 192.168.1.1")
        assert "10.0.1.5" in ips
        assert "192.168.1.1" in ips

    def test_cidr_range(self):
        ips = extract_ips("Scan of 10.0.0.0/24 completed")
        assert "10.0.0.0/24" in ips


class TestExtractUsers:
    def test_user_keyword(self):
        assert "ops_admin" in extract_users("User ops_admin logged in")

    def test_by_keyword(self):
        users = extract_users("Executed by ops_admin on server")
        assert "ops_admin" in users

    def test_service_account(self):
        users = extract_users("Process running as svc_backup")
        assert "svc_backup" in users


class TestExtractProcesses:
    def test_exe_files(self):
        procs = extract_processes("Process powershell.exe spawned cmd.exe")
        assert "powershell.exe" in procs
        assert "cmd.exe" in procs

    def test_known_tools(self):
        procs = extract_processes("Detected mimikatz and nmap running")
        assert "mimikatz" in procs
        assert "nmap" in procs


class TestExtractCVEs:
    def test_cve_format(self):
        cves = extract_cves("Found CVE-2024-1234 and CVE-2024-5678")
        assert "CVE-2024-1234" in cves
        assert "CVE-2024-5678" in cves


class TestExtractCVSS:
    def test_cvss_score(self):
        assert extract_cvss("CVSS 9.8 critical vulnerability") == 9.8

    def test_low_cvss(self):
        assert extract_cvss("CVSS 2.1 informational") == 2.1

    def test_no_cvss(self):
        assert extract_cvss("No vulnerability score present") is None


class TestAuthorizationSignals:
    def test_pentest(self):
        sigs = extract_authorization_signals("Approved pentest engagement")
        assert any("pentest" in s.lower() for s in sigs)

    def test_change_ticket(self):
        sigs = extract_authorization_signals("Change ticket CHG-123 filed")
        assert any("change ticket" in s.lower() for s in sigs)


class TestThreatSignals:
    def test_reverse_shell(self):
        sigs = extract_threat_signals("Reverse shell connection detected")
        assert any("reverse shell" in s.lower() for s in sigs)

    def test_exfil(self):
        sigs = extract_threat_signals("Data exfil via DNS tunnel")
        assert any("exfil" in s.lower() for s in sigs)


class TestBuildStructuredContext:
    def test_produces_output(self):
        ctx = build_structured_context(
            "Port scan from 10.0.1.5 by user admin. Reverse shell detected."
        )
        assert "--- STRUCTURED CONTEXT ---" in ctx
        assert "--- END CONTEXT ---" in ctx
        assert "10.0.1.5" in ctx
