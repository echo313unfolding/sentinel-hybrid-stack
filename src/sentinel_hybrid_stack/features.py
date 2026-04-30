"""Level 0 hand-feature extraction from alert text.

Pure regex-based extraction of IPs, users, processes, CVEs, CVSS scores,
time signals, authorization signals, and threat indicators. No state,
no model calls — deterministic feature extraction only.
"""

import re
from typing import List, Optional


def extract_ips(text: str) -> List[str]:
    """Extract all IP addresses from alert text."""
    return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b', text)))


def extract_users(text: str) -> List[str]:
    """Extract usernames/accounts from alert text."""
    users = set()
    stopwords = {
        'the', 'this', 'that', 'from', 'with', 'root', 'a', 'an', 'in', 'on', 'to',
    }
    for m in re.finditer(r'(?:user|account|by|operator)\s+(\w[\w.-]{1,30})', text, re.I):
        u = m.group(1).lower()
        if u not in stopwords:
            users.add(m.group(1))
    for m in re.finditer(r'(\w[\w.+-]+)@[\w.-]+', text):
        users.add(m.group(1))
    for m in re.finditer(r'\b(root|www-data|svc_\w+|redteam_\w+)\b', text):
        users.add(m.group(1))
    return sorted(users)


def extract_processes(text: str) -> List[str]:
    """Extract process/binary names from alert text."""
    procs = set()
    for m in re.finditer(r'\b(\w+\.exe)\b', text, re.I):
        procs.add(m.group(1).lower())
    tools = [
        'nmap', 'nuclei', 'burp', 'metasploit', 'mimikatz', 'cobalt strike',
        'bloodhound', 'sharphound', 'responder', 'empire', 'powershell',
        'psexec', 'certutil', 'mshta', 'regsvr32', 'rundll32', 'bitsadmin',
        'wmic', 'ansible', 'terraform', 'docker', 'pip', 'npm', 'maven',
        'curl', 'wget', 'scp', 'ssh', 'sshd', 'sudo',
    ]
    text_lower = text.lower()
    for t in tools:
        if t in text_lower:
            procs.add(t)
    return sorted(procs)


def extract_cves(text: str) -> List[str]:
    """Extract CVE IDs from alert text."""
    return list(set(re.findall(r'CVE-\d{4}-\d+', text)))


def extract_cvss(text: str) -> Optional[float]:
    """Extract CVSS score if present."""
    m = re.search(r'CVSS\s+([\d.]+)', text)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return None


def extract_time_signals(text: str) -> List[str]:
    """Extract time-related signals."""
    signals = []
    for m in re.finditer(r'\b(\d{1,2}:\d{2})\s*(UTC|local|JST|EST|PST)?\b', text):
        signals.append(m.group(0))
    for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
        if day in text:
            signals.append(day)
    schedule_words = [
        'scheduled', 'maintenance window', 'planned', 'quarterly',
        'cron', 'automated', 'pipeline', 'on-call', 'engagement window',
        'DR drill', 'DR exercise', 'deployment window',
    ]
    text_lower = text.lower()
    for sw in schedule_words:
        if sw.lower() in text_lower:
            signals.append(f"scheduled:{sw}")
    return signals


def extract_authorization_signals(text: str) -> List[str]:
    """Extract signals of authorized activity."""
    signals = []
    auth_words = [
        'approved', 'authorized', 'engagement', 'pentest', 'red team',
        'change ticket', 'change request', 'JIRA', 'ticket', 'SOW',
        'peer-reviewed', 'DR runbook', 'on-call', 'confirmed',
        'isolated', 'test VLAN', 'lab', 'staging',
    ]
    text_lower = text.lower()
    for aw in auth_words:
        if aw.lower() in text_lower:
            signals.append(aw)
    return signals


def extract_threat_signals(text: str) -> List[str]:
    """Extract indicators of malicious activity."""
    signals = []
    threat_words = [
        'obfuscated', 'base64', 'encoded', 'typosquat', 'exfil',
        'reverse shell', 'webshell', 'payload', 'c2', 'beacon',
        'lateral movement', 'privilege escalation', 'brute force',
        'credential', 'NTDS', 'mimikatz', 'kerberoasting',
        'phishing', 'macro', 'dropper', 'malware',
        'force push', 'secrets dump', 'postinstall',
        'Tor exit', 'resignation', 'PIP',
    ]
    text_lower = text.lower()
    for tw in threat_words:
        if tw.lower() in text_lower:
            signals.append(tw)
    return signals


def build_structured_context(alert_text: str) -> str:
    """Extract all hand-features and format as structured context block."""
    ips = extract_ips(alert_text)
    users = extract_users(alert_text)
    procs = extract_processes(alert_text)
    cves = extract_cves(alert_text)
    cvss = extract_cvss(alert_text)
    time_sigs = extract_time_signals(alert_text)
    auth_sigs = extract_authorization_signals(alert_text)
    threat_sigs = extract_threat_signals(alert_text)

    lines = ["--- STRUCTURED CONTEXT ---"]
    if ips:
        lines.append(f"IPs: {', '.join(ips)}")
    if users:
        lines.append(f"USERS: {', '.join(users)}")
    if procs:
        lines.append(f"PROCESSES: {', '.join(procs)}")
    if cves:
        lines.append(f"CVEs: {', '.join(cves)}")
    if cvss is not None:
        sev = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
        lines.append(f"CVSS: {cvss} ({sev})")
    if time_sigs:
        lines.append(f"TIME_SIGNALS: {', '.join(time_sigs)}")
    if auth_sigs:
        lines.append(f"AUTHORIZATION: {', '.join(auth_sigs)}")
    if threat_sigs:
        lines.append(f"THREAT_INDICATORS: {', '.join(threat_sigs)}")

    n_auth = len(auth_sigs)
    n_threat = len(threat_sigs)
    if n_auth > 0 and n_threat == 0:
        lines.append("CONTEXT_SUMMARY: Multiple authorization signals present, no threat indicators.")
    elif n_threat > 0 and n_auth == 0:
        lines.append("CONTEXT_SUMMARY: Threat indicators present, no authorization signals.")
    elif n_auth > 0 and n_threat > 0:
        lines.append(f"CONTEXT_SUMMARY: Mixed signals — {n_auth} authorization, {n_threat} threat indicators.")
    else:
        lines.append("CONTEXT_SUMMARY: No strong signals extracted.")

    lines.append("--- END CONTEXT ---")
    return "\n".join(lines)
