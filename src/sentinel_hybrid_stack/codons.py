"""Codon encoding — deterministic entity/action/quality signal mapping.

Maps alert text to structured codon representations used by the SSM layer.
Codons are short symbolic codes (E_INT, A_SCN, Q_SUS, etc.) that encode
entity type, observed action, and quality assessment for each entity
mentioned in an alert.
"""

import re
from collections import defaultdict
from typing import Dict, List, Set

from .features import (
    extract_ips, extract_users,
    extract_authorization_signals, extract_threat_signals,
)


# ═══════════════════════════════════════════════════════════════════════════
# Codon Lookup Tables
# ═══════════════════════════════════════════════════════════════════════════

ENTITY_CODONS = {
    "ip_internal": "E_INT",
    "ip_external": "E_EXT",
    "ip_pentest": "E_PEN",
    "user_admin": "E_ADM",
    "user_service": "E_SVC",
    "user_normal": "E_USR",
    "host": "E_HST",
    "process": "E_PRC",
}

ACTION_CODONS = {
    "scan": "A_SCN",
    "auth_fail": "A_AFL",
    "auth_success": "A_ASC",
    "exec": "A_EXC",
    "create": "A_CRF",
    "modify": "A_MOD",
    "delete": "A_DEL",
    "transfer": "A_TFR",
    "escalate_priv": "A_ESC",
    "lateral_move": "A_LAT",
    "exfil": "A_EXF",
    "install": "A_INS",
    "maintenance": "A_MNT",
    "login": "A_LGN",
    "cleanup": "A_CLN",
}

QUALITY_CODONS = {
    "authorized": "Q_AUT",
    "suspicious": "Q_SUS",
    "malicious": "Q_MAL",
    "benign": "Q_BEN",
    "unknown": "Q_UNK",
}

# Escalation patterns: if all actions in a pattern appear, flag fires.
ESCALATION_PATTERNS = [
    ({"A_SCN", "A_AFL"}, "recon_to_brute"),
    ({"A_SCN", "A_AFL", "A_ASC"}, "brute_force_success"),
    ({"A_SCN", "A_AFL", "A_EXC"}, "kill_chain"),
    ({"A_ASC", "A_LAT"}, "lateral_after_auth"),
    ({"A_LAT", "A_EXC"}, "post_exploitation"),
    ({"A_EXC", "A_TFR"}, "exfil_after_exploit"),
    ({"A_CRF", "A_CLN"}, "anti_forensics"),
    ({"A_CRF", "A_DEL"}, "anti_forensics"),
]

# Known pentest ranges (synthetic — replace with your environment's ranges)
PENTEST_PREFIXES = ("10.0.99.",)
INTERNAL_PREFIXES = ("10.0.", "192.168.", "172.16.", "172.17.", "172.18.")

# Match hostnames like ws-finance-03, db-master-01, prod-app-01
_HOST_RE = re.compile(r'\b((?:prod|staging|db|jump|web|vpn|ws|dc)(?:-[\w]+)+)\b')

# Users that are clearly not real users (false positives from keyword extraction)
_USER_STOPLIST = {
    "ssh", "merge", "main", "session", "process", "service", "system",
    "target", "source", "host", "server", "client", "team", "group",
    "all", "new", "old", "the", "via", "not", "any", "per",
    "clearing", "was", "account", "added", "user", "ciso",
    "netops", "configuration", "installed", "external", "matching",
    "is", "has", "entered", "placed", "approved", "permissions",
    "standard", "domain", "associated", "analyst",
}


# ═══════════════════════════════════════════════════════════════════════════
# Classifiers
# ═══════════════════════════════════════════════════════════════════════════

def classify_ip(ip: str) -> str:
    for prefix in PENTEST_PREFIXES:
        if ip.startswith(prefix):
            return "ip_pentest"
    for prefix in INTERNAL_PREFIXES:
        if ip.startswith(prefix):
            return "ip_internal"
    return "ip_external"


def classify_user(user: str) -> str:
    admin_names = {"root", "admin", "administrator", "jdoe", "sysadmin"}
    if user.lower() in admin_names:
        return "user_admin"
    if user.lower().startswith("svc_") or user.lower() in ("www-data", "daemon", "nobody"):
        return "user_service"
    return "user_normal"


def detect_actions(text: str) -> Set[str]:
    """Detect action codons from alert text via keyword patterns."""
    actions = set()
    tl = text.lower()

    if any(w in tl for w in ("scan", "nmap", "nuclei", "port scan", "syn scan", "recon")):
        actions.add("scan")
    if any(w in tl for w in ("failed ssh", "failed login", "brute force", "failed attempt")):
        actions.add("auth_fail")
    if any(w in tl for w in ("login succeeded", "successful login", "authenticated",
                              "login success", "logged in successfully",
                              "session established")):
        actions.add("auth_success")
    if any(w in tl for w in ("powershell", "cmd.exe", "execute", "executed", "payload",
                              "downloadstring", "iex(", "reverse shell",
                              "curl", "wget")):
        actions.add("exec")
    if any(w in tl for w in ("psexec", "lateral movement", "lateral move", "wmic")):
        actions.add("lateral_move")
    if any(w in tl for w in ("new user", "new account", "cron job installed",
                              "account created", "new cron")):
        actions.add("create")
    if any(w in tl for w in ("modified", "updated", "patched")):
        actions.add("modify")
    if any(w in tl for w in ("shred", "deleted", "removed", "clearing", "clear")):
        actions.add("delete")
    if any(w in tl for w in ("scp transfer", "data transfer", "tar.gz", "exfil",
                              "archive created")):
        actions.add("transfer")
    if any(w in tl for w in ("privilege escalat", "added to sudo", "got root")):
        actions.add("escalate_priv")
    if any(w in tl for w in ("scheduled", "maintenance", "patch applied", "kernel update",
                              "cron.daily", "ansible", "deploy", "log rotation",
                              "dr drill", "dr test", "dr exercise", "failover",
                              "unattended-upgrades", "change ticket")):
        actions.add("maintenance")
    if any(w in tl for w in ("shred", "anti-forensic", "cleanup", "clearing system logs")):
        actions.add("cleanup")
    if any(w in tl for w in ("installed", "persistence", "cron job")):
        actions.add("install")
    if "login" in tl or "ssh" in tl:
        actions.add("login")

    return actions


def detect_quality(auth_signals: list, threat_signals: list) -> str:
    n_auth = len(auth_signals)
    n_threat = len(threat_signals)
    if n_auth > 0 and n_threat == 0:
        return "authorized"
    elif n_threat >= 2:
        return "malicious"
    elif n_threat > 0 and n_auth == 0:
        return "suspicious"
    elif n_auth > 0 and n_threat > 0:
        return "suspicious"
    return "unknown"


def event_to_codons(alert_text: str) -> List[dict]:
    """Map alert text to a list of codon dicts keyed by entity."""
    ips = extract_ips(alert_text)
    users = extract_users(alert_text)
    auth_sigs = extract_authorization_signals(alert_text)
    threat_sigs = extract_threat_signals(alert_text)
    actions = detect_actions(alert_text)
    quality = detect_quality(auth_sigs, threat_sigs)

    action_codes = sorted(ACTION_CODONS.get(a, a) for a in actions)
    quality_code = QUALITY_CODONS.get(quality, "Q_UNK")

    codons = []
    for ip in ips:
        if "/" in ip:
            continue
        codons.append({
            "entity_key": ip,
            "entity_codon": ENTITY_CODONS[classify_ip(ip)],
            "actions": action_codes,
            "quality": quality_code,
        })
    for user in users:
        user_clean = user.rstrip(".,;:!?")
        if user_clean.lower() in _USER_STOPLIST or not user_clean:
            continue
        codons.append({
            "entity_key": f"user:{user_clean}",
            "entity_codon": ENTITY_CODONS[classify_user(user_clean)],
            "actions": action_codes,
            "quality": quality_code,
        })
    for host in set(_HOST_RE.findall(alert_text)):
        codons.append({
            "entity_key": f"host:{host}",
            "entity_codon": ENTITY_CODONS["host"],
            "actions": action_codes,
            "quality": quality_code,
        })
    return codons


class EntityAccumulator:
    """Track per-entity codon state across sequential events."""

    def __init__(self, history_window: int = 20):
        self.history_window = history_window
        self.entities: Dict[str, dict] = defaultdict(lambda: {
            "events": [],
            "action_counts": defaultdict(int),
            "quality_history": [],
            "first_seen": None,
            "last_seen": None,
            "entity_codon": None,
            "escalation_flags": [],
        })
        self.co_occurrences: Dict[str, Set[str]] = defaultdict(set)

    def ingest(self, event_id: int, codons: List[dict]):
        entity_keys = [c["entity_key"] for c in codons]
        for i, key_a in enumerate(entity_keys):
            for key_b in entity_keys[i + 1:]:
                self.co_occurrences[key_a].add(key_b)
                self.co_occurrences[key_b].add(key_a)

        for codon in codons:
            key = codon["entity_key"]
            entry = self.entities[key]
            entry["events"].append(event_id)
            entry["events"] = entry["events"][-self.history_window:]
            entry["entity_codon"] = codon["entity_codon"]
            for action in codon["actions"]:
                entry["action_counts"][action] += 1
            entry["quality_history"].append(codon["quality"])
            entry["quality_history"] = entry["quality_history"][-self.history_window:]
            if entry["first_seen"] is None:
                entry["first_seen"] = event_id
            entry["last_seen"] = event_id
            self._check_escalation(key)

    def _check_escalation(self, entity_key: str):
        entry = self.entities[entity_key]
        action_set = set(entry["action_counts"].keys())
        for pattern, flag in ESCALATION_PATTERNS:
            if pattern.issubset(action_set) and flag not in entry["escalation_flags"]:
                entry["escalation_flags"].append(flag)
