"""Shared constants for safe sandbox report processing."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"
SIGMA_OUTPUT_DIR = OUTPUT_DIR / "sigma"
WAZUH_OUTPUT_DIR = OUTPUT_DIR / "wazuh"
TEST_EVENTS_OUTPUT_DIR = OUTPUT_DIR / "test_events"
REPORTS_OUTPUT_DIR = OUTPUT_DIR / "reports"
IOCS_OUTPUT_DIR = OUTPUT_DIR / "iocs"
NAVIGATOR_OUTPUT_DIR = OUTPUT_DIR / "navigator"
MAX_REPORT_SIZE_BYTES = 50 * 1024 * 1024
ATTACK_VERSION = "19.1"
ATTACK_NAVIGATOR_VERSION = "4.9"
ATTACK_LAYER_VERSION = "4.5"

OUTPUT_PATHS = {
    "sigma": SIGMA_OUTPUT_DIR,
    "wazuh": WAZUH_OUTPUT_DIR,
    "test_events": TEST_EVENTS_OUTPUT_DIR,
    "reports": REPORTS_OUTPUT_DIR,
    "iocs": IOCS_OUTPUT_DIR,
    "navigator": NAVIGATOR_OUTPUT_DIR,
}

SIGMA_TO_WAZUH_LEVEL = {
    "informational": 2,
    "low": 4,
    "medium": 7,
    "high": 10,
    "critical": 14,
}

COMMON_ATTACK_MAPPINGS = {
    "process": {
        "process_create": {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "execution"},
        "process_injection": {"technique_id": "T1055", "technique_name": "Process Injection", "tactic": "stealth"},
        "powershell": {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "execution"},
        "cmd": {"technique_id": "T1059.003", "technique_name": "Windows Command Shell", "tactic": "execution"},
        "mshta": {"technique_id": "T1218.005", "technique_name": "Mshta", "tactic": "stealth"},
        "regsvr32": {"technique_id": "T1218.010", "technique_name": "Regsvr32", "tactic": "stealth"},
        "rundll32": {"technique_id": "T1218.011", "technique_name": "Rundll32", "tactic": "stealth"},
    },
    "registry": {
        "run_key": {"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactic": "persistence"},
        "registry_modification": {"technique_id": "T1112", "technique_name": "Modify Registry", "tactic": "defense_impairment"},
    },
    "file": {
        "file_create": {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "command_and_control"},
        "file_delete": {"technique_id": "T1070.004", "technique_name": "File Deletion", "tactic": "stealth"},
        "masquerading": {"technique_id": "T1036", "technique_name": "Masquerading", "tactic": "stealth"},
    },
    "network": {
        "dns_query": {"technique_id": "T1071.004", "technique_name": "DNS", "tactic": "command_and_control"},
        "http_beacon": {"technique_id": "T1071.001", "technique_name": "Web Protocols", "tactic": "command_and_control"},
        "file_transfer_protocol": {"technique_id": "T1071.002", "technique_name": "File Transfer Protocols", "tactic": "command_and_control"},
        "non_standard_port": {"technique_id": "T1571", "technique_name": "Non-Standard Port", "tactic": "command_and_control"},
        "remote_service": {"technique_id": "T1021", "technique_name": "Remote Services", "tactic": "lateral_movement"},
        "smb": {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "tactic": "lateral_movement"},
    },
    "persistence": {
        "scheduled_task": {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "persistence"},
        "startup_folder": {"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactic": "persistence"},
        "service_install": {"technique_id": "T1543.003", "technique_name": "Windows Service", "tactic": "persistence"},
    },
}

ATTACK_TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "command_and_control": "TA0011",
    "stealth": "TA0005",
    "defense_impairment": "TA0112",
    "execution": "TA0002",
    "privilege_escalation": "TA0004",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    "persistence": "TA0003",
}

WAZUH_CUSTOM_RULE_ID_RANGE = range(100000, 120000)
WAZUH_RULE_ID_START = WAZUH_CUSTOM_RULE_ID_RANGE.start
WAZUH_RULE_ID_END = WAZUH_CUSTOM_RULE_ID_RANGE.stop - 1

SUPPORTED_SANDBOXES = ("cuckoo", "cape", "anyrun")

