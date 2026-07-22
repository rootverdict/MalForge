"""Process behavior extraction from normalized sandbox reports."""

from __future__ import annotations

import re
from typing import Any, Mapping

from core.constants import COMMON_ATTACK_MAPPINGS
from core.models import Behavior
from core.schema import ensure_list, ensure_mapping

SUSPICIOUS_PROCESS_NAMES = {
    "cmd.exe": ("Suspicious command shell execution", "high", ["suspicious_process", "cmd"]),
    "powershell.exe": ("Suspicious PowerShell execution", "high", ["suspicious_process", "powershell"]),
    "rundll32.exe": ("Suspicious rundll32 execution", "high", ["suspicious_process", "rundll32"]),
    "regsvr32.exe": ("Suspicious regsvr32 execution", "high", ["suspicious_process", "regsvr32"]),
    "mshta.exe": ("Suspicious mshta execution", "high", ["suspicious_process", "mshta"]),
}

SUSPICIOUS_PROCESS_TECHNIQUE_KEYS = {
    "cmd.exe": "cmd",
    "powershell.exe": "powershell",
    "rundll32.exe": "rundll32",
    "regsvr32.exe": "regsvr32",
    "mshta.exe": "mshta",
}


def _process_name(process: Mapping[str, Any]) -> str:
    return str(
        process.get("process_name")
        or process.get("name")
        or process.get("image")
        or "unknown_process"
    )


def _process_basename(value: str) -> str:
    parts = [part for part in re.split(r"[\\/]", value.strip()) if part]
    return parts[-1] if parts else value.strip()


def extract_behaviors(normalized_report: Mapping[str, Any]) -> list[Behavior]:
    """Extract process behaviors from a normalized report."""
    source = str(normalized_report.get("sandbox", "unknown"))
    behaviors: list[Behavior] = []

    for item in ensure_list(normalized_report.get("processes")):
        process = ensure_mapping(item)
        if not process:
            continue

        name = _process_name(process)
        command_line = str(process.get("command_line") or process.get("cmd") or "").strip()
        pid = process.get("pid")
        suspicious_name = _process_basename(name).lower()
        suspicious = SUSPICIOUS_PROCESS_NAMES.get(suspicious_name)
        description = f"Process created: {name}"
        if command_line:
            description = f"{description} ({command_line})"

        if not suspicious:
            behaviors.append(
                Behavior(
                    category="process",
                    description=description,
                    source=source,
                    severity="medium",
                    evidence=[
                        {
                            "process_name": name,
                            "pid": pid,
                            "command_line": command_line,
                        }
                    ],
                    tags=["process_create"],
                    technique_ids=[COMMON_ATTACK_MAPPINGS["process"]["process_create"]["technique_id"]],
                )
            )

        if suspicious:
            suspicious_description, severity, tags = suspicious
            technique_key = SUSPICIOUS_PROCESS_TECHNIQUE_KEYS.get(suspicious_name, "process_create")
            behaviors.append(
                Behavior(
                    category="process",
                    description=suspicious_description,
                    source=source,
                    severity=severity,
                    evidence=[
                        {
                            "process_name": name,
                            "pid": pid,
                            "command_line": command_line,
                        }
                    ],
                    tags=tags,
                    technique_ids=[
                        COMMON_ATTACK_MAPPINGS["process"][technique_key]["technique_id"]
                    ],
                )
            )

    return behaviors
