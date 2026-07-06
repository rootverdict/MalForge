"""Sigma rule generation from behaviors and ATT&CK mappings."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections import defaultdict
from dataclasses import asdict
from urllib.parse import urlparse

from core.models import AttackMapping, Behavior, SigmaRule

GENERATOR_NAME = "malware-behavior-detection-generator"


def _stable_rule_id(behavior: Behavior) -> str:
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    return str(uuid.uuid5(namespace, f"{behavior.category}|{behavior.description}"))


def _title_from_behavior(behavior: Behavior) -> str:
    base_description = behavior.description.split("(", 1)[0].strip()
    words = base_description.replace(":", " ").split()
    if not words:
        return f"{behavior.category.title()} Behavior Detection"
    return " ".join(words[:8])


def _is_non_windows_behavior(behavior: Behavior) -> bool:
    return any(tag in behavior.tags for tag in {"platform_non_windows", "platform_linux_or_iot", "format_elf", "arch_mips"})


def _platform_context(behavior: Behavior) -> str:
    if _is_non_windows_behavior(behavior):
        if "arch_mips" in behavior.tags or "format_elf" in behavior.tags:
            return "linux_or_iot"
        return "non_windows"
    return "windows"


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


def _basename(value: str) -> str:
    parts = [part for part in re.split(r"[\\/]", value.strip()) if part]
    return parts[-1] if parts else value.strip()


def _mapping_tags_for_behavior(
    behavior: Behavior,
    mappings_by_behavior: dict[str, list[AttackMapping]],
) -> list[str]:
    tags = {f"attack.{technique_id.lower()}" for technique_id in behavior.technique_ids}
    for mapping in mappings_by_behavior.get(behavior.description, []):
        tags.add(f"attack.{mapping.technique_id.lower()}")
    return sorted(tags)


def _selector_reason(behavior: Behavior, detection: dict[str, object]) -> str:
    if not isinstance(detection, dict):
        keys = ""
    else:
        selector_keys: list[str] = []
        for name, value in detection.items():
            if name.startswith("selection") and isinstance(value, dict):
                selector_keys.extend(str(key) for key in value.keys())
        keys = ", ".join(sorted(selector_keys))
    platform = _platform_context(behavior)
    if behavior.category == "process":
        return f"Process selector chosen for {platform} telemetry from executable and command line evidence using: {keys or 'no selectors'}."
    if behavior.category == "registry":
        return f"Registry selector chosen from modified key evidence using: {keys or 'no selectors'}."
    if behavior.category == "file":
        return f"File selector chosen for {platform} telemetry from observed file path evidence using: {keys or 'no selectors'}."
    if behavior.category == "network":
        lowered_keys = keys.lower()
        if "destination.ip" in lowered_keys or "destinationip" in lowered_keys:
            evidence_type = "IP"
        elif "url" in lowered_keys or "uri" in lowered_keys:
            evidence_type = "URL"
        elif "query" in lowered_keys or "domain" in lowered_keys:
            evidence_type = "DNS/domain"
        else:
            evidence_type = "network"
        return f"Network selector chosen for {platform} telemetry from observed {evidence_type} evidence using: {keys or 'no selectors'}."
    if behavior.category == "persistence":
        return f"Persistence selector chosen from startup/service/task evidence using: {keys or 'no selectors'}."
    return f"Selector chosen using: {keys or 'no selectors'}."


def _build_trace_metadata(
    behavior: Behavior,
    detection: dict[str, object],
    mappings_by_behavior: dict[str, list[AttackMapping]],
) -> dict[str, object]:
    attack_ids = sorted(
        {
            *behavior.technique_ids,
            *(mapping.technique_id for mapping in mappings_by_behavior.get(behavior.description, [])),
        }
    )
    return {
        "source_behavior_category": behavior.category,
        "source_behavior_description": behavior.description,
        "source_behavior_evidence": behavior.evidence,
        "source_behavior_tags": list(behavior.tags),
        "platform_context": _platform_context(behavior),
        "attack_technique_ids": attack_ids,
        "attack_tags": [f"attack.{technique_id.lower()}" for technique_id in attack_ids],
        "selector_reason": _selector_reason(behavior, detection),
    }


def _build_process_rule(behavior: Behavior) -> tuple[dict[str, str], dict[str, object], list[str]]:
    evidence = behavior.evidence[0] if behavior.evidence else {}
    process_name = str(evidence.get("process_name") or evidence.get("name") or "").strip()
    command_line = str(evidence.get("command_line") or evidence.get("cmdline") or "").strip()

    if _is_non_windows_behavior(behavior):
        logsource = {"category": "process_creation", "product": "linux", "service": "auditd"}
        detection: dict[str, object] = {}
        fields: list[str] = []
        if process_name:
            detection["selection_exe"] = {"exe|endswith": _basename(process_name)}
            fields.append("exe")
        if command_line:
            detection["selection_cmdline"] = {"cmdline|contains": command_line}
            fields.append("cmdline")
        detection["condition"] = "all of them" if len(detection) > 1 else next(iter(detection), "selection")
        if not fields:
            detection["selection"] = {}
            detection["condition"] = "selection"
        return logsource, detection, fields

    logsource = {"category": "process_creation", "product": "windows"}
    detection = {}
    fields = []
    if process_name:
        detection["selection_image"] = {"Image|endswith": process_name}
        fields.append("Image")
    if command_line:
        detection["selection_cmdline"] = {"CommandLine|contains": command_line}
        fields.append("CommandLine")
    if "selection_image" in detection and "selection_cmdline" in detection:
        detection["condition"] = "all of them"
    elif "selection_image" in detection:
        detection["condition"] = "selection_image"
    elif "selection_cmdline" in detection:
        detection["condition"] = "selection_cmdline"
    else:
        detection["selection"] = {}
        detection["condition"] = "selection"
    return logsource, detection, fields


def _build_registry_rule(behavior: Behavior) -> tuple[dict[str, str], dict[str, object], list[str]]:
    evidence = behavior.evidence[0] if behavior.evidence else {}
    key = str(evidence.get("key") or "").strip()
    logsource = {"category": "registry_event", "product": "windows"}
    selection = {"TargetObject|contains": key} if key else {}
    return logsource, {"selection": selection, "condition": "selection"}, ["TargetObject"] if key else []


def _build_file_rule(behavior: Behavior) -> tuple[dict[str, str], dict[str, object], list[str]]:
    evidence = behavior.evidence[0] if behavior.evidence else {}
    path = str(evidence.get("path") or "").strip()
    if _is_non_windows_behavior(behavior):
        value = _basename(path) if path else ""
        logsource = {"category": "file_event", "product": "linux", "service": "auditd"}
        selection = {"file.path|contains": value} if value else {}
        return logsource, {"selection": selection, "condition": "selection"}, ["file.path"] if value else []
    logsource = {"category": "file_event", "product": "windows"}
    selection = {"TargetFilename|contains": path} if path else {}
    return logsource, {"selection": selection, "condition": "selection"}, ["TargetFilename"] if path else []


def _build_network_rule(behavior: Behavior) -> tuple[dict[str, str], dict[str, object], list[str]]:
    evidence = behavior.evidence[0] if behavior.evidence else {}
    non_windows = _is_non_windows_behavior(behavior)

    if "domain" in evidence:
        value = str(evidence.get("domain") or "").strip()
        if _is_ip_address(value):
            key = "destination.ip" if non_windows else "DestinationIp"
            category = "network_connection"
            product = "linux" if non_windows else "windows"
            return {"category": category, "product": product}, {"selection": {key: value} if value else {}, "condition": "selection"}, [key] if value else []
        key = "query|contains" if non_windows else "QueryName|contains"
        product = "linux" if non_windows else "windows"
        return {"category": "dns_query", "product": product}, {"selection": {key: value} if value else {}, "condition": "selection"}, [key] if value else []

    if "uri" in evidence or "url" in evidence:
        value = str(evidence.get("uri") or evidence.get("url") or "").strip()
        hostname = urlparse(value).hostname or value
        if non_windows:
            selection: dict[str, str] = {"url|contains": value} if value else {}
            if hostname and _is_ip_address(hostname):
                selection["destination.ip"] = hostname
            elif hostname:
                selection["destination.domain|contains"] = hostname
            return {"category": "network_connection", "product": "linux"}, {"selection": selection, "condition": "selection"}, list(selection.keys())
        if hostname and _is_ip_address(hostname):
            return {"category": "network_connection", "product": "windows"}, {"selection": {"DestinationIp": hostname}, "condition": "selection"}, ["DestinationIp"]
        return {"category": "network_connection", "product": "windows"}, {"selection": {"DestinationHostname|contains": hostname} if hostname else {}, "condition": "selection"}, ["DestinationHostname"] if hostname else []

    if "ip" in evidence or "ipv6" in evidence:
        value = str(evidence.get("ip") or evidence.get("ipv6") or "").strip()
        key = "destination.ip" if non_windows else "DestinationIp"
        product = "linux" if non_windows else "windows"
        return {"category": "network_connection", "product": product}, {"selection": {key: value} if value else {}, "condition": "selection"}, [key] if value else []

    product = "linux" if non_windows else "windows"
    return {"category": "network_connection", "product": product}, {"selection": {}, "condition": "selection"}, []


def _build_persistence_rule(behavior: Behavior) -> tuple[dict[str, str], dict[str, object], list[str]]:
    evidence = behavior.evidence[0] if behavior.evidence else {}
    persistence_type = str(evidence.get("type") or evidence.get("method") or "").strip().lower()

    if "task" in persistence_type:
        return {"category": "process_creation", "product": "windows"}, {"selection": {"Image|endswith": "schtasks.exe"}, "condition": "selection"}, ["Image"]
    if "service" in persistence_type:
        return {"category": "process_creation", "product": "windows"}, {"selection": {"Image|endswith": "sc.exe"}, "condition": "selection"}, ["Image"]
    if "startup" in persistence_type or "run" in persistence_type:
        return {"category": "registry_event", "product": "windows"}, {"selection": {"TargetObject|contains": "Run"}, "condition": "selection"}, ["TargetObject"]
    return {"category": "process_creation", "product": "windows"}, {"selection": {}, "condition": "selection"}, []


def _build_sigma_components(behavior: Behavior) -> tuple[dict[str, str], dict[str, object], list[str]] | None:
    if not behavior.description.strip():
        return None
    if behavior.category == "process":
        return _build_process_rule(behavior)
    if behavior.category == "registry":
        return _build_registry_rule(behavior)
    if behavior.category == "file":
        return _build_file_rule(behavior)
    if behavior.category == "network":
        return _build_network_rule(behavior)
    if behavior.category == "persistence":
        return _build_persistence_rule(behavior)
    return None


def _is_useful_behavior(behavior: Behavior) -> bool:
    if not behavior.description.strip():
        return False
    if behavior.category not in {"process", "registry", "file", "network", "persistence"}:
        return False
    components = _build_sigma_components(behavior)
    if not components:
        return False
    _, detection, _ = components
    if not isinstance(detection, dict):
        return False
    return any(isinstance(value, dict) and bool(value) for key, value in detection.items() if key.startswith("selection"))


def generate_sigma_rules(behaviors: list[Behavior] | None, mappings: list[AttackMapping] | None = None) -> list[SigmaRule]:
    """Generate Sigma rules from behavior and ATT&CK mappings."""
    if not behaviors:
        return []

    mappings_by_behavior: dict[str, list[AttackMapping]] = defaultdict(list)
    for mapping in mappings or []:
        mappings_by_behavior[mapping.source_behavior].append(mapping)

    rules: list[SigmaRule] = []
    seen: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

    for behavior in behaviors:
        if not _is_useful_behavior(behavior):
            continue
        components = _build_sigma_components(behavior)
        if not components:
            continue
        logsource, detection, fields = components
        selector_entries: list[tuple[str, str]] = []
        for key, value in detection.items():
            if key.startswith("selection") and isinstance(value, dict):
                selector_entries.extend((f"{key}:{field}", str(field_value)) for field, field_value in value.items())
        selector_key = tuple(sorted(selector_entries))
        dedupe_key = (behavior.category, behavior.description, selector_key)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        tags = _mapping_tags_for_behavior(behavior, mappings_by_behavior)
        rules.append(
            SigmaRule(
                title=_title_from_behavior(behavior),
                rule_id=_stable_rule_id(behavior),
                description=behavior.description,
                logsource=logsource,
                detection=detection,
                level=behavior.severity,
                status="experimental",
                author=GENERATOR_NAME,
                tags=tags,
                references=[f"generated-by:{GENERATOR_NAME}", f"source:{behavior.source}"],
                falsepositives=["Unknown"],
                fields=fields,
                metadata={
                    "tool": GENERATOR_NAME,
                    "behavior_category": behavior.category,
                    "platform_context": _platform_context(behavior),
                    "trace": _build_trace_metadata(behavior, detection, mappings_by_behavior),
                },
            )
        )

    return rules


def rule_to_dict(rule: SigmaRule) -> dict[str, object]:
    """Serialize a SigmaRule dataclass into a YAML-compatible dictionary."""
    payload = asdict(rule)
    payload["id"] = payload.pop("rule_id")
    return payload
