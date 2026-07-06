"""Conversion from Sigma rules to Wazuh rules and XML."""

from __future__ import annotations

import hashlib
from pathlib import PureWindowsPath
import xml.etree.ElementTree as ET

from core.constants import SIGMA_TO_WAZUH_LEVEL, WAZUH_CUSTOM_RULE_ID_RANGE, WAZUH_RULE_ID_END, WAZUH_RULE_ID_START
from core.models import SigmaRule, WazuhRule

DEFAULT_GROUP_NAME = "malware_behavior_detection_generator,"

WINDOWS_LOGSOURCE_MAPPING = {
    "process_creation": {"group": "sysmon,process_creation,", "decoded_as": None, "if_sid": 61603},
    "registry_event": {"group": "sysmon,registry_event,", "decoded_as": "json"},
    "file_event": {"group": "sysmon,file_event,", "decoded_as": "json"},
    "network_connection": {"group": "sysmon,network_connection,", "decoded_as": "json"},
    "dns_query": {"group": "sysmon,dns,", "decoded_as": "json"},
}

LINUX_LOGSOURCE_MAPPING = {
    "process_creation": {"group": "linux,auditd,process_creation,", "decoded_as": "json"},
    "file_event": {"group": "linux,auditd,file_event,", "decoded_as": "json"},
    "network_connection": {"group": "linux,network_connection,", "decoded_as": "json"},
    "dns_query": {"group": "linux,dns,", "decoded_as": "json"},
}

WINDOWS_LOGSOURCE_EVENT_IDS = {
    "registry_event": "12",
    "file_event": "11",
    "network_connection": "3",
    "dns_query": "22",
}

FIELD_NAME_MAPPING = {
    "Image|endswith": "win.eventdata.image",
    "CommandLine|contains": "win.eventdata.commandLine",
    "TargetObject|contains": "win.eventdata.targetObject",
    "TargetFilename|contains": "win.eventdata.targetFilename",
    "DestinationIp": "win.eventdata.destinationIp",
    "DestinationHostname|contains": "win.eventdata.destinationHostname",
    "QueryName|contains": "win.eventdata.queryName",
    "exe|endswith": "audit.exe",
    "cmdline|contains": "audit.command",
    "file.path|contains": "audit.file.path",
    "destination.ip": "dstip",
    "destination.domain|contains": "dsthost",
    "url|contains": "url",
    "query|contains": "dns.query",
}


def configure_wazuh_id_range(start: int, end: int) -> None:
    """Update the active Wazuh custom rule ID range for this process."""
    global WAZUH_CUSTOM_RULE_ID_RANGE, WAZUH_RULE_ID_START, WAZUH_RULE_ID_END
    if start <= 0 or end <= start:
        raise ValueError("Wazuh rule ID range must satisfy start > 0 and end > start")
    WAZUH_RULE_ID_START = start
    WAZUH_RULE_ID_END = end
    WAZUH_CUSTOM_RULE_ID_RANGE = range(start, end + 1)


def _deterministic_wazuh_id(rule_id: str) -> int:
    span = len(WAZUH_CUSTOM_RULE_ID_RANGE)
    digest = hashlib.sha1(rule_id.encode("utf-8")).hexdigest()
    offset = int(digest[:8], 16) % span
    return WAZUH_RULE_ID_START + offset


def _extract_attack_ids(tags: list[str]) -> list[str]:
    attack_ids = []
    for tag in tags:
        if not tag.startswith("attack."):
            continue
        attack_ids.append(tag.split(".", 1)[1].upper())
    return sorted(set(attack_ids))


def _selector_mappings(detection: dict[str, object]) -> list[dict[str, object]]:
    selectors: list[dict[str, object]] = []
    for key, value in detection.items():
        if key.startswith("selection") and isinstance(value, dict):
            selectors.append(value)
    selection = detection.get("selection", {})
    if isinstance(selection, dict):
        selectors.append(selection)
    return selectors


def _convert_detection_fields(detection: dict[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for selector in _selector_mappings(detection):
        for key, value in selector.items():
            field_name = FIELD_NAME_MAPPING.get(str(key))
            if not field_name:
                continue
            fields[field_name] = str(value)
    return fields


def _allocate_wazuh_id(rule_id: str, used_ids: set[int]) -> int:
    span = len(WAZUH_CUSTOM_RULE_ID_RANGE)
    wazuh_id = _deterministic_wazuh_id(rule_id)
    attempts = 0
    while wazuh_id in used_ids:
        wazuh_id += 1
        attempts += 1
        if wazuh_id > WAZUH_CUSTOM_RULE_ID_RANGE.stop - 1:
            wazuh_id = WAZUH_RULE_ID_START
        if attempts >= span:
            raise RuntimeError(
                f"Wazuh rule ID space exhausted: all {span} IDs in range "
                f"{WAZUH_RULE_ID_START}-{WAZUH_CUSTOM_RULE_ID_RANGE.stop - 1} are used."
            )
    return wazuh_id


def _escape_field_value(field_name: str, value: str) -> str:
    if field_name == "win.eventdata.image":
        return PureWindowsPath(value).name or value
    escaped = []
    for char in str(value):
        if char == "\\":
            escaped.append("\\\\")
        elif char in ".^$*+?{}[]|()":
            escaped.append(f"\\{char}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _process_creation_fields(rule: SigmaRule) -> dict[str, str]:
    fields = _convert_detection_fields(rule.detection)
    image = str(fields.get("win.eventdata.image") or "").strip()
    command_line = str(fields.get("win.eventdata.commandLine") or "").strip()
    if not image and not command_line:
        return {}
    process_fields: dict[str, str] = {}
    if not image and command_line:
        image = PureWindowsPath(command_line.split()[0]).name
    if image:
        process_fields["win.eventdata.image"] = PureWindowsPath(image).name or image
    if command_line:
        process_fields["win.eventdata.commandLine"] = command_line
    return process_fields


def _mapping_for_rule(sigma_rule: SigmaRule) -> dict[str, object] | None:
    category = str(sigma_rule.logsource.get("category") or "")
    product = str(sigma_rule.logsource.get("product") or "windows").lower()
    if product == "linux":
        return LINUX_LOGSOURCE_MAPPING.get(category)
    return WINDOWS_LOGSOURCE_MAPPING.get(category)


def _conversion_reason(category: str, product: str) -> str:
    if product == "linux":
        return "Rule converted using Linux/generic JSON field matching; no Windows Sysmon parent or win.eventdata fields are used."
    if category == "process_creation":
        return "Process creation converted using Sysmon parent rule 61603 and win.eventdata image and commandLine fields when available."
    return "Non-process Windows rule converted using decoded JSON Wazuh field matching."


def convert_sigma_to_wazuh(sigma_rules: list[SigmaRule] | None) -> list[WazuhRule]:
    """Convert SigmaRule objects into WazuhRule objects."""
    if not sigma_rules:
        return []

    converted: list[WazuhRule] = []
    seen: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    used_ids: set[int] = set()

    for sigma_rule in sigma_rules:
        category = str(sigma_rule.logsource.get("category") or "")
        product = str(sigma_rule.logsource.get("product") or "windows").lower()
        mapping = _mapping_for_rule(sigma_rule)
        if not mapping:
            continue

        if product == "windows" and category == "process_creation":
            fields = _process_creation_fields(sigma_rule)
            if not fields:
                continue
        else:
            fields = _convert_detection_fields(sigma_rule.detection)
            if not fields:
                continue
            event_id = WINDOWS_LOGSOURCE_EVENT_IDS.get(category) if product == "windows" else None
            if event_id:
                fields.setdefault("win.system.eventID", event_id)
        dedupe_key = (sigma_rule.description, tuple(sorted(fields.items())))
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        wazuh_id = _allocate_wazuh_id(sigma_rule.rule_id, used_ids)
        used_ids.add(wazuh_id)

        converted.append(
            WazuhRule(
                rule_id=wazuh_id,
                level=SIGMA_TO_WAZUH_LEVEL.get(sigma_rule.level, SIGMA_TO_WAZUH_LEVEL["medium"]),
                description=sigma_rule.description,
                group=str(mapping["group"]),
                decoded_as=mapping.get("decoded_as"),
                if_sid=mapping.get("if_sid"),
                fields=fields,
                mitre_ids=_extract_attack_ids(sigma_rule.tags),
                options={
                    "title": sigma_rule.title,
                    "sigma_rule_id": sigma_rule.rule_id,
                    "status": sigma_rule.status,
                    "author": sigma_rule.author,
                    "references": list(sigma_rule.references),
                    "metadata": dict(sigma_rule.metadata),
                    "trace": {
                        "source_sigma_rule_id": sigma_rule.rule_id,
                        "source_sigma_rule_title": sigma_rule.title,
                        "source_sigma_rule_description": sigma_rule.description,
                        "source_sigma_trace": dict(sigma_rule.metadata.get("trace", {})),
                        "conversion_reason": _conversion_reason(category, product),
                    },
                },
            )
        )

    return converted


def wazuh_rule_to_xml(rule: WazuhRule) -> str:
    """Serialize a single WazuhRule to parseable XML."""
    rule_element = ET.Element("rule", id=str(rule.rule_id), level=str(rule.level))
    process_creation_shape = bool(rule.if_sid == 61603 and rule.fields and not rule.decoded_as)

    if process_creation_shape:
        if_sid = ET.SubElement(rule_element, "if_sid")
        if_sid.text = str(rule.if_sid)
        for name, value in sorted(rule.fields.items()):
            field = ET.SubElement(rule_element, "field", name=name)
            field.text = _escape_field_value(name, value)
        description = ET.SubElement(rule_element, "description")
        description.text = rule.description
        if rule.group:
            group = ET.SubElement(rule_element, "group")
            group.text = rule.group
    else:
        if rule.decoded_as:
            decoded_as = ET.SubElement(rule_element, "decoded_as")
            decoded_as.text = rule.decoded_as

        description = ET.SubElement(rule_element, "description")
        description.text = rule.description

        if rule.group:
            group = ET.SubElement(rule_element, "group")
            group.text = rule.group

        if rule.if_sid is not None:
            if_sid = ET.SubElement(rule_element, "if_sid")
            if_sid.text = str(rule.if_sid)

        for name, value in sorted(rule.fields.items()):
            field = ET.SubElement(rule_element, "field", name=name)
            field.text = _escape_field_value(name, value)

    if rule.mitre_ids:
        mitre = ET.SubElement(rule_element, "mitre")
        for technique_id in rule.mitre_ids:
            technique = ET.SubElement(mitre, "id")
            technique.text = technique_id

    ET.indent(rule_element, space="  ")
    return ET.tostring(rule_element, encoding="unicode")


def wazuh_rules_to_xml(rules: list[WazuhRule] | None, group_name: str = DEFAULT_GROUP_NAME) -> str:
    """Serialize multiple Wazuh rules into a single parseable XML document."""
    root = ET.Element("group", name=group_name)
    for rule in rules or []:
        root.append(ET.fromstring(wazuh_rule_to_xml(rule)))
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode")
