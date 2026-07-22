"""Conversion from Sigma rules to Wazuh rules and XML."""

from __future__ import annotations

import hashlib
from fnmatch import fnmatchcase
import re
from typing import MutableMapping
import xml.etree.ElementTree as ET

from core.constants import SIGMA_TO_WAZUH_LEVEL, WAZUH_CUSTOM_RULE_ID_RANGE, WAZUH_RULE_ID_END, WAZUH_RULE_ID_START
from core.models import SigmaRule, WazuhRule

DEFAULT_GROUP_NAME = "malware_behavior_detection_generator,"

WINDOWS_LOGSOURCE_MAPPING = {
    "process_creation": {"group": "sysmon,process_creation,", "decoded_as": None, "if_sid": 61603},
    "registry_event": {"group": "sysmon,registry_event,", "decoded_as": None, "if_sid": "61614,61615,61616"},
    "file_event": {"group": "sysmon,file_event,", "decoded_as": None, "if_group": "sysmon_event_11"},
    "network_connection": {"group": "sysmon,network_connection,", "decoded_as": None, "if_group": "sysmon_event3"},
    "dns_query": {"group": "sysmon,dns,", "decoded_as": None, "if_group": "sysmon_event_22"},
}

LINUX_LOGSOURCE_MAPPING = {
    "process_creation": {"group": "linux,auditd,process_creation,", "decoded_as": "json"},
    "file_event": {"group": "linux,auditd,file_event,", "decoded_as": "json"},
    "network_connection": {"group": "linux,network_connection,", "decoded_as": "json"},
    "dns_query": {"group": "linux,dns,", "decoded_as": "json"},
}

WINDOWS_LOGSOURCE_EVENT_IDS = {
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


def _validated_wazuh_id_range(id_range: range | None) -> range:
    active_range = WAZUH_CUSTOM_RULE_ID_RANGE if id_range is None else id_range
    if len(active_range) == 0:
        raise ValueError("Wazuh rule ID range cannot be empty")
    if active_range.step != 1:
        raise ValueError("Wazuh rule ID range must use a step of 1")
    if active_range.start <= 0:
        raise ValueError("Wazuh rule IDs must be positive")
    return active_range


def _validated_registry_ids(
    id_registry: MutableMapping[str, int] | None,
    active_range: range,
) -> set[int]:
    if id_registry is None:
        return set()

    used_ids: set[int] = set()
    for key, value in id_registry.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Wazuh ID registry keys must be non-empty strings")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"Wazuh ID registry value for {key!r} must be an integer")
        if value not in active_range:
            raise ValueError(f"Registered Wazuh rule ID is outside the active range: {value}")
        if value in used_ids:
            raise ValueError(f"Wazuh ID registry contains a duplicate numeric ID: {value}")
        used_ids.add(value)
    return used_ids


def _deterministic_wazuh_id(rule_id: str, id_range: range | None = None) -> int:
    active_range = _validated_wazuh_id_range(id_range)
    span = len(active_range)
    digest = hashlib.sha1(rule_id.encode("utf-8")).hexdigest()
    offset = int(digest[:8], 16) % span
    return active_range.start + offset


def _extract_attack_ids(tags: list[str]) -> list[str]:
    attack_ids = []
    for tag in tags:
        if not tag.startswith("attack."):
            continue
        attack_ids.append(tag.split(".", 1)[1].upper())
    return sorted(set(attack_ids))


def _selector_mappings(detection: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    selectors: list[tuple[str, dict[str, object]]] = []
    for key, value in detection.items():
        if key.startswith("selection") and isinstance(value, dict):
            selectors.append((key, value))
    return selectors


def _selector_groups(detection: dict[str, object]) -> list[list[tuple[str, dict[str, object]]]]:
    selectors = _selector_mappings(detection)
    if not selectors:
        return []

    selector_by_name = dict(selectors)
    condition = str(detection.get("condition") or "").strip()
    if not condition:
        if len(selectors) == 1:
            return [selectors]
        raise ValueError("Sigma detection with multiple selectors requires an explicit condition")
    if condition in selector_by_name:
        return [[(condition, selector_by_name[condition])]]

    quantified = re.fullmatch(r"(all|1)\s+of\s+(them|[A-Za-z0-9_*?]+)", condition, flags=re.IGNORECASE)
    if quantified:
        quantifier, pattern = quantified.groups()
        matched = selectors if pattern.lower() == "them" else [
            item for item in selectors if fnmatchcase(item[0], pattern)
        ]
        if not matched:
            raise ValueError(f"Sigma condition does not match any selectors: {condition}")
        matched = sorted(matched, key=lambda item: item[0])
        return [matched] if quantifier.lower() == "all" else [[item] for item in matched]

    parts = re.split(r"\s+(and|or)\s+", condition, flags=re.IGNORECASE)
    if len(parts) >= 3 and len(parts) % 2 == 1:
        names = parts[::2]
        operators = {operator.lower() for operator in parts[1::2]}
        if len(operators) != 1 or any(name not in selector_by_name for name in names):
            raise ValueError(f"Unsupported Sigma condition: {condition}")
        selected = [(name, selector_by_name[name]) for name in names]
        return [selected] if operators == {"and"} else [[item] for item in selected]

    raise ValueError(f"Unsupported Sigma condition: {condition}")


def _convert_selector_group(selectors: list[tuple[str, dict[str, object]]]) -> tuple[dict[str, str], dict[str, str]]:
    fields: dict[str, str] = {}
    match_types: dict[str, str] = {}
    for _, selector in selectors:
        for key, value in selector.items():
            sigma_field = str(key)
            base_field, *modifiers = sigma_field.split("|")
            unsupported_modifiers = set(modifiers) - {"contains", "endswith", "startswith"}
            if unsupported_modifiers:
                unsupported = ", ".join(sorted(unsupported_modifiers))
                raise ValueError(f"Unsupported Sigma field modifier(s) for {sigma_field}: {unsupported}")
            match_modifiers = [modifier for modifier in modifiers if modifier in {"contains", "endswith", "startswith"}]
            if len(match_modifiers) > 1:
                raise ValueError(f"Conflicting Sigma match modifiers for Wazuh conversion: {sigma_field}")
            if isinstance(value, (list, tuple, set, dict)):
                raise ValueError(
                    f"Sigma list selector values and other collections are not supported for Wazuh conversion: {sigma_field}"
                )
            field_name = FIELD_NAME_MAPPING.get(sigma_field)
            if field_name is None:
                field_name = next(
                    (
                        mapped_name
                        for mapped_sigma_field, mapped_name in FIELD_NAME_MAPPING.items()
                        if mapped_sigma_field.split("|", 1)[0] == base_field
                    ),
                    None,
                )
            if not field_name:
                continue
            match_type = match_modifiers[0] if match_modifiers else "exact"
            normalized_value = str(value)
            if field_name in fields and (
                fields[field_name] != normalized_value or match_types[field_name] != match_type
            ):
                raise ValueError(f"Cannot preserve multiple Sigma constraints for Wazuh field: {field_name}")
            fields[field_name] = normalized_value
            match_types[field_name] = match_type
    return fields, match_types


def _convert_detection_fields(detection: dict[str, object]) -> tuple[dict[str, str], dict[str, str]]:
    groups = _selector_groups(detection)
    if not groups:
        return {}, {}
    if len(groups) != 1:
        raise ValueError("Sigma OR conditions require separate Wazuh rule branches")
    return _convert_selector_group(groups[0])


def _allocate_wazuh_id(rule_id: str, used_ids: set[int], *, id_range: range | None = None) -> int:
    active_range = _validated_wazuh_id_range(id_range)
    span = len(active_range)
    wazuh_id = _deterministic_wazuh_id(rule_id, active_range) if id_range is not None else _deterministic_wazuh_id(rule_id)
    attempts = 0
    while wazuh_id in used_ids:
        wazuh_id += 1
        attempts += 1
        if wazuh_id > active_range.stop - 1:
            wazuh_id = active_range.start
        if attempts >= span:
            raise ValueError(
                f"Wazuh rule ID space exhausted: all {span} IDs in range "
                f"{active_range.start}-{active_range.stop - 1} are used."
            )
    return wazuh_id


def _escape_field_value(value: str, match_type: str = "contains") -> str:
    escaped = []
    for char in str(value):
        if char == "\\":
            escaped.append("\\\\")
        elif char in ".^$*+?{}[]|()":
            escaped.append(f"\\{char}")
        else:
            escaped.append(char)
    pattern = "".join(escaped)
    if match_type == "exact":
        return f"(?i)^{pattern}$"
    if match_type == "endswith":
        return f"(?i){pattern}$"
    if match_type == "startswith":
        return f"(?i)^{pattern}"
    return f"(?i){pattern}"


def _process_creation_fields(
    selectors: list[tuple[str, dict[str, object]]],
) -> tuple[dict[str, str], dict[str, str]]:
    fields, match_types = _convert_selector_group(selectors)
    image = str(fields.get("win.eventdata.image") or "").strip()
    command_line = str(fields.get("win.eventdata.commandLine") or "").strip()
    if not image and not command_line:
        return {}, {}
    process_fields: dict[str, str] = {}
    if image:
        process_fields["win.eventdata.image"] = image
    if command_line:
        process_fields["win.eventdata.commandLine"] = command_line
    return process_fields, {name: match_types.get(name, "contains") for name in process_fields}


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
    if category == "registry_event":
        return "Registry rule converted using the Sysmon Event ID 12, 13, and 14 parent rules and win.eventdata field matching."
    event_group = WINDOWS_LOGSOURCE_MAPPING.get(category, {}).get("if_group", "the matching Sysmon event group")
    return f"Non-process Windows rule converted using Wazuh parent group {event_group} and win.eventdata field matching."


def convert_sigma_to_wazuh(
    sigma_rules: list[SigmaRule] | None,
    *,
    id_registry: MutableMapping[str, int] | None = None,
    id_namespace: str | None = None,
    id_range: range | None = None,
) -> list[WazuhRule]:
    """Convert SigmaRule objects into WazuhRule objects."""
    active_id_range = _validated_wazuh_id_range(id_range)
    used_ids = _validated_registry_ids(id_registry, active_id_range)
    if not sigma_rules:
        return []

    sigma_rules_by_id: dict[str, SigmaRule] = {}
    for sigma_rule in sigma_rules:
        previous = sigma_rules_by_id.get(sigma_rule.rule_id)
        if previous is not None and previous != sigma_rule:
            raise ValueError(f"Conflicting Sigma rules share rule ID: {sigma_rule.rule_id}")
        sigma_rules_by_id[sigma_rule.rule_id] = sigma_rule

    converted: list[WazuhRule] = []
    seen: set[tuple[str, str, tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]] = set()

    for sigma_rule in sigma_rules:
        category = str(sigma_rule.logsource.get("category") or "")
        product = str(sigma_rule.logsource.get("product") or "windows").lower()
        mapping = _mapping_for_rule(sigma_rule)
        if not mapping:
            continue
        selector_groups = _selector_groups(sigma_rule.detection)
        for selector_group in selector_groups:
            if product == "windows" and category == "process_creation":
                fields, field_match_types = _process_creation_fields(selector_group)
            else:
                fields, field_match_types = _convert_selector_group(selector_group)
                event_id = WINDOWS_LOGSOURCE_EVENT_IDS.get(category) if product == "windows" else None
                if event_id:
                    fields.setdefault("win.system.eventID", event_id)
                    field_match_types.setdefault("win.system.eventID", "exact")
            if not fields:
                continue

            dedupe_key = (
                sigma_rule.rule_id,
                sigma_rule.description,
                tuple(sorted(fields.items())),
                tuple(sorted(field_match_types.items())),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            base_registry_key = f"{id_namespace}|{sigma_rule.rule_id}" if id_namespace else sigma_rule.rule_id
            selector_names = [name for name, _ in selector_group]
            registry_key = base_registry_key
            if len(selector_groups) > 1:
                registry_key = f"{base_registry_key}|branch:{'+'.join(selector_names)}"
            registered_id = id_registry.get(registry_key) if id_registry is not None else None
            wazuh_id = registered_id if registered_id is not None else _allocate_wazuh_id(
                registry_key,
                used_ids,
                id_range=active_id_range if id_range is not None else None,
            )
            used_ids.add(wazuh_id)
            if id_registry is not None:
                id_registry[registry_key] = wazuh_id

            converted.append(
                WazuhRule(
                    rule_id=wazuh_id,
                    level=SIGMA_TO_WAZUH_LEVEL.get(sigma_rule.level, SIGMA_TO_WAZUH_LEVEL["medium"]),
                    description=sigma_rule.description,
                    group=str(mapping["group"]),
                    decoded_as=mapping.get("decoded_as"),
                    if_sid=mapping.get("if_sid"),
                    if_group=mapping.get("if_group"),
                    fields=fields,
                    field_match_types=field_match_types,
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
                            "source_sigma_condition": sigma_rule.detection.get("condition"),
                            "source_sigma_selectors": selector_names,
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
            field = ET.SubElement(rule_element, "field", name=name, type="pcre2")
            field.text = _escape_field_value(value, rule.field_match_types.get(name, "contains"))
        description = ET.SubElement(rule_element, "description")
        description.text = rule.description
        if rule.group:
            group = ET.SubElement(rule_element, "group")
            group.text = rule.group
    else:
        if rule.if_group:
            if_group = ET.SubElement(rule_element, "if_group")
            if_group.text = rule.if_group

        if rule.decoded_as:
            decoded_as = ET.SubElement(rule_element, "decoded_as")
            decoded_as.text = rule.decoded_as

        if rule.if_sid is not None:
            if_sid = ET.SubElement(rule_element, "if_sid")
            if_sid.text = str(rule.if_sid)

        for name, value in sorted(rule.fields.items()):
            field = ET.SubElement(rule_element, "field", name=name, type="pcre2")
            field.text = _escape_field_value(value, rule.field_match_types.get(name, "contains"))

        description = ET.SubElement(rule_element, "description")
        description.text = rule.description

        if rule.group:
            group = ET.SubElement(rule_element, "group")
            group.text = rule.group

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
