"""Local validation helpers for Sigma and Wazuh rules."""

from __future__ import annotations

from collections import Counter
import ipaddress
import re
import xml.etree.ElementTree as ET

from converters.wazuh_converter import _selector_groups, wazuh_rule_to_xml
from core.models import SigmaRule, ValidationResult, WazuhRule

GENERIC_PROCESS_IMAGES = {
    "cmd.exe",
    "powershell.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "sc.exe",
    "schtasks.exe",
}


def _warn_for_sigma_rule(rule: SigmaRule) -> list[str]:
    warnings: list[str] = []
    if isinstance(rule.detection, dict):
        for name, selection in rule.detection.items():
            if not name.startswith("selection") or not isinstance(selection, dict) or len(selection) != 1:
                continue
            only_value = next(iter(selection.values()), "")
            if str(only_value).strip().lower() in GENERIC_PROCESS_IMAGES:
                warnings.append("Selector may be overly broad for a common process image.")
                break

    if not any(tag.startswith("attack.") for tag in rule.tags):
        warnings.append("Missing ATT&CK tags.")
    if not rule.falsepositives:
        warnings.append("False positive guidance is empty.")
    if rule.level in {"low", "informational"}:
        warnings.append("Rule severity is weak and may need stronger evidence.")

    return warnings


def validate_sigma_rule(rule: SigmaRule) -> ValidationResult:
    """Validate a SigmaRule for required fields and basic quality signals."""
    errors: list[str] = []

    if not rule.title.strip():
        errors.append("Missing title.")
    if not isinstance(rule.logsource, dict) or not rule.logsource:
        errors.append("Missing logsource.")
    if not isinstance(rule.detection, dict) or not rule.detection:
        errors.append("Missing detection.")
    if not isinstance(rule.detection, dict) or not str(rule.detection.get("condition") or "").strip():
        errors.append("Missing detection condition.")
    if isinstance(rule.detection, dict):
        populated_selectors = 0
        for selector_name, selector in rule.detection.items():
            if not selector_name.startswith("selection") or not isinstance(selector, dict):
                continue
            if selector:
                populated_selectors += 1
            for key, value in selector.items():
                if not str(value).strip():
                    errors.append(f"Selector value is empty for {key}.")
                base_field = str(key).split("|", 1)[0]
                if base_field in {"DestinationIp", "destination.ip"}:
                    try:
                        ipaddress.ip_address(str(value).strip().strip("[]"))
                    except ValueError:
                        errors.append(f"Selector contains an invalid IP address for {key}.")
        if populated_selectors == 0:
            errors.append("Detection has no populated selectors.")
        elif str(rule.detection.get("condition") or "").strip():
            try:
                _selector_groups(rule.detection)
            except ValueError as exc:
                errors.append(f"Unsupported detection condition: {exc}")
    if not rule.level.strip():
        errors.append("Missing level.")

    warnings = _warn_for_sigma_rule(rule)
    is_valid = not errors
    score = max(0.0, min(1.0, 1.0 - (0.25 * len(errors)) - (0.05 * len(warnings))))
    return ValidationResult(
        is_valid=is_valid,
        validator="sigma",
        score=score,
        errors=errors,
        warnings=warnings,
        details={"rule_id": rule.rule_id, "title": rule.title},
    )


def validate_sigma_rules(rules: list[SigmaRule] | None) -> list[ValidationResult]:
    """Validate a list of Sigma rules."""
    rule_list = rules or []
    results = [validate_sigma_rule(rule) for rule in rule_list]
    duplicate_ids = {rule_id for rule_id, count in Counter(rule.rule_id for rule in rule_list).items() if count > 1}
    for rule, result in zip(rule_list, results, strict=True):
        if rule.rule_id in duplicate_ids:
            result.errors.append(f"Duplicate Sigma rule ID: {rule.rule_id}.")
            result.is_valid = False
            result.score = max(0.0, result.score - 0.25)
    return results


def _warn_for_wazuh_rule(rule: WazuhRule) -> list[str]:
    warnings: list[str] = []
    if not rule.mitre_ids:
        warnings.append("Missing ATT&CK technique IDs.")
    if type(rule.level) is int and rule.level <= 4:
        warnings.append("Rule severity is weak and may need stronger evidence.")
    if len(rule.fields) <= 1:
        only_value = next(iter(rule.fields.values()), "")
        if str(only_value).strip().lower() in GENERIC_PROCESS_IMAGES:
            warnings.append("Selector may be overly broad for a common process image.")
    return warnings


def validate_wazuh_rule(rule: WazuhRule) -> ValidationResult:
    """Validate a WazuhRule and its XML serialization."""
    errors: list[str] = []

    if type(rule.rule_id) is not int or not 1 <= rule.rule_id <= 999999:
        errors.append("Invalid rule ID.")
    if type(rule.level) is not int or not 1 <= rule.level <= 16:
        errors.append("Invalid level.")
    if not rule.description.strip():
        errors.append("Missing description.")
    if rule.decoded_as is not None and not str(rule.decoded_as).strip():
        errors.append("Decoder metadata is empty.")
    if rule.if_group is not None and not str(rule.if_group).strip():
        errors.append("Parent group metadata is empty.")
    if rule.if_sid is not None:
        if isinstance(rule.if_sid, bool):
            errors.append("Parent rule metadata must contain positive numeric Wazuh rule IDs.")
        elif isinstance(rule.if_sid, int):
            if not 1 <= rule.if_sid <= 999999:
                errors.append("Parent rule metadata must contain positive numeric Wazuh rule IDs.")
        elif re.fullmatch(r"\s*[1-9]\d{0,5}\s*(?:,\s*[1-9]\d{0,5}\s*)*", str(rule.if_sid)) is None:
            errors.append("Parent rule metadata must contain positive numeric Wazuh rule IDs.")
    if any(name.startswith("win.") for name in rule.fields) and not (rule.if_sid or rule.if_group or rule.decoded_as == "windows_eventchannel"):
        errors.append("Windows EventChannel fields require a Sysmon parent rule/group or windows_eventchannel decoder.")
    invalid_match_types = set(rule.field_match_types.values()) - {"exact", "contains", "endswith", "startswith"}
    if invalid_match_types:
        errors.append(f"Unsupported field match types: {', '.join(sorted(str(value) for value in invalid_match_types))}.")
    unknown_match_fields = set(rule.field_match_types) - set(rule.fields)
    if unknown_match_fields:
        errors.append(f"Match types reference unknown fields: {', '.join(sorted(unknown_match_fields))}.")

    try:
        ET.fromstring(wazuh_rule_to_xml(rule))
    except ET.ParseError as exc:
        errors.append(f"Generated XML is not parseable: {exc}")

    warnings = _warn_for_wazuh_rule(rule)
    is_valid = not errors
    score = max(0.0, min(1.0, 1.0 - (0.25 * len(errors)) - (0.05 * len(warnings))))
    return ValidationResult(
        is_valid=is_valid,
        validator="wazuh",
        score=score,
        errors=errors,
        warnings=warnings,
        details={"rule_id": rule.rule_id, "group": rule.group},
    )


def validate_wazuh_rules(rules: list[WazuhRule] | None) -> list[ValidationResult]:
    """Validate a list of Wazuh rules."""
    rule_list = rules or []
    results = [validate_wazuh_rule(rule) for rule in rule_list]
    duplicate_ids = {rule_id for rule_id, count in Counter(rule.rule_id for rule in rule_list).items() if count > 1}
    for rule, result in zip(rule_list, results, strict=True):
        if rule.rule_id in duplicate_ids:
            result.errors.append(f"Duplicate Wazuh rule ID: {rule.rule_id}.")
            result.is_valid = False
            result.score = max(0.0, result.score - 0.25)
    return results
