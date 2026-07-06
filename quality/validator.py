"""Local validation helpers for Sigma and Wazuh rules."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from converters.wazuh_converter import wazuh_rule_to_xml
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
    selection = rule.detection.get("selection", {})

    if isinstance(selection, dict) and len(selection) == 1:
        only_value = next(iter(selection.values()), "")
        if str(only_value).strip().lower() in GENERIC_PROCESS_IMAGES:
            warnings.append("Selector may be overly broad for a common process image.")

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
        for selector_name, selector in rule.detection.items():
            if not selector_name.startswith("selection") or not isinstance(selector, dict):
                continue
            for key, value in selector.items():
                if not str(value).strip():
                    errors.append(f"Selector value is empty for {key}.")
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
    return [validate_sigma_rule(rule) for rule in rules or []]


def _warn_for_wazuh_rule(rule: WazuhRule) -> list[str]:
    warnings: list[str] = []
    if not rule.mitre_ids:
        warnings.append("Missing ATT&CK technique IDs.")
    if rule.level <= 4:
        warnings.append("Rule severity is weak and may need stronger evidence.")
    if len(rule.fields) <= 1:
        only_value = next(iter(rule.fields.values()), "")
        if str(only_value).strip().lower() in GENERIC_PROCESS_IMAGES:
            warnings.append("Selector may be overly broad for a common process image.")
    return warnings


def validate_wazuh_rule(rule: WazuhRule) -> ValidationResult:
    """Validate a WazuhRule and its XML serialization."""
    errors: list[str] = []

    if rule.rule_id <= 0:
        errors.append("Invalid rule ID.")
    if rule.level <= 0:
        errors.append("Invalid level.")
    if not rule.description.strip():
        errors.append("Missing description.")
    if rule.decoded_as is not None and not str(rule.decoded_as).strip():
        errors.append("Decoder metadata is empty.")

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
    return [validate_wazuh_rule(rule) for rule in rules or []]
