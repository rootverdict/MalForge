"""Synthetic local test event generation for Sigma and Wazuh rules."""

from __future__ import annotations

from core.models import SigmaRule, WazuhRule


def _negative_value(field_name: str) -> str:
    if field_name.endswith("image") or "Image" in field_name:
        return "notepad.exe"
    if field_name.endswith("commandLine") or "CommandLine" in field_name:
        return "notepad.exe C:\\notes.txt"
    if "TargetObject" in field_name or field_name.endswith("targetObject"):
        return "HKCU\\Software\\BenignApp"
    if "TargetFilename" in field_name or field_name.endswith("targetFilename"):
        return "C:\\Users\\Public\\notes.txt"
    if "DestinationIp" in field_name or field_name.endswith("destinationIp"):
        return "127.0.0.1"
    if "QueryName" in field_name or field_name.endswith("queryName"):
        return "localhost.localdomain"
    if "DestinationHostname" in field_name or field_name.endswith("destinationHostname"):
        return "localhost.localdomain"
    return "benign-value"


def generate_sigma_test_events(rule: SigmaRule) -> dict[str, list[dict[str, object]]]:
    """Generate deterministic positive and negative synthetic events for a Sigma rule."""
    selections: list[dict[str, object]] = []
    if isinstance(rule.detection, dict):
        for key, value in rule.detection.items():
            if key.startswith("selection") and isinstance(value, dict):
                selections.append(value)
    positive_event: dict[str, object] = {"event_type": rule.logsource.get("category", "unknown")}
    negative_event: dict[str, object] = {"event_type": rule.logsource.get("category", "unknown")}

    for selection in selections:
        for key, value in selection.items():
            field_name = str(key).split("|", 1)[0]
            positive_event[field_name] = value
            negative_event[field_name] = _negative_value(field_name)

    return {"positive": [positive_event], "negative": [negative_event]}


def generate_wazuh_test_events(rule: WazuhRule) -> dict[str, list[dict[str, object]]]:
    """Generate deterministic positive and negative synthetic events for a Wazuh rule."""
    positive_event: dict[str, object] = {"group": rule.group, "decoder": rule.decoded_as or ""}
    negative_event: dict[str, object] = {"group": rule.group, "decoder": rule.decoded_as or ""}

    for field_name, value in rule.fields.items():
        positive_event[field_name] = value
        negative_event[field_name] = _negative_value(field_name)

    return {"positive": [positive_event], "negative": [negative_event]}


def generate_test_events(rule: SigmaRule | WazuhRule) -> dict[str, list[dict[str, object]]]:
    """Generate synthetic log-like test events for a Sigma or Wazuh rule."""
    if isinstance(rule, SigmaRule):
        return generate_sigma_test_events(rule)
    return generate_wazuh_test_events(rule)
