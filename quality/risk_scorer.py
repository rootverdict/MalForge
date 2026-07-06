"""Deterministic local risk scoring for Sigma and Wazuh rules."""

from __future__ import annotations

from core.models import RiskScore, SigmaRule, WazuhRule

SIGMA_SEVERITY_SCORE = {
    "informational": 10.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 90.0,
}


def _severity_from_wazuh_level(level: int) -> str:
    if level >= 14:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def _score_sigma_rule(rule: SigmaRule) -> RiskScore:
    selection_items: list[tuple[object, object]] = []
    if isinstance(rule.detection, dict):
        for key, value in rule.detection.items():
            if key.startswith("selection") and isinstance(value, dict):
                selection_items.extend(value.items())
    factors = {
        "severity_base": SIGMA_SEVERITY_SCORE[rule.level],
        "selector_specificity": 0.0,
        "false_positive_penalty": 0.0,
        "attack_bonus": 0.0,
    }
    rationale: list[str] = [f"Base score derived from Sigma level {rule.level}."]

    for field_name, value in selection_items:
        normalized_field = str(field_name)
        normalized_value = str(value).strip()
        if any(token in normalized_field for token in ("CommandLine", "TargetObject", "TargetFilename", "DestinationIp", "QueryName", "DestinationHostname")):
            factors["selector_specificity"] += 12.0
            rationale.append(f"Specific selector present: {normalized_field}.")
        elif "Image" in normalized_field:
            factors["selector_specificity"] += 5.0
            if normalized_value.lower() in {"cmd.exe", "powershell.exe", "rundll32.exe"}:
                factors["false_positive_penalty"] += 8.0
                rationale.append("Generic process image selector increases false positive risk.")

    factors["selector_specificity"] = min(factors["selector_specificity"], 30.0)
    factors["false_positive_penalty"] = min(factors["false_positive_penalty"], 20.0)

    if any(tag.startswith("attack.") for tag in rule.tags):
        factors["attack_bonus"] = 8.0
        rationale.append("ATT&CK tags increase confidence in rule intent.")

    if not rule.falsepositives:
        factors["false_positive_penalty"] += 10.0
        rationale.append("Missing false positive guidance increases uncertainty.")

    score = (
        factors["severity_base"]
        + factors["selector_specificity"]
        + factors["attack_bonus"]
        - factors["false_positive_penalty"]
    )
    score = max(0.0, min(100.0, score))
    return RiskScore(score=score, severity=rule.level, rationale=rationale, factors=factors)


def _score_wazuh_rule(rule: WazuhRule) -> RiskScore:
    severity = _severity_from_wazuh_level(rule.level)
    factors = {
        "severity_base": SIGMA_SEVERITY_SCORE[severity],
        "field_specificity": 0.0,
        "false_positive_penalty": 0.0,
        "attack_bonus": 0.0,
    }
    rationale: list[str] = [f"Base score derived from Wazuh level {rule.level}."]

    for field_name, value in rule.fields.items():
        normalized_field = str(field_name)
        normalized_value = str(value).strip()
        if any(token in normalized_field for token in ("commandLine", "targetObject", "targetFilename", "destinationIp", "queryName", "destinationHostname")):
            factors["field_specificity"] += 12.0
            rationale.append(f"Specific field present: {normalized_field}.")
        elif normalized_field.endswith(".image"):
            factors["field_specificity"] += 5.0
            if normalized_value.lower() in {"cmd.exe", "powershell.exe", "rundll32.exe"}:
                factors["false_positive_penalty"] += 8.0
                rationale.append("Generic process image selector increases false positive risk.")

    factors["field_specificity"] = min(factors["field_specificity"], 30.0)
    factors["false_positive_penalty"] = min(factors["false_positive_penalty"], 20.0)

    if rule.mitre_ids:
        factors["attack_bonus"] = 8.0
        rationale.append("MITRE technique IDs increase confidence in rule intent.")

    if len(rule.fields) <= 1:
        factors["false_positive_penalty"] += 6.0
        rationale.append("Single-field selector may be noisier.")

    score = (
        factors["severity_base"]
        + factors["field_specificity"]
        + factors["attack_bonus"]
        - factors["false_positive_penalty"]
    )
    score = max(0.0, min(100.0, score))
    return RiskScore(score=score, severity=severity, rationale=rationale, factors=factors)


def score_rule(rule: SigmaRule | WazuhRule) -> RiskScore:
    """Score a Sigma or Wazuh rule using simple deterministic heuristics."""
    if isinstance(rule, SigmaRule):
        return _score_sigma_rule(rule)
    return _score_wazuh_rule(rule)
