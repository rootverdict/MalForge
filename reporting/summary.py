"""Machine-readable reporting summary helpers."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping

from core.models import (
    AttackMapping,
    Behavior,
    IOC,
    RiskScore,
    SigmaRule,
    ValidationResult,
    WazuhRule,
)

TOOL_NAME = "malware-behavior-detection-generator"
TOOL_VERSION = "0.1.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _average(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 4)


def build_summary(
    *,
    normalized_report: Mapping[str, Any] | None = None,
    behaviors: list[Behavior] | None = None,
    iocs: list[IOC] | None = None,
    attack_mappings: list[AttackMapping] | None = None,
    sigma_rules: list[SigmaRule] | None = None,
    wazuh_rules: list[WazuhRule] | None = None,
    validation_results: list[ValidationResult] | None = None,
    risk_scores: list[RiskScore] | None = None,
    review_records: list[dict[str, Any]] | None = None,
    navigator_layer: Mapping[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-serializable summary from pipeline artifacts."""
    normalized_report = dict(normalized_report or {})
    behaviors = behaviors or []
    iocs = iocs or []
    attack_mappings = attack_mappings or []
    sigma_rules = sigma_rules or []
    wazuh_rules = wazuh_rules or []
    validation_results = validation_results or []
    risk_scores = risk_scores or []
    review_records = review_records or []
    navigator_layer = dict(navigator_layer or {})

    sample = dict(normalized_report.get("sample") or {})
    hashes = dict(sample.get("hashes") or {})
    missing_hashes = [name for name in ("md5", "sha1", "sha256") if not hashes.get(name)]

    behavior_counts = dict(sorted(Counter(item.category for item in behaviors).items()))
    ioc_counts = dict(sorted(Counter(item.type for item in iocs).items()))
    technique_ids = sorted({item.technique_id for item in attack_mappings})
    validation_failures = sum(1 for result in validation_results if not result.is_valid)
    validation_passes = sum(1 for result in validation_results if result.is_valid)
    validation_warning_count = sum(len(result.warnings) for result in validation_results)
    mapping_confidence_average = _average([item.confidence for item in attack_mappings])
    risk_average = _average([item.score for item in risk_scores])

    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": generated_at or _now_iso(),
        "sample": {
            "sandbox": normalized_report.get("sandbox", "unknown"),
            "name": sample.get("name"),
            "hashes": {
                "md5": hashes.get("md5"),
                "sha1": hashes.get("sha1"),
                "sha256": hashes.get("sha256"),
            },
            "hash_status": {
                "missing": missing_hashes,
                "complete": not missing_hashes,
                "note": "Payload hashes unavailable from source report." if missing_hashes else "All primary payload hashes are available.",
            },
        },
        "counts": {
            "behaviors_by_category": behavior_counts,
            "iocs_by_type": ioc_counts,
            "attack_technique_count": len(technique_ids),
            "sigma_rule_count": len(sigma_rules),
            "wazuh_rule_count": len(wazuh_rules),
            "validation": {
                "passed": validation_passes,
                "failed": validation_failures,
                "warning_count": validation_warning_count,
            },
        },
        "averages": {
            "attack_confidence": mapping_confidence_average,
            "risk_score": risk_average,
        },
        "artifacts": {
            "attack_techniques": technique_ids,
            "sigma_rule_ids": [rule.rule_id for rule in sigma_rules],
            "wazuh_rule_ids": [rule.rule_id for rule in wazuh_rules],
            "ioc_values": [{"type": item.type, "value": item.value} for item in iocs],
            "review_states": [record.get("status", "unreviewed") for record in review_records],
            "navigator_technique_count": len(navigator_layer.get("techniques", [])),
            "sigma_rule_traces": [
                {
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "trace": dict(rule.metadata.get("trace", {})),
                }
                for rule in sigma_rules
            ],
            "wazuh_rule_traces": [
                {
                    "rule_id": rule.rule_id,
                    "trace": dict(rule.options.get("trace", {})),
                }
                for rule in wazuh_rules
            ],
        },
    }
