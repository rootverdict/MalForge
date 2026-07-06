"""Markdown reporting helpers for pipeline artifacts."""

from __future__ import annotations

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
from reporting.summary import build_summary


def _render_key_value_lines(items: list[tuple[str, Any]]) -> list[str]:
    return [f"- {label}: {value}" for label, value in items]


def generate_markdown_report(
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
    summary: Mapping[str, Any] | None = None,
) -> str:
    """Generate a deterministic Markdown report from pipeline artifacts."""
    if summary is None:
        summary = build_summary(
            normalized_report=normalized_report,
            behaviors=behaviors,
            iocs=iocs,
            attack_mappings=attack_mappings,
            sigma_rules=sigma_rules,
            wazuh_rules=wazuh_rules,
            validation_results=validation_results,
            risk_scores=risk_scores,
            review_records=review_records,
            navigator_layer=navigator_layer,
            generated_at=generated_at,
        )

    sample = summary.get("sample", {})
    counts = summary.get("counts", {})
    averages = summary.get("averages", {})
    artifacts = summary.get("artifacts", {})
    validation = counts.get("validation", {})
    review_states = artifacts.get("review_states", [])

    lines: list[str] = [
        "# Malware Behavior Detection Report",
        "",
        "## Sample Overview",
        *(_render_key_value_lines(
            [
                ("Sandbox", sample.get("sandbox", "unknown")),
                ("Sample name", sample.get("name") or "unknown"),
                ("MD5", sample.get("hashes", {}).get("md5") or "n/a"),
                ("SHA256", sample.get("hashes", {}).get("sha256") or "n/a"),
                ("Generated at", summary.get("generated_at", "n/a")),
            ]
        )),
        "",
        "## Behavior Summary",
    ]

    hash_status = sample.get("hash_status", {})
    if hash_status.get("missing"):
        lines.extend(
            [
                "",
                "## Source Data Limitations",
                f"- Missing payload hashes: {', '.join(hash_status.get('missing', []))}",
                f"- Note: {hash_status.get('note', 'Payload hashes unavailable from source report.')}",
            ]
        )

    behavior_counts = counts.get("behaviors_by_category", {})
    if behavior_counts:
        lines.extend(f"- {category}: {count}" for category, count in behavior_counts.items())
    else:
        lines.append("- No behaviors extracted.")

    lines.extend(["", "## IOC Summary"])
    ioc_counts = counts.get("iocs_by_type", {})
    if ioc_counts:
        lines.extend(f"- {ioc_type}: {count}" for ioc_type, count in ioc_counts.items())
    else:
        lines.append("- No IOCs extracted.")
    ioc_values = artifacts.get("ioc_values", [])
    if ioc_values:
        lines.append("")
        lines.append("### IOC Values")
        lines.extend(f"- {entry.get('type')}: {entry.get('value')}" for entry in ioc_values)

    lines.extend(["", "## ATT&CK Mappings"])
    attack_techniques = artifacts.get("attack_techniques", [])
    if attack_techniques:
        lines.extend(f"- {technique_id}" for technique_id in attack_techniques)
    else:
        lines.append("- No ATT&CK mappings generated.")

    lines.extend(["", "## Generated Sigma Rules"])
    sigma_rule_ids = artifacts.get("sigma_rule_ids", [])
    if sigma_rule_ids:
        lines.extend(f"- {rule_id}" for rule_id in sigma_rule_ids)
    else:
        lines.append("- No Sigma rules generated.")

    lines.extend(["", "## Generated Wazuh Rules"])
    wazuh_rule_ids = artifacts.get("wazuh_rule_ids", [])
    if wazuh_rule_ids:
        lines.extend(f"- {rule_id}" for rule_id in wazuh_rule_ids)
    else:
        lines.append("- No Wazuh rules generated.")

    lines.extend(["", "## Rule Generation Rationale"])
    sigma_rule_traces = artifacts.get("sigma_rule_traces", [])
    wazuh_rule_traces = artifacts.get("wazuh_rule_traces", [])
    if sigma_rule_traces or wazuh_rule_traces:
        for entry in sigma_rule_traces:
            trace = entry.get("trace", {})
            lines.append(f"- Sigma {entry.get('rule_id')}: {trace.get('source_behavior_description', 'n/a')}")
            lines.append(f"  ATT&CK: {', '.join(trace.get('attack_technique_ids', [])) or 'n/a'}")
            lines.append(f"  Why: {trace.get('selector_reason', 'n/a')}")
        for entry in wazuh_rule_traces:
            trace = entry.get("trace", {})
            lines.append(f"- Wazuh {entry.get('rule_id')}: {trace.get('source_sigma_rule_id', 'n/a')}")
            lines.append(f"  Why: {trace.get('conversion_reason', 'n/a')}")
    else:
        lines.append("- No rule rationale available.")

    lines.extend(["", "## Validation Warnings"])
    if validation.get("warning_count", 0):
        lines.append(f"- Warning count: {validation['warning_count']}")
        lines.append(f"- Passed validations: {validation.get('passed', 0)}")
        lines.append(f"- Failed validations: {validation.get('failed', 0)}")
    else:
        lines.append("- No validation warnings.")

    lines.extend(["", "## Risk Scoring"])
    risk_average = averages.get("risk_score")
    lines.append(f"- Average risk score: {risk_average if risk_average is not None else 'n/a'}")
    lines.append(
        f"- Average ATT&CK confidence: {averages.get('attack_confidence') if averages.get('attack_confidence') is not None else 'n/a'}"
    )

    lines.extend(["", "## Review Status"])
    if review_states:
        for state in review_states:
            lines.append(f"- {state}")
    else:
        lines.append("- No review records.")

    lines.extend(["", "## Output Artifact List"])
    lines.extend(
        _render_key_value_lines(
            [
                ("Navigator techniques", artifacts.get("navigator_technique_count", 0)),
                ("Sigma rule count", counts.get("sigma_rule_count", 0)),
                ("Wazuh rule count", counts.get("wazuh_rule_count", 0)),
            ]
        )
    )

    return "\n".join(lines)
