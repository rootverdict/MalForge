"""Local end-to-end pipeline orchestration and output helpers."""

from __future__ import annotations

import json
from dataclasses import asdict
import re
from pathlib import Path
from typing import Any, Mapping

from attck.mapper import map_behaviors_to_attack
from attck.navigator import generate_navigator_layer
from converters.wazuh_converter import configure_wazuh_id_range, convert_sigma_to_wazuh, wazuh_rules_to_xml
from core.models import PipelineResult, RiskScore
from core.schema import detect_sandbox, load_json_report
from extractor import extract_behaviors
from generators.sigma_generator import generate_sigma_rules, rule_to_dict
from ingestion.anyrun import parse_report as parse_anyrun_report
from ingestion.cape import parse_report as parse_cape_report
from ingestion.cuckoo import parse_report as parse_cuckoo_report
from ioc.ioc_extractor import extract_all_iocs
from quality.risk_scorer import score_rule
from quality.test_event_generator import generate_test_events
from quality.validator import validate_sigma_rules, validate_wazuh_rules
from reporting.report_generator import generate_markdown_report
from reporting.summary import build_summary
from review.reviewer import apply_review_to_rules, create_review_record
from review.versioner import _now_iso
from review.versioner import version_rules
from enrichment.virustotal import build_lookup_request as build_virustotal_lookup_request
from enrichment.misp import build_lookup_request as build_misp_lookup_request
from enrichment.urlhaus import enrich_iocs_with_urlhaus

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

PARSER_MAP = {
    "cuckoo": parse_cuckoo_report,
    "cape": parse_cape_report,
    "anyrun": parse_anyrun_report,
}

_WINDOWS_RESERVED = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{i}" for i in range(1, 10)),
        *(f"lpt{i}" for i in range(1, 10)),
    }
)


def _slugify(value: str, max_length: int = 80) -> str:
    slug = "".join(char.lower() if char.isalnum() else "_" for char in value)
    while "__" in slug:
        slug = slug.replace("__", "_")
    slug = slug.strip("_") or "report"
    if slug in _WINDOWS_RESERVED:
        slug = f"sample_{slug}"
    return slug[:max_length]


def _derive_summary_risk(risk_scores: list[RiskScore]) -> RiskScore | None:
    if not risk_scores:
        return None
    sorted_scores = sorted(item.score for item in risk_scores)
    count = len(sorted_scores)
    p90_index = min(count - 1, max(0, -(-count * 9 // 10) - 1))
    p90_value = sorted_scores[p90_index]
    top_n = max(1, count // 10)
    top_avg = sum(sorted_scores[-top_n:]) / top_n
    representative = round((p90_value + top_avg) / 2, 4)
    representative = max(0.0, min(100.0, representative))
    if representative >= 85:
        severity = "critical"
    elif representative >= 70:
        severity = "high"
    elif representative >= 45:
        severity = "medium"
    elif representative >= 20:
        severity = "low"
    else:
        severity = "informational"
    return RiskScore(
        score=representative,
        severity=severity,
        rationale=[
            f"P90 score across {count} rules: {p90_value}.",
            f"Top-decile average ({top_n} rule(s)): {round(top_avg, 4)}.",
            "Representative is the midpoint of p90 and top-decile average.",
        ],
        factors={
            "rule_count": count,
            "p90_score": p90_value,
            "top_n": top_n,
            "top_avg": round(top_avg, 4),
        },
    )


def _resolve_report_input(report_input: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    if isinstance(report_input, Mapping):
        return dict(report_input), None
    report_path = Path(report_input)
    if not report_path.exists():
        raise FileNotFoundError(f"Report path does not exist: {report_path}")
    return load_json_report(report_path), str(report_path)


def _valid_sha256(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if re.fullmatch(r"[a-f0-9]{64}", normalized) else None


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_pipeline_outputs(
    result: PipelineResult,
    output_dir: str | Path,
    *,
    base_name: str = "report",
) -> dict[str, list[str]]:
    """Write pipeline artifacts under the configured output directory only."""
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    file_map: dict[str, list[str]] = {
        "sigma": [],
        "wazuh": [],
        "test_events": [],
        "reports": [],
        "iocs": [],
        "navigator": [],
    }

    sigma_dir = output_root / "sigma"
    for rule in result.sigma_rules:
        payload = rule_to_dict(rule)
        if yaml is not None:
            sigma_path = sigma_dir / f"{base_name}_{rule.rule_id}.yml"
            _write_text(sigma_path, yaml.safe_dump(payload, sort_keys=False))
        else:
            sigma_path = sigma_dir / f"{base_name}_{rule.rule_id}.json"
            _write_json(sigma_path, payload)
        file_map["sigma"].append(str(sigma_path))

    if result.wazuh_rules:
        wazuh_path = output_root / "wazuh" / f"{base_name}.xml"
        _write_text(wazuh_path, wazuh_rules_to_xml(result.wazuh_rules))
        file_map["wazuh"].append(str(wazuh_path))

    test_event_path = output_root / "test_events" / f"{base_name}.json"
    _write_json(test_event_path, result.metadata.get("test_events", {}))
    file_map["test_events"].append(str(test_event_path))

    report_path = output_root / "reports" / f"{base_name}_report.md"
    _write_text(report_path, str(result.metadata.get("markdown_report", "")))
    file_map["reports"].append(str(report_path))

    summary_path = output_root / "reports" / f"{base_name}_summary.json"
    _write_json(summary_path, result.metadata.get("summary", {}))
    file_map["reports"].append(str(summary_path))

    iocs_json_path = output_root / "iocs" / f"{base_name}_iocs.json"
    iocs_txt_path = output_root / "iocs" / f"{base_name}_iocs.txt"
    _write_json(iocs_json_path, [asdict(item) for item in result.iocs])
    _write_text(iocs_txt_path, "\n".join(f"{item.type}: {item.value}" for item in result.iocs))
    file_map["iocs"].extend([str(iocs_json_path), str(iocs_txt_path)])

    navigator_path = output_root / "navigator" / f"{base_name}_navigator_layer.json"
    _write_json(navigator_path, result.metadata.get("navigator_layer", {}))
    file_map["navigator"].append(str(navigator_path))
    return file_map


def run_pipeline(
    report_input: str | Path | Mapping[str, Any],
    *,
    sandbox: str = "auto",
    output_dir: str | Path = "output",
    write_output: bool = True,
    timestamp: str | None = None,
    enrich: bool = False,
    urlhaus_csv: str | Path | None = None,
    wazuh_id_start: int | None = None,
    wazuh_id_end: int | None = None,
) -> PipelineResult:
    """Run the full local pipeline on a sandbox report."""
    raw_report, input_path = _resolve_report_input(report_input)
    sandbox_name = sandbox if sandbox != "auto" else detect_sandbox(raw_report)
    if sandbox_name == "unknown":
        raise ValueError("Could not detect sandbox type from report")
    if sandbox_name not in PARSER_MAP:
        raise ValueError(f"Unsupported sandbox type: {sandbox_name}")
    run_timestamp = timestamp or _now_iso()
    if wazuh_id_start is not None or wazuh_id_end is not None:
        if wazuh_id_start is None or wazuh_id_end is None:
            raise ValueError("Both wazuh_id_start and wazuh_id_end must be provided together")
        configure_wazuh_id_range(wazuh_id_start, wazuh_id_end)

    normalized_report = PARSER_MAP[sandbox_name](raw_report)
    behaviors = extract_behaviors(normalized_report)
    iocs = extract_all_iocs(normalized_report, behaviors)
    attack_mappings = map_behaviors_to_attack(behaviors)
    navigator_layer = generate_navigator_layer(
        attack_mappings,
        name=f"{normalized_report.get('sample', {}).get('name', 'Sample')} ATT&CK Layer",
    )

    review_record = create_review_record("unreviewed")
    sigma_rules = generate_sigma_rules(behaviors, attack_mappings)
    sigma_rules = [rule for rule in apply_review_to_rules(sigma_rules, review_record) if hasattr(rule, "rule_id")]
    sample_hash = _valid_sha256(normalized_report.get("sample", {}).get("hashes", {}).get("sha256"))
    sigma_rules = [rule for rule in version_rules(sigma_rules, timestamp=run_timestamp, source_report_hash=sample_hash) if hasattr(rule, "rule_id")]

    wazuh_rules = convert_sigma_to_wazuh(sigma_rules)
    wazuh_rules = [rule for rule in apply_review_to_rules(wazuh_rules, review_record) if hasattr(rule, "rule_id")]
    wazuh_rules = [rule for rule in version_rules(wazuh_rules, timestamp=run_timestamp, source_report_hash=sample_hash) if hasattr(rule, "rule_id")]

    validation_results = validate_sigma_rules(sigma_rules) + validate_wazuh_rules(wazuh_rules)
    risk_scores = [score_rule(rule) for rule in [*sigma_rules, *wazuh_rules]]
    aggregate_risk = _derive_summary_risk(risk_scores)
    test_events = {
        "sigma": {rule.rule_id: generate_test_events(rule) for rule in sigma_rules},
        "wazuh": {str(rule.rule_id): generate_test_events(rule) for rule in wazuh_rules},
    }
    enrichment = {}
    if enrich:
        enrichment = {
            "virustotal": [build_virustotal_lookup_request(item.type, item.value) for item in iocs],
            "misp": [build_misp_lookup_request(item.type, item.value) for item in iocs],
        }
        if urlhaus_csv:
            enrichment["urlhaus"] = enrich_iocs_with_urlhaus(iocs, urlhaus_csv)

    summary = build_summary(
        normalized_report=normalized_report,
        behaviors=behaviors,
        iocs=iocs,
        attack_mappings=attack_mappings,
        sigma_rules=sigma_rules,
        wazuh_rules=wazuh_rules,
        validation_results=validation_results,
        risk_scores=risk_scores,
        review_records=[review_record],
        navigator_layer=navigator_layer,
        generated_at=run_timestamp,
    )
    markdown_report = generate_markdown_report(summary=summary)

    result = PipelineResult(
        source=sandbox_name,
        input_file=input_path,
        behaviors=behaviors,
        iocs=iocs,
        sigma_rules=sigma_rules,
        wazuh_rules=wazuh_rules,
        attack_mappings=attack_mappings,
        validation_results=validation_results,
        risk_score=aggregate_risk,
        metadata={
            "normalized_report": normalized_report,
            "navigator_layer": navigator_layer,
            "summary": summary,
            "markdown_report": markdown_report,
            "test_events": test_events,
            "enrichment": enrichment,
            "review_records": [review_record],
            "risk_scores": [asdict(item) for item in risk_scores],
            "output_files": {},
        },
    )

    if write_output:
        sample_name = str(normalized_report.get("sample", {}).get("name") or Path(input_path or "report").stem)
        result.metadata["output_files"] = write_pipeline_outputs(
            result,
            output_dir,
            base_name=_slugify(sample_name),
        )

    return result
